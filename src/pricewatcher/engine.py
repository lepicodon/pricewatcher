"""Core polling engine: fetch -> normalize -> match -> diff -> notify -> persist."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import inspect
import threading
import time
from typing import Any, cast
import weakref

from pricewatcher.adapters import get_adapter
from pricewatcher.adapters.base import FetchOutcome, Listing, SourceAdapter
from pricewatcher.config import ConfigStore, SettingsConfig, SourceConfig, WatchConfig
from pricewatcher.matcher import evaluate_listing
from pricewatcher.notifiers.base import (
    NotificationDispatcher,
    format_deal_alert,
    format_startup_summary,
)
from pricewatcher.storage import Database


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts)
        return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)
    except ValueError:
        return None


def _accepts_http_ctx(fetch_fn: Any) -> bool:
    try:
        sig = inspect.signature(fetch_fn)
    except TypeError, ValueError:
        return False
    return any(
        p.name == "http_ctx" or p.kind == inspect.Parameter.VAR_KEYWORD
        for p in sig.parameters.values()
    )


@dataclass
class WatchRunReport:
    watch_id: str
    status: str
    skipped: bool = False
    already_running: bool = False
    sources_checked: int = 0
    sources_ok: int = 0
    items_fetched: int = 0
    items_matched: int = 0
    alerts_triggered: int = 0
    alerts_delivered: int = 0
    tier_bests: dict[str, dict[str, Any]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


class PollEngine:
    """Executes poll cycles across watches with failure-safe alert state updates."""

    def __init__(
        self,
        *,
        store: ConfigStore,
        db: Database,
        dispatcher: NotificationDispatcher | None = None,
        adapter_factory: Callable[[str], SourceAdapter] = get_adapter,
        http_ctx: Any = None,
    ) -> None:
        self.store = store
        self.db = db
        self._dispatcher = dispatcher
        self.adapter_factory = adapter_factory
        self.http_ctx = http_ctx
        self._watch_locks: dict[str, asyncio.Lock] = {}
        self._watch_locks_loop: asyncio.AbstractEventLoop | None = None
        self._extra_loop_locks: weakref.WeakKeyDictionary[
            asyncio.AbstractEventLoop, dict[str, asyncio.Lock]
        ] = weakref.WeakKeyDictionary()
        self._locks_guard = threading.RLock()

    def _get_watch_lock(self, watch_id: str) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        with self._locks_guard:
            if self._watch_locks_loop is not loop:
                if self._watch_locks_loop is None or self._watch_locks_loop.is_closed():
                    self._watch_locks.clear()
                    self._watch_locks_loop = loop
                else:
                    loop_map = self._extra_loop_locks.setdefault(loop, {})
                    lock = loop_map.get(watch_id)
                    if lock is None:
                        lock = asyncio.Lock()
                        loop_map[watch_id] = lock
                    return lock
            lock = self._watch_locks.get(watch_id)
            if lock is None:
                lock = asyncio.Lock()
                self._watch_locks[watch_id] = lock
            return lock

    def _get_dispatcher(self, settings: SettingsConfig) -> NotificationDispatcher:
        return self._dispatcher or NotificationDispatcher(settings)

    async def poll_watch(
        self,
        watch: WatchConfig,
        *,
        settings: SettingsConfig | None = None,
        dry_run: bool = False,
        force: bool = False,
        now: datetime | None = None,
    ) -> WatchRunReport:
        current = now or _utcnow()
        lock = self._get_watch_lock(watch.id)
        if lock.locked():
            return WatchRunReport(
                watch_id=watch.id,
                status=watch.effective_status(now=current),
                skipped=True,
                already_running=True,
            )

        await lock.acquire()
        try:
            effective_status = watch.effective_status(now=current)
            if effective_status == "expired":
                await asyncio.to_thread(
                    self.db.update_watch_runtime,
                    watch_id=watch.id,
                    last_run_at=current.isoformat(),
                    last_status="expired",
                )
                return WatchRunReport(watch_id=watch.id, status="expired", skipped=True)

            if effective_status == "paused" and not force:
                return WatchRunReport(watch_id=watch.id, status="paused", skipped=True)

            loaded_settings = (
                settings
                if settings is not None
                else await asyncio.to_thread(self.store.load_settings)
            )
            dispatcher = self._get_dispatcher(loaded_settings)

            enabled_sources = [source for source in watch.sources if source.enabled]
            report = WatchRunReport(
                watch_id=watch.id,
                status=effective_status,
                sources_checked=len(enabled_sources),
            )
            now_iso = current.isoformat()

            concurrency = max(1, loaded_settings.server.fetch_concurrency)
            semaphore = asyncio.Semaphore(concurrency)

            async def _fetch_source(source: SourceConfig) -> tuple[SourceConfig, FetchOutcome]:
                async with semaphore:
                    started = time.monotonic()
                    try:
                        adapter = self.adapter_factory(source.adapter)
                        if self.http_ctx is not None and _accepts_http_ctx(adapter.fetch):
                            outcome = await cast(Any, adapter).fetch(source, http_ctx=self.http_ctx)
                        else:
                            outcome = await adapter.fetch(source)
                    except Exception as exc:
                        outcome = FetchOutcome(
                            error=f"{type(exc).__name__}: {exc}",
                            latency_ms=int((time.monotonic() - started) * 1000),
                        )
                    return source, outcome

            fetch_results: list[tuple[SourceConfig, FetchOutcome]] = []
            if enabled_sources:
                fetch_results = list(
                    await asyncio.gather(*(_fetch_source(source) for source in enabled_sources))
                )

            def _persist_and_load() -> tuple[
                dict[str, Listing],
                dict[str, list[Listing]],
                dict[str, dict[str, Any]],
                dict[str, Any] | None,
            ]:
                local_bests: dict[str, Listing] = {}
                local_ties: dict[str, list[Listing]] = {}

                with self.db.transaction():
                    for source, outcome in fetch_results:
                        if outcome.error:
                            report.errors.append(f"{source.name}: {outcome.error}")
                        else:
                            report.sources_ok += 1

                        report.items_fetched += len(outcome.listings)
                        matched_in_source = 0

                        for listing in outcome.listings:
                            match = evaluate_listing(listing, watch.rules)
                            if not match.matched:
                                continue
                            matched_in_source += 1
                            report.items_matched += 1

                            normalized_listing = listing.model_copy(
                                update={"condition": match.normalized_condition}
                            )
                            self.db.upsert_observation(
                                watch_id=watch.id,
                                tier_key=match.tier_key,
                                source_name=normalized_listing.source_name,
                                merchant=normalized_listing.merchant,
                                title=normalized_listing.title,
                                url=normalized_listing.url,
                                price=normalized_listing.price,
                                currency=normalized_listing.currency,
                                condition=normalized_listing.condition,
                                in_stock=normalized_listing.in_stock,
                                promo_code=normalized_listing.promo_code,
                                specs=match.extracted,
                                observed_at=now_iso,
                            )
                            existing_best = local_bests.get(match.tier_key)
                            if (
                                existing_best is None
                                or normalized_listing.price < existing_best.price - 0.005
                            ):
                                local_bests[match.tier_key] = normalized_listing
                                local_ties[match.tier_key] = [normalized_listing]
                            elif abs(normalized_listing.price - existing_best.price) <= 0.005:
                                ties = local_ties.setdefault(match.tier_key, [existing_best])
                                if all(
                                    t.merchant.strip().lower()
                                    != normalized_listing.merchant.strip().lower()
                                    for t in ties
                                ):
                                    ties.append(normalized_listing)

                        self.db.upsert_source_health(
                            watch_id=watch.id,
                            source_name=source.name,
                            url=source.url,
                            http_status=outcome.http_status,
                            item_count=len(outcome.listings),
                            matched_count=matched_in_source,
                            latency_ms=outcome.latency_ms,
                            last_error=outcome.error,
                            checked_at=now_iso,
                        )

                    for tier_key, best_listing in local_bests.items():
                        ties = local_ties.get(tier_key, [best_listing])
                        merchants_joined = ", ".join(t.merchant for t in ties)
                        self.db.upsert_tier_seen(
                            watch_id=watch.id,
                            tier_key=tier_key,
                            best_price=best_listing.price,
                            best_merchant=merchants_joined,
                            best_url=best_listing.url,
                            best_title=best_listing.title,
                            best_promo_code=best_listing.promo_code,
                            seen_at=now_iso,
                        )
                        report.tier_bests[tier_key] = {
                            "price": best_listing.price,
                            "merchant": merchants_joined,
                            "merchants": [t.merchant for t in ties],
                            "title": best_listing.title,
                            "url": best_listing.url,
                        }

                    states = {
                        tk: self.db.get_tier_state(watch.id, tk) or {} for tk in sorted(local_bests)
                    }
                    rt = self.db.get_watch_runtime(watch.id)

                return local_bests, local_ties, states, rt

            tier_bests, tier_ties, tier_states_by_key, runtime = await asyncio.to_thread(
                _persist_and_load
            )

            # Evaluate deal alerts per tier
            cooldown_delta = timedelta(hours=watch.rules.price.cooldown_hours)
            min_drop = watch.rules.price.min_drop_delta
            target = watch.rules.price.target
            alerted_tiers: list[tuple[str, float]] = []

            for tier_key, best_listing in sorted(tier_bests.items()):
                state = tier_states_by_key.get(tier_key, {})
                last_alerted_price: float | None = state.get("last_alerted_price")
                last_alerted_at = _parse_iso(state.get("last_alerted_at"))
                cooldown_elapsed = (
                    True
                    if last_alerted_at is None
                    else (current - last_alerted_at) >= cooldown_delta
                )

                alert_type: str | None = None
                if target is not None:
                    if best_listing.price <= target:
                        if last_alerted_price is None:
                            alert_type = "target_hit"
                        elif best_listing.price <= last_alerted_price - min_drop:
                            alert_type = "new_low"
                        elif cooldown_elapsed:
                            alert_type = "target_hit"
                    elif (
                        last_alerted_price is not None
                        and best_listing.price <= last_alerted_price - min_drop
                    ):
                        alert_type = "new_low"
                else:
                    if (
                        last_alerted_price is None
                        or best_listing.price <= last_alerted_price - min_drop
                    ):
                        alert_type = "new_low"

                if alert_type is None:
                    continue

                report.alerts_triggered += 1
                ties = tier_ties.get(tier_key, [best_listing])
                subject, body = format_deal_alert(
                    watch=watch,
                    tier_key=tier_key,
                    alert_type=alert_type,
                    listing=best_listing,
                    previous_price=last_alerted_price,
                    tied_listings=ties,
                )
                delivery_results = await dispatcher.dispatch(
                    watch=watch,
                    tier_key=tier_key,
                    alert_type=alert_type,
                    subject=subject,
                    message=body,
                    price=best_listing.price,
                    merchant=", ".join(t.merchant for t in ties),
                    db=self.db,
                    dry_run=dry_run,
                )
                # Only advance alerted state when NOT dry_run AND at least one delivery succeeded
                if not dry_run and any(r.ok for r in delivery_results):
                    report.alerts_delivered += 1
                    alerted_tiers.append((tier_key, best_listing.price))

            # Startup summary once per watch (only mark sent when delivery succeeds)
            needs_startup = watch.alerts.send_startup_summary and (
                runtime is None or runtime.get("startup_summary_sent_at") is None
            )
            startup_sent = False
            if needs_startup and report.sources_checked > 0:
                subj, summary_msg = format_startup_summary(
                    watch=watch,
                    tier_bests=tier_bests,
                    sources_ok=report.sources_ok,
                    sources_total=report.sources_checked,
                    tier_ties=tier_ties,
                )
                summary_results = await dispatcher.dispatch(
                    watch=watch,
                    tier_key="summary",
                    alert_type="startup_summary",
                    subject=subj,
                    message=summary_msg,
                    db=self.db,
                    dry_run=dry_run,
                )
                if not dry_run and any(r.ok for r in summary_results):
                    startup_sent = True

            def _finalize_poll_state() -> None:
                with self.db.transaction():
                    for tier_key, alerted_price in alerted_tiers:
                        self.db.mark_tier_alerted(
                            watch_id=watch.id,
                            tier_key=tier_key,
                            alerted_price=alerted_price,
                            alerted_at=now_iso,
                        )
                    self.db.update_watch_runtime(
                        watch_id=watch.id,
                        last_run_at=now_iso,
                        last_status="ok"
                        if report.sources_ok > 0 or report.sources_checked == 0
                        else "degraded",
                        mark_startup_sent=startup_sent,
                    )

            await asyncio.to_thread(_finalize_poll_state)
            return report
        finally:
            lock.release()

    async def poll_all(
        self, *, dry_run: bool = False, now: datetime | None = None
    ) -> list[WatchRunReport]:
        settings = await asyncio.to_thread(self.store.load_settings)
        watches = await asyncio.to_thread(self.store.load_watches)
        reports: list[WatchRunReport] = []
        for watch in watches:
            reports.append(
                await self.poll_watch(watch, settings=settings, dry_run=dry_run, now=now)
            )
        return reports
