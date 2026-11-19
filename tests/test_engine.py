"""Tests for PollEngine: tier state tracking, cooldowns, startup summary, failure-safe alerts."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
import sqlite3
import time

import pytest

from pricewatcher.adapters.base import FetchOutcome, Listing
from pricewatcher.config import (
    AlertsConfig,
    ConfigStore,
    EmailConfig,
    ExtractorConfig,
    NotificationsConfig,
    PriceRulesConfig,
    RecipientConfig,
    RulesConfig,
    ScheduleConfig,
    ServerConfig,
    SettingsConfig,
    SourceConfig,
    WahaConfig,
    WatchConfig,
)
from pricewatcher.engine import PollEngine
import pricewatcher.http_client as http_client_module
from pricewatcher.main import create_app, scheduler_loop
from pricewatcher.notifiers.base import NotificationDispatcher
from pricewatcher.notifiers.waha import ChannelSendResult
from pricewatcher.storage import SCHEMA_VERSION, Database


class FakeAdapter:
    def __init__(self, listings_by_call: list[list[Listing]]) -> None:
        self._batches = list(listings_by_call)
        self._idx = 0

    async def fetch(self, source: SourceConfig) -> FetchOutcome:
        batch = self._batches[min(self._idx, len(self._batches) - 1)]
        self._idx += 1
        return FetchOutcome(listings=batch, http_status=200, latency_ms=25)


class FakeWaha:
    def __init__(self, should_succeed: bool = True) -> None:
        self.should_succeed = should_succeed
        self.sent: list[tuple[str, str]] = []

    async def send_text(self, chat_id: str, text: str) -> ChannelSendResult:
        self.sent.append((chat_id, text))
        if self.should_succeed:
            return ChannelSendResult(ok=True)
        return ChannelSendResult(ok=False, error="WAHA down")


class FakeEmail:
    def __init__(self, should_succeed: bool = True) -> None:
        self.should_succeed = should_succeed
        self.sent: list[tuple[str, str, str]] = []

    async def send_email(self, to_addr: str, subject: str, body: str) -> ChannelSendResult:
        self.sent.append((to_addr, subject, body))
        if self.should_succeed:
            return ChannelSendResult(ok=True)
        return ChannelSendResult(ok=False, error="SMTP error")


def _setup_store(
    tmp_path: Path, *, email_enabled: bool = True
) -> tuple[ConfigStore, SettingsConfig, WatchConfig]:
    cfg_dir = tmp_path / "config"
    (cfg_dir / "watches").mkdir(parents=True)
    settings = SettingsConfig(
        notifications=NotificationsConfig(
            waha=WahaConfig(url="http://waha.docker", session="pricewatcher"),
            email=EmailConfig(enabled=email_enabled),
            recipients={
                "primary": RecipientConfig(
                    name="Primary User",
                    waha_chat_id="15551234567@c.us",
                    email="user@example.com",
                )
            },
        )
    )
    watch = WatchConfig(
        id="mac-studio-test",
        name="Mac Studio Test",
        enabled=True,
        schedule=ScheduleConfig(
            interval_minutes=30,
            start_at=datetime(2026, 11, 15, 0, 0, tzinfo=UTC),
            duration_days=14,
        ),
        rules=RulesConfig(
            include_keyword_groups=[["Mac Studio"], ["M5 Max"]],
            extractors={
                "ram_gb": ExtractorConfig(
                    pattern=r"(\d{2,3})\s*GB", type="int", min=64, required=True
                ),
                "ssd_gb": ExtractorConfig(
                    pattern=r"(?:(\d+)\s*TB|(512|1024)\s*GB)",
                    type="storage_gb",
                    min=512,
                    required=True,
                ),
            },
            price=PriceRulesConfig(
                min=1500,
                max=4000,
                target=3450,
                msrp=3699,
                min_drop_delta=25,
                cooldown_hours=24,
            ),
            tier_by=["ram_gb", "ssd_gb", "condition"],
        ),
        alerts=AlertsConfig(
            recipients=["primary"],
            delivery="waha_with_email_fallback",
            send_startup_summary=True,
        ),
        sources=[
            SourceConfig(
                name="Fake Store",
                adapter="json_api",
                url="https://example.com/products.json",
            )
        ],
    )
    store = ConfigStore(cfg_dir)
    store.save_watch(watch)
    return store, settings, watch


async def test_poll_engine_target_hit_dedup_and_new_low(tmp_path: Path) -> None:
    store, settings, watch = _setup_store(tmp_path)
    db = Database(tmp_path / "prices.db")
    try:
        listing_target = Listing(
            source_name="Fake Store",
            merchant="Adorama",
            title="Mac Studio M5 Max 64GB 512GB",
            url="https://example.com/1",
            price=3449.0,
        )
        listing_same = Listing(
            source_name="Fake Store",
            merchant="Adorama",
            title="Mac Studio M5 Max 64GB 512GB",
            url="https://example.com/1",
            price=3449.0,
        )
        listing_lower = Listing(
            source_name="Fake Store",
            merchant="Adorama",
            title="Mac Studio M5 Max 64GB 512GB",
            url="https://example.com/1",
            price=3399.0,
        )
        adapter = FakeAdapter([[listing_target], [listing_same], [listing_lower]])
        waha = FakeWaha(should_succeed=True)
        email = FakeEmail(should_succeed=True)
        dispatcher = NotificationDispatcher(
            settings,
            waha_client=waha,  # type: ignore[arg-type]
            email_client=email,  # type: ignore[arg-type]
        )
        engine = PollEngine(
            store=store,
            db=db,
            dispatcher=dispatcher,
            adapter_factory=lambda _: adapter,  # type: ignore[return-value]
        )

        t0 = datetime(2026, 11, 16, 10, 0, tzinfo=UTC)
        rep1 = await engine.poll_watch(watch, settings=settings, now=t0)
        assert rep1.items_matched == 1
        assert rep1.alerts_triggered == 1
        assert rep1.alerts_delivered == 1
        # target_hit + baseline startup summary both sent via WAHA
        assert len(waha.sent) == 2
        assert len(email.sent) == 0

        # Same price within cooldown should NOT trigger another alert or summary
        rep2 = await engine.poll_watch(watch, settings=settings, now=t0 + timedelta(minutes=30))
        assert rep2.alerts_triggered == 0
        assert len(waha.sent) == 2

        # Price drop >= min_drop_delta ($50 drop) triggers new_low
        rep3 = await engine.poll_watch(watch, settings=settings, now=t0 + timedelta(hours=1))
        assert rep3.alerts_triggered == 1
        assert rep3.alerts_delivered == 1
        assert len(waha.sent) == 3

        tier_state = db.get_tier_state(watch.id, "64GB / 512GB / new")
        assert tier_state is not None
        assert tier_state["last_alerted_price"] == 3399.0
    finally:
        db.close()


async def test_failure_safe_alert_retry_and_email_fallback(tmp_path: Path) -> None:
    store, settings, watch = _setup_store(tmp_path, email_enabled=True)
    db = Database(tmp_path / "prices.db")
    try:
        listing = Listing(
            source_name="Fake Store",
            merchant="Adorama",
            title="Mac Studio M5 Max 64GB 512GB",
            url="https://example.com/1",
            price=3400.0,
        )
        adapter = FakeAdapter([[listing], [listing]])
        waha = FakeWaha(should_succeed=False)
        email_fail = FakeEmail(should_succeed=False)
        dispatcher_fail = NotificationDispatcher(
            settings,
            waha_client=waha,  # type: ignore[arg-type]
            email_client=email_fail,  # type: ignore[arg-type]
        )
        engine = PollEngine(
            store=store,
            db=db,
            dispatcher=dispatcher_fail,
            adapter_factory=lambda _: adapter,  # type: ignore[return-value]
        )

        t0 = datetime(2026, 11, 16, 10, 0, tzinfo=UTC)
        rep_fail = await engine.poll_watch(watch, settings=settings, now=t0)
        assert rep_fail.alerts_triggered == 1
        assert rep_fail.alerts_delivered == 0

        # Neither alerted state nor startup summary should be marked sent when all channels fail
        tier_state = db.get_tier_state(watch.id, "64GB / 512GB / new")
        assert tier_state is not None
        assert tier_state["last_alerted_price"] is None
        runtime = db.get_watch_runtime(watch.id)
        assert runtime is not None
        assert runtime["startup_summary_sent_at"] is None

        # Next run with working email fallback succeeds and advances state
        email_ok = FakeEmail(should_succeed=True)
        engine._dispatcher = NotificationDispatcher(
            settings,
            waha_client=waha,  # type: ignore[arg-type]
            email_client=email_ok,  # type: ignore[arg-type]
        )
        rep_retry = await engine.poll_watch(
            watch, settings=settings, now=t0 + timedelta(minutes=30)
        )
        assert rep_retry.alerts_triggered == 1
        assert rep_retry.alerts_delivered == 1
        assert len(email_ok.sent) == 2

        tier_state_after = db.get_tier_state(watch.id, "64GB / 512GB / new")
        assert tier_state_after is not None
        assert tier_state_after["last_alerted_price"] == 3400.0
        runtime_after = db.get_watch_runtime(watch.id)
        assert runtime_after is not None
        assert runtime_after["startup_summary_sent_at"] is not None
    finally:
        db.close()


async def test_expired_watch_is_skipped(tmp_path: Path) -> None:
    store, settings, watch = _setup_store(tmp_path)
    db = Database(tmp_path / "prices.db")
    try:
        called = False

        class GuardAdapter:
            async def fetch(self, source: SourceConfig) -> FetchOutcome:
                nonlocal called
                called = True
                return FetchOutcome()

        engine = PollEngine(
            store=store,
            db=db,
            adapter_factory=lambda _: GuardAdapter(),  # type: ignore[return-value]
        )
        far_future = datetime(2026, 12, 5, 0, 0, tzinfo=UTC)
        rep = await engine.poll_watch(watch, settings=settings, now=far_future)
        assert rep.status == "expired"
        assert rep.skipped is True
        assert called is False
    finally:
        db.close()


async def test_tied_vendors_appear_in_alerts_summary_and_tier_state(tmp_path: Path) -> None:
    store, settings, watch = _setup_store(tmp_path)
    db = Database(tmp_path / "prices.db")
    try:
        adorama = Listing(
            source_name="Fake Store",
            merchant="Adorama",
            title="Mac Studio M5 Max 64GB 512GB",
            url="https://example.com/adorama",
            price=3449.0,
            promo_code="APINSIDER",
        )
        bh = Listing(
            source_name="Fake Store",
            merchant="B&H Photo",
            title="Mac Studio M5 Max 64GB 512GB",
            url="https://example.com/bh",
            price=3449.0,
        )
        adapter = FakeAdapter([[adorama, bh]])
        waha = FakeWaha(should_succeed=True)
        dispatcher = NotificationDispatcher(
            settings,
            waha_client=waha,  # type: ignore[arg-type]
        )
        engine = PollEngine(
            store=store,
            db=db,
            dispatcher=dispatcher,
            adapter_factory=lambda _: adapter,  # type: ignore[return-value]
        )

        t0 = datetime(2026, 11, 16, 10, 0, tzinfo=UTC)
        rep = await engine.poll_watch(watch, settings=settings, now=t0)
        assert rep.alerts_delivered == 1
        assert rep.tier_bests["64GB / 512GB / new"]["merchants"] == ["Adorama", "B&H Photo"]

        tier_state = db.get_tier_state(watch.id, "64GB / 512GB / new")
        assert tier_state is not None
        assert tier_state["best_merchant"] == "Adorama, B&H Photo"

        assert len(waha.sent) == 2
        deal_msg = waha.sent[0][1]
        summary_msg = waha.sent[1][1]
        for msg in (deal_msg, summary_msg):
            assert "*Vendors (2):* Adorama, B&H Photo" in msg
            assert "https://example.com/adorama" in msg
            assert "https://example.com/bh" in msg
            assert "`APINSIDER`" in msg
            assert "*[PriceWatcher]" in msg
    finally:
        db.close()


def test_schema_v1_to_v2_migration_and_backfill(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy_v1.db"
    conn = sqlite3.connect(str(db_path))
    conn.executescript(
        """
        CREATE TABLE observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            watch_id TEXT NOT NULL,
            tier_key TEXT NOT NULL,
            source_name TEXT NOT NULL,
            merchant TEXT NOT NULL,
            title TEXT NOT NULL,
            url TEXT NOT NULL,
            price REAL NOT NULL,
            currency TEXT NOT NULL DEFAULT 'USD',
            condition TEXT NOT NULL DEFAULT 'new',
            in_stock INTEGER NOT NULL DEFAULT 1,
            promo_code TEXT,
            specs_json TEXT NOT NULL DEFAULT '{}',
            observed_at TEXT NOT NULL
        );
        CREATE TABLE tier_state (
            watch_id TEXT NOT NULL,
            tier_key TEXT NOT NULL,
            best_price REAL,
            best_merchant TEXT,
            best_url TEXT,
            best_title TEXT,
            best_promo_code TEXT,
            last_seen_at TEXT,
            last_alerted_price REAL,
            last_alerted_at TEXT,
            PRIMARY KEY (watch_id, tier_key)
        );
        INSERT INTO observations (
            watch_id, tier_key, source_name, merchant, title, url,
            price, currency, condition, in_stock, promo_code, specs_json, observed_at
        ) VALUES (
            'mac-studio', '64GB / 512GB / new', 'Adorama', 'Adorama',
            'Mac Studio M5 Max', 'https://example.com/1',
            3449.0, 'USD', 'new', 1, NULL, '{}', '2026-11-01T10:00:00+00:00'
        );
        """
    )
    conn.commit()
    conn.close()

    db = Database(db_path)
    try:
        user_ver = db._conn.execute("PRAGMA user_version").fetchone()[0]
        assert user_ver == SCHEMA_VERSION == 2

        cols = {r["name"] for r in db._conn.execute("PRAGMA table_info(observations)").fetchall()}
        assert "last_seen_at" in cols

        mig_rows = db._conn.execute("SELECT version FROM schema_migrations").fetchall()
        assert [r["version"] for r in mig_rows] == [2]

        idx = db._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_observations_dedup'"
        ).fetchone()
        assert idx is not None

        obs = db.get_observations("mac-studio")
        assert len(obs) == 1
        assert obs[0]["last_seen_at"] == "2026-11-01T10:00:00+00:00"
    finally:
        db.close()

    # Re-opening migrated DB is idempotent
    db2 = Database(db_path)
    try:
        assert db2._conn.execute("PRAGMA user_version").fetchone()[0] == 2
        assert len(db2.get_observations("mac-studio")) == 1
    finally:
        db2.close()


def test_observation_dedup_and_prune(tmp_path: Path) -> None:
    db = Database(tmp_path / "dedup.db")
    try:
        t0 = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
        common = {
            "watch_id": "w1",
            "tier_key": "default",
            "source_name": "Store A",
            "merchant": "Store A",
            "title": "Item",
            "url": "https://example.com/item",
            "currency": "USD",
            "condition": "new",
            "promo_code": None,
            "specs": {},
        }

        id1 = db.upsert_observation(
            **common, price=100.0, in_stock=True, observed_at=t0.isoformat()
        )
        # Same price & stock within 24h updates last_seen_at without inserting
        id1_dup = db.upsert_observation(
            **common,
            price=100.0,
            in_stock=True,
            observed_at=(t0 + timedelta(hours=2)).isoformat(),
        )
        assert id1_dup == id1
        # Still <= 24h from prev last_seen_at (23h after t0+2h)
        id1_dup2 = db.upsert_observation(
            **common,
            price=100.0,
            in_stock=True,
            observed_at=(t0 + timedelta(hours=25)).isoformat(),
        )
        assert id1_dup2 == id1
        assert len(db.get_observations("w1")) == 1
        assert (
            db.get_observations("w1")[0]["last_seen_at"] == (t0 + timedelta(hours=25)).isoformat()
        )

        # > 24h since last_seen_at inserts a new row
        id2 = db.upsert_observation(
            **common,
            price=100.0,
            in_stock=True,
            observed_at=(t0 + timedelta(hours=50)).isoformat(),
        )
        assert id2 != id1

        # Changed price inserts a new row
        id3 = db.upsert_observation(
            **common,
            price=99.99,
            in_stock=True,
            observed_at=(t0 + timedelta(hours=51)).isoformat(),
        )
        assert id3 != id2

        # Changed stock state inserts a new row
        id4 = db.upsert_observation(
            **common,
            price=99.99,
            in_stock=False,
            observed_at=(t0 + timedelta(hours=52)).isoformat(),
        )
        assert id4 != id3
        assert len(db.get_observations("w1")) == 4

        # Retention pruning uses COALESCE(last_seen_at, observed_at)
        now = datetime.now(UTC)
        db.upsert_observation(
            **{**common, "url": "https://example.com/old"},
            price=50.0,
            in_stock=True,
            observed_at=(now - timedelta(days=200)).isoformat(),
        )
        active_old_id = db.upsert_observation(
            **{**common, "url": "https://example.com/still-seen"},
            price=60.0,
            in_stock=True,
            observed_at=(now - timedelta(days=200)).isoformat(),
        )
        db._conn.execute(
            "UPDATE observations SET last_seen_at = ? WHERE id = ?",
            ((now - timedelta(days=2)).isoformat(), active_old_id),
        )
        db._conn.commit()

        deleted = db.prune_old_observations(retention_days=180)
        # Note: t0 rows in 2026 depend on current wall clock; ensure specifically old url is gone and still-seen stays
        remaining_urls = {row["url"] for row in db.get_observations("w1")}
        assert deleted >= 1
        assert "https://example.com/old" not in remaining_urls
        assert "https://example.com/still-seen" in remaining_urls
    finally:
        db.close()


def test_database_transaction_commit_and_rollback(tmp_path: Path) -> None:
    db = Database(tmp_path / "tx.db")
    try:
        with pytest.raises(RuntimeError, match="boom"), db.transaction():
            db.upsert_observation(
                watch_id="w1",
                tier_key="default",
                source_name="S1",
                merchant="S1",
                title="T1",
                url="https://example.com/1",
                price=100.0,
                currency="USD",
                condition="new",
                in_stock=True,
                promo_code=None,
                specs={},
            )
            db.upsert_source_health(
                watch_id="w1",
                source_name="S1",
                url="https://example.com/1",
                http_status=200,
                item_count=1,
                matched_count=1,
                latency_ms=10,
                last_error=None,
            )
            raise RuntimeError("boom")

        assert db.get_observations("w1") == []
        assert db.get_source_health("w1") == []

        # Nested savepoint rollback leaves outer write intact
        with db.transaction():
            db.upsert_source_health(
                watch_id="w1",
                source_name="S1",
                url="https://example.com/1",
                http_status=200,
                item_count=1,
                matched_count=1,
                latency_ms=10,
                last_error=None,
            )
            with pytest.raises(ValueError), db.transaction():
                db.upsert_source_health(
                    watch_id="w1",
                    source_name="S2",
                    url="https://example.com/2",
                    http_status=500,
                    item_count=0,
                    matched_count=0,
                    latency_ms=5,
                    last_error="err",
                )
                raise ValueError("inner fail")

        health = db.get_source_health("w1")
        assert [h["source_name"] for h in health] == ["S1"]
    finally:
        db.close()


def test_dashboard_summary_accuracy_and_batching(tmp_path: Path) -> None:
    db = Database(tmp_path / "dash.db")
    try:
        now = datetime.now(UTC)
        d1 = (now - timedelta(days=2)).isoformat()
        d2 = (now - timedelta(days=1)).isoformat()
        old = (now - timedelta(days=10)).isoformat()

        db.upsert_observation(
            watch_id="w1",
            tier_key="64GB",
            source_name="S1",
            merchant="M1",
            title="Mac 1",
            url="https://example.com/1",
            price=3500.0,
            currency="USD",
            condition="new",
            in_stock=True,
            promo_code=None,
            specs={"ram_gb": 64},
            observed_at=d1,
        )
        db.upsert_observation(
            watch_id="w1",
            tier_key="64GB",
            source_name="S2",
            merchant="M2",
            title="Mac 1",
            url="https://example.com/2",
            price=3400.0,
            currency="USD",
            condition="new",
            in_stock=True,
            promo_code=None,
            specs={"ram_gb": 64},
            observed_at=d2,
        )
        db.upsert_observation(
            watch_id="w1",
            tier_key="64GB",
            source_name="S3",
            merchant="M3",
            title="Mac Old",
            url="https://example.com/old",
            price=3100.0,
            currency="USD",
            condition="new",
            in_stock=True,
            promo_code=None,
            specs={},
            observed_at=old,
        )
        db.upsert_tier_seen(
            watch_id="w1",
            tier_key="64GB",
            best_price=3400.0,
            best_merchant="M2",
            best_url="https://example.com/2",
            best_title="Mac 1",
            best_promo_code=None,
            seen_at=d2,
        )
        db.upsert_source_health(
            watch_id="w1",
            source_name="S1",
            url="https://example.com/1",
            http_status=200,
            item_count=5,
            matched_count=1,
            latency_ms=20,
            last_error=None,
            checked_at=d2,
        )
        db.upsert_source_health(
            watch_id="w1",
            source_name="S2",
            url="https://example.com/2",
            http_status=503,
            item_count=0,
            matched_count=0,
            latency_ms=30,
            last_error="HTTP 503",
            checked_at=d2,
        )
        db.update_watch_runtime(watch_id="w1", last_run_at=d2, last_status="ok")
        for idx in range(3):
            db.record_alert(
                watch_id="w1" if idx < 2 else "w2",
                tier_key="64GB",
                alert_type="new_low",
                recipient="primary",
                channel="waha",
                price=3400.0 - idx,
                merchant="M2",
                message=f"alert {idx}",
                status="sent",
                created_at=(now - timedelta(minutes=3 - idx)).isoformat(),
            )

        statements: list[str] = []
        db._conn.set_trace_callback(statements.append)
        summary_3 = db.get_dashboard_summary(["w1", "w2", "w3"], history_days=7, alert_limit=2)
        count_3 = len(statements)
        statements.clear()
        summary_10 = db.get_dashboard_summary(
            [f"w{i}" for i in range(1, 11)], history_days=7, alert_limit=2
        )
        count_10 = len(statements)
        db._conn.set_trace_callback(None)

        assert count_3 == count_10 <= 6
        assert len(summary_10["watches"]) == 10

        w1 = summary_3["watches"]["w1"]
        assert w1["runtime"]["last_status"] == "ok"
        assert len(w1["tier_states"]) == 1
        assert w1["latest_observation"]["price"] == 3400.0
        assert [pt["min_price"] for pt in w1["sparkline"]] == [3500.0, 3400.0]
        assert w1["source_health"]["total"] == 2
        assert w1["source_health"]["ok"] == 1
        assert w1["source_health"]["error"] == 1
        assert len(summary_3["recent_alerts"]) == 2
        assert summary_3["recent_alerts"][0]["watch_id"] == "w2"
    finally:
        db.close()


async def test_poll_engine_bounded_concurrency_and_optional_http_ctx(tmp_path: Path) -> None:
    store, settings, base_watch = _setup_store(tmp_path)
    settings = settings.model_copy(update={"server": ServerConfig(fetch_concurrency=3)})
    sources = [
        SourceConfig(name=f"Slow {i}", adapter="json_api", url=f"https://example.com/{i}")
        for i in range(6)
    ]
    watch = base_watch.model_copy(update={"sources": sources})
    db = Database(tmp_path / "conc.db")
    try:
        active = 0
        max_active = 0

        class SlowAdapter:
            async def fetch(self, source: SourceConfig) -> FetchOutcome:
                nonlocal active, max_active
                active += 1
                max_active = max(max_active, active)
                try:
                    await asyncio.sleep(0.12)
                    return FetchOutcome(
                        listings=[
                            Listing(
                                source_name=source.name,
                                merchant=source.name,
                                title="Mac Studio M5 Max 64GB 512GB",
                                url=source.url,
                                price=3449.0,
                            )
                        ],
                        http_status=200,
                        latency_ms=120,
                    )
                finally:
                    active -= 1

        waha = FakeWaha(should_succeed=True)
        dispatcher = NotificationDispatcher(settings, waha_client=waha)  # type: ignore[arg-type]
        engine = PollEngine(
            store=store,
            db=db,
            dispatcher=dispatcher,
            adapter_factory=lambda _: SlowAdapter(),  # type: ignore[return-value]
            http_ctx=object(),
        )
        t0 = time.monotonic()
        rep = await engine.poll_watch(watch, settings=settings)
        elapsed = time.monotonic() - t0

        assert rep.sources_checked == 6
        assert rep.sources_ok == 6
        assert 2 <= max_active <= 3
        # 6 sources @ 0.12s with concurrency 3 => ~0.24s, much less than sequential 0.72s
        assert elapsed < 0.55
        # Deterministic source ordering preserved for tied listings
        assert rep.tier_bests["64GB / 512GB / new"]["merchants"] == [f"Slow {i}" for i in range(6)]

        # Adapter accepting http_ctx receives it cleanly
        received_ctx: list[object | None] = []

        class CtxAwareAdapter:
            async def fetch(
                self, source: SourceConfig, *, http_ctx: object | None = None
            ) -> FetchOutcome:
                received_ctx.append(http_ctx)
                return FetchOutcome(http_status=200)

        sentinel_ctx = object()
        engine_ctx = PollEngine(
            store=store,
            db=db,
            dispatcher=dispatcher,
            adapter_factory=lambda _: CtxAwareAdapter(),  # type: ignore[return-value]
            http_ctx=sentinel_ctx,
        )
        await engine_ctx.poll_watch(base_watch, settings=settings)
        assert received_ctx == [sentinel_ctx]
    finally:
        db.close()


async def test_poll_engine_per_watch_lock_prevents_overlap(tmp_path: Path) -> None:
    store, settings, watch = _setup_store(tmp_path)
    db = Database(tmp_path / "lock.db")
    try:
        started = asyncio.Event()
        release = asyncio.Event()
        fetch_calls = 0

        class BlockingAdapter:
            async def fetch(self, source: SourceConfig) -> FetchOutcome:
                nonlocal fetch_calls
                fetch_calls += 1
                started.set()
                await release.wait()
                return FetchOutcome(
                    listings=[
                        Listing(
                            source_name=source.name,
                            merchant="Adorama",
                            title="Mac Studio M5 Max 64GB 512GB",
                            url="https://example.com/1",
                            price=3400.0,
                        )
                    ],
                    http_status=200,
                )

        waha = FakeWaha(should_succeed=True)
        dispatcher = NotificationDispatcher(settings, waha_client=waha)  # type: ignore[arg-type]
        engine = PollEngine(
            store=store,
            db=db,
            dispatcher=dispatcher,
            adapter_factory=lambda _: BlockingAdapter(),  # type: ignore[return-value]
        )

        task1 = asyncio.create_task(engine.poll_watch(watch, settings=settings))
        await started.wait()

        rep_overlap = await engine.poll_watch(watch, settings=settings)
        assert rep_overlap.skipped is True
        assert rep_overlap.already_running is True
        assert fetch_calls == 1
        assert len(waha.sent) == 0

        release.set()
        rep1 = await task1
        assert rep1.already_running is False
        assert rep1.alerts_delivered == 1
        assert fetch_calls == 1
        assert len(waha.sent) == 2
    finally:
        db.close()


async def test_scheduler_loop_runs_watches_independently_and_cancels_cleanly(
    tmp_path: Path,
) -> None:
    store, settings, base_watch = _setup_store(tmp_path)
    store.delete_watch(base_watch.id)
    settings = settings.model_copy(update={"server": ServerConfig(retention_days=30)})
    store.save_settings(settings)
    w1 = base_watch.model_copy(
        update={
            "id": "watch-one",
            "name": "Watch One",
            "sources": [SourceConfig(name="S1", adapter="json_api", url="https://ex.com/1")],
        }
    )
    w2 = base_watch.model_copy(
        update={
            "id": "watch-two",
            "name": "Watch Two",
            "sources": [SourceConfig(name="S2", adapter="json_api", url="https://ex.com/2")],
        }
    )
    store.save_watch(w1)
    store.save_watch(w2)

    db = Database(tmp_path / "sched.db")
    try:
        # Insert an observation 45 days old (> retention_days=30) to verify daily prune
        stale_ts = (datetime.now(UTC) - timedelta(days=45)).isoformat()
        db.upsert_observation(
            watch_id="watch-one",
            tier_key="default",
            source_name="S1",
            merchant="S1",
            title="Stale",
            url="https://ex.com/stale",
            price=100.0,
            currency="USD",
            condition="new",
            in_stock=True,
            promo_code=None,
            specs={},
            observed_at=stale_ts,
        )

        both_started = asyncio.Event()
        release = asyncio.Event()
        started_ids: set[str] = set()

        class CoordinatedAdapter:
            async def fetch(self, source: SourceConfig) -> FetchOutcome:
                started_ids.add(source.url)
                if len(started_ids) >= 2:
                    both_started.set()
                await release.wait()
                return FetchOutcome(http_status=200)

        engine = PollEngine(
            store=store,
            db=db,
            adapter_factory=lambda _: CoordinatedAdapter(),  # type: ignore[return-value]
        )
        wakeup_event = asyncio.Event()
        stop_event = asyncio.Event()
        sched_task = asyncio.create_task(
            scheduler_loop(
                store=store,
                db=db,
                engine=engine,
                wakeup_event=wakeup_event,
                stop_event=stop_event,
            )
        )

        # Both watches start concurrently without waiting for the first to finish
        await asyncio.wait_for(both_started.wait(), timeout=2.0)
        assert started_ids == {"https://ex.com/1", "https://ex.com/2"}
        assert db.get_observations("watch-one") == []

        # Stop cancels in-flight watch tasks cleanly
        stop_event.set()
        await asyncio.wait_for(sched_task, timeout=2.0)
    finally:
        db.close()


async def test_lifespan_wires_optional_http_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, settings, _ = _setup_store(tmp_path)
    store.save_settings(settings)
    db = Database(tmp_path / "lifespan.db")

    events: list[str] = []

    class FakeHttpContext:
        async def __aenter__(self) -> FakeHttpContext:
            events.append("enter")
            return self

        async def __aexit__(self, *args: object) -> None:
            events.append("exit")

    monkeypatch.setattr(http_client_module, "HttpContext", FakeHttpContext, raising=False)
    try:
        app = create_app(store=store, db=db, start_scheduler=False)
        async with app.router.lifespan_context(app):
            assert isinstance(app.state.http_ctx, FakeHttpContext)
            assert app.state.engine.http_ctx is app.state.http_ctx
        assert events == ["enter", "exit"]
        assert app.state.engine.http_ctx is None
    finally:
        db.close()
