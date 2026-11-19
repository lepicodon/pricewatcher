"""Notification formatting and multi-recipient delivery dispatcher."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from pricewatcher.adapters.base import Listing
from pricewatcher.config import SettingsConfig, WatchConfig
from pricewatcher.notifiers.email import EmailClient
from pricewatcher.notifiers.waha import WahaClient
from pricewatcher.storage import Database


@dataclass
class DeliveryResult:
    recipient_key: str
    recipient_name: str
    channel: str
    ok: bool
    error: str | None = None


def _dedupe_by_merchant(listings: list[Listing] | None, *, fallback: Listing) -> list[Listing]:
    items = listings if listings else [fallback]
    seen: set[str] = set()
    unique: list[Listing] = []
    for item in items:
        key = item.merchant.strip().lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique or [fallback]


def format_deal_alert(
    *,
    watch: WatchConfig,
    tier_key: str,
    alert_type: str,
    listing: Listing,
    previous_price: float | None = None,
    tied_listings: list[Listing] | None = None,
) -> tuple[str, str]:
    ties = _dedupe_by_merchant(tied_listings, fallback=listing)
    if alert_type == "target_hit":
        header = "🎯 *[PriceWatcher] TARGET HIT*"
        subj_prefix = "TARGET HIT"
    else:
        header = "📉 *[PriceWatcher] PRICE DROP*"
        subj_prefix = "PRICE DROP"

    lines = [
        header,
        f"*{watch.name}*",
        "",
        f"🖥️ *Tier:* {tier_key}",
        f"💰 *Price:* *${listing.price:,.2f}*",
    ]
    if len(ties) > 1:
        merchants_str = ", ".join(t.merchant for t in ties)
        lines.append(f"🏬 *Vendors ({len(ties)}):* {merchants_str}")
    else:
        lines.append(f"🏬 *Vendor:* {ties[0].merchant}")

    context_lines: list[str] = []
    if previous_price is not None and listing.price < previous_price:
        drop_amt = previous_price - listing.price
        context_lines.append(f"📉 *Drop:* -${drop_amt:,.2f} _(was ${previous_price:,.2f})_")
    if watch.rules.price.target is not None:
        target = watch.rules.price.target
        diff = target - listing.price
        if diff >= 0:
            context_lines.append(f"🎯 *Target:* ${target:,.2f} (✅ *${diff:,.2f} under target!*)")
        else:
            context_lines.append(f"🎯 *Target:* ${target:,.2f} _(+${abs(diff):,.2f} above target)_")
    if watch.rules.price.msrp is not None and listing.price < watch.rules.price.msrp:
        msrp = watch.rules.price.msrp
        savings = msrp - listing.price
        pct = round((savings / msrp) * 100)
        context_lines.append(f"🏷️ *MSRP:* ${msrp:,.2f} (Save *${savings:,.2f}* / *{pct}% off*)")

    promo_codes: list[str] = []
    for item in ties:
        if item.promo_code and item.promo_code not in promo_codes:
            promo_codes.append(item.promo_code)
    if promo_codes:
        codes_str = ", ".join(f"`{code}`" for code in promo_codes)
        context_lines.append(f"🎟️ *Promo Code:* {codes_str}")

    if context_lines:
        lines.append("")
        lines.extend(context_lines)

    lines.extend(["", f"📦 *Listing:* {listing.title}", ""])
    if len(ties) > 1:
        lines.append("🔗 *Buy Links:*")
        for item in ties:
            lines.append(f"  • *{item.merchant}:* {item.url}")
    else:
        lines.append(f"🔗 *Buy Now:* {ties[0].url}")

    body = "\n".join(lines)
    subject = f"[PriceWatcher] {subj_prefix}: {watch.name} — ${listing.price:,.2f} ({tier_key})"
    return subject, body


def format_startup_summary(
    *,
    watch: WatchConfig,
    tier_bests: dict[str, Listing],
    sources_ok: int,
    sources_total: int,
    tier_ties: dict[str, list[Listing]] | None = None,
) -> tuple[str, str]:
    subject = f"[PriceWatcher] Baseline Summary: {watch.name}"
    lines = [
        "📊 *[PriceWatcher] Baseline Summary*",
        f"*{watch.name}*",
        f"✅ *Sources Checked:* {sources_ok}/{sources_total}",
    ]

    ref_parts: list[str] = []
    if watch.rules.price.target is not None:
        ref_parts.append(f"🎯 *Target:* ${watch.rules.price.target:,.2f}")
    if watch.rules.price.msrp is not None:
        ref_parts.append(f"🏷️ *MSRP:* ${watch.rules.price.msrp:,.2f}")
    if ref_parts:
        lines.append("  |  ".join(ref_parts))

    lines.extend(["", "────────────────────"])

    if not tier_bests:
        lines.append("ℹ️ No qualifying in-stock listings matched current rules yet.")
    else:
        sorted_tiers = sorted(tier_bests.items(), key=lambda kv: (kv[1].price, kv[0]))
        for idx, (tier_key, item) in enumerate(sorted_tiers):
            if idx > 0:
                lines.append("")
            ties = _dedupe_by_merchant(
                tier_ties.get(tier_key) if tier_ties else [item], fallback=item
            )
            lines.append(f"🖥️ *{tier_key}*")
            lines.append(f"💰 *Best Price:* *${item.price:,.2f}*")

            if watch.rules.price.msrp is not None and item.price < watch.rules.price.msrp:
                msrp = watch.rules.price.msrp
                savings = msrp - item.price
                pct = round((savings / msrp) * 100)
                lines.append(f"🏷️ *vs MSRP:* Save *${savings:,.2f}* _({pct}% off ${msrp:,.2f})_")

            if watch.rules.price.target is not None:
                target = watch.rules.price.target
                diff = target - item.price
                if diff >= 0:
                    lines.append(f"🎯 *vs Target:* ✅ *${diff:,.2f} under ${target:,.2f} target!*")
                else:
                    lines.append(
                        f"🎯 *vs Target:* _+${abs(diff):,.2f} above ${target:,.2f} target_"
                    )

            if len(ties) > 1:
                merchants_str = ", ".join(t.merchant for t in ties)
                lines.append(f"🏬 *Vendors ({len(ties)}):* {merchants_str}")
            else:
                lines.append(f"🏬 *Vendor:* {ties[0].merchant}")

            promo_codes: list[str] = []
            for t in ties:
                if t.promo_code and t.promo_code not in promo_codes:
                    promo_codes.append(t.promo_code)
            if promo_codes:
                lines.append(f"🎟️ *Promo Code:* {', '.join(f'`{c}`' for c in promo_codes)}")

            lines.append("🔗 *Links:*")
            for t in ties:
                lines.append(f"  • *{t.merchant}:* {t.url}")

    return subject, "\n".join(lines)


class NotificationDispatcher:
    """Dispatches alerts per watch recipient directory & delivery policy."""

    def __init__(
        self,
        settings: SettingsConfig,
        *,
        waha_client: WahaClient | None = None,
        email_client: EmailClient | None = None,
    ) -> None:
        self.settings = settings
        self.waha = waha_client or WahaClient(settings.notifications.waha)
        self.email = email_client or EmailClient(settings.notifications.email)

    async def dispatch(
        self,
        *,
        watch: WatchConfig,
        tier_key: str,
        alert_type: str,
        subject: str,
        message: str,
        price: float | None = None,
        merchant: str | None = None,
        db: Database | None = None,
        dry_run: bool = False,
    ) -> list[DeliveryResult]:
        results: list[DeliveryResult] = []
        policy = watch.alerts.delivery

        for recipient_key in watch.alerts.recipients:
            recipient = self.settings.notifications.recipients.get(recipient_key)
            if recipient is None:
                res = DeliveryResult(
                    recipient_key=recipient_key,
                    recipient_name=recipient_key,
                    channel="none",
                    ok=False,
                    error=f"Unknown recipient key {recipient_key!r}",
                )
                results.append(res)
                continue

            if dry_run:
                res = DeliveryResult(
                    recipient_key=recipient_key,
                    recipient_name=recipient.name,
                    channel="dry_run",
                    ok=False,
                    error="dry_run enabled",
                )
                results.append(res)
                if db is not None:
                    await asyncio.to_thread(
                        db.record_alert,
                        watch_id=watch.id,
                        tier_key=tier_key,
                        alert_type=alert_type,
                        recipient=recipient_key,
                        channel="dry_run",
                        price=price,
                        merchant=merchant,
                        message=message,
                        status="dry_run",
                    )
                continue

            attempted: list[tuple[str, bool, str | None]] = []

            if policy in ("waha_only", "waha_with_email_fallback", "all"):
                if recipient.waha_chat_id:
                    send_res = await self.waha.send_text(recipient.waha_chat_id, message)
                    attempted.append(("waha", send_res.ok, send_res.error))
                elif policy == "waha_only":
                    attempted.append(("waha", False, "No waha_chat_id configured"))

            waha_succeeded = any(ch == "waha" and ok for ch, ok, _ in attempted)
            should_try_email = (
                policy == "email_only"
                or policy == "all"
                or (policy == "waha_with_email_fallback" and not waha_succeeded)
            )

            if should_try_email:
                if recipient.email and self.settings.notifications.email.enabled:
                    email_res = await self.email.send_email(recipient.email, subject, message)
                    attempted.append(("email", email_res.ok, email_res.error))
                elif policy == "email_only":
                    attempted.append(
                        ("email", False, "Email disabled or recipient missing address")
                    )

            if not attempted:
                attempted.append(("none", False, "No enabled delivery channel for recipient"))

            for ch, ok, err in attempted:
                results.append(
                    DeliveryResult(
                        recipient_key=recipient_key,
                        recipient_name=recipient.name,
                        channel=ch,
                        ok=ok,
                        error=err,
                    )
                )
                if db is not None:
                    await asyncio.to_thread(
                        db.record_alert,
                        watch_id=watch.id,
                        tier_key=tier_key,
                        alert_type=alert_type,
                        recipient=recipient_key,
                        channel=ch,
                        price=price,
                        merchant=merchant,
                        message=message,
                        status="sent" if ok else "failed",
                        error=err,
                    )

        return results
