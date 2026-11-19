"""Generic RSS/Atom feed adapter (Slickdeals, Reddit, deal blogs)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import re
import time
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
import feedparser

from pricewatcher.adapters.base import (
    FetchOutcome,
    Listing,
    detect_condition,
    extract_promo_code,
    extract_purchase_price,
    is_monthly_only_price,
    sanitize_listing_url,
)
from pricewatcher.config import SourceConfig
from pricewatcher.http_client import HttpContext, polite_get

KNOWN_MERCHANTS_RE = re.compile(
    r"\b(Micro Center|B&H|Adorama|Amazon|Best Buy|Apple|Expercom|DataVision|Abt|Costco|Walmart|Target|Newegg)\b",
    re.IGNORECASE,
)

DEFAULT_SLICKDEALS_MAX_AGE_DAYS = 7.0

EXPIRED_DEAL_RE = re.compile(
    r"(?:\[(?:expired|dead|closed)\]|\((?:expired|dead|closed)\)|"
    r"\b(?:deal\s+(?:is\s+)?expired|deal\s+ended|no\s+longer\s+available|expired\s+deal)\b|"
    r"^\s*expired\s*[:\-])",
    re.IGNORECASE,
)
OUT_OF_STOCK_RE = re.compile(
    r"(?:\[(?:oos|out\s+of\s+stock|sold\s+out)\]|\((?:oos|out\s+of\s+stock|sold\s+out)\)|"
    r"\b(?:out\s+of\s+stock|sold\s+out|currently\s+unavailable)\b)",
    re.IGNORECASE,
)


def _resolve_max_age_days(source: SourceConfig) -> float | None:
    if "max_age_days" in source.options:
        raw = source.options["max_age_days"]
        if raw is None:
            return None
        try:
            val = float(raw)
        except TypeError, ValueError:
            return None
        return val if val > 0 else None
    host = urlparse(source.url).netloc.lower()
    if "slickdeals" in host:
        return DEFAULT_SLICKDEALS_MAX_AGE_DAYS
    return None


def _entry_published_at(entry: Any) -> datetime | None:
    parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    if parsed is None:
        return None
    try:
        return datetime(
            int(parsed[0]),
            int(parsed[1]),
            int(parsed[2]),
            int(parsed[3]),
            int(parsed[4]),
            int(parsed[5]),
            tzinfo=UTC,
        )
    except IndexError, TypeError, ValueError:
        return None


def _has_expired_tag(entry: Any) -> bool:
    tags = entry.get("tags") or []
    return any(
        isinstance(t, dict) and str(t.get("term") or "").strip().lower() in {"expired", "dead"}
        for t in tags
    )


def _merchant_from_entry(title: str, summary: str, source: SourceConfig) -> str:
    match = KNOWN_MERCHANTS_RE.search(f"{title} {summary}")
    if match:
        return match.group(1)
    host = urlparse(source.url).netloc.lower()
    if "slickdeals" in host:
        return "Slickdeals"
    if "reddit" in host:
        return "Reddit"
    return source.name


def parse_rss_feed(
    xml_text: str,
    source: SourceConfig,
    *,
    now: datetime | None = None,
) -> list[Listing]:
    feed = feedparser.parse(xml_text)
    max_age_days = _resolve_max_age_days(source)
    cutoff = (
        (now if now is not None else datetime.now(UTC)) - timedelta(days=max_age_days)
        if max_age_days is not None
        else None
    )
    listings: list[Listing] = []
    for entry in feed.entries:
        title = str(entry.get("title") or "").strip()
        if not title:
            continue

        published_at = _entry_published_at(entry)
        if cutoff is not None and published_at is not None and published_at < cutoff:
            continue

        raw_link = str(entry.get("link") or "").strip()
        link = sanitize_listing_url(urljoin(source.url, raw_link) if raw_link else source.url)

        raw_summary = ""
        if entry.get("summary"):
            raw_summary = str(entry.get("summary"))
        elif entry.get("content"):
            content_list = entry.get("content") or []
            if content_list and isinstance(content_list[0], dict):
                raw_summary = str(content_list[0].get("value") or "")

        summary_text = (
            BeautifulSoup(raw_summary, "lxml").get_text(" ", strip=True) if raw_summary else ""
        )
        combined = f"{title} {summary_text}".strip()

        if _has_expired_tag(entry) or EXPIRED_DEAL_RE.search(combined):
            continue

        price = extract_purchase_price(title)
        if price is None and summary_text:
            price = extract_purchase_price(summary_text)
        if price is None:
            # Skip non-price RSS discussions unless monthly-only needs matcher rejection tests
            if is_monthly_only_price(combined):
                continue
            continue

        promo = extract_promo_code(combined)
        condition = detect_condition(combined, default="new")
        merchant = _merchant_from_entry(title, summary_text, source)
        in_stock = not bool(OUT_OF_STOCK_RE.search(combined))

        raw_specs: dict[str, Any] = {
            "structured_price": False,
            "summary": summary_text[:500],
            "spec_text": summary_text[:500],
        }
        if published_at is not None:
            raw_specs["published_at"] = published_at.isoformat()

        listings.append(
            Listing(
                source_name=source.name,
                merchant=merchant,
                title=title,
                url=link,
                price=price,
                currency="USD",
                condition=condition,
                in_stock=in_stock,
                promo_code=promo,
                raw_specs=raw_specs,
            )
        )
    return listings


class RssAdapter:
    async def fetch(
        self, source: SourceConfig, http_ctx: HttpContext | None = None
    ) -> FetchOutcome:
        started = time.monotonic()
        raw_delay = source.options.get("politeness_delay_seconds")
        try:
            delay = float(raw_delay) if raw_delay is not None else None
            resp = await polite_get(
                source.url,
                politeness_delay_seconds=delay,
                http_ctx=http_ctx,
            )
        except Exception as exc:
            return FetchOutcome(
                error=f"{type(exc).__name__}: {exc}",
                latency_ms=int((time.monotonic() - started) * 1000),
            )

        latency = int((time.monotonic() - started) * 1000)
        if resp.status_code >= 400:
            return FetchOutcome(
                http_status=resp.status_code,
                error=f"HTTP {resp.status_code}",
                latency_ms=latency,
            )

        listings = parse_rss_feed(resp.text, source)
        return FetchOutcome(
            listings=listings,
            http_status=resp.status_code,
            latency_ms=latency,
        )
