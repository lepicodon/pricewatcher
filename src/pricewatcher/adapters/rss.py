"""Generic RSS/Atom feed adapter (Slickdeals, Reddit, deal blogs)."""

from __future__ import annotations

import re
import time
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


def parse_rss_feed(xml_text: str, source: SourceConfig) -> list[Listing]:
    feed = feedparser.parse(xml_text)
    listings: list[Listing] = []
    for entry in feed.entries:
        title = str(entry.get("title") or "").strip()
        if not title:
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

        listings.append(
            Listing(
                source_name=source.name,
                merchant=merchant,
                title=title,
                url=link,
                price=price,
                currency="USD",
                condition=condition,
                in_stock=True,
                promo_code=promo,
                raw_specs={
                    "structured_price": False,
                    "summary": summary_text[:500],
                    "spec_text": summary_text[:500],
                },
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
