"""AppleInsider Price Guide JSON-LD adapter."""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from pricewatcher.adapters.base import FetchOutcome, Listing, sanitize_listing_url
from pricewatcher.config import SourceConfig
from pricewatcher.http_client import HttpContext, polite_get


def _walk_products(node: Any, out: list[dict[str, Any]]) -> None:
    if isinstance(node, list):
        for item in node:
            _walk_products(item, out)
    elif isinstance(node, dict):
        node_type = node.get("@type")
        types = node_type if isinstance(node_type, list) else [node_type]
        if any("Product" in str(t) for t in types if t):
            out.append(node)
        for key in ("@graph", "itemListElement", "mainEntity", "item"):
            if key in node:
                _walk_products(node[key], out)


def _iter_offers(offers_node: Any) -> list[dict[str, Any]]:
    if isinstance(offers_node, list):
        result: list[dict[str, Any]] = []
        for item in offers_node:
            result.extend(_iter_offers(item))
        return result
    if isinstance(offers_node, dict):
        nested = offers_node.get("offers")
        if isinstance(nested, list):
            return [o for o in nested if isinstance(o, dict)]
        if isinstance(nested, dict):
            return [nested]
        if "price" in offers_node or "lowPrice" in offers_node:
            return [offers_node]
    return []


def parse_appleinsider_html(html_text: str, source: SourceConfig) -> list[Listing]:
    soup = BeautifulSoup(html_text, "lxml")
    products: list[dict[str, Any]] = []
    for script in soup.select('script[type="application/ld+json"]'):
        raw = script.string or script.get_text()
        if not raw or not raw.strip():
            continue
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            continue
        _walk_products(parsed, products)

    listings: list[Listing] = []
    needs_prefix = "mac-studio" in source.url.lower() or "mac studio" in source.name.lower()

    for prod in products:
        raw_name = str(prod.get("name") or "").strip()
        if not raw_name:
            continue
        title = (
            raw_name
            if "mac studio" in raw_name.lower() or not needs_prefix
            else f"Mac Studio {raw_name}"
        )
        offers = _iter_offers(prod.get("offers"))
        for offer in offers:
            raw_price = offer.get("price") or offer.get("lowPrice")
            if raw_price is None:
                continue
            try:
                price = float(str(raw_price).replace(",", "").strip())
            except ValueError:
                continue
            seller = offer.get("seller")
            merchant = (
                str(seller.get("name")).strip()
                if isinstance(seller, dict) and seller.get("name")
                else "AppleInsider Partner"
            )
            raw_offer_url = str(offer.get("url") or "").strip()
            offer_url = sanitize_listing_url(
                urljoin(source.url, raw_offer_url) if raw_offer_url else source.url
            )
            avail = str(offer.get("availability") or "")
            in_stock = True if not avail else ("instock" in avail.lower())

            listings.append(
                Listing(
                    source_name=source.name,
                    merchant=merchant,
                    title=title,
                    url=offer_url,
                    price=price,
                    currency=str(offer.get("priceCurrency") or "USD"),
                    condition="new",
                    in_stock=in_stock,
                    raw_specs={
                        "structured_price": True,
                        "mpn": prod.get("mpn"),
                        "sku": prod.get("sku"),
                    },
                )
            )
    return listings


class AppleInsiderAdapter:
    async def fetch(
        self, source: SourceConfig, http_ctx: HttpContext | None = None
    ) -> FetchOutcome:
        started = time.monotonic()
        try:
            resp = await polite_get(source.url, http_ctx=http_ctx)
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
        listings = parse_appleinsider_html(resp.text, source)
        return FetchOutcome(
            listings=listings,
            http_status=resp.status_code,
            latency_ms=latency,
        )
