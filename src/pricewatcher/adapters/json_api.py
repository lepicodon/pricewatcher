"""Generic JSON API adapter: Shopify products.json/suggest.json, Apple Refurbished, and JSON feeds."""

from __future__ import annotations

import json
import re
import time
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from pricewatcher.adapters.base import (
    FetchOutcome,
    Listing,
    detect_condition,
    extract_purchase_price,
    sanitize_listing_url,
)
from pricewatcher.config import SourceConfig
from pricewatcher.http_client import HttpContext, polite_get

REFURB_BOOTSTRAP_RE = re.compile(
    r"window\.REFURB_GRID_BOOTSTRAP\s*=\s*(\{.*?\})\s*;\s*</script>",
    re.IGNORECASE | re.DOTALL,
)


def _merchant_from_source(source: SourceConfig) -> str:
    explicit = source.options.get("merchant")
    if explicit:
        return str(explicit)
    host = urlparse(source.url).netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    root = host.split(".")[0] if host else source.name
    known = {
        "expercom": "Expercom",
        "datavision": "DataVision",
        "apple": "Apple Certified Refurbished",
    }
    return known.get(root, root.capitalize() if root else source.name)


def _parse_apple_refurb_html(text: str, source: SourceConfig) -> list[Listing]:
    match = REFURB_BOOTSTRAP_RE.search(text)
    if not match:
        return []
    try:
        data = json.loads(match.group(1))
    except json.JSONDecodeError:
        return []

    tiles = data.get("tiles")
    if not isinstance(tiles, list):
        return []

    listings: list[Listing] = []
    for tile in tiles:
        if not isinstance(tile, dict):
            continue
        base_title = str(tile.get("title") or "").strip()
        if not base_title:
            continue

        dims = (tile.get("filters") or {}).get("dimensions") or {}
        mem = str(dims.get("tsMemorySize") or "").upper()
        cap = str(dims.get("dimensionCapacity") or "").upper()
        spec_parts = [p for p in (mem, cap) if p]
        title = (
            f"{base_title} ({', '.join(spec_parts)})"
            if spec_parts and all(p.lower() not in base_title.lower() for p in spec_parts)
            else base_title
        )

        price_obj = tile.get("price") or {}
        cur = price_obj.get("currentPrice") if isinstance(price_obj, dict) else {}
        price: float | None = None
        if isinstance(cur, dict):
            raw_amt = cur.get("raw_amount")
            if raw_amt is not None:
                try:
                    price = float(str(raw_amt).replace(",", ""))
                except ValueError:
                    price = None
            if price is None and cur.get("amount"):
                amt_txt = BeautifulSoup(str(cur["amount"]), "lxml").get_text(" ", strip=True)
                price = extract_purchase_price(amt_txt)

        if price is None:
            continue

        details_url = str(tile.get("productDetailsUrl") or "").strip()
        raw_full_url = urljoin("https://www.apple.com", details_url) if details_url else source.url
        full_url = sanitize_listing_url(raw_full_url)

        listings.append(
            Listing(
                source_name=source.name,
                merchant="Apple Certified Refurbished",
                title=title,
                url=full_url,
                price=price,
                currency="USD",
                condition="refurbished",
                in_stock=bool(tile.get("available", True)),
                raw_specs={
                    "structured_price": True,
                    "part_number": tile.get("partNumber"),
                    "dimensions": dims,
                    "spec_text": f"{mem} {cap}".strip(),
                },
            )
        )
    return listings


def _parse_shopify_products(data: dict[str, Any], source: SourceConfig) -> list[Listing]:
    products = data.get("products")
    if not isinstance(products, list):
        return []
    parsed_url = urlparse(source.url)
    base_origin = f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url.netloc else ""
    merchant = _merchant_from_source(source)

    listings: list[Listing] = []
    for prod in products:
        if not isinstance(prod, dict):
            continue
        prod_title = str(prod.get("title") or "").strip()
        if not prod_title:
            continue
        handle = str(prod.get("handle") or "").strip()
        variants = prod.get("variants") if isinstance(prod.get("variants"), list) else []
        if not variants:
            continue

        for var in variants:
            if not isinstance(var, dict):
                continue
            raw_price = var.get("price")
            if raw_price is None:
                continue
            try:
                price = float(str(raw_price).replace(",", "").strip())
            except ValueError:
                continue

            var_title = str(var.get("title") or "").strip()
            if (
                var_title
                and var_title.lower() != "default title"
                and var_title.lower() not in prod_title.lower()
            ):
                full_title = f"{prod_title} - {var_title}"
            else:
                full_title = prod_title

            var_id = var.get("id")
            if base_origin and handle:
                raw_item_url = (
                    f"{base_origin}/products/{handle}?variant={var_id}"
                    if var_id
                    else f"{base_origin}/products/{handle}"
                )
            else:
                raw_item_url = source.url
            item_url = sanitize_listing_url(raw_item_url)

            in_stock = bool(var.get("available", True))
            condition = detect_condition(full_title, default="new")
            listings.append(
                Listing(
                    source_name=source.name,
                    merchant=merchant,
                    title=full_title,
                    url=item_url,
                    price=price,
                    currency="USD",
                    condition=condition,
                    in_stock=in_stock,
                    raw_specs={
                        "structured_price": True,
                        "sku": var.get("sku"),
                        "vendor": prod.get("vendor"),
                    },
                )
            )
    return listings


def _parse_shopify_suggest(data: dict[str, Any], source: SourceConfig) -> list[Listing]:
    results = (data.get("resources") or {}).get("results") or {}
    products = results.get("products")
    if not isinstance(products, list):
        return []

    parsed_url = urlparse(source.url)
    base_origin = f"{parsed_url.scheme}://{parsed_url.netloc}" if parsed_url.netloc else ""
    merchant = _merchant_from_source(source)

    listings: list[Listing] = []
    for prod in products:
        if not isinstance(prod, dict):
            continue
        title = str(prod.get("title") or "").strip()
        if not title:
            continue
        raw_price = prod.get("price")
        if raw_price is None:
            continue
        try:
            if isinstance(raw_price, int) and raw_price >= 10000:
                price = float(raw_price) / 100.0
            else:
                price = float(str(raw_price).replace(",", "").replace("$", "").strip())
        except ValueError:
            continue

        rel_url = str(prod.get("url") or "").strip()
        raw_item_url = (
            urljoin(base_origin, rel_url) if (base_origin and rel_url) else (rel_url or source.url)
        )
        item_url = sanitize_listing_url(raw_item_url)
        in_stock = bool(prod.get("available", True))
        condition = detect_condition(title, default="new")

        listings.append(
            Listing(
                source_name=source.name,
                merchant=merchant,
                title=title,
                url=item_url,
                price=price,
                currency="USD",
                condition=condition,
                in_stock=in_stock,
                raw_specs={
                    "structured_price": True,
                    "vendor": prod.get("vendor"),
                    "handle": prod.get("handle"),
                },
            )
        )
    return listings


def parse_json_api_payload(raw_text: str, source: SourceConfig) -> list[Listing]:
    mode = str(source.options.get("mode") or "").lower()
    if mode == "apple_refurb" or "REFURB_GRID_BOOTSTRAP" in raw_text:
        return _parse_apple_refurb_html(raw_text, source)

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError:
        return []

    if isinstance(data, dict):
        if isinstance(data.get("products"), list):
            return _parse_shopify_products(data, source)
        if isinstance(data.get("resources"), dict):
            return _parse_shopify_suggest(data, source)

    # Generic configurable JSON list/path fallback
    items_path = source.options.get("items_path")
    items: Any = data
    if isinstance(items_path, str) and isinstance(data, dict):
        for segment in items_path.split("."):
            if isinstance(items, dict):
                items = items.get(segment)
            else:
                items = None
                break
    if not isinstance(items, list):
        return []

    title_key = str(source.options.get("title_key", "title"))
    price_key = str(source.options.get("price_key", "price"))
    url_key = str(source.options.get("url_key", "url"))
    merchant = _merchant_from_source(source)

    listings: list[Listing] = []
    for obj in items:
        if not isinstance(obj, dict):
            continue
        title = str(obj.get(title_key) or "").strip()
        raw_price = obj.get(price_key)
        if not title or raw_price is None:
            continue
        try:
            price = float(str(raw_price).replace(",", "").replace("$", "").strip())
        except ValueError:
            continue
        raw_item_url = str(obj.get(url_key) or "").strip()
        url = sanitize_listing_url(
            urljoin(source.url, raw_item_url) if raw_item_url else source.url
        )
        listings.append(
            Listing(
                source_name=source.name,
                merchant=merchant,
                title=title,
                url=url,
                price=price,
                condition=detect_condition(title, default="new"),
                in_stock=bool(obj.get("in_stock", obj.get("available", True))),
                raw_specs={"structured_price": True},
            )
        )
    return listings


class JsonApiAdapter:
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

        listings = parse_json_api_payload(resp.text, source)
        return FetchOutcome(
            listings=listings,
            http_status=resp.status_code,
            latency_ms=latency,
        )
