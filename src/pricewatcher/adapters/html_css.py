"""HTML/CSS + JSON-LD (+ optional Playwright) adapter."""

from __future__ import annotations

import json
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
from pricewatcher.http_client import (
    BROWSER_UA,
    HttpContext,
    ResponseTooLargeError,
    SSRFBlockedError,
    get_max_response_bytes,
    polite_get,
    validate_outbound_url,
)

JSONLD_ITEM_TYPES = {
    "product",
    "individualproduct",
    "productmodel",
    "someproducts",
    "vehicle",
    "car",
    "motorcycle",
    "motorizedbicycle",
}


def _merchant_from_source(source: SourceConfig) -> str:
    explicit = source.options.get("merchant")
    if explicit:
        return str(explicit)
    host = urlparse(source.url).netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    if host.endswith(".craigslist.org"):
        return "Craigslist"
    root = host.split(".")[0] if host else source.name
    known = {
        "abt": "Abt",
        "craigslist": "Craigslist",
        "truecar": "TrueCar",
        "classic": "Classic.com",
        "swappa": "Swappa",
    }
    return known.get(root, root.capitalize() if root else source.name)


def _is_jsonld_item_type(type_val: Any) -> bool:
    types = type_val if isinstance(type_val, list) else [type_val]
    for t in types:
        if not t:
            continue
        short = str(t).rsplit("/", 1)[-1].rsplit(":", 1)[-1].strip().lower()
        if short in JSONLD_ITEM_TYPES:
            return True
    return False


def _walk_jsonld_products(node: Any, out: list[dict[str, Any]]) -> None:
    if isinstance(node, list):
        for item in node:
            _walk_jsonld_products(item, out)
    elif isinstance(node, dict):
        if _is_jsonld_item_type(node.get("@type")):
            out.append(node)
        for key in ("@graph", "itemListElement", "mainEntity", "item"):
            if key in node:
                _walk_jsonld_products(node[key], out)


def parse_jsonld_products(soup: BeautifulSoup, source: SourceConfig) -> list[Listing]:
    products: list[dict[str, Any]] = []
    for script in soup.select('script[type="application/ld+json"]'):
        raw = script.string or script.get_text()
        if not raw or not raw.strip():
            continue
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            continue
        _walk_jsonld_products(parsed, products)

    default_merchant = _merchant_from_source(source)
    default_cond = str(source.options.get("default_condition") or "new")
    listings: list[Listing] = []
    for prod in products:
        title = str(prod.get("name") or "").strip()
        if not title:
            continue

        mileage_raw = prod.get("mileageFromOdometer")
        mileage_val: int | None = None
        if isinstance(mileage_raw, dict) and mileage_raw.get("value") is not None:
            try:
                mileage_val = int(float(str(mileage_raw["value"]).replace(",", "")))
            except ValueError:
                mileage_val = None
        display_title = (
            f"{title} ({mileage_val:,} mi)"
            if mileage_val is not None and " mi" not in title.lower()
            else title
        )

        offers_raw = prod.get("offers")
        offer_list: list[dict[str, Any]] = []
        if isinstance(offers_raw, dict):
            nested = offers_raw.get("offers")
            if isinstance(nested, list):
                offer_list = [o for o in nested if isinstance(o, dict)]
            else:
                offer_list = [offers_raw]
        elif isinstance(offers_raw, list):
            offer_list = [o for o in offers_raw if isinstance(o, dict)]

        for offer in offer_list:
            raw_price = offer.get("price") or offer.get("lowPrice")
            if raw_price is None:
                continue
            try:
                price = float(str(raw_price).replace(",", "").strip())
            except ValueError:
                continue

            seller = offer.get("seller")
            if isinstance(seller, dict) and seller.get("name"):
                merchant = str(seller.get("name")).strip()
            elif isinstance(seller, str) and seller.strip():
                merchant = seller.strip()
            else:
                merchant = default_merchant

            raw_item_url = str(offer.get("url") or prod.get("url") or "").strip()
            url = sanitize_listing_url(
                urljoin(source.url, raw_item_url) if raw_item_url else source.url
            )
            avail = str(offer.get("availability") or "")
            in_stock = True if not avail else ("instock" in avail.lower())
            item_cond_raw = str(offer.get("itemCondition") or prod.get("itemCondition") or "")
            condition = detect_condition(f"{title} {item_cond_raw}", default=default_cond)
            specs: dict[str, Any] = {"structured_price": True}
            if mileage_val is not None:
                specs["mileage"] = mileage_val
                specs["spec_text"] = f"{mileage_val:,} mi"

            listings.append(
                Listing(
                    source_name=source.name,
                    merchant=merchant,
                    title=display_title,
                    url=url,
                    price=price,
                    currency=str(offer.get("priceCurrency") or "USD"),
                    condition=condition,
                    in_stock=in_stock,
                    raw_specs=specs,
                )
            )
    return listings


def _parse_abt_search(soup: BeautifulSoup, source: SourceConfig) -> list[Listing]:
    cards = soup.select("ul#category_results_list > li[data-productId]")
    listings: list[Listing] = []
    for card in cards:
        title_link = card.select_one("a.categoryTitleLink") or card.select_one(
            "a.productPageLink[href]"
        )
        if not title_link:
            continue
        title = title_link.get_text(" ", strip=True)
        if not title:
            continue

        href = str(title_link.get("href") or "").strip()
        url = sanitize_listing_url(urljoin(source.url, href) if href else source.url)

        price_el = card.select_one(".cl_price, .pricing-item-price, .category_price_container")
        price_text = (
            price_el.get_text(" ", strip=True) if price_el else card.get_text(" ", strip=True)
        )
        price = extract_purchase_price(price_text)
        if price is None:
            continue

        card_text = card.get_text(" ", strip=True)
        lower_card = card_text.lower()
        in_stock = not ("sold out" in lower_card or "out of stock" in lower_card)

        listings.append(
            Listing(
                source_name=source.name,
                merchant="Abt",
                title=title,
                url=url,
                price=price,
                currency="USD",
                condition=detect_condition(title, default="new"),
                in_stock=in_stock,
                raw_specs={
                    "structured_price": True,
                    "product_id": card.get("data-productid"),
                    "spec_text": card_text,
                },
            )
        )
    return listings


def _parse_css_selectors(soup: BeautifulSoup, source: SourceConfig) -> list[Listing]:
    item_sel = source.options.get("item_selector")
    title_sel = source.options.get("title_selector")
    price_sel = source.options.get("price_selector")
    link_sel = source.options.get("link_selector")
    if not item_sel or not title_sel or not price_sel:
        return []

    merchant = _merchant_from_source(source)
    default_cond = str(source.options.get("default_condition") or "new")
    price_sel_str = str(price_sel).strip()
    listings: list[Listing] = []
    for node in soup.select(str(item_sel)):
        title_candidates = node.select(str(title_sel))
        title_el = next(
            (el for el in title_candidates if el.get_text(" ", strip=True)),
            title_candidates[0] if title_candidates else None,
        )
        price_el = node if price_sel_str == ":scope" else node.select_one(price_sel_str)
        if not title_el or not price_el:
            continue
        title = title_el.get_text(" ", strip=True)
        price = extract_purchase_price(price_el.get_text(" ", strip=True))
        if not title or price is None:
            continue

        link_el = node.select_one(str(link_sel)) if link_sel else title_el
        href = link_el.get("href") if link_el and link_el.has_attr("href") else None
        href_str = str(href).strip() if href is not None else ""
        url = sanitize_listing_url(urljoin(source.url, href_str) if href_str else source.url)

        node_txt = node.get_text(" ", strip=True)
        lower_txt = node_txt.lower()
        in_stock = not ("sold out" in lower_txt or "out of stock" in lower_txt)
        listings.append(
            Listing(
                source_name=source.name,
                merchant=merchant,
                title=title,
                url=url,
                price=price,
                condition=detect_condition(f"{title} {node_txt}", default=default_cond),
                in_stock=in_stock,
                raw_specs={"structured_price": True, "spec_text": node_txt[:500]},
            )
        )
    return listings


def parse_html_css(html_text: str, source: SourceConfig) -> list[Listing]:
    soup = BeautifulSoup(html_text, "lxml")
    preset = str(source.options.get("preset") or "").lower()
    if preset == "abt_search":
        return _parse_abt_search(soup, source)

    if source.options.get("item_selector"):
        css_listings = _parse_css_selectors(soup, source)
        if css_listings:
            return css_listings

    jsonld_listings = parse_jsonld_products(soup, source)
    if jsonld_listings:
        return jsonld_listings

    return _parse_css_selectors(soup, source)


_STRIP_FULFILL_HEADERS = frozenset(
    {"content-encoding", "content-length", "transfer-encoding", "connection"}
)


async def _fetch_with_playwright(
    url: str,
    *,
    max_response_bytes: int | None = None,
    http_ctx: HttpContext | None = None,
) -> str:
    validate_outbound_url(url)
    limit = max_response_bytes if max_response_bytes is not None else get_max_response_bytes()
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise RuntimeError(
            "render_js=True requested, but Playwright is not installed in this image "
            "(rebuild with INSTALL_PLAYWRIGHT=true)"
        ) from exc

    async def _handle_route(route: Any, request: Any = None) -> None:
        req = request if request is not None else route.request
        req_url = str(req.url)
        method = str(getattr(req, "method", "GET") or "GET").upper()
        parsed_req = urlparse(req_url)
        scheme = parsed_req.scheme.lower()
        if scheme in {"http", "https"}:
            if method not in {"GET", "HEAD"}:
                await route.abort()
                return
            try:
                resp = await polite_get(
                    req_url,
                    min_interval_s=0.0,
                    http_ctx=http_ctx,
                    max_response_bytes=limit,
                )
            except SSRFBlockedError, ResponseTooLargeError, Exception:
                await route.abort()
                return
            fulfill_headers = {
                k: v for k, v in resp.headers.items() if k.lower() not in _STRIP_FULFILL_HEADERS
            }
            body = resp.raw_body if resp.raw_body else resp.text.encode("utf-8")
            await route.fulfill(
                status=resp.status_code,
                headers=fulfill_headers,
                body=body,
            )
            return
        if req_url == "about:blank" or (
            scheme == "data" and req_url.lower().startswith("data:image/")
        ):
            await route.continue_()
            return
        await route.abort()

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            page = await browser.new_page(user_agent=BROWSER_UA)
            await page.route("**/*", _handle_route)
            await page.goto(url, wait_until="networkidle", timeout=30000)

            final_url = getattr(page, "url", "")
            if isinstance(final_url, str) and final_url and final_url != "about:blank":
                validate_outbound_url(final_url)

            content = str(await page.content())
            encoded = content.encode("utf-8", errors="replace")
            if len(encoded) > limit:
                content = encoded[:limit].decode("utf-8", errors="ignore")
            return content
        finally:
            await browser.close()


class HtmlCssAdapter:
    async def fetch(
        self, source: SourceConfig, http_ctx: HttpContext | None = None
    ) -> FetchOutcome:
        started = time.monotonic()
        if source.render_js:
            try:
                html_text = await _fetch_with_playwright(
                    source.url,
                    max_response_bytes=http_ctx.max_response_bytes
                    if http_ctx is not None
                    else None,
                    http_ctx=http_ctx,
                )
            except Exception as exc:
                return FetchOutcome(
                    error=f"{type(exc).__name__}: {exc}",
                    latency_ms=int((time.monotonic() - started) * 1000),
                )
            listings = parse_html_css(html_text, source)
            return FetchOutcome(
                listings=listings,
                http_status=200,
                latency_ms=int((time.monotonic() - started) * 1000),
            )

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

        listings = parse_html_css(resp.text, source)
        return FetchOutcome(
            listings=listings,
            http_status=resp.status_code,
            latency_ms=latency,
        )
