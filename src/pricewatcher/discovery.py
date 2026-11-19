"""Live URL discovery / 'Probe Source' engine."""

from __future__ import annotations

import asyncio
import inspect
import json
import re
from typing import Any, Literal
from urllib.parse import quote_plus, urlparse

from bs4 import BeautifulSoup
from pydantic import BaseModel, Field

from pricewatcher.adapters import get_adapter
from pricewatcher.adapters.appleinsider import parse_appleinsider_html
from pricewatcher.adapters.base import Listing
from pricewatcher.adapters.html_css import parse_html_css
from pricewatcher.adapters.json_api import parse_json_api_payload
from pricewatcher.adapters.rss import parse_rss_feed
from pricewatcher.config import (
    QUERY_SYNONYM_GROUPS as QUERY_SYNONYM_GROUPS,
)
from pricewatcher.config import (
    SourceConfig,
    detect_vehicle_make_model,
    expand_include_keyword_groups,
    normalize_search_query,
)
from pricewatcher.config import (
    extract_core_query_tokens as extract_core_query_tokens,
)
from pricewatcher.http_client import (
    HttpContext,
    HttpResponse,
    ResponseTooLargeError,
    SSRFBlockedError,
    polite_get,
)

ACTIVE_BLOCK_MARKERS = (
    "just a moment...",
    "_cf_chl_opt",
    "px-captcha",
    "perimeterx",
    "pardon our interruption",
    "captcha-delivery.com",
    "enable javascript and cookies to continue",
    "attention required! | cloudflare",
    "please verify you are a human",
)


class ProbePreviewItem(BaseModel):
    title: str
    price: float
    merchant: str
    condition: str
    in_stock: bool
    url: str


class ProbeResult(BaseModel):
    url: str
    recommended_url: str
    classification: Literal["A_CLEAN_HTTP", "B_NEEDS_PLAYWRIGHT", "C_BOT_BLOCKED", "ERROR"]
    format_detected: str
    recommended_adapter: Literal["rss", "json_api", "html_css", "appleinsider"] | None = None
    recommended_options: dict[str, Any] = Field(default_factory=dict)
    recommended_name: str = ""
    http_status: int | None = None
    item_count: int = 0
    preview_items: list[ProbePreviewItem] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _to_preview(listings: list[Listing], limit: int = 8) -> list[ProbePreviewItem]:
    return [
        ProbePreviewItem(
            title=item.title,
            price=item.price,
            merchant=item.merchant,
            condition=item.condition,
            in_stock=item.in_stock,
            url=item.url,
        )
        for item in listings[:limit]
    ]


def _default_name_for_url(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    return host or "Custom Source"


def _has_active_block(resp: HttpResponse) -> bool:
    if resp.status_code in (403, 429, 503):
        return True
    if resp.headers.get("cf-mitigated") or resp.headers.get("x-datadome"):
        return True
    lower = resp.text.lower()
    return any(marker in lower for marker in ACTIVE_BLOCK_MARKERS)


def analyze_probe_response(url: str, resp: HttpResponse) -> ProbeResult:
    name = _default_name_for_url(url)
    text = resp.text
    stripped = text.lstrip()

    if _has_active_block(resp):
        return ProbeResult(
            url=url,
            recommended_url=url,
            classification="C_BOT_BLOCKED",
            format_detected="bot_challenge_or_blocked",
            recommended_name=name,
            http_status=resp.status_code,
            notes=[
                f"Blocked or challenged (HTTP {resp.status_code}). Consider an aggregator/RSS feed instead."
            ],
        )

    if resp.status_code >= 400:
        return ProbeResult(
            url=url,
            recommended_url=url,
            classification="ERROR",
            format_detected=f"http_{resp.status_code}",
            recommended_name=name,
            http_status=resp.status_code,
            notes=[f"Endpoint returned HTTP {resp.status_code}"],
        )

    # 1. RSS / Atom XML
    if (
        stripped.startswith("<?xml")
        or "<rss" in stripped[:600].lower()
        or "<feed" in stripped[:600].lower()
    ):
        src = SourceConfig(name=name, adapter="rss", url=url)
        listings = parse_rss_feed(text, src)
        return ProbeResult(
            url=url,
            recommended_url=url,
            classification="A_CLEAN_HTTP",
            format_detected="rss_atom_xml",
            recommended_adapter="rss",
            recommended_name=name,
            http_status=resp.status_code,
            item_count=len(listings),
            preview_items=_to_preview(listings),
            notes=["Valid RSS/Atom feed detected."],
        )

    # 2. JSON API (Shopify products.json / search suggest / generic array)
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            parsed_json = json.loads(text)
        except json.JSONDecodeError:
            parsed_json = None
        if parsed_json is not None:
            src = SourceConfig(name=name, adapter="json_api", url=url)
            listings = parse_json_api_payload(text, src)
            fmt = "json_api"
            if isinstance(parsed_json, dict) and "products" in parsed_json:
                fmt = "shopify_products_json"
            elif isinstance(parsed_json, dict) and "resources" in parsed_json:
                fmt = "shopify_suggest_json"
            return ProbeResult(
                url=url,
                recommended_url=url,
                classification="A_CLEAN_HTTP",
                format_detected=fmt,
                recommended_adapter="json_api",
                recommended_name=name,
                http_status=resp.status_code,
                item_count=len(listings),
                preview_items=_to_preview(listings),
                notes=["Clean JSON API detected."],
            )

    # 3. AppleInsider Price Guide
    if "prices.appleinsider.com" in url.lower():
        src = SourceConfig(name="AppleInsider Guide", adapter="appleinsider", url=url)
        listings = parse_appleinsider_html(text, src)
        if listings:
            return ProbeResult(
                url=url,
                recommended_url=url,
                classification="A_CLEAN_HTTP",
                format_detected="appleinsider_jsonld",
                recommended_adapter="appleinsider",
                recommended_name="AppleInsider Guide",
                http_status=resp.status_code,
                item_count=len(listings),
                preview_items=_to_preview(listings),
                notes=["AppleInsider schema.org/Product JSON-LD extracted cleanly."],
            )

    # 4. Apple Certified Refurbished bootstrap JSON
    if "REFURB_GRID_BOOTSTRAP" in text:
        src = SourceConfig(
            name="Apple Certified Refurbished",
            adapter="json_api",
            url=url,
            options={"mode": "apple_refurb"},
        )
        listings = parse_json_api_payload(text, src)
        return ProbeResult(
            url=url,
            recommended_url=url,
            classification="A_CLEAN_HTTP",
            format_detected="apple_refurb_bootstrap_json",
            recommended_adapter="json_api",
            recommended_options={"mode": "apple_refurb"},
            recommended_name="Apple Certified Refurbished",
            http_status=resp.status_code,
            item_count=len(listings),
            preview_items=_to_preview(listings),
            notes=["Apple Refurbished embedded bootstrap JSON detected."],
        )

    # 5. Abt Search HTML preset
    if "abt.com" in url.lower() and "category_results_list" in text:
        src = SourceConfig(
            name="Abt",
            adapter="html_css",
            url=url,
            options={"preset": "abt_search"},
        )
        listings = parse_html_css(text, src)
        if listings:
            return ProbeResult(
                url=url,
                recommended_url=url,
                classification="A_CLEAN_HTTP",
                format_detected="abt_server_html",
                recommended_adapter="html_css",
                recommended_options={"preset": "abt_search"},
                recommended_name="Abt",
                http_status=resp.status_code,
                item_count=len(listings),
                preview_items=_to_preview(listings),
                notes=["Server-rendered Abt search catalog detected."],
            )

    # 5b. Craigslist static search HTML
    if "craigslist.org" in url.lower() and "cl-static-search-result" in text:
        cl_opts = {
            "item_selector": "li.cl-static-search-result",
            "title_selector": ".title",
            "price_selector": ".price",
            "link_selector": "a[href]",
            "default_condition": "used",
            "merchant": "Craigslist",
        }
        src = SourceConfig(
            name=name,
            adapter="html_css",
            url=url,
            options=cl_opts,
        )
        listings = parse_html_css(text, src)
        if listings:
            return ProbeResult(
                url=url,
                recommended_url=url,
                classification="A_CLEAN_HTTP",
                format_detected="craigslist_static_html",
                recommended_adapter="html_css",
                recommended_options=cl_opts,
                recommended_name=name,
                http_status=resp.status_code,
                item_count=len(listings),
                preview_items=_to_preview(listings),
                notes=["Craigslist static search listings detected."],
            )

    # 6. Generic schema.org/Product or Vehicle JSON-LD in HTML
    soup = BeautifulSoup(text, "lxml")
    if soup.select('script[type="application/ld+json"]'):
        src = SourceConfig(name=name, adapter="html_css", url=url)
        listings = parse_html_css(text, src)
        if listings:
            return ProbeResult(
                url=url,
                recommended_url=url,
                classification="A_CLEAN_HTTP",
                format_detected="html_jsonld",
                recommended_adapter="html_css",
                recommended_name=name,
                http_status=resp.status_code,
                item_count=len(listings),
                preview_items=_to_preview(listings),
                notes=["schema.org/Product JSON-LD extracted from HTML."],
            )

    return ProbeResult(
        url=url,
        recommended_url=url,
        classification="B_NEEDS_PLAYWRIGHT",
        format_detected="html_js_shell",
        recommended_adapter="html_css",
        recommended_name=name,
        http_status=resp.status_code,
        notes=[
            "HTTP 200 HTML returned, but no RSS, JSON, or schema.org/Product JSON-LD prices were found. "
            "Try custom CSS selectors, a Shopify /products.json endpoint, or enable render_js with Playwright."
        ],
    )


def _accepts_http_ctx(fn: Any) -> bool:
    try:
        params = inspect.signature(fn).parameters
    except TypeError, ValueError:
        return False
    return "http_ctx" in params or any(
        p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()
    )


async def _polite_get_with_ctx(url: str, http_ctx: HttpContext | None) -> HttpResponse:
    if http_ctx is not None and _accepts_http_ctx(polite_get):
        return await polite_get(url, http_ctx=http_ctx)
    return await polite_get(url)


async def _probe_url_with_ctx(url: str, http_ctx: HttpContext) -> ProbeResult:
    clean_url = url.strip()
    parsed = urlparse(clean_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return ProbeResult(
            url=url,
            recommended_url=url,
            classification="ERROR",
            format_detected="invalid_url",
            notes=["Please provide a full http:// or https:// URL."],
        )

    try:
        resp = await _polite_get_with_ctx(clean_url, http_ctx)
    except SSRFBlockedError as exc:
        return ProbeResult(
            url=clean_url,
            recommended_url=clean_url,
            classification="ERROR",
            format_detected="ssrf_blocked",
            notes=[f"{type(exc).__name__}: {exc}"],
        )
    except ResponseTooLargeError as exc:
        return ProbeResult(
            url=clean_url,
            recommended_url=clean_url,
            classification="ERROR",
            format_detected="response_too_large",
            notes=[f"{type(exc).__name__}: {exc}"],
        )
    except Exception as exc:
        return ProbeResult(
            url=clean_url,
            recommended_url=clean_url,
            classification="ERROR",
            format_detected="network_error",
            notes=[f"{type(exc).__name__}: {exc}"],
        )

    result = analyze_probe_response(clean_url, resp)

    # Auto-check Shopify /products.json when user pastes an HTML store/collection URL
    if result.classification == "B_NEEDS_PLAYWRIGHT" and not parsed.path.endswith(".json"):
        base_path = parsed.path.rstrip("/")
        candidate = f"{parsed.scheme}://{parsed.netloc}{base_path}/products.json"
        try:
            json_resp = await _polite_get_with_ctx(candidate, http_ctx)
            if json_resp.status_code == 200:
                src = SourceConfig(
                    name=result.recommended_name or _default_name_for_url(clean_url),
                    adapter="json_api",
                    url=candidate,
                )
                listings = parse_json_api_payload(json_resp.text, src)
                if listings:
                    return ProbeResult(
                        url=clean_url,
                        recommended_url=candidate,
                        classification="A_CLEAN_HTTP",
                        format_detected="shopify_products_json_autodiscovered",
                        recommended_adapter="json_api",
                        recommended_name=src.name,
                        http_status=200,
                        item_count=len(listings),
                        preview_items=_to_preview(listings),
                        notes=[
                            f"HTML page lacked JSON-LD, but auto-discovered clean Shopify JSON at {candidate}."
                        ],
                    )
        except Exception:
            pass

    return result


async def probe_url(url: str, http_ctx: HttpContext | None = None) -> ProbeResult:
    if http_ctx is not None:
        return await _probe_url_with_ctx(url, http_ctx)
    async with HttpContext() as owned_ctx:
        return await _probe_url_with_ctx(url, owned_ctx)


APPLE_QUERY_RE = re.compile(
    r"\b(?:apple|mac|macbook|mac\s+studio|mac\s+mini|imac|ipad|iphone|airpods)\b",
    re.IGNORECASE,
)

AUTOMOTIVE_TERM_RE = re.compile(
    r"\b(?:pickup|truck|car|suv|sedan|coupe|van|vehicle|auto|automobile|motorcycle|combi|kombi|microbus|vanagon|westfalia|transporter)\b",
    re.IGNORECASE,
)

CLASSIC_VEHICLE_RE = re.compile(
    r"\b(?:combi|kombi|type\s*2|microbus|vanagon|westfalia|transporter|classic|vintage|19[4-8]\d)\b",
    re.IGNORECASE,
)

TECH_SWAPPABLE_RE = re.compile(
    r"\b(?:iphone|galaxy|pixel|ipad|macbook|watch|tablet|phone|laptop|camera|switch|playstation|xbox|gpu)\b",
    re.IGNORECASE,
)

HOME_FURNITURE_RE = re.compile(
    r"\b(?:chair|desk|sofa|couch|table|aeron|embody|herman\s+miller|steelcase|appliance|refrigerator|washer|dryer|dishwasher|espresso|miele|bosch)\b",
    re.IGNORECASE,
)

BIKE_SPORTS_RE = re.compile(
    r"\b(?:bike|bicycle|ebike|e-bike|trek|specialized|cannondale|giant|cervelo|brompton|kayak|peloton)\b",
    re.IGNORECASE,
)


class VendorSearchCandidate(BaseModel):
    name: str
    adapter: Literal["rss", "json_api", "html_css", "appleinsider"]
    url: str
    options: dict[str, Any] = Field(default_factory=dict)
    status: Literal["A_CLEAN_HTTP", "EMPTY", "ERROR"]
    http_status: int | None = None
    total_fetched: int = 0
    matching_count: int = 0
    preview_items: list[ProbePreviewItem] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class VendorSearchResponse(BaseModel):
    query: str
    tokens: list[str] = Field(default_factory=list)
    candidates: list[VendorSearchCandidate] = Field(default_factory=list)


def _craigslist_source(
    region: str, label: str, category: str, query_label: str, query_str: str
) -> SourceConfig:
    encoded = quote_plus(query_str)
    return SourceConfig(
        name=f"Craigslist {label} ({query_label})",
        adapter="html_css",
        url=f"https://{region}.craigslist.org/search/{category}?query={encoded}",
        options={
            "item_selector": "li.cl-static-search-result",
            "title_selector": ".title",
            "price_selector": ".price",
            "link_selector": "a[href]",
            "default_condition": "used",
            "merchant": f"Craigslist {label}",
        },
    )


def build_vendor_search_sources(
    query: str, *, include_reddit_all: bool = True
) -> list[SourceConfig]:
    clean = " ".join(query.strip().split())
    if not clean:
        return []
    core_query = normalize_search_query(clean) or clean
    encoded_core = quote_plus(core_query)

    slickdeals_src = SourceConfig(
        name=f"Slickdeals ({core_query})",
        adapter="rss",
        url=(
            "https://slickdeals.net/newsearch.php"
            f"?mode=frontpage&searcharea=deals&searchin=first&rss=1&q={encoded_core}"
        ),
        options={"max_age_days": 7},
    )

    vehicle = detect_vehicle_make_model(clean)
    is_automotive = vehicle is not None or bool(AUTOMOTIVE_TERM_RE.search(clean))
    if is_automotive:
        is_classic = bool(CLASSIC_VEHICLE_RE.search(clean))
        sources: list[SourceConfig] = []
        if is_classic:
            is_vw_bus = any(
                tok in clean.lower()
                for tok in ("combi", "kombi", "microbus", "westfalia", "type 2", "type2")
            )
            cl_query = "Volkswagen Bus" if is_vw_bus else core_query
            sources.append(
                SourceConfig(
                    name=f"Classic.com ({core_query})",
                    adapter="html_css",
                    url=f"https://www.classic.com/search?q={encoded_core}",
                    options={
                        "item_selector": "div.border-gray-300.rounded-lg",
                        "title_selector": "h3 a[href*='/veh/']",
                        "price_selector": ":scope",
                        "link_selector": "h3 a[href*='/veh/']",
                        "default_condition": "used",
                        "merchant": "Classic.com",
                    },
                )
            )
            if is_vw_bus:
                sources.append(
                    SourceConfig(
                        name="Classic.com (Volkswagen Type 2)",
                        adapter="html_css",
                        url="https://www.classic.com/search?q=Volkswagen+Type+2",
                        options={
                            "item_selector": "div.border-gray-300.rounded-lg",
                            "title_selector": "h3 a[href*='/veh/']",
                            "price_selector": ":scope",
                            "link_selector": "h3 a[href*='/veh/']",
                            "default_condition": "used",
                            "merchant": "Classic.com",
                        },
                    )
                )
            sources.extend(
                [
                    _craigslist_source(
                        "washingtondc", "DC Cars & Trucks", "cta", cl_query, cl_query
                    ),
                    _craigslist_source(
                        "baltimore", "Baltimore Cars & Trucks", "cta", cl_query, cl_query
                    ),
                    _craigslist_source("newyork", "NY Cars & Trucks", "cta", cl_query, cl_query),
                ]
            )
            return sources

        if vehicle is not None:
            make_slug, model_slug = vehicle
            sources.extend(
                [
                    SourceConfig(
                        name=f"TrueCar Used ({core_query})",
                        adapter="html_css",
                        url=f"https://www.truecar.com/used-cars-for-sale/listings/{make_slug}/{model_slug}/",
                        options={"default_condition": "used"},
                    ),
                    SourceConfig(
                        name=f"TrueCar New ({core_query})",
                        adapter="html_css",
                        url=f"https://www.truecar.com/new-cars-for-sale/listings/{make_slug}/{model_slug}/",
                        options={"default_condition": "new"},
                    ),
                ]
            )
        sources.extend(
            [
                _craigslist_source(
                    "washingtondc", "DC Cars & Trucks", "cta", core_query, core_query
                ),
                _craigslist_source(
                    "baltimore", "Baltimore Cars & Trucks", "cta", core_query, core_query
                ),
                SourceConfig(
                    name=f"Classic.com ({core_query})",
                    adapter="html_css",
                    url=f"https://www.classic.com/search?q={encoded_core}",
                    options={
                        "item_selector": "div.border-gray-300.rounded-lg",
                        "title_selector": "h3 a[href*='/veh/']",
                        "price_selector": ":scope",
                        "link_selector": "h3 a[href*='/veh/']",
                        "default_condition": "used",
                        "merchant": "Classic.com",
                    },
                ),
                slickdeals_src,
            ]
        )
        return sources

    sources = [slickdeals_src]
    if BIKE_SPORTS_RE.search(clean):
        sources.extend(
            [
                _craigslist_source("washingtondc", "DC Bicycles", "bia", core_query, core_query),
                _craigslist_source(
                    "baltimore", "Baltimore Bicycles", "bia", core_query, core_query
                ),
                _craigslist_source("newyork", "NY Bicycles", "bia", core_query, core_query),
            ]
        )
        return sources

    if HOME_FURNITURE_RE.search(clean):
        sources.extend(
            [
                _craigslist_source("washingtondc", "DC Furniture", "fua", core_query, core_query),
                _craigslist_source("washingtondc", "DC Appliances", "ppa", core_query, core_query),
                _craigslist_source(
                    "baltimore", "Baltimore Furniture", "fua", core_query, core_query
                ),
                SourceConfig(
                    name=f"Abt ({core_query})",
                    adapter="html_css",
                    url=f"https://www.abt.com/resources/pages/search.php?keywords={encoded_core}",
                    options={"preset": "abt_search"},
                ),
            ]
        )
        return sources

    sources.extend(
        [
            _craigslist_source("washingtondc", "DC For Sale", "sss", core_query, core_query),
            _craigslist_source("baltimore", "Baltimore For Sale", "sss", core_query, core_query),
            SourceConfig(
                name=f"Abt ({core_query})",
                adapter="html_css",
                url=f"https://www.abt.com/resources/pages/search.php?keywords={encoded_core}",
                options={"preset": "abt_search"},
            ),
            SourceConfig(
                name=f"DataVision ({core_query})",
                adapter="json_api",
                url=f"https://datavision.com/search/suggest.json?q={encoded_core}&resources[type]=product",
            ),
            SourceConfig(
                name=f"Expercom ({core_query})",
                adapter="json_api",
                url=f"https://expercom.com/search/suggest.json?q={encoded_core}&resources[type]=product",
            ),
        ]
    )
    if TECH_SWAPPABLE_RE.search(clean):
        sources.append(
            SourceConfig(
                name=f"Swappa ({core_query})",
                adapter="html_css",
                url=f"https://swappa.com/search?q={encoded_core}",
                options={
                    "item_selector": "div.cell_product",
                    "title_selector": "a[href*='/listings/']",
                    "price_selector": ":scope",
                    "link_selector": "a[href*='/listings/']",
                    "default_condition": "used",
                    "merchant": "Swappa",
                },
            )
        )
    if APPLE_QUERY_RE.search(clean):
        sources.append(
            SourceConfig(
                name="Apple Certified Refurbished",
                adapter="json_api",
                url="https://www.apple.com/shop/refurbished/mac",
                options={"mode": "apple_refurb"},
            )
        )
    return sources


async def _evaluate_vendor_candidate(
    src: SourceConfig,
    token_groups: list[list[str]],
    http_ctx: HttpContext | None = None,
) -> VendorSearchCandidate:
    try:
        adapter = get_adapter(src.adapter)
        if http_ctx is not None and _accepts_http_ctx(adapter.fetch):
            outcome = await adapter.fetch(src, http_ctx=http_ctx)
        else:
            outcome = await adapter.fetch(src)
    except Exception as exc:
        return VendorSearchCandidate(
            name=src.name,
            adapter=src.adapter,
            url=src.url,
            options=src.options,
            status="ERROR",
            notes=[f"{type(exc).__name__}: {exc}"],
        )

    if outcome.error:
        return VendorSearchCandidate(
            name=src.name,
            adapter=src.adapter,
            url=src.url,
            options=src.options,
            status="ERROR",
            http_status=outcome.http_status,
            total_fetched=len(outcome.listings),
            notes=[outcome.error],
        )

    min_hits = len(token_groups) if len(token_groups) <= 2 else max(2, (len(token_groups) + 1) // 2)
    scored: list[tuple[int, Listing]] = []
    for item in outcome.listings:
        lower_title = item.title.lower()
        hits = sum(1 for group in token_groups if any(alt.lower() in lower_title for alt in group))
        if not token_groups or hits >= min_hits:
            scored.append((hits, item))

    scored.sort(key=lambda pair: (-pair[0], pair[1].price))
    matched_items = [pair[1] for pair in scored]
    total_fetched = len(outcome.listings)
    matching_count = len(matched_items)

    if matching_count > 0:
        status: Literal["A_CLEAN_HTTP", "EMPTY", "ERROR"] = "A_CLEAN_HTTP"
        notes = [f"{matching_count} matching items (out of {total_fetched} fetched)."]
    else:
        status = "EMPTY"
        notes = [
            f"Endpoint responded cleanly (HTTP {outcome.http_status or 200}), "
            f"fetched {total_fetched} items with 0 query matches."
        ]

    return VendorSearchCandidate(
        name=src.name,
        adapter=src.adapter,
        url=src.url,
        options=src.options,
        status=status,
        http_status=outcome.http_status,
        total_fetched=total_fetched,
        matching_count=matching_count,
        preview_items=_to_preview(matched_items, limit=5),
        notes=notes,
    )


async def search_vendors_for_query(
    query: str, *, http_ctx: HttpContext | None = None
) -> VendorSearchResponse:
    clean = " ".join(query.strip().split())
    groups = expand_include_keyword_groups(clean)
    tokens = [group[0].lower() for group in groups if group and len(group[0]) >= 2]
    sources = build_vendor_search_sources(clean, include_reddit_all=False)
    if not sources:
        return VendorSearchResponse(query=clean, tokens=tokens, candidates=[])

    if http_ctx is not None:
        results = await asyncio.gather(
            *(_evaluate_vendor_candidate(src, groups, http_ctx=http_ctx) for src in sources)
        )
    else:
        async with HttpContext() as owned_ctx:
            results = await asyncio.gather(
                *(_evaluate_vendor_candidate(src, groups, http_ctx=owned_ctx) for src in sources)
            )
    ordered = sorted(
        results,
        key=lambda c: (
            0 if c.matching_count > 0 else (1 if c.status != "ERROR" else 2),
            -c.matching_count,
            -c.total_fetched,
            c.name,
        ),
    )
    return VendorSearchResponse(query=clean, tokens=tokens, candidates=ordered)
