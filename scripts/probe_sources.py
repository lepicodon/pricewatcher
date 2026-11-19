#!/usr/bin/env python3.14
"""Phase 1 Source Verification Gate for PriceWatcher.

Probes candidate Mac Studio M5 Max sources using Python 3.14 stdlib + curl
fallback, saves sanitized fixture snapshots under tests/fixtures/, and
classifies each source as:
  - A_CLEAN_HTTP: Clean HTTP / RSS / JSON / JSON-LD / embedded bootstrap JSON
  - B_NEEDS_PLAYWRIGHT: HTTP 200 HTML shell requiring JS rendering
  - C_BOT_BLOCKED: HTTP 403/429/503 or anti-bot / CAPTCHA challenge
"""

from __future__ import annotations

import contextlib
import dataclasses
from dataclasses import dataclass, field
from datetime import UTC, datetime
import gzip
import html
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zlib

ROOT_DIR = Path(__file__).resolve().parent.parent
FIXTURES_DIR = ROOT_DIR / "tests" / "fixtures"

BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)
DEFAULT_CONTACT_URL = "https://github.com/your-username/pricewatcher"
REDDIT_CUSTOM_UA = (
    "PriceWatcher/1.0 (Mac Studio deal monitor; "
    f"+{os.environ.get('PRICEWATCHER_CONTACT_URL', '').strip() or DEFAULT_CONTACT_URL})"
)

BOT_BLOCK_MARKERS = [
    "cf-mitigated",
    "just a moment...",
    "_cf_chl_opt",
    "px-captcha",
    "perimeterx",
    "pardon our interruption",
    "access denied",
    "captcha-delivery.com",
    "datadome",
    "akamaighost",
    "please verify you are a human",
    "verify you are human",
    "enable javascript and cookies to continue",
    "attention required! | cloudflare",
]
PASSIVE_TELEMETRY_MARKERS = [
    "challenge-platform/scripts/jsd",
    "challenge-platform",
]

PRICE_RE = re.compile(r"\$[1-9](?:,\d{3}|\d{3})(?:\.\d{2})?")
MAC_STUDIO_RE = re.compile(r"mac\s+studio", re.IGNORECASE)
JSON_LD_RE = re.compile(
    r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)
NEXT_DATA_RE = re.compile(
    r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)
REFURB_BOOTSTRAP_RE = re.compile(
    r"window\.REFURB_GRID_BOOTSTRAP\s*=\s*(\{.*?\})\s*;\s*</script>",
    re.IGNORECASE | re.DOTALL,
)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@dataclass
class FetchResult:
    method: str
    url: str
    final_url: str
    status_code: int | None
    content_type: str
    headers: dict[str, str]
    body_bytes: bytes
    error: str | None = None

    @property
    def body_text(self) -> str:
        return self.body_bytes.decode("utf-8", errors="replace")


@dataclass
class ProbeAnalysis:
    source_group: str
    label: str
    url: str
    fetch_method: str
    final_url: str
    status_code: int | None
    content_type: str
    body_size_bytes: int
    classification: str
    format_detected: str
    page_title: str | None = None
    bot_markers_found: list[str] = field(default_factory=list)
    rss_item_count: int = 0
    json_product_count: int = 0
    json_variant_count: int = 0
    jsonld_product_count: int = 0
    refurb_tile_count: int = 0
    next_data_present: bool = False
    mac_studio_mentions: int = 0
    price_matches_count: int = 0
    sample_items: list[str] = field(default_factory=list)
    sample_prices: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    fixture_file: str | None = None
    fallback_attempts: list[dict[str, str | int | None]] = field(default_factory=list)


def decompress_body(raw: bytes, content_encoding: str | None) -> bytes:
    encoding = (content_encoding or "").lower()
    if "gzip" in encoding:
        try:
            return gzip.decompress(raw)
        except OSError:
            pass
    if "deflate" in encoding:
        try:
            return zlib.decompress(raw)
        except zlib.error:
            try:
                return zlib.decompress(raw, -zlib.MAX_WBITS)
            except zlib.error:
                pass
    return raw


def build_headers(user_agent: str, accept: str | None = None) -> dict[str, str]:
    return {
        "User-Agent": user_agent,
        "Accept": accept
        or "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Cache-Control": "no-cache",
    }


def fetch_with_urllib(
    url: str,
    user_agent: str = BROWSER_UA,
    accept: str | None = None,
    timeout: int = 20,
) -> FetchResult:
    headers = build_headers(user_agent, accept)
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            raw = resp.read()
            body = decompress_body(raw, resp_headers.get("content-encoding"))
            return FetchResult(
                method="urllib",
                url=url,
                final_url=resp.geturl(),
                status_code=resp.status,
                content_type=resp_headers.get("content-type", ""),
                headers=resp_headers,
                body_bytes=body,
            )
    except urllib.error.HTTPError as exc:
        resp_headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        raw = b""
        with contextlib.suppress(Exception):
            raw = exc.read()
        body = decompress_body(raw, resp_headers.get("content-encoding"))
        return FetchResult(
            method="urllib",
            url=url,
            final_url=exc.geturl() or url,
            status_code=exc.code,
            content_type=resp_headers.get("content-type", ""),
            headers=resp_headers,
            body_bytes=body,
            error=f"HTTP {exc.code}: {exc.reason}",
        )
    except Exception as exc:
        return FetchResult(
            method="urllib",
            url=url,
            final_url=url,
            status_code=None,
            content_type="",
            headers={},
            body_bytes=b"",
            error=f"{type(exc).__name__}: {exc}",
        )


def parse_last_header_block(header_bytes: bytes) -> dict[str, str]:
    text = header_bytes.decode("latin-1", errors="replace")
    blocks = [b.strip() for b in re.split(r"\r?\n\r?\n", text) if b.strip()]
    if not blocks:
        return {}
    last_block = blocks[-1]
    headers: dict[str, str] = {}
    for line in last_block.splitlines()[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return headers


def fetch_with_curl(
    url: str,
    user_agent: str = BROWSER_UA,
    accept: str | None = None,
    timeout: int = 20,
) -> FetchResult:
    accept_hdr = (
        accept
        or "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7"
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        hdr_path = Path(tmpdir) / "headers.txt"
        body_path = Path(tmpdir) / "body.bin"
        cmd = [
            "/usr/bin/curl",
            "-sS",
            "-L",
            "--compressed",
            "--max-time",
            str(timeout),
            "-A",
            user_agent,
            "-H",
            f"Accept: {accept_hdr}",
            "-H",
            "Accept-Language: en-US,en;q=0.9",
            "-D",
            str(hdr_path),
            "-o",
            str(body_path),
            "-w",
            "%{http_code}\n%{url_effective}\n%{content_type}",
            url,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        body = body_path.read_bytes() if body_path.exists() else b""
        hdrs = parse_last_header_block(hdr_path.read_bytes()) if hdr_path.exists() else {}
        if proc.returncode != 0:
            return FetchResult(
                method="curl",
                url=url,
                final_url=url,
                status_code=None,
                content_type=hdrs.get("content-type", ""),
                headers=hdrs,
                body_bytes=body,
                error=f"curl exit {proc.returncode}: {proc.stderr.strip()}",
            )
        lines = proc.stdout.splitlines()
        status_code = int(lines[0]) if lines and lines[0].isdigit() else None
        final_url = lines[1] if len(lines) > 1 and lines[1] else url
        content_type = lines[2] if len(lines) > 2 else hdrs.get("content-type", "")
        return FetchResult(
            method="curl",
            url=url,
            final_url=final_url,
            status_code=status_code,
            content_type=content_type or hdrs.get("content-type", ""),
            headers=hdrs,
            body_bytes=body,
            error=None if status_code and status_code < 400 else f"HTTP {status_code}",
        )


def detect_bot_markers(res: FetchResult) -> list[str]:
    markers: list[str] = []
    if res.headers.get("cf-mitigated"):
        markers.append(f"header:cf-mitigated={res.headers['cf-mitigated']}")
    if res.headers.get("x-datadome"):
        markers.append("header:x-datadome")
    if any(k.startswith("x-px-") for k in res.headers):
        markers.append("header:x-px")
    lower = res.body_text.lower()
    for marker in BOT_BLOCK_MARKERS:
        if marker in lower:
            markers.append(marker)
    return markers


def detect_passive_markers(res: FetchResult) -> list[str]:
    lower = res.body_text.lower()
    return [m for m in PASSIVE_TELEMETRY_MARKERS if m in lower]


def extract_page_title(text: str) -> str | None:
    match = TITLE_RE.search(text)
    if not match:
        return None
    cleaned = re.sub(r"\s+", " ", html.unescape(match.group(1))).strip()
    return cleaned[:160] if cleaned else None


def inspect_rss_atom(text: str) -> tuple[bool, int, list[str]]:
    stripped = text.lstrip()
    if not (
        stripped.startswith("<?xml")
        or "<rss" in stripped[:500].lower()
        or "<feed" in stripped[:500].lower()
    ):
        return False, 0, []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return False, 0, []

    tag = root.tag.lower()
    samples: list[str] = []
    if tag.endswith("rss") or root.find("./channel") is not None:
        items = root.findall(".//item")
        for item in items[:3]:
            title = (item.findtext("title") or "").strip()
            link = (item.findtext("link") or "").strip()
            if title or link:
                samples.append(f"{title} ({link})" if link else title)
        return True, len(items), samples

    if tag.endswith("feed"):
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}", 1)[0] + "}"
        entries = root.findall(f".//{ns}entry")
        for entry in entries[:3]:
            title = (entry.findtext(f"{ns}title") or "").strip()
            link_el = entry.find(f"{ns}link")
            link = link_el.attrib.get("href", "").strip() if link_el is not None else ""
            if title or link:
                samples.append(f"{title} ({link})" if link else title)
        return True, len(entries), samples

    return False, 0, []


def inspect_json_payload(text: str) -> tuple[bool, str, int, int, list[str], list[str]]:
    stripped = text.lstrip()
    if not (stripped.startswith("{") or stripped.startswith("[")):
        return False, "", 0, 0, [], []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return False, "", 0, 0, [], []

    if isinstance(data, dict) and isinstance(data.get("products"), list):
        products = data["products"]
        variants_count = 0
        samples: list[str] = []
        prices: list[str] = []
        for prod in products:
            if not isinstance(prod, dict):
                continue
            variants = prod.get("variants") if isinstance(prod.get("variants"), list) else []
            variants_count += len(variants)
            if len(samples) < 4:
                title = str(prod.get("title") or prod.get("name") or "").strip()
                price = ""
                if variants and isinstance(variants[0], dict):
                    price = str(variants[0].get("price") or "")
                elif prod.get("price") is not None:
                    price = str(prod.get("price"))
                if title:
                    samples.append(f"{title} [${price}]" if price else title)
                if price:
                    prices.append(f"${price}")
        return True, "shopify_products_json", len(products), variants_count, samples, prices

    if isinstance(data, dict) and isinstance(data.get("resources"), dict):
        results = data["resources"].get("results") or {}
        products = results.get("products") if isinstance(results.get("products"), list) else []
        samples = []
        prices = []
        for prod in products[:4]:
            if isinstance(prod, dict):
                title = str(prod.get("title") or "").strip()
                price = str(prod.get("price") or "").strip()
                if title:
                    samples.append(f"{title} [${price}]" if price else title)
                if price:
                    prices.append(f"${price}")
        return True, "shopify_suggest_json", len(products), 0, samples, prices

    if isinstance(data, list):
        return True, "json_array", len(data), 0, [], []

    if isinstance(data, dict):
        keys = ", ".join(list(data.keys())[:5])
        return True, f"json_object({keys})", 0, 0, [], []

    return False, "", 0, 0, [], []


def _walk_jsonld_items(node: object, found: list[dict[str, object]]) -> None:
    if isinstance(node, list):
        for item in node:
            _walk_jsonld_items(item, found)
    elif isinstance(node, dict):
        node_type = node.get("@type")
        types = node_type if isinstance(node_type, list) else [node_type]
        type_strs = [str(t) for t in types if t]
        if any("Product" in t or "Offer" in t for t in type_strs):
            found.append(node)
        for k, v in node.items():
            if k in ("@graph", "itemListElement", "mainEntity", "item", "offers"):
                _walk_jsonld_items(v, found)


def inspect_jsonld(text: str) -> tuple[int, list[str], list[str]]:
    blocks = JSON_LD_RE.findall(text)
    if not blocks:
        return 0, [], []
    products: list[dict[str, object]] = []
    for raw in blocks:
        try:
            parsed = json.loads(raw.strip())
        except json.JSONDecodeError:
            continue
        _walk_jsonld_items(parsed, products)

    samples: list[str] = []
    prices: list[str] = []
    product_only = [p for p in products if "Product" in str(p.get("@type", ""))]
    for prod in product_only[:4]:
        name = str(prod.get("name") or "").strip()
        offers = prod.get("offers")
        price_val = None
        if isinstance(offers, dict):
            price_val = offers.get("price") or offers.get("lowPrice")
        elif isinstance(offers, list) and offers and isinstance(offers[0], dict):
            price_val = offers[0].get("price") or offers[0].get("lowPrice")
        if name:
            samples.append(f"{name} [${price_val}]" if price_val is not None else name)
        if price_val is not None:
            prices.append(f"${price_val}")
    return len(product_only), samples, prices


def inspect_refurb_bootstrap(text: str) -> tuple[int, list[str], list[str]]:
    match = REFURB_BOOTSTRAP_RE.search(text)
    if not match:
        return 0, [], []
    try:
        data = json.loads(match.group(1))
    except json.JSONDecodeError:
        return 0, [], []
    tiles = data.get("tiles") if isinstance(data, dict) else None
    if not isinstance(tiles, list):
        return 0, [], []
    samples: list[str] = []
    prices: list[str] = []
    for tile in tiles[:5]:
        if not isinstance(tile, dict):
            continue
        title = str(tile.get("title") or "").strip()
        price_obj = tile.get("price") or {}
        current_price = ""
        if isinstance(price_obj, dict):
            current_price = str(
                price_obj.get("currentPrice", {}).get("amount")
                or price_obj.get("currentPrice", {}).get("raw_amount")
                or ""
            )
        if title:
            samples.append(f"{title} [{current_price}]" if current_price else title)
        if current_price:
            prices.append(current_price)
    return len(tiles), samples, prices


def sanitize_slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    return slug[:80]


def save_fixture(slug: str, res: FetchResult, format_detected: str) -> str:
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    if "rss" in format_detected or "atom" in format_detected:
        ext = "xml"
    elif (
        "json" in format_detected
        and "html" not in format_detected
        and "jsonld" not in format_detected
    ):
        ext = "json"
    else:
        ext = "html"
    path = FIXTURES_DIR / f"{slug}.{ext}"
    max_bytes = 2_500_000
    data = res.body_bytes[:max_bytes]
    path.write_bytes(data)
    return str(path.relative_to(ROOT_DIR))


def analyze_response(
    source_group: str,
    label: str,
    url: str,
    res: FetchResult,
    fallback_attempts: list[dict[str, str | int | None]],
) -> ProbeAnalysis:
    text = res.body_text
    page_title = extract_page_title(text)
    bot_markers = detect_bot_markers(res)
    passive_markers = detect_passive_markers(res)
    mac_mentions = len(MAC_STUDIO_RE.findall(text))
    price_matches = PRICE_RE.findall(text)

    is_rss, rss_count, rss_samples = inspect_rss_atom(text)
    is_json, json_fmt, json_prod_cnt, json_var_cnt, json_samples, json_prices = (
        inspect_json_payload(text)
    )
    jsonld_cnt, jsonld_samples, jsonld_prices = inspect_jsonld(text)
    refurb_cnt, refurb_samples, refurb_prices = inspect_refurb_bootstrap(text)
    next_data_present = bool(NEXT_DATA_RE.search(text))

    notes: list[str] = []
    if res.error:
        notes.append(res.error)

    # Determine format and classification
    status = res.status_code
    is_challenge_title = bool(
        page_title
        and any(
            kw in page_title.lower()
            for kw in (
                "just a moment",
                "access denied",
                "attention required",
                "pardon our interruption",
                "robot or human",
            )
        )
    )
    has_structured_data = (
        is_rss or (is_json and json_prod_cnt > 0) or jsonld_cnt > 0 or refurb_cnt > 0
    )

    if (
        status in (403, 429, 503)
        or is_challenge_title
        or (bot_markers and not has_structured_data and status != 200)
    ):
        classification = "C_BOT_BLOCKED"
        fmt = "blocked_challenge"
    elif status == 404:
        classification = "NOT_FOUND_404"
        fmt = "http_404"
    elif status is None or status >= 400:
        classification = "C_BOT_BLOCKED"
        fmt = f"http_error_{status or 'network'}"
    elif is_rss:
        classification = "A_CLEAN_HTTP"
        fmt = "rss_atom_xml"
    elif is_json:
        if "shopify" in json_fmt or json_prod_cnt > 0:
            classification = "A_CLEAN_HTTP"
            fmt = json_fmt
        else:
            classification = "A_CLEAN_HTTP"
            fmt = json_fmt
    elif refurb_cnt > 0:
        classification = "A_CLEAN_HTTP"
        fmt = "html_refurb_bootstrap_json"
    elif jsonld_cnt > 0:
        classification = "A_CLEAN_HTTP"
        fmt = "html_jsonld"
    elif mac_mentions > 0 and len(price_matches) >= 2 and not bot_markers:
        classification = "A_CLEAN_HTTP"
        fmt = "html_server_rendered"
    elif bot_markers and not (mac_mentions > 0 and len(price_matches) >= 2):
        classification = "C_BOT_BLOCKED"
        fmt = "html_bot_interstitial"
    else:
        classification = "B_NEEDS_PLAYWRIGHT"
        fmt = "html_js_shell"
        if next_data_present:
            notes.append("__NEXT_DATA__ found without Product JSON-LD")

    samples = rss_samples or json_samples or refurb_samples or jsonld_samples
    if not samples and classification == "A_CLEAN_HTTP" and "prices.appleinsider.com" in url:
        # Extract sample price/config snippets from AppleInsider HTML if present
        ai_matches = re.findall(r"(Mac Studio[^<]{0,120})", text, flags=re.IGNORECASE)
        samples = [re.sub(r"\s+", " ", html.unescape(m)).strip() for m in ai_matches[:4]]

    sample_prices = (
        json_prices or refurb_prices or jsonld_prices or list(dict.fromkeys(price_matches))[:6]
    )

    if passive_markers:
        notes.append(f"passive telemetry noted: {', '.join(passive_markers)}")
    if bot_markers and classification == "A_CLEAN_HTTP":
        notes.append(f"passive markers noted: {', '.join(bot_markers)}")

    slug = sanitize_slug(f"{source_group}_{label}")
    fixture_file = save_fixture(slug, res, fmt) if res.body_bytes else None

    return ProbeAnalysis(
        source_group=source_group,
        label=label,
        url=url,
        fetch_method=res.method,
        final_url=res.final_url,
        status_code=res.status_code,
        content_type=res.content_type,
        body_size_bytes=len(res.body_bytes),
        classification=classification,
        format_detected=fmt,
        page_title=page_title,
        bot_markers_found=bot_markers,
        rss_item_count=rss_count,
        json_product_count=json_prod_cnt,
        json_variant_count=json_var_cnt,
        jsonld_product_count=jsonld_cnt,
        refurb_tile_count=refurb_cnt,
        next_data_present=next_data_present,
        mac_studio_mentions=mac_mentions,
        price_matches_count=len(price_matches),
        sample_items=samples,
        sample_prices=sample_prices,
        notes=notes,
        fixture_file=fixture_file,
        fallback_attempts=fallback_attempts,
    )


def smart_fetch(
    url: str, is_reddit: bool = False
) -> tuple[FetchResult, list[dict[str, str | int | None]]]:
    attempts: list[dict[str, str | int | None]] = []

    def record(res: FetchResult, ua_label: str) -> None:
        attempts.append(
            {
                "method": res.method,
                "ua": ua_label,
                "status": res.status_code,
                "bytes": len(res.body_bytes),
                "error": res.error,
            }
        )

    accept = (
        "application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.8"
        if (".rss" in url or "rss=1" in url)
        else "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    )

    if is_reddit:
        # Test custom descriptive User-Agent first (and compare browser UA if blocked)
        res_custom = fetch_with_urllib(url, user_agent=REDDIT_CUSTOM_UA, accept=accept)
        record(res_custom, "custom_pricewatcher_ua")
        if res_custom.status_code == 200 and not detect_bot_markers(res_custom):
            return res_custom, attempts

        res_curl_custom = fetch_with_curl(url, user_agent=REDDIT_CUSTOM_UA, accept=accept)
        record(res_curl_custom, "custom_pricewatcher_ua")
        if res_curl_custom.status_code == 200 and not detect_bot_markers(res_curl_custom):
            return res_curl_custom, attempts

        res_curl_browser = fetch_with_curl(url, user_agent=BROWSER_UA, accept=accept)
        record(res_curl_browser, "browser_ua")
        return res_curl_browser, attempts

    res_urllib = fetch_with_urllib(url, user_agent=BROWSER_UA, accept=accept)
    record(res_urllib, "browser_ua")

    markers = detect_bot_markers(res_urllib)
    needs_curl = res_urllib.status_code != 200 or bool(markers) or len(res_urllib.body_bytes) < 500
    if not needs_curl:
        return res_urllib, attempts

    res_curl = fetch_with_curl(url, user_agent=BROWSER_UA, accept=accept)
    record(res_curl, "browser_ua")

    # Prefer whichever got HTTP 200 without block markers, or HTTP 200 with larger body
    curl_markers = detect_bot_markers(res_curl)
    if res_curl.status_code == 200 and not curl_markers:
        return res_curl, attempts
    if res_urllib.status_code == 200 and not markers:
        return res_urllib, attempts
    if (res_curl.status_code or 0) == 200 and len(res_curl.body_bytes) > len(res_urllib.body_bytes):
        return res_curl, attempts
    if res_curl.status_code is not None and res_urllib.status_code is None:
        return res_curl, attempts
    return res_urllib, attempts


def discover_appleinsider_mac_studio_urls(hub_res: FetchResult) -> list[str]:
    text = hub_res.body_text
    hrefs = re.findall(r'href=["\']([^"\']*mac-studio[^"\']*)["\']', text, flags=re.IGNORECASE)
    urls: list[str] = []
    seen: set[str] = set()
    for href in hrefs:
        abs_url = urllib.parse.urljoin("https://prices.appleinsider.com/", href).split("#")[0]
        if "prices.appleinsider.com" in abs_url and abs_url not in seen:
            seen.add(abs_url)
            urls.append(abs_url)
    return urls


def build_probe_targets() -> list[tuple[str, str, str, bool]]:
    """Return list of (source_group, label, url, is_reddit)."""
    targets: list[tuple[str, str, str, bool]] = []

    # 1. AppleInsider hub + dynamic discovery
    hub_url = "https://prices.appleinsider.com/"
    targets.append(("AppleInsider", "Price Guide Hub", hub_url, False))

    # Candidate static URLs will be supplemented after probing the hub in run_probes()
    return targets


def summarize_group(analyses: list[ProbeAnalysis]) -> dict[str, list[ProbeAnalysis]]:
    grouped: dict[str, list[ProbeAnalysis]] = {}
    for item in analyses:
        grouped.setdefault(item.source_group, []).append(item)
    return grouped


def group_classification(items: list[ProbeAnalysis]) -> str:
    classes = {i.classification for i in items}
    if "A_CLEAN_HTTP" in classes:
        return "A_CLEAN_HTTP"
    if "B_NEEDS_PLAYWRIGHT" in classes:
        return "B_NEEDS_PLAYWRIGHT"
    if "C_BOT_BLOCKED" in classes:
        return "C_BOT_BLOCKED"
    return "NOT_FOUND_404"


def run_probes() -> list[ProbeAnalysis]:
    analyses: list[ProbeAnalysis] = []

    # Step 1: Probe AppleInsider hub & discover exact Mac Studio URLs
    print("Probing AppleInsider hub for Mac Studio guide URLs...")
    hub_url = "https://prices.appleinsider.com/"
    hub_res, hub_attempts = smart_fetch(hub_url)
    analyses.append(analyze_response("AppleInsider", "Hub", hub_url, hub_res, hub_attempts))

    discovered_ai = discover_appleinsider_mac_studio_urls(hub_res)
    ai_candidates = [
        *discovered_ai,
        "https://prices.appleinsider.com/mac-studio-m5-max",
        "https://prices.appleinsider.com/mac-studio-m4-max",
        "https://prices.appleinsider.com/mac-studio",
    ]
    seen_ai: set[str] = set()
    unique_ai_urls: list[str] = []
    for u in ai_candidates:
        if u not in seen_ai:
            seen_ai.add(u)
            unique_ai_urls.append(u)

    candidate_list: list[tuple[str, str, str, bool]] = []
    for u in unique_ai_urls:
        slug = u.rstrip("/").rsplit("/", 1)[-1] or "root"
        candidate_list.append(("AppleInsider", f"Guide {slug}", u, False))

    candidate_list.extend(
        [
            # 2. Slickdeals RSS
            (
                "Slickdeals RSS",
                "Search Mac Studio",
                "https://slickdeals.net/newsearch.php?mode=frontpage&searcharea=deals&searchin=first&rss=1&q=Mac+Studio",
                False,
            ),
            (
                "Slickdeals RSS",
                "Search Mac Studio M5",
                "https://slickdeals.net/newsearch.php?mode=frontpage&searcharea=deals&searchin=first&rss=1&q=Mac+Studio+M5",
                False,
            ),
            # 3. Reddit RSS
            (
                "Reddit RSS",
                "r/appledeals new",
                "https://www.reddit.com/r/appledeals/new/.rss",
                True,
            ),
            ("Reddit RSS", "r/macstudio new", "https://www.reddit.com/r/macstudio/new/.rss", True),
            (
                "Reddit RSS",
                "r/appledeals search",
                "https://www.reddit.com/r/appledeals/search.rss?q=Mac+Studio&restrict_sr=on&sort=new",
                True,
            ),
            # 4. Apple Certified Refurbished
            (
                "Apple Refurbished",
                "Mac Studio Refurb",
                "https://www.apple.com/shop/refurbished/mac/mac-studio",
                False,
            ),
            # 5. Expercom
            (
                "Expercom",
                "Collection products.json",
                "https://expercom.com/collections/mac-studio/products.json",
                False,
            ),
            (
                "Expercom",
                "Search suggest.json",
                "https://expercom.com/search/suggest.json?q=Mac%20Studio&resources[type]=product",
                False,
            ),
            (
                "Expercom",
                "Collection HTML",
                "https://expercom.com/collections/mac-studio",
                False,
            ),
            # 6. DataVision
            (
                "DataVision",
                "Collection products.json",
                "https://datavision.com/collections/mac-studio/products.json",
                False,
            ),
            (
                "DataVision",
                "Root products.json",
                "https://datavision.com/products.json?limit=25",
                False,
            ),
            (
                "DataVision",
                "Search suggest.json",
                "https://datavision.com/search/suggest.json?q=Mac%20Studio&resources[type]=product",
                False,
            ),
            (
                "DataVision",
                "Search HTML",
                "https://datavision.com/search?q=mac+studio",
                False,
            ),
            # 7. Abt Electronics
            (
                "Abt",
                "Mac Studio Category",
                "https://www.abt.com/Apple-Mac-Studio-Desktop-Computers/c/4648.html",
                False,
            ),
            (
                "Abt",
                "Search Mac Studio",
                "https://www.abt.com/resources/pages/search.php?keywords=mac+studio",
                False,
            ),
            # 8. B&H Photo Video
            (
                "B&H",
                "Category Mac Studio",
                "https://www.bhphotovideo.com/c/buy/mac-studio/ci/52157",
                False,
            ),
            (
                "B&H",
                "Search Mac Studio",
                "https://www.bhphotovideo.com/c/search?Ntt=Mac%20Studio&N=0",
                False,
            ),
            # 9. Adorama
            (
                "Adorama",
                "Category Mac Studio",
                "https://www.adorama.com/l/Computers/Apple-Computers/Mac-Studio",
                False,
            ),
            # 10. Micro Center
            (
                "Micro Center",
                "Search Mac Studio",
                "https://www.microcenter.com/search/search_results.aspx?Ntt=mac+studio",
                False,
            ),
        ]
    )

    reddit_seen = 0
    for source_group, label, url, is_reddit in candidate_list:
        if is_reddit:
            if reddit_seen > 0:
                time.sleep(2.0)
            reddit_seen += 1
        print(f"Probing [{source_group}] {label}: {url}")
        res, attempts = smart_fetch(url, is_reddit=is_reddit)
        analysis = analyze_response(source_group, label, url, res, attempts)
        analyses.append(analysis)

    return analyses


def print_report(analyses: list[ProbeAnalysis]) -> None:
    grouped = summarize_group(analyses)

    print("\n" + "=" * 96)
    print("PHASE 1 SOURCE VERIFICATION GATE — SUMMARY BY SOURCE")
    print("=" * 96)
    print(f"{'Source':<20} | {'Gate Class':<20} | {'Best Endpoint / Format'}")
    print("-" * 96)

    for group, items in grouped.items():
        g_class = group_classification(items)
        best = next((i for i in items if i.classification == g_class), items[0])
        detail = (
            f"{best.label} ({best.format_detected}, HTTP {best.status_code}, {best.fetch_method})"
        )
        print(f"{group:<20} | {g_class:<20} | {detail}")

    print("\n" + "=" * 96)
    print("DETAILED ENDPOINT BREAKDOWN")
    print("=" * 96)
    for item in analyses:
        print(
            f"\n[{item.source_group}] {item.label}\n"
            f"  URL:            {item.url}\n"
            f"  Final URL:      {item.final_url}\n"
            f"  Classification: {item.classification} | Format: {item.format_detected}\n"
            f"  Fetch:          {item.fetch_method} | HTTP {item.status_code} | {item.body_size_bytes} bytes | {item.content_type}\n"
            f"  Title:          {item.page_title}\n"
            f"  Counts:         rss={item.rss_item_count}, json_prod={item.json_product_count} (vars={item.json_variant_count}), "
            f"jsonld={item.jsonld_product_count}, refurb_tiles={item.refurb_tile_count}, "
            f"mac_studio={item.mac_studio_mentions}, prices={item.price_matches_count}"
        )
        if item.bot_markers_found:
            print(f"  Bot markers:    {', '.join(item.bot_markers_found)}")
        if item.sample_items:
            print(f"  Sample items:   {' | '.join(item.sample_items[:3])}")
        if item.sample_prices:
            print(f"  Sample prices:  {', '.join(item.sample_prices[:6])}")
        if item.notes:
            print(f"  Notes:          {'; '.join(item.notes)}")
        if item.fixture_file:
            print(f"  Fixture:        {item.fixture_file}")
        if len(item.fallback_attempts) > 1:
            print(f"  Attempts:       {item.fallback_attempts}")


def main() -> int:
    analyses = run_probes()
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

    grouped = summarize_group(analyses)
    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "python_version": "3.14",
        "group_summary": {
            group: {
                "classification": group_classification(items),
                "endpoints": [i.url for i in items],
            }
            for group, items in grouped.items()
        },
        "endpoints": [dataclasses.asdict(a) for a in analyses],
    }

    report_path = FIXTURES_DIR / "probe_report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print_report(analyses)
    print(f"\nSaved full JSON report to {report_path.relative_to(ROOT_DIR)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
