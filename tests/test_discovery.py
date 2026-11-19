"""Unit tests for discovery probing, vendor source building, and search orchestration."""

from __future__ import annotations

import json
import socket
from types import TracebackType
from typing import Any

import httpx
import pytest

from pricewatcher import discovery, http_client
from pricewatcher.adapters.base import FetchOutcome, Listing
from pricewatcher.config import SourceConfig
from pricewatcher.http_client import HttpContext, HttpResponse


def _mock_dns(monkeypatch: pytest.MonkeyPatch, mapping: dict[str, list[tuple[int, str]]]) -> None:
    """Mock socket.getaddrinfo so discovery probes never issue real DNS queries."""

    def fake_getaddrinfo(
        host: str,
        port: Any,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[tuple[Any, ...]]:
        del family, type, proto, flags
        key = str(host).lower()
        if key not in mapping:
            raise socket.gaierror(socket.EAI_NONAME, f"No mock DNS entry for {key}")
        entries: list[tuple[Any, ...]] = []
        for fam, ip in mapping[key]:
            sockaddr: tuple[Any, ...] = (
                (ip, int(port or 0), 0, 0) if fam == socket.AF_INET6 else (ip, int(port or 0))
            )
            entries.append((fam, socket.SOCK_STREAM, 6, "", sockaddr))
        return entries

    monkeypatch.setattr(http_client.socket, "getaddrinfo", fake_getaddrinfo)


@pytest.mark.parametrize(
    ("status_code", "headers", "body"),
    [
        (403, {}, "<html>Forbidden</html>"),
        (429, {}, "<html>Rate limited</html>"),
        (503, {}, "<html>Service unavailable</html>"),
        (200, {"cf-mitigated": "challenge"}, "<html>Challenge</html>"),
        (200, {"x-datadome": "protected"}, "<html>Captcha</html>"),
        (200, {}, "<html><title>Just a moment...</title></html>"),
        (200, {}, "<html><script>window._cf_chl_opt = {};</script></html>"),
        (200, {}, "<html><body>Please verify you are a human</body></html>"),
    ],
)
def test_analyze_probe_response_active_blocks(
    status_code: int,
    headers: dict[str, str],
    body: str,
) -> None:
    resp = HttpResponse(
        status_code=status_code,
        url="https://www.blocked.example.com/deals",
        headers=headers,
        text=body,
    )
    res = discovery.analyze_probe_response(resp.url, resp)
    assert res.classification == "C_BOT_BLOCKED"
    assert res.format_detected == "bot_challenge_or_blocked"
    assert res.recommended_name == "blocked.example.com"
    assert res.http_status == status_code


@pytest.mark.parametrize("status_code", [404, 410, 500, 502])
def test_analyze_probe_response_http_errors(status_code: int) -> None:
    resp = HttpResponse(
        status_code=status_code,
        url="https://shop.example.com/missing",
        headers={},
        text="Not Found",
    )
    res = discovery.analyze_probe_response(resp.url, resp)
    assert res.classification == "ERROR"
    assert res.format_detected == f"http_{status_code}"
    assert res.http_status == status_code


def test_analyze_probe_response_rss_and_atom() -> None:
    rss_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0"><channel><title>Deals</title>
      <item>
        <title>Mac Studio M5 Max at Adorama - $3,449</title>
        <link>https://deals.example.com/item1</link>
        <description>Great deal</description>
      </item>
    </channel></rss>"""
    rss_res = discovery.analyze_probe_response(
        "https://www.deals.example.com/feed.rss",
        HttpResponse(
            status_code=200, url="https://www.deals.example.com/feed.rss", headers={}, text=rss_xml
        ),
    )
    assert rss_res.classification == "A_CLEAN_HTTP"
    assert rss_res.format_detected == "rss_atom_xml"
    assert rss_res.recommended_adapter == "rss"
    assert rss_res.recommended_name == "deals.example.com"
    assert rss_res.item_count == 1
    assert rss_res.preview_items[0].price == 3449.0

    atom_xml = """<feed xmlns="http://www.w3.org/2005/Atom">
      <title>Atom Deals</title>
      <entry>
        <title>Mac Mini M4 Pro - $1,199</title>
        <link href="https://atom.example.com/1"/>
        <summary>On sale at B&amp;H</summary>
      </entry>
    </feed>"""
    atom_res = discovery.analyze_probe_response(
        "https://atom.example.com/deals.atom",
        HttpResponse(
            status_code=200, url="https://atom.example.com/deals.atom", headers={}, text=atom_xml
        ),
    )
    assert atom_res.classification == "A_CLEAN_HTTP"
    assert atom_res.format_detected == "rss_atom_xml"
    assert atom_res.recommended_adapter == "rss"
    assert atom_res.item_count == 1


def test_analyze_probe_response_json_variants_and_malformed_json() -> None:
    shopify_products = json.dumps(
        {
            "products": [
                {
                    "title": "Mac Studio M5 Max",
                    "handle": "mac-studio-m5-max",
                    "variants": [
                        {"id": 101, "title": "64GB / 512GB", "price": "3499.00", "available": True}
                    ],
                }
            ]
        }
    )
    res_products = discovery.analyze_probe_response(
        "https://expercom.com/products.json",
        HttpResponse(
            status_code=200,
            url="https://expercom.com/products.json",
            headers={},
            text=shopify_products,
        ),
    )
    assert res_products.classification == "A_CLEAN_HTTP"
    assert res_products.format_detected == "shopify_products_json"
    assert res_products.recommended_adapter == "json_api"
    assert res_products.item_count == 1
    assert res_products.preview_items[0].merchant == "Expercom"

    shopify_suggest = json.dumps(
        {
            "resources": {
                "results": {
                    "products": [
                        {
                            "title": "MacBook Pro 16",
                            "price": "2399.00",
                            "url": "/products/mbp-16",
                            "available": True,
                        }
                    ]
                }
            }
        }
    )
    res_suggest = discovery.analyze_probe_response(
        "https://datavision.com/search/suggest.json?q=macbook",
        HttpResponse(
            status_code=200,
            url="https://datavision.com/search/suggest.json?q=macbook",
            headers={},
            text=shopify_suggest,
        ),
    )
    assert res_suggest.classification == "A_CLEAN_HTTP"
    assert res_suggest.format_detected == "shopify_suggest_json"
    assert res_suggest.recommended_adapter == "json_api"
    assert res_suggest.item_count == 1

    generic_array = json.dumps(
        [{"title": "Monitor 27", "price": 499.0, "url": "https://api.example.com/mon"}]
    )
    res_generic = discovery.analyze_probe_response(
        "https://api.example.com/items.json",
        HttpResponse(
            status_code=200,
            url="https://api.example.com/items.json",
            headers={},
            text=generic_array,
        ),
    )
    assert res_generic.classification == "A_CLEAN_HTTP"
    assert res_generic.format_detected == "json_api"
    assert res_generic.recommended_adapter == "json_api"
    assert res_generic.item_count == 1

    malformed = discovery.analyze_probe_response(
        "https://api.example.com/broken.json",
        HttpResponse(
            status_code=200,
            url="https://api.example.com/broken.json",
            headers={},
            text="{not valid json",
        ),
    )
    assert malformed.classification == "B_NEEDS_PLAYWRIGHT"
    assert malformed.format_detected == "html_js_shell"


def test_analyze_probe_response_appleinsider_refurb_abt_craigslist_jsonld_and_shell() -> None:
    # 1. AppleInsider Price Guide
    ai_html = """<html><head><script type="application/ld+json">
    {"@type": "Product", "name": "M5 Max 64GB 512GB",
     "offers": [{"price": "3449.00", "url": "https://adorama.example/1", "seller": {"name": "Adorama"}}]}
    </script></head><body></body></html>"""
    ai_res = discovery.analyze_probe_response(
        "https://prices.appleinsider.com/mac-studio-m5-max",
        HttpResponse(
            status_code=200,
            url="https://prices.appleinsider.com/mac-studio-m5-max",
            headers={},
            text=ai_html,
        ),
    )
    assert ai_res.classification == "A_CLEAN_HTTP"
    assert ai_res.format_detected == "appleinsider_jsonld"
    assert ai_res.recommended_adapter == "appleinsider"
    assert ai_res.recommended_name == "AppleInsider Guide"
    assert ai_res.item_count == 1
    assert ai_res.preview_items[0].title == "Mac Studio M5 Max 64GB 512GB"

    # 2. Apple Certified Refurbished bootstrap JSON
    refurb_html = (
        "<script>window.REFURB_GRID_BOOTSTRAP = "
        '{"tiles": [{"title": "Refurbished Mac Studio", '
        '"filters": {"dimensions": {"tsMemorySize": "64GB", "dimensionCapacity": "1TB"}}, '
        '"price": {"currentPrice": {"raw_amount": "2999.00"}}, '
        '"productDetailsUrl": "/shop/product/F123", "available": true}]};</script>'
    )
    refurb_res = discovery.analyze_probe_response(
        "https://www.apple.com/shop/refurbished/mac",
        HttpResponse(
            status_code=200,
            url="https://www.apple.com/shop/refurbished/mac",
            headers={},
            text=refurb_html,
        ),
    )
    assert refurb_res.classification == "A_CLEAN_HTTP"
    assert refurb_res.format_detected == "apple_refurb_bootstrap_json"
    assert refurb_res.recommended_adapter == "json_api"
    assert refurb_res.recommended_options == {"mode": "apple_refurb"}
    assert refurb_res.recommended_name == "Apple Certified Refurbished"
    assert refurb_res.item_count == 1
    assert refurb_res.preview_items[0].condition == "refurbished"

    # 3. Abt search HTML preset
    abt_html = """<ul id="category_results_list">
      <li data-productId="42">
        <a class="categoryTitleLink" href="/product/42">Bosch Dishwasher 800 Series</a>
        <span class="cl_price">$1,249.00</span>
      </li>
    </ul>"""
    abt_res = discovery.analyze_probe_response(
        "https://www.abt.com/resources/pages/search.php?keywords=bosch",
        HttpResponse(
            status_code=200,
            url="https://www.abt.com/resources/pages/search.php?keywords=bosch",
            headers={},
            text=abt_html,
        ),
    )
    assert abt_res.classification == "A_CLEAN_HTTP"
    assert abt_res.format_detected == "abt_server_html"
    assert abt_res.recommended_adapter == "html_css"
    assert abt_res.recommended_options == {"preset": "abt_search"}
    assert abt_res.recommended_name == "Abt"
    assert abt_res.item_count == 1

    # 4. Craigslist static search HTML
    cl_html = """<ol>
      <li class="cl-static-search-result">
        <a href="https://washingtondc.craigslist.org/doc/cto/d/bus/123.html">
          <div class="title">1972 VW Kombi Bus</div>
          <div class="price">$19,500</div>
        </a>
      </li>
    </ol>"""
    cl_res = discovery.analyze_probe_response(
        "https://washingtondc.craigslist.org/search/cta?query=volkswagen+bus",
        HttpResponse(
            status_code=200,
            url="https://washingtondc.craigslist.org/search/cta?query=volkswagen+bus",
            headers={},
            text=cl_html,
        ),
    )
    assert cl_res.classification == "A_CLEAN_HTTP"
    assert cl_res.format_detected == "craigslist_static_html"
    assert cl_res.recommended_adapter == "html_css"
    assert cl_res.recommended_options["item_selector"] == "li.cl-static-search-result"
    assert cl_res.recommended_options["merchant"] == "Craigslist"
    assert cl_res.recommended_options["default_condition"] == "used"
    assert cl_res.item_count == 1
    assert cl_res.preview_items[0].price == 19500.0

    # 5. Generic schema.org JSON-LD HTML
    jsonld_html = """<html><head><script type="application/ld+json">
    {"@type": "Product", "name": "Herman Miller Aeron",
     "offers": {"price": "895.00", "priceCurrency": "USD", "url": "https://chair.example.com/aeron"}}
    </script></head><body></body></html>"""
    jsonld_res = discovery.analyze_probe_response(
        "https://chair.example.com/aeron",
        HttpResponse(
            status_code=200,
            url="https://chair.example.com/aeron",
            headers={},
            text=jsonld_html,
        ),
    )
    assert jsonld_res.classification == "A_CLEAN_HTTP"
    assert jsonld_res.format_detected == "html_jsonld"
    assert jsonld_res.recommended_adapter == "html_css"
    assert jsonld_res.item_count == 1

    # 6. HTML JS shell fallback (also when JSON-LD has no Product listings)
    shell_html = """<html><head><script type="application/ld+json">
    {"@type": "Organization", "name": "Store"}
    </script></head><body><div id="app">Loading...</div></body></html>"""
    shell_res = discovery.analyze_probe_response(
        "https://spa.example.com/catalog",
        HttpResponse(
            status_code=200,
            url="https://spa.example.com/catalog",
            headers={},
            text=shell_html,
        ),
    )
    assert shell_res.classification == "B_NEEDS_PLAYWRIGHT"
    assert shell_res.format_detected == "html_js_shell"
    assert shell_res.recommended_adapter == "html_css"
    assert shell_res.item_count == 0


@pytest.mark.parametrize("bad_url", ["", "   ", "example.com/feed", "ftp://example.com/feed"])
async def test_probe_url_invalid_urls(bad_url: str) -> None:
    async with HttpContext(
        min_interval_s=0.0,
        client=httpx.AsyncClient(transport=httpx.MockTransport(lambda _r: httpx.Response(200))),
    ) as ctx:
        res = await discovery.probe_url(bad_url, http_ctx=ctx)
    assert res.classification == "ERROR"
    assert res.format_detected == "invalid_url"


async def test_probe_url_ssrf_response_too_large_and_network_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PRICEWATCHER_ALLOW_PRIVATE_HOSTS", raising=False)
    _mock_dns(
        monkeypatch,
        {
            "127.0.0.1": [(socket.AF_INET, "127.0.0.1")],
            "big.example.com": [(socket.AF_INET, "93.184.216.34")],
            "timeout.example.com": [(socket.AF_INET, "93.184.216.35")],
        },
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("host") == "big.example.com":
            return httpx.Response(200, headers={"Content-Length": "5000"}, text="x" * 200)
        raise httpx.ConnectTimeout("connect timed out", request=request)

    async with HttpContext(
        min_interval_s=0.0,
        max_response_bytes=128,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    ) as ctx:
        ssrf_res = await discovery.probe_url("http://127.0.0.1/admin", http_ctx=ctx)
        assert ssrf_res.classification == "ERROR"
        assert ssrf_res.format_detected == "ssrf_blocked"

        big_res = await discovery.probe_url("https://big.example.com/feed", http_ctx=ctx)
        assert big_res.classification == "ERROR"
        assert big_res.format_detected == "response_too_large"

        net_res = await discovery.probe_url("https://timeout.example.com/feed", http_ctx=ctx)
        assert net_res.classification == "ERROR"
        assert net_res.format_detected == "network_error"
        assert "ConnectTimeout" in net_res.notes[0]


async def test_probe_url_shopify_autodiscovery_and_fallbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PRICEWATCHER_ALLOW_PRIVATE_HOSTS", raising=False)
    _mock_dns(
        monkeypatch,
        {
            "mystore.example.com": [(socket.AF_INET, "93.184.216.34")],
            "nodiscover.example.com": [(socket.AF_INET, "93.184.216.35")],
        },
    )

    requested_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.headers.get("host")
        requested_paths.append(f"{host}{request.url.path}")
        if host == "mystore.example.com":
            if request.url.path == "/collections/mac/":
                return httpx.Response(200, text="<html><body><div id='app'>SPA</div></body></html>")
            if request.url.path == "/collections/mac/products.json":
                return httpx.Response(
                    200,
                    json={
                        "products": [
                            {
                                "title": "MacBook Pro 14",
                                "handle": "macbook-pro-14",
                                "variants": [
                                    {
                                        "id": 1,
                                        "title": "Base",
                                        "price": "1599.00",
                                        "available": True,
                                    }
                                ],
                            }
                        ]
                    },
                )
        if host == "nodiscover.example.com":
            if request.url.path == "/collections/other":
                return httpx.Response(200, text="<html><body>No JSON-LD</body></html>")
            if request.url.path == "/collections/other/products.json":
                return httpx.Response(404, text="not found")
            if request.url.path == "/broken.json":
                return httpx.Response(200, text="{malformed")
        return httpx.Response(404)

    async with HttpContext(
        min_interval_s=0.0,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    ) as ctx:
        discovered = await discovery.probe_url(
            "https://mystore.example.com/collections/mac/", http_ctx=ctx
        )
        assert discovered.classification == "A_CLEAN_HTTP"
        assert discovered.format_detected == "shopify_products_json_autodiscovered"
        assert (
            discovered.recommended_url
            == "https://mystore.example.com/collections/mac/products.json"
        )
        assert discovered.recommended_adapter == "json_api"
        assert discovered.item_count == 1
        assert discovered.preview_items[0].price == 1599.0

        # Non-Shopify JS shell falls back to B_NEEDS_PLAYWRIGHT
        not_shopify = await discovery.probe_url(
            "https://nodiscover.example.com/collections/other", http_ctx=ctx
        )
        assert not_shopify.classification == "B_NEEDS_PLAYWRIGHT"
        assert not_shopify.recommended_url == "https://nodiscover.example.com/collections/other"

        # URL already ending with .json does not probe .../products.json
        requested_paths.clear()
        dot_json = await discovery.probe_url(
            "https://nodiscover.example.com/broken.json", http_ctx=ctx
        )
        assert dot_json.classification == "B_NEEDS_PLAYWRIGHT"
        assert requested_paths == ["nodiscover.example.com/broken.json"]


def test_build_vendor_search_sources_branches() -> None:
    # 1. Empty / whitespace query
    assert discovery.build_vendor_search_sources("") == []
    assert discovery.build_vendor_search_sources("   \t\n ") == []

    # 2. Classic VW bus
    vw_sources = discovery.build_vendor_search_sources("1967 Volkswagen Combi")
    vw_urls = [s.url for s in vw_sources]
    assert any("classic.com/search?q=1967+Volkswagen+Kombi" in u for u in vw_urls)
    assert any("classic.com/search?q=Volkswagen+Type+2" in u for u in vw_urls)
    assert any("washingtondc.craigslist.org/search/cta?query=Volkswagen+Bus" in u for u in vw_urls)
    assert any("baltimore.craigslist.org/search/cta?query=Volkswagen+Bus" in u for u in vw_urls)
    assert any("newyork.craigslist.org/search/cta?query=Volkswagen+Bus" in u for u in vw_urls)
    assert not any("truecar.com" in u or "slickdeals.net" in u for u in vw_urls)

    # 3. Modern vehicle (known make/model + generic automotive fallback)
    tundra_sources = discovery.build_vendor_search_sources("2024 Toyota Tundra Pickup")
    tundra_urls = [s.url for s in tundra_sources]
    assert any("truecar.com/used-cars-for-sale/listings/toyota/tundra/" in u for u in tundra_urls)
    assert any("truecar.com/new-cars-for-sale/listings/toyota/tundra/" in u for u in tundra_urls)
    assert any(
        "washingtondc.craigslist.org/search/cta?query=2024+Toyota+Tundra" in u for u in tundra_urls
    )
    assert any("classic.com/search?q=2024+Toyota+Tundra" in u for u in tundra_urls)
    assert any("slickdeals.net/newsearch.php" in u for u in tundra_urls)

    generic_auto = discovery.build_vendor_search_sources("used pickup truck")
    generic_auto_urls = [s.url for s in generic_auto]
    assert not any("truecar.com" in u for u in generic_auto_urls)
    assert any("craigslist.org/search/cta" in u for u in generic_auto_urls)
    assert any("classic.com/search" in u for u in generic_auto_urls)
    assert any("slickdeals.net/newsearch.php" in u for u in generic_auto_urls)

    # 4. Bike / sports
    bike_sources = discovery.build_vendor_search_sources("Specialized Tarmac Bike")
    bike_urls = [s.url for s in bike_sources]
    assert any("slickdeals.net/newsearch.php" in u for u in bike_urls)
    assert any(
        "washingtondc.craigslist.org/search/bia?query=Specialized+Tarmac" in u for u in bike_urls
    )
    assert any(
        "baltimore.craigslist.org/search/bia?query=Specialized+Tarmac" in u for u in bike_urls
    )
    assert any("newyork.craigslist.org/search/bia?query=Specialized+Tarmac" in u for u in bike_urls)
    assert not any("abt.com" in u or "datavision.com" in u or "truecar.com" in u for u in bike_urls)

    # 5. Home / furniture
    home_sources = discovery.build_vendor_search_sources("Herman Miller Aeron Chair")
    home_urls = [s.url for s in home_sources]
    assert any("slickdeals.net/newsearch.php" in u for u in home_urls)
    assert any(
        "washingtondc.craigslist.org/search/fua?query=Herman+Miller+Aeron" in u for u in home_urls
    )
    assert any(
        "washingtondc.craigslist.org/search/ppa?query=Herman+Miller+Aeron" in u for u in home_urls
    )
    assert any(
        "baltimore.craigslist.org/search/fua?query=Herman+Miller+Aeron" in u for u in home_urls
    )
    assert any(
        "abt.com/resources/pages/search.php?keywords=Herman+Miller+Aeron" in u for u in home_urls
    )
    assert not any("datavision.com" in u or "expercom.com" in u for u in home_urls)

    # 6. Electronics / Apple vs generic non-Apple retail
    apple_sources = discovery.build_vendor_search_sources("Apple MacBook Pro")
    apple_urls = [s.url for s in apple_sources]
    assert any("slickdeals.net/newsearch.php" in u for u in apple_urls)
    assert any(
        "washingtondc.craigslist.org/search/sss?query=Apple+MacBook+Pro" in u for u in apple_urls
    )
    assert any(
        "abt.com/resources/pages/search.php?keywords=Apple+MacBook+Pro" in u for u in apple_urls
    )
    assert any("datavision.com/search/suggest.json" in u for u in apple_urls)
    assert any("expercom.com/search/suggest.json" in u for u in apple_urls)
    assert any("swappa.com/search?q=Apple+MacBook+Pro" in u for u in apple_urls)
    assert any("apple.com/shop/refurbished/mac" in u for u in apple_urls)

    tool_sources = discovery.build_vendor_search_sources("DeWalt DWS779")
    tool_urls = [s.url for s in tool_sources]
    assert any("datavision.com/search/suggest.json" in u for u in tool_urls)
    assert not any("swappa.com" in u or "apple.com/shop/refurbished" in u for u in tool_urls)


async def test_search_vendors_for_query_empty_classification_and_sorting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called(_name: str) -> Any:
        raise AssertionError("get_adapter must not be called for empty queries")

    monkeypatch.setattr(discovery, "get_adapter", fail_if_called)
    empty_res = await discovery.search_vendors_for_query("   ")
    assert empty_res.query == ""
    assert empty_res.tokens == []
    assert empty_res.candidates == []

    # Owned HttpContext guard to ensure zero real network client usage if http_ctx=None
    class DummyHttpContext:
        async def __aenter__(self) -> DummyHttpContext:
            return self

        async def __aexit__(
            self,
            _exc_type: type[BaseException] | None,
            _exc_val: BaseException | None,
            _exc_tb: TracebackType | None,
        ) -> None:
            return None

    monkeypatch.setattr(discovery, "HttpContext", DummyHttpContext)

    class FakeSearchAdapter:
        async def fetch(self, source: SourceConfig, http_ctx: Any = None) -> FetchOutcome:
            del http_ctx
            if source.name.startswith("Expercom"):
                # 6 matching items (preview_items capped at 5, sorted by hits desc then price asc)
                items = [
                    Listing(
                        source_name=source.name,
                        merchant="Expercom",
                        title=f"Apple MacBook Pro 16 M4 #{i}",
                        url=f"https://expercom.com/{i}",
                        price=2500.0 - (i * 50),
                    )
                    for i in range(6)
                ]
                return FetchOutcome(listings=items, http_status=200)
            if source.name.startswith("DataVision"):
                # 2 matches + 1 non-match; 3-hit item should sort ahead of cheaper 2-hit item
                return FetchOutcome(
                    listings=[
                        Listing(
                            source_name=source.name,
                            merchant="DataVision",
                            title="MacBook Pro Sleeve Case",
                            url="https://datavision.com/2hits",
                            price=199.0,
                        ),
                        Listing(
                            source_name=source.name,
                            merchant="DataVision",
                            title="Apple MacBook Pro 14",
                            url="https://datavision.com/3hits",
                            price=1999.0,
                        ),
                        Listing(
                            source_name=source.name,
                            merchant="DataVision",
                            title="USB-C Cable",
                            url="https://datavision.com/0hits",
                            price=19.0,
                        ),
                    ],
                    http_status=200,
                )
            if source.name.startswith("Abt"):
                return FetchOutcome(
                    listings=[
                        Listing(
                            source_name=source.name,
                            merchant="Abt",
                            title="Dell XPS 15 Laptop",
                            url="https://abt.com/xps",
                            price=1500.0,
                        )
                    ],
                    http_status=200,
                )
            if source.name.startswith("Slickdeals"):
                return FetchOutcome(http_status=403, error="HTTP 403")
            if source.name.startswith("Swappa"):
                raise RuntimeError("socket failure")
            return FetchOutcome(listings=[], http_status=200)

    monkeypatch.setattr(discovery, "get_adapter", lambda _name: FakeSearchAdapter())

    res = await discovery.search_vendors_for_query("Apple MacBook Pro")
    assert res.query == "Apple MacBook Pro"
    assert res.tokens == ["apple", "macbook", "pro"]

    by_prefix = {c.name.split(" (")[0]: c for c in res.candidates}
    assert by_prefix["Expercom"].status == "A_CLEAN_HTTP"
    assert by_prefix["Expercom"].matching_count == 6
    assert len(by_prefix["Expercom"].preview_items) == 5
    # Cheapest matching item comes first among equal hits
    assert by_prefix["Expercom"].preview_items[0].price == 2250.0

    assert by_prefix["DataVision"].status == "A_CLEAN_HTTP"
    assert by_prefix["DataVision"].total_fetched == 3
    assert by_prefix["DataVision"].matching_count == 2
    assert by_prefix["DataVision"].preview_items[0].title == "Apple MacBook Pro 14"

    assert by_prefix["Abt"].status == "EMPTY"
    assert by_prefix["Abt"].total_fetched == 1
    assert by_prefix["Abt"].matching_count == 0

    assert by_prefix["Slickdeals"].status == "ERROR"
    assert by_prefix["Slickdeals"].http_status == 403
    assert "HTTP 403" in by_prefix["Slickdeals"].notes[0]

    assert by_prefix["Swappa"].status == "ERROR"
    assert "RuntimeError: socket failure" in by_prefix["Swappa"].notes[0]

    # Verify strict bucket & tie-breaker ordering:
    # 1. Matching candidates sorted by (-matching_count, -total_fetched, name)
    # 2. Empty candidates sorted by (-total_fetched, name)
    # 3. Error candidates sorted by (-total_fetched, name)
    ordered_statuses = [c.status for c in res.candidates]
    assert ordered_statuses[:2] == ["A_CLEAN_HTTP", "A_CLEAN_HTTP"]
    assert res.candidates[0].name.startswith("Expercom")
    assert res.candidates[1].name.startswith("DataVision")
    first_empty = ordered_statuses.index("EMPTY")
    first_error = ordered_statuses.index("ERROR")
    assert first_empty < first_error
    assert res.candidates[first_empty].name.startswith("Abt")
    assert all(s == "ERROR" for s in ordered_statuses[first_error:])


async def test_search_vendors_synonym_expansion_and_no_http_ctx_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class LegacyNoCtxAdapter:
        async def fetch(self, source: SourceConfig) -> FetchOutcome:
            if source.name == "Classic.com (Volkswagen Type 2)":
                return FetchOutcome(
                    listings=[
                        Listing(
                            source_name=source.name,
                            merchant="Classic.com",
                            title="1967 VW Microbus Deluxe",
                            url="https://www.classic.com/veh/vw-1",
                            price=42000.0,
                        )
                    ],
                    http_status=200,
                )
            return FetchOutcome(listings=[], http_status=200)

    monkeypatch.setattr(discovery, "get_adapter", lambda _name: LegacyNoCtxAdapter())

    sentinel_ctx = object()
    res = await discovery.search_vendors_for_query(
        "volkswagen combi",
        http_ctx=sentinel_ctx,  # type: ignore[arg-type]
    )
    assert res.tokens == ["volkswagen", "kombi"]
    top = res.candidates[0]
    assert top.name == "Classic.com (Volkswagen Type 2)"
    assert top.status == "A_CLEAN_HTTP"
    assert top.matching_count == 1
    assert top.preview_items[0].title == "1967 VW Microbus Deluxe"
