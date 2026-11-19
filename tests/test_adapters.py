"""Offline adapter and discovery tests against saved Phase 1 fixtures."""

from __future__ import annotations

from pathlib import Path

from pricewatcher.adapters.appleinsider import parse_appleinsider_html
from pricewatcher.adapters.base import (
    detect_condition,
    extract_purchase_price,
    is_monthly_only_price,
    sanitize_listing_url,
)
from pricewatcher.adapters.html_css import parse_html_css
from pricewatcher.adapters.json_api import parse_json_api_payload
from pricewatcher.adapters.rss import parse_rss_feed
from pricewatcher.config import SourceConfig
from pricewatcher.discovery import (
    analyze_probe_response,
    build_vendor_search_sources,
    detect_vehicle_make_model,
    expand_include_keyword_groups,
    extract_core_query_tokens,
)
from pricewatcher.http_client import HttpResponse

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_monthly_financing_not_mistaken_for_purchase_price() -> None:
    assert is_monthly_only_price("Apple Mac Studio starting at $316/mo for 12 months") is True
    assert extract_purchase_price("From $316/mo for 12 mo with APR") is None
    assert extract_purchase_price("Pay $316/mo or $3,499.00 today on Mac Studio") == 3499.0


def test_appleinsider_fixture_parses_m5_max_offers() -> None:
    html = (FIXTURES_DIR / "appleinsider_guide_mac_studio_m5_max.html").read_text(encoding="utf-8")
    src = SourceConfig(
        name="AppleInsider M5 Max Guide",
        adapter="appleinsider",
        url="https://prices.appleinsider.com/mac-studio-m5-max",
    )
    listings = parse_appleinsider_html(html, src)
    assert len(listings) > 0
    assert any("Mac Studio" in item.title and item.price >= 1500 for item in listings)


def test_expercom_shopify_products_fixture() -> None:
    raw = (FIXTURES_DIR / "expercom_collection_products_json.json").read_text(encoding="utf-8")
    src = SourceConfig(
        name="Expercom Mac Studio",
        adapter="json_api",
        url="https://expercom.com/collections/mac-studio/products.json",
    )
    listings = parse_json_api_payload(raw, src)
    assert len(listings) > 0
    assert all(item.merchant == "Expercom" for item in listings)
    assert any("M5 Max" in item.title for item in listings)


def test_datavision_shopify_suggest_fixture() -> None:
    raw = (FIXTURES_DIR / "datavision_search_suggest_json.json").read_text(encoding="utf-8")
    src = SourceConfig(
        name="DataVision Search Suggest",
        adapter="json_api",
        url="https://datavision.com/search/suggest.json?q=Mac%20Studio&resources[type]=product",
    )
    listings = parse_json_api_payload(raw, src)
    assert len(listings) > 0
    assert all(item.merchant == "DataVision" for item in listings)


def test_apple_refurbished_bootstrap_fixture_extracts_dimension_specs() -> None:
    html = (FIXTURES_DIR / "apple_refurbished_mac_studio_refurb.html").read_text(encoding="utf-8")
    src = SourceConfig(
        name="Apple Certified Refurbished",
        adapter="json_api",
        url="https://www.apple.com/shop/refurbished/mac/mac-studio",
        options={"mode": "apple_refurb"},
    )
    listings = parse_json_api_payload(html, src)
    assert len(listings) > 0
    assert all(item.condition == "refurbished" for item in listings)
    assert any("GB" in item.title and item.raw_specs.get("dimensions") for item in listings)


def test_abt_search_fixture_extracts_prices_and_stock_state() -> None:
    html = (FIXTURES_DIR / "abt_search_mac_studio.html").read_text(encoding="utf-8")
    src = SourceConfig(
        name="Abt Mac Studio Search",
        adapter="html_css",
        url="https://www.abt.com/resources/pages/search.php?keywords=mac+studio",
        options={"preset": "abt_search"},
    )
    listings = parse_html_css(html, src)
    assert len(listings) > 0
    assert any("M5 Max" in item.title for item in listings)
    assert any(item.in_stock is False for item in listings)


def test_rss_adapter_extracts_price_promo_and_ignores_monthly_only() -> None:
    rss_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0"><channel><title>Deals</title>
      <item>
        <title>Mac Studio M5 Max 64GB 512GB at Adorama - $3,449 (Promo code: APINSIDER)</title>
        <link>https://example.com/deal1</link>
        <description>In stock now at Adorama.</description>
      </item>
      <item>
        <title>Mac Studio financing only $316/mo for 12 mo at Apple</title>
        <link>https://example.com/deal2</link>
        <description>0% APR monthly plan.</description>
      </item>
    </channel></rss>
    """
    src = SourceConfig(name="Test RSS", adapter="rss", url="https://slickdeals.net/rss")
    listings = parse_rss_feed(rss_xml, src)
    assert len(listings) == 1
    assert listings[0].price == 3449.0
    assert listings[0].promo_code == "APINSIDER"
    assert listings[0].merchant.lower() == "adorama"


def test_discovery_classifies_rss_json_bot_block_and_js_shell() -> None:
    rss_resp = HttpResponse(
        status_code=200,
        url="https://slickdeals.net/newsearch.php?q=Mac+Studio&rss=1",
        headers={"content-type": "application/rss+xml"},
        text=(FIXTURES_DIR / "slickdeals_rss_search_mac_studio.xml").read_text(encoding="utf-8"),
    )
    probe_rss = analyze_probe_response(rss_resp.url, rss_resp)
    assert probe_rss.classification == "A_CLEAN_HTTP"
    assert probe_rss.recommended_adapter == "rss"

    ai_resp = HttpResponse(
        status_code=200,
        url="https://prices.appleinsider.com/mac-studio-m5-max",
        headers={"content-type": "text/html"},
        text=(FIXTURES_DIR / "appleinsider_guide_mac_studio_m5_max.html").read_text(
            encoding="utf-8"
        ),
    )
    probe_ai = analyze_probe_response(ai_resp.url, ai_resp)
    assert probe_ai.classification == "A_CLEAN_HTTP"
    assert probe_ai.recommended_adapter == "appleinsider"
    assert probe_ai.item_count > 0

    blocked_resp = HttpResponse(
        status_code=403,
        url="https://www.bhphotovideo.com/c/buy/mac-studio",
        headers={"content-type": "text/html"},
        text="<html><title>Just a moment...</title></html>",
    )
    probe_blocked = analyze_probe_response(blocked_resp.url, blocked_resp)
    assert probe_blocked.classification == "C_BOT_BLOCKED"

    js_shell_resp = HttpResponse(
        status_code=200,
        url="https://spa-store.example.com/deals",
        headers={"content-type": "text/html"},
        text="<html><body><div id='app'>Loading prices...</div></body></html>",
    )
    probe_js = analyze_probe_response(js_shell_resp.url, js_shell_resp)
    assert probe_js.classification == "B_NEEDS_PLAYWRIGHT"


def test_vehicle_jsonld_and_scope_css_and_condition_detection() -> None:
    assert detect_condition("2023 Toyota Tundra Used") == "used"
    assert detect_condition("Certified Pre-Owned Tundra") == "refurbished"
    assert detect_condition("Open-Box Mac Studio") == "open-box"

    vehicle_html = """<!doctype html><html><head>
    <script type="application/ld+json">
    {"@context":"https://schema.org","@graph":[{"@type":"CollectionPage","mainEntity":{"@type":"ItemList","itemListElement":[
      {"@type":"ListItem","position":1,"item":{"@type":"Vehicle","name":"2023 Toyota Tundra SR5","mileageFromOdometer":{"@type":"QuantitativeValue","value":42894},"itemCondition":"UsedCondition","offers":{"@type":"Offer","price":"33489.00","priceCurrency":"USD","url":"https://www.truecar.com/used-cars-for-sale/listing/VIN123/","seller":"Sheehy Toyota of Laurel"}}}
    ]}}]}
    </script></head><body></body></html>"""
    src_tc = SourceConfig(
        name="TrueCar Used",
        adapter="html_css",
        url="https://www.truecar.com/used-cars-for-sale/listings/toyota/tundra/",
        options={"default_condition": "used"},
    )
    tc_listings = parse_html_css(vehicle_html, src_tc)
    assert len(tc_listings) == 1
    assert tc_listings[0].merchant == "Sheehy Toyota of Laurel"
    assert tc_listings[0].price == 33489.0
    assert tc_listings[0].condition == "used"
    assert "42,894 mi" in tc_listings[0].title

    classic_html = """<div class="border-gray-300 rounded-lg">
      <h3><a href="/veh/2006-tundra-1/">2006 Toyota Tundra Double Cab SR5</a></h3>
      <span>For Sale $11,895</span>
    </div>"""
    src_clx = SourceConfig(
        name="Classic.com",
        adapter="html_css",
        url="https://www.classic.com/search?q=Toyota+Tundra",
        options={
            "item_selector": "div.border-gray-300.rounded-lg",
            "title_selector": "h3 a[href*='/veh/']",
            "price_selector": ":scope",
            "link_selector": "h3 a[href*='/veh/']",
            "default_condition": "used",
            "merchant": "Classic.com",
        },
    )
    clx_listings = parse_html_css(classic_html, src_clx)
    assert len(clx_listings) == 1
    assert clx_listings[0].merchant == "Classic.com"
    assert clx_listings[0].price == 11895.0
    assert clx_listings[0].condition == "used"
    assert clx_listings[0].url == "https://www.classic.com/veh/2006-tundra-1/"


def test_universal_and_vehicle_discovery_query_tokens() -> None:
    assert extract_core_query_tokens("Toyota Tundra Pickup") == ["Toyota", "Tundra"]
    assert detect_vehicle_make_model("Toyota Tundra Pickup") == ("toyota", "tundra")
    assert detect_vehicle_make_model("Herman Miller Aeron Chair") is None

    car_sources = build_vendor_search_sources("Toyota Tundra Pickup")
    assert any(
        "truecar.com/used-cars-for-sale/listings/toyota/tundra/" in s.url for s in car_sources
    )
    assert any(
        "washingtondc.craigslist.org/search/cta?query=Toyota+Tundra" in s.url for s in car_sources
    )
    assert any("classic.com/search?q=Toyota+Tundra" in s.url for s in car_sources)

    chair_sources = build_vendor_search_sources("Herman Miller Aeron Chair")
    assert any(
        "washingtondc.craigslist.org/search/fua?query=Herman+Miller+Aeron" in s.url
        for s in chair_sources
    )
    assert not any("truecar.com" in s.url for s in chair_sources)

    generic_sources = build_vendor_search_sources("DeWalt DWS779")
    assert any(
        "washingtondc.craigslist.org/search/sss?query=DeWalt+DWS779" in s.url
        for s in generic_sources
    )

    vw_sources = build_vendor_search_sources("volkswagen combi")
    assert any("classic.com/search?q=volkswagen+Kombi" in s.url for s in vw_sources)
    assert any("classic.com/search?q=Volkswagen+Type+2" in s.url for s in vw_sources)
    assert not any("truecar.com" in s.url for s in vw_sources)

    groups = expand_include_keyword_groups("volkswagen combi")
    assert groups[0] == ["Volkswagen", "VW"]
    assert "Kombi" in groups[1] and "Type 2" in groups[1]

    swappa_html = """<div class="cell_product search">
      <a href="/listings/apple-iphone-16-pro"><img></a>
      <a href="/listings/apple-iphone-16-pro">Apple iPhone 16 Pro</a>
      <span>$515+</span>
    </div>"""
    swappa_src = SourceConfig(
        name="Swappa",
        adapter="html_css",
        url="https://swappa.com/search?q=iPhone+16+Pro",
        options={
            "item_selector": "div.cell_product",
            "title_selector": "a[href*='/listings/']",
            "price_selector": ":scope",
            "link_selector": "a[href*='/listings/']",
            "default_condition": "used",
            "merchant": "Swappa",
        },
    )
    swappa_listings = parse_html_css(swappa_html, swappa_src)
    assert len(swappa_listings) == 1
    assert swappa_listings[0].title == "Apple iPhone 16 Pro"
    assert swappa_listings[0].price == 515.0
    assert swappa_listings[0].url == "https://swappa.com/listings/apple-iphone-16-pro"


def test_abt_and_sanitize_listing_url_filters_unsafe_hrefs() -> None:
    assert sanitize_listing_url("https://www.abt.com/item/1") == "https://www.abt.com/item/1"
    assert sanitize_listing_url("javascript:alert(1)") == ""
    assert sanitize_listing_url("data:text/html,xss") == ""

    abt_html = """<ul id="category_results_list">
      <li data-productId="123">
        <a class="categoryTitleLink" href="javascript:alert(1)">Mac Studio M5 Max</a>
        <span class="cl_price">$3,499.00</span>
      </li>
    </ul>"""
    abt_src = SourceConfig(
        name="Abt",
        adapter="html_css",
        url="https://www.abt.com/resources/pages/search.php?keywords=mac+studio",
        options={"preset": "abt_search"},
    )
    abt_listings = parse_html_css(abt_html, abt_src)
    assert len(abt_listings) == 1
    assert abt_listings[0].url == ""
