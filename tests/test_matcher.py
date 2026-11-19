"""Tests for generic rule matcher, spec extractors, and tier keys."""

from __future__ import annotations

import logging
from pathlib import Path
import time

import pytest
import yaml

from pricewatcher.adapters.base import Listing
from pricewatcher.config import ExtractorConfig, PriceRulesConfig, RulesConfig, WatchConfig
from pricewatcher.matcher import evaluate_listing


def _mac_studio_rules() -> RulesConfig:
    example_path = (
        Path(__file__).resolve().parent.parent / "config" / "watches" / "example-watch.yaml.example"
    )
    raw = yaml.safe_load(example_path.read_text(encoding="utf-8"))
    watch = WatchConfig.model_validate(raw)
    return watch.rules


def test_accepts_qualifying_m5_max_tiers() -> None:
    rules = _mac_studio_rules()

    base64 = Listing(
        source_name="AppleInsider M5 Max Guide",
        merchant="Adorama",
        title="Apple Mac Studio M5 Max, 64GB, 512GB",
        url="https://example.com/1",
        price=3499.0,
        condition="new",
        in_stock=True,
    )
    res1 = evaluate_listing(base64, rules)
    assert res1.matched is True
    assert res1.extracted["ram_gb"] == 64
    assert res1.extracted["ssd_gb"] == 512
    assert res1.tier_key == "64GB / 512GB / new"

    high128 = Listing(
        source_name="Expercom Mac Studio",
        merchant="Expercom",
        title="Apple Mac Studio M5 Max (128GB Unified Memory, 1TB SSD)",
        url="https://example.com/2",
        price=3899.0,
        condition="new",
        in_stock=True,
    )
    res2 = evaluate_listing(high128, rules)
    assert res2.matched is True
    assert res2.extracted["ram_gb"] == 128
    assert res2.extracted["ssd_gb"] == 1024
    assert res2.tier_key == "128GB / 1TB / new"


def test_rejects_m4_max_low_ram_accessories_and_out_of_stock() -> None:
    rules = _mac_studio_rules()

    m4 = Listing(
        source_name="Expercom",
        merchant="Expercom",
        title="Apple Mac Studio M4 Max 64GB 1TB SSD",
        url="https://example.com/m4",
        price=2899.0,
    )
    assert evaluate_listing(m4, rules).matched is False

    ram36 = Listing(
        source_name="Expercom",
        merchant="Expercom",
        title="Apple Mac Studio M5 Max 36GB Memory 512GB SSD",
        url="https://example.com/36",
        price=1999.0,
    )
    assert evaluate_listing(ram36, rules).matched is False

    ram48 = Listing(
        source_name="Expercom",
        merchant="Expercom",
        title="Apple Mac Studio M5 Max 48GB Memory 1TB SSD",
        url="https://example.com/48",
        price=2599.0,
    )
    assert evaluate_listing(ram48, rules).matched is False

    dock = Listing(
        source_name="Slickdeals",
        merchant="Amazon",
        title="Mac Studio M5 Max Aluminum Dock Mount 64GB 512GB",
        url="https://example.com/dock",
        price=1899.0,
    )
    assert evaluate_listing(dock, rules).matched is False

    oos = Listing(
        source_name="Abt",
        merchant="Abt",
        title="Apple Mac Studio M5 Max 64GB 1TB SSD",
        url="https://example.com/oos",
        price=3799.0,
        in_stock=False,
    )
    res_oos = evaluate_listing(oos, rules)
    assert res_oos.matched is False
    assert res_oos.reason == "out of stock"


def test_rejects_monthly_financing_only_and_price_bounds() -> None:
    rules = _mac_studio_rules()

    monthly = Listing(
        source_name="RSS",
        merchant="Apple",
        title="Mac Studio M5 Max 64GB 512GB starting at $316/mo for 12 mo",
        url="https://example.com/monthly",
        price=316.0,
        raw_specs={"structured_price": False},
    )
    assert evaluate_listing(monthly, rules).matched is False

    too_expensive = Listing(
        source_name="Expercom",
        merchant="Expercom",
        title="Apple Mac Studio M5 Max 128GB 4TB SSD",
        url="https://example.com/4tb",
        price=5499.0,
    )
    assert evaluate_listing(too_expensive, rules).matched is False


def test_disambiguates_ram_and_ssd_from_raw_specs() -> None:
    rules = _mac_studio_rules()
    listing = Listing(
        source_name="Apple Certified Refurbished",
        merchant="Apple Certified Refurbished",
        title="Refurbished Mac Studio Apple M5 Max Chip",
        url="https://www.apple.com/shop/product/G1234",
        price=3199.0,
        condition="refurbished",
        raw_specs={"spec_text": "64GB, 512GB"},
    )
    res = evaluate_listing(listing, rules)
    assert res.matched is True
    assert res.extracted["ram_gb"] == 64
    assert res.extracted["ssd_gb"] == 512
    assert res.tier_key == "64GB / 512GB / refurbished"


def test_universal_vehicle_watch_allows_used_and_matches_without_generic_suffix() -> None:
    rules = RulesConfig(
        include_keyword_groups=[["Toyota"], ["Tundra"]],
        exclude_keywords=["Hot Wheels", "Diecast", "1:64"],
        conditions_allowed=["new", "refurbished", "open-box", "used"],
        require_in_stock=True,
        price=PriceRulesConfig(min=10000.0, max=60000.0),
    )

    used_tundra = Listing(
        source_name="TrueCar Used (Toyota Tundra)",
        merchant="Sheehy Toyota of Laurel",
        title="2023 Toyota Tundra SR5 (64,321 mi)",
        url="https://www.truecar.com/used-cars-for-sale/listing/5TFLA5DB2PX121990/",
        price=33489.0,
        condition="used",
        in_stock=True,
    )
    res_ok = evaluate_listing(used_tundra, rules)
    assert res_ok.matched is True
    assert res_ok.normalized_condition == "used"

    toy_tundra = Listing(
        source_name="Craigslist DC",
        merchant="Craigslist DC",
        title="Hot Wheels Toyota Tundra 1:64 Diecast",
        url="https://example.com/toy",
        price=12000.0,
        condition="used",
    )
    assert evaluate_listing(toy_tundra, rules).matched is False


def test_redos_catastrophic_backtracking_aborted_cleanly(
    caplog: pytest.LogCaptureFixture,
) -> None:
    rules = RulesConfig(
        extractors={
            "bad_spec": ExtractorConfig(
                pattern=r"(a+)+$",
                type="str",
                required=True,
            )
        },
        price=PriceRulesConfig(min=10.0, max=5000.0),
    )
    evil_listing = Listing(
        source_name="Evil",
        merchant="Evil",
        title="Product " + ("a" * 500) + "!",
        url="https://example.com/evil",
        price=100.0,
    )

    t0 = time.monotonic()
    with caplog.at_level(logging.WARNING, logger="pricewatcher.matcher"):
        res = evaluate_listing(evil_listing, rules)
    elapsed = time.monotonic() - t0

    assert elapsed < 0.5
    assert res.matched is False
    assert "missing required spec 'bad_spec'" in res.reason
    assert any("timed out" in rec.message.lower() for rec in caplog.records)
