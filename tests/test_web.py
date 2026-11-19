"""Tests for FastAPI Web UI pages and REST/form endpoints."""

from __future__ import annotations

from pathlib import Path
import re
import shutil
import socket
import threading
from typing import Any

from fastapi.testclient import TestClient
import httpx
import pytest

from pricewatcher.adapters.base import FetchOutcome, Listing
from pricewatcher.config import ConfigStore, SourceConfig
from pricewatcher.discovery import ProbePreviewItem, VendorSearchCandidate, VendorSearchResponse
from pricewatcher.engine import PollEngine
from pricewatcher.main import create_app
from pricewatcher.storage import Database
from pricewatcher.web.auth import hash_password


class StaticAdapter:
    async def fetch(self, source: SourceConfig) -> FetchOutcome:
        return FetchOutcome(
            listings=[
                Listing(
                    source_name=source.name,
                    merchant="Adorama",
                    title="Mac Studio M5 Max 64GB 512GB",
                    url="https://example.com/item",
                    price=3499.0,
                )
            ],
            http_status=200,
            latency_ms=10,
        )


def _extract_csrf(html: str) -> str:
    match = re.search(r'<meta\s+name="csrf-token"\s+content="([^"]*)"', html)
    assert match is not None, "Missing csrf-token meta tag"
    return match.group(1)


def _make_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[TestClient, ConfigStore, Database, str]:
    monkeypatch.setenv("PRICEWATCHER_ADMIN_PASSWORD_HASH", hash_password("test-admin-pw"))
    monkeypatch.setenv("PRICEWATCHER_SESSION_SECRET", "test-session-secret-32-bytes-minimum")
    monkeypatch.delenv("PRICEWATCHER_INSECURE_NO_AUTH", raising=False)
    monkeypatch.delenv("PRICEWATCHER_COOKIE_SECURE", raising=False)

    repo_cfg = Path(__file__).resolve().parent.parent / "config"
    cfg_dir = tmp_path / "config"
    (cfg_dir / "watches").mkdir(parents=True)
    shutil.copy2(repo_cfg / "settings.example.yaml", cfg_dir / "settings.yaml")
    shutil.copy2(
        repo_cfg / "watches" / "example-watch.yaml.example",
        cfg_dir / "watches" / "example-watch.yaml",
    )
    store = ConfigStore(cfg_dir)
    db = Database(tmp_path / "prices.db")
    engine = PollEngine(
        store=store,
        db=db,
        adapter_factory=lambda _: StaticAdapter(),  # type: ignore[return-value]
    )
    app = create_app(store=store, db=db, engine=engine, start_scheduler=False)
    client = TestClient(app)

    login_page = client.get("/login")
    assert login_page.status_code == 200
    pre_csrf = _extract_csrf(login_page.text)
    login_resp = client.post(
        "/login",
        data={"password": "test-admin-pw", "csrf_token": pre_csrf, "next": "/"},
        follow_redirects=True,
    )
    assert login_resp.status_code == 200
    csrf_token = _extract_csrf(login_resp.text)
    return client, store, db, csrf_token


def test_html_pages_render_and_healthz(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _, db, _ = _make_client(tmp_path, monkeypatch)
    try:
        health = client.get("/healthz")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"

        for route in ("/", "/watches/example-watch", "/manage", "/settings"):
            resp = client.get(route)
            assert resp.status_code == 200
            assert "PriceWatcher" in resp.text

        db.upsert_source_health(
            watch_id="example-watch",
            source_name="Test Source",
            url="https://example.com/rss",
            http_status=200,
            item_count=1,
            matched_count=0,
            latency_ms=42,
            last_error=None,
            fetched_items=[
                {
                    "title": "Unrelated Item $19.99",
                    "price": 19.99,
                    "currency": "USD",
                    "merchant": "Example",
                    "url": "https://example.com/item",
                    "condition": "new",
                    "in_stock": True,
                    "matched": False,
                    "reason": "missing keyword group",
                    "tier_key": None,
                }
            ],
        )
        detail_resp = client.get("/watches/example-watch")
        assert detail_resp.status_code == 200
        assert 'id="source-fetched-dialog"' in detail_resp.text
        assert "data-fetched-modal" in detail_resp.text
        assert "Unrelated Item $19.99" in detail_resp.text

        assert client.get("/watches/nonexistent-watch").status_code == 404
    finally:
        db.close()


def test_form_create_toggle_duplicate_run_and_delete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, store, db, csrf = _make_client(tmp_path, monkeypatch)
    try:
        form_data = {
            "csrf_token": csrf,
            "is_edit": "false",
            "name": "Canon R5 Mark II",
            "id": "canon-r5-ii",
            "query": "Canon R5 Mark II",
            "interval_minutes": "45",
            "jitter_seconds": "60",
            "duration_days": "30",
            "include_groups_text": "Canon, EOS R5\nMark II, II",
            "exclude_keywords_text": "Battery, Strap",
            "tier_by_text": "condition",
            "conditions_allowed": ["new", "refurbished"],
            "require_in_stock": "true",
            "enabled": "true",
            "price_min": "2500",
            "price_max": "4500",
            "price_target": "3699",
            "price_msrp": "4299",
            "min_drop_delta": "25",
            "cooldown_hours": "24",
            "alert_recipients": ["primary"],
            "delivery": "waha_with_email_fallback",
            "send_startup_summary": "true",
            "source_name": ["Slickdeals Canon"],
            "source_adapter": ["rss"],
            "source_url": ["https://slickdeals.net/newsearch.php?q=Canon+R5+II&rss=1"],
            "source_options_json": ["{}"],
            "source_render_js": ["false"],
        }
        create_resp = client.post("/api/watches", data=form_data, follow_redirects=False)
        assert create_resp.status_code == 303

        created = store.get_watch("canon-r5-ii")
        assert created is not None
        assert created.schedule.interval_minutes == 45
        assert created.rules.price.target == 3699.0

        # Invalid JSON in extractors returns 422
        bad_form = dict(form_data, extractors_json="{bad json")
        bad_resp = client.post("/api/watches", data=bad_form)
        assert bad_resp.status_code == 422

        # Toggle enabled -> paused
        toggle_resp = client.post(
            "/api/watches/canon-r5-ii/toggle",
            headers={"Accept": "application/json", "X-CSRF-Token": csrf},
        )
        assert toggle_resp.status_code == 200
        assert toggle_resp.json()["enabled"] is False

        # Duplicate watch
        dup_resp = client.post(
            "/api/watches/canon-r5-ii/duplicate",
            headers={"Accept": "application/json", "X-CSRF-Token": csrf},
        )
        assert dup_resp.status_code == 200
        assert dup_resp.json()["watch"]["id"] == "canon-r5-ii-copy"
        assert store.get_watch("canon-r5-ii-copy") is not None

        # Run poll on existing example-watch via API
        run_resp = client.post(
            "/api/watches/example-watch/run",
            headers={"X-CSRF-Token": csrf},
        )
        assert run_resp.status_code == 200
        payload = run_resp.json()
        assert payload["ok"] is True
        assert payload["report"]["items_matched"] >= 1
        assert "64GB / 512GB / new" in payload["report"]["tier_bests"]

        # Dashboard renders observed tier after run
        dash = client.get("/")
        assert "64GB / 512GB / new" in dash.text

        # Delete copy
        del_resp = client.delete(
            "/api/watches/canon-r5-ii-copy",
            headers={"X-CSRF-Token": csrf},
        )
        assert del_resp.status_code == 200
        assert store.get_watch("canon-r5-ii-copy") is None
    finally:
        db.close()


def test_source_pack_render_and_probe_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, store, db, csrf = _make_client(tmp_path, monkeypatch)
    csrf_headers = {"X-CSRF-Token": csrf}
    try:
        render_resp = client.post(
            "/api/source-packs/render",
            json={"pack_id": "universal_deals", "query": "Mac Studio M5 Max"},
            headers=csrf_headers,
        )
        assert render_resp.status_code == 200
        sources = render_resp.json()["sources"]
        assert len(sources) >= 2
        assert any("slickdeals.net" in s["url"] for s in sources)

        bad_probe = client.post("/api/probe", json={"url": "ftp://invalid"}, headers=csrf_headers)
        assert bad_probe.status_code == 400

        ssrf_probe = client.post(
            "/api/probe",
            json={"url": "http://127.0.0.1:8080/healthz"},
            headers=csrf_headers,
        )
        assert ssrf_probe.status_code == 422

        ssrf_meta = client.post(
            "/api/probe",
            json={"url": "http://169.254.169.254/latest/meta-data/"},
            headers=csrf_headers,
        )
        assert ssrf_meta.status_code == 422

        ssrf_test_source = client.post(
            "/api/source-packs/test-source",
            json={
                "name": "Internal Probe",
                "adapter": "rss",
                "url_template": "http://127.0.0.1:8080/healthz?q={query_encoded}",
                "query": "mac studio",
            },
            headers=csrf_headers,
        )
        assert ssrf_test_source.status_code == 422

        json_create = client.post(
            "/api/watches",
            json={
                "id": "json-watch-test",
                "name": "JSON Watch Test",
                "enabled": False,
                "rules": {"price": {"min": 100, "max": 500}},
            },
            headers=csrf_headers,
        )
        assert json_create.status_code == 200
        assert json_create.json()["ok"] is True
        assert store.get_watch("json-watch-test") is not None

        bad_json_create = client.post(
            "/api/watches",
            json={"id": "../bad", "name": "Bad"},
            headers=csrf_headers,
        )
        assert bad_json_create.status_code == 422

        test_alert = client.post(
            "/api/test-alert",
            json={"recipient_key": "unknown"},
            headers=csrf_headers,
        )
        assert test_alert.status_code == 404
    finally:
        db.close()


def test_minimal_form_create_populates_smart_defaults_and_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, store, db, csrf = _make_client(tmp_path, monkeypatch)
    try:
        minimal_form = {
            "csrf_token": csrf,
            "is_edit": "false",
            "name": "Samsung Galaxy S25 Ultra",
            "id": "samsung-galaxy-s25-ultra",
            "query": "",
            "interval_minutes": "180",
            "jitter_seconds": "180",
            "duration_days": "7",
            "start_at": "",
            "include_groups_text": "",
            "exclude_keywords_text": "",
            "tier_by_text": "",
            "conditions_allowed": ["new", "refurbished"],
            "require_in_stock": "true",
            "enabled": "true",
            "price_min": "0",
            "price_max": "1300",
            "price_target": "",
            "price_msrp": "",
            "min_drop_delta": "20",
            "cooldown_hours": "24",
            "alert_recipients": ["primary"],
            "delivery": "waha_only",
            "send_startup_summary": "true",
        }
        resp = client.post("/api/watches", data=minimal_form, follow_redirects=False)
        assert resp.status_code == 303

        saved = store.get_watch("samsung-galaxy-s25-ultra")
        assert saved is not None
        assert saved.query == "Samsung Galaxy S25 Ultra"
        assert saved.schedule.start_at is not None
        assert saved.rules.include_keyword_groups == [
            ["Samsung"],
            ["Galaxy"],
            ["S25"],
            ["Ultra"],
        ]
        assert "Case" in saved.rules.exclude_keywords
        assert "Diecast" in saved.rules.exclude_keywords
        assert saved.rules.price.min == 325.0
        assert len(saved.sources) == 7
        assert any("slickdeals.net" in s.url for s in saved.sources)
        assert any("craigslist.org/search/sss" in s.url for s in saved.sources)
        assert any("swappa.com" in s.url for s in saved.sources)

        # Vehicle minimal create strips generic 'Pickup', allows 'used', attaches automotive sources
        car_form = {
            "csrf_token": csrf,
            "is_edit": "false",
            "name": "Toyota Tundra Pickup",
            "id": "toyota-tundra-pickup",
            "query": "",
            "interval_minutes": "30",
            "jitter_seconds": "180",
            "duration_days": "14",
            "start_at": "",
            "include_groups_text": "",
            "exclude_keywords_text": "",
            "tier_by_text": "",
            "conditions_allowed": ["new", "refurbished", "open-box", "used"],
            "require_in_stock": "true",
            "enabled": "true",
            "price_min": "10000",
            "price_max": "40000",
            "price_target": "",
            "price_msrp": "",
            "min_drop_delta": "20",
            "cooldown_hours": "24",
            "alert_recipients": ["primary"],
            "delivery": "waha_only",
            "send_startup_summary": "true",
        }
        car_resp = client.post("/api/watches", data=car_form, follow_redirects=False)
        assert car_resp.status_code == 303
        car_saved = store.get_watch("toyota-tundra-pickup")
        assert car_saved is not None
        assert car_saved.rules.include_keyword_groups == [["Toyota"], ["Tundra"]]
        assert "used" in car_saved.rules.conditions_allowed
        assert any(
            "truecar.com/used-cars-for-sale/listings/toyota/tundra/" in s.url
            for s in car_saved.sources
        )
        assert any(
            "washingtondc.craigslist.org/search/cta?query=Toyota+Tundra" in s.url
            for s in car_saved.sources
        )
    finally:
        db.close()


def test_vendor_search_endpoint_validation_and_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _, db, csrf = _make_client(tmp_path, monkeypatch)
    csrf_headers = {"X-CSRF-Token": csrf}
    try:
        bad = client.post("/api/vendors/search", json={"query": "a"}, headers=csrf_headers)
        assert bad.status_code == 400

        async def fake_search(query: str) -> VendorSearchResponse:
            return VendorSearchResponse(
                query=query,
                tokens=["samsung", "galaxy", "s25", "ultra"],
                candidates=[
                    VendorSearchCandidate(
                        name=f"Slickdeals ({query})",
                        adapter="rss",
                        url="https://slickdeals.net/newsearch.php?q=Samsung+Galaxy+S25+Ultra&rss=1",
                        status="A_CLEAN_HTTP",
                        http_status=200,
                        total_fetched=10,
                        matching_count=2,
                        preview_items=[
                            ProbePreviewItem(
                                title="Samsung Galaxy S25 Ultra 256GB Unlocked",
                                price=999.99,
                                merchant="Best Buy",
                                condition="new",
                                in_stock=True,
                                url="https://slickdeals.net/f/1",
                            )
                        ],
                        notes=["2 matching items (out of 10 fetched)."],
                    )
                ],
            )

        monkeypatch.setattr("pricewatcher.web.router.search_vendors_for_query", fake_search)
        ok = client.post(
            "/api/vendors/search",
            json={"query": "Samsung Galaxy S25 Ultra"},
            headers=csrf_headers,
        )
        assert ok.status_code == 200
        body = ok.json()
        assert body["query"] == "Samsung Galaxy S25 Ultra"
        assert len(body["candidates"]) == 1
        assert body["candidates"][0]["status"] == "A_CLEAN_HTTP"
        assert body["candidates"][0]["matching_count"] == 2

        manage_html = client.get("/manage")
        assert manage_html.status_code == 200
        assert "vendor-search-input" in manage_html.text
        assert "vendor-search-btn" in manage_html.text
    finally:
        db.close()


def test_source_pack_crud_test_source_and_volkswagen_combi_synonyms(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pricewatcher.adapters.base import FetchOutcome, Listing

    client, store, db, csrf = _make_client(tmp_path, monkeypatch)
    csrf_headers = {"X-CSRF-Token": csrf}
    try:
        list_resp = client.get("/api/source-packs")
        assert list_resp.status_code == 200
        packs = list_resp.json()["source_packs"]
        assert "automotive_vehicles" in packs
        assert "classic_collector_cars" in packs
        assert "bikes_outdoor_sports" in packs

        settings_page = client.get("/settings")
        assert settings_page.status_code == 200
        assert "source-packs-section" in settings_page.text

        packs_page = client.get("/packs")
        assert packs_page.status_code == 200
        assert "source-packs-list" in packs_page.text
        assert "sync-builtin-packs-btn" in packs_page.text
        assert "pack-probe-section" in packs_page.text
        assert "tools_diy" in packs_page.text

        sync_resp = client.post("/api/source-packs/sync", headers=csrf_headers)
        assert sync_resp.status_code == 200
        assert sync_resp.json()["ok"] is True

        # Create/save a custom source pack
        save_resp = client.post(
            "/api/source-packs/audio_hifi",
            json={
                "label": "Hi-Fi Audio Gear",
                "description": "Turntables and amps",
                "sources": [
                    {
                        "name": "Slickdeals ({query})",
                        "adapter": "rss",
                        "url_template": "https://slickdeals.net/newsearch.php?q={query_encoded}&rss=1",
                        "options": {},
                    }
                ],
            },
            headers=csrf_headers,
        )
        assert save_resp.status_code == 200
        assert save_resp.json()["ok"] is True
        assert "audio_hifi" in store.load_settings().source_packs

        # Mock adapter.fetch for test-source endpoint
        class FakeRssAdapter:
            async def fetch(self, source):
                return FetchOutcome(
                    listings=[
                        Listing(
                            source_name=source.name,
                            merchant="Classic.com",
                            title="1996 Volkswagen Type 2 Kombi",
                            url="https://www.classic.com/veh/1",
                            price=19900.0,
                            condition="used",
                        )
                    ],
                    http_status=200,
                    latency_ms=42,
                )

        def fake_getaddrinfo(
            host: str,
            port: Any,
            *_args: Any,
            **_kwargs: Any,
        ) -> list[tuple[Any, ...]]:
            if str(host).lower() == "www.classic.com":
                return [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", int(port or 0)))
                ]
            raise socket.gaierror(socket.EAI_NONAME, f"Unexpected DNS lookup for {host}")

        monkeypatch.setattr("pricewatcher.http_client.socket.getaddrinfo", fake_getaddrinfo)
        monkeypatch.setattr("pricewatcher.web.router.get_adapter", lambda _name: FakeRssAdapter())
        test_resp = client.post(
            "/api/source-packs/test-source",
            json={
                "name": "Classic.com ({query})",
                "adapter": "html_css",
                "url_template": "https://www.classic.com/search?q={query_encoded}",
                "options": {},
                "query": "volkswagen combi",
            },
            headers=csrf_headers,
        )
        assert test_resp.status_code == 200
        tbody = test_resp.json()
        assert tbody["ok"] is True
        assert tbody["rendered_url"] == "https://www.classic.com/search?q=volkswagen+Kombi"
        assert tbody["item_count"] == 1
        assert tbody["matching_count"] == 1

        # Reject {make}/{model} test-source if sample query has no identifiable make/model
        bad_mm = client.post(
            "/api/source-packs/test-source",
            json={
                "name": "TrueCar Used ({query})",
                "adapter": "html_css",
                "url_template": "https://www.truecar.com/used-cars-for-sale/listings/{make}/{model}/",
                "query": "chair",
            },
            headers=csrf_headers,
        )
        assert bad_mm.status_code == 400

        # Delete custom pack
        del_resp = client.delete("/api/source-packs/audio_hifi", headers=csrf_headers)
        assert del_resp.status_code == 200
        assert "audio_hifi" not in store.load_settings().source_packs

        # Minimal create for "volkswagen combi" expands synonym keyword groups
        vw_resp = client.post(
            "/api/watches",
            data={
                "csrf_token": csrf,
                "is_edit": "false",
                "name": "volkswagen combi",
                "id": "volkswagen-combi",
                "query": "",
                "interval_minutes": "240",
                "jitter_seconds": "180",
                "duration_days": "90",
                "start_at": "",
                "include_groups_text": "",
                "exclude_keywords_text": "",
                "tier_by_text": "",
                "conditions_allowed": ["new", "refurbished", "open-box", "used"],
                "require_in_stock": "true",
                "enabled": "true",
                "price_min": "6000",
                "price_max": "80000",
                "price_target": "20000",
                "price_msrp": "",
                "min_drop_delta": "20",
                "cooldown_hours": "24",
                "alert_recipients": ["primary"],
                "delivery": "waha_only",
                "send_startup_summary": "true",
            },
            follow_redirects=False,
        )
        assert vw_resp.status_code == 303
        vw_saved = store.get_watch("volkswagen-combi")
        assert vw_saved is not None
        assert vw_saved.rules.include_keyword_groups[0] == ["Volkswagen", "VW"]
        assert "Kombi" in vw_saved.rules.include_keyword_groups[1]
        assert any("classic.com/search?q=volkswagen+Kombi" in s.url for s in vw_saved.sources)
    finally:
        db.close()


def test_recipient_crud_on_admin_page(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client, store, db, csrf = _make_client(tmp_path, monkeypatch)
    csrf_headers = {"X-CSRF-Token": csrf}
    monkeypatch.setenv("WAHA_API_KEY", "test-waha-key")
    try:
        admin_page = client.get("/settings")
        assert admin_page.status_code == 200
        assert "Admin" in admin_page.text

        # Create/update user
        save_resp = client.post(
            "/api/recipients/alex",
            json={
                "name": "Alex",
                "waha_chat_id": "15551234567@c.us",
                "email": "alex@example.com",
            },
            headers=csrf_headers,
        )
        assert save_resp.status_code == 200
        assert save_resp.json()["ok"] is True
        saved = store.load_settings().notifications.recipients.get("alex")
        assert saved is not None
        assert saved.name == "Alex"
        assert saved.waha_chat_id == "15551234567@c.us"
        assert saved.email == "alex@example.com"

        # Delete user
        del_resp = client.delete("/api/recipients/alex", headers=csrf_headers)
        assert del_resp.status_code == 200
        assert "alex" not in store.load_settings().notifications.recipients
    finally:
        db.close()


def test_healthz_lightweight_skips_disk_and_db(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, store, db, _ = _make_client(tmp_path, monkeypatch)
    try:

        def _forbid(*_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("/healthz must not perform disk or DB I/O")

        monkeypatch.setattr(store, "load_watches", _forbid)
        monkeypatch.setattr(store, "load_settings", _forbid)
        monkeypatch.setattr(db, "get_alerts", _forbid)

        health = client.get("/healthz")
        assert health.status_code == 200
        assert health.json() == {"status": "ok"}
    finally:
        db.close()


async def test_route_handlers_offload_store_io_off_event_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PRICEWATCHER_INSECURE_NO_AUTH", "1")
    monkeypatch.delenv("PRICEWATCHER_ADMIN_PASSWORD_HASH", raising=False)
    monkeypatch.setenv("PRICEWATCHER_SESSION_SECRET", "test-session-secret-32-bytes-minimum")

    repo_cfg = Path(__file__).resolve().parent.parent / "config"
    cfg_dir = tmp_path / "config"
    (cfg_dir / "watches").mkdir(parents=True)
    shutil.copy2(repo_cfg / "settings.example.yaml", cfg_dir / "settings.yaml")
    shutil.copy2(
        repo_cfg / "watches" / "example-watch.yaml.example",
        cfg_dir / "watches" / "example-watch.yaml",
    )

    store = ConfigStore(cfg_dir)
    db = Database(tmp_path / "prices.db")
    engine = PollEngine(
        store=store,
        db=db,
        adapter_factory=lambda _: StaticAdapter(),  # type: ignore[return-value]
    )

    async def _fake_waha_health(_self: Any) -> dict[str, Any]:
        return {
            "ok": False,
            "status": "down",
            "url": "http://waha.docker",
            "session": "pricewatcher",
            "detail": "mocked",
        }

    monkeypatch.setattr("pricewatcher.web.router.WahaClient.check_health", _fake_waha_health)

    event_loop_thread = threading.current_thread()
    recorded_calls: list[tuple[str, threading.Thread]] = []

    for method_name in (
        "load_watches",
        "load_settings",
        "get_watch",
        "save_watch",
        "update_watch",
        "delete_watch",
        "update_settings",
    ):
        orig = getattr(store, method_name)

        def _make_wrapper(name: str, fn: Any) -> Any:
            def _wrapped(*args: Any, **kwargs: Any) -> Any:
                recorded_calls.append((name, threading.current_thread()))
                return fn(*args, **kwargs)

            return _wrapped

        monkeypatch.setattr(store, method_name, _make_wrapper(method_name, orig))

    import pricewatcher.web.router as router_mod

    for fn_name in ("load_builtin_source_packs", "sync_builtin_source_packs"):
        orig_fn = getattr(router_mod, fn_name)

        def _make_mod_wrapper(name: str, fn: Any) -> Any:
            def _wrapped(*args: Any, **kwargs: Any) -> Any:
                recorded_calls.append((name, threading.current_thread()))
                return fn(*args, **kwargs)

            return _wrapped

        monkeypatch.setattr(router_mod, fn_name, _make_mod_wrapper(fn_name, orig_fn))

    app = create_app(store=store, db=db, engine=engine, start_scheduler=False)

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as async_client:
            dash_resp = await async_client.get("/")
            assert dash_resp.status_code == 200
            csrf = _extract_csrf(dash_resp.text)
            headers = {"Accept": "application/json", "X-CSRF-Token": csrf}

            recorded_calls.clear()

            assert (await async_client.get("/api/watches")).status_code == 200
            assert (
                await async_client.post(
                    "/api/watches",
                    json={"id": "thread-watch", "name": "Thread Watch", "query": "Thread Watch"},
                    headers=headers,
                )
            ).status_code == 200
            assert (
                await async_client.post("/api/watches/thread-watch/delete", headers=headers)
            ).status_code == 200
            assert (
                await async_client.post("/api/watches/example-watch/toggle", headers=headers)
            ).status_code == 200
            assert (
                await async_client.post("/api/watches/example-watch/duplicate", headers=headers)
            ).status_code == 200
            assert (
                await async_client.delete("/api/watches/example-watch-copy", headers=headers)
            ).status_code == 200
            assert (
                await async_client.post(
                    "/api/recipients/thread-test",
                    json={"name": "Thread Test", "email": "thread@example.com"},
                    headers=headers,
                )
            ).status_code == 200
            assert (
                await async_client.delete("/api/recipients/thread-test", headers=headers)
            ).status_code == 200
            assert (
                await async_client.post(
                    "/api/source-packs/thread-pack",
                    json={"label": "Thread Pack", "description": "Test", "sources": []},
                    headers=headers,
                )
            ).status_code == 200
            assert (
                await async_client.delete("/api/source-packs/thread-pack", headers=headers)
            ).status_code == 200
            assert (await async_client.get("/api/source-packs")).status_code == 200
            assert (
                await async_client.post("/api/source-packs/sync", headers=headers)
            ).status_code == 200
            assert (
                await async_client.post(
                    "/api/source-packs/render",
                    json={"pack_id": "universal_deals", "query": "Mac Studio"},
                    headers=headers,
                )
            ).status_code == 200
            assert (await async_client.get("/manage?edit=example-watch")).status_code == 200
            assert (await async_client.get("/settings")).status_code == 200
            assert (await async_client.get("/packs")).status_code == 200

        called_methods = {name for name, _ in recorded_calls}
        assert {
            "load_watches",
            "load_settings",
            "get_watch",
            "save_watch",
            "update_watch",
            "delete_watch",
            "update_settings",
            "load_builtin_source_packs",
            "sync_builtin_source_packs",
        }.issubset(called_methods)
        assert all(thread is not event_loop_thread for _, thread in recorded_calls)
    finally:
        db.close()
