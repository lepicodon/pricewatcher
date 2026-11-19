"""Tests for Pydantic v2 config models and atomic YAML persistence."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import logging
import os
from pathlib import Path
import re
import shutil
import threading
import time

from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest
import yaml

from pricewatcher.config import (
    AlertsConfig,
    ConfigStore,
    ExtractorConfig,
    PriceRulesConfig,
    RecipientConfig,
    RulesConfig,
    ScheduleConfig,
    ServerConfig,
    SettingsConfig,
    SourceConfig,
    SourcePackConfig,
    SourceTemplateConfig,
    WatchConfig,
)
from pricewatcher.main import create_app
from pricewatcher.storage import Database


def test_load_example_settings_and_example_watch(tmp_path: Path) -> None:
    repo_cfg = Path(__file__).resolve().parent.parent / "config"
    cfg_dir = tmp_path / "config"
    (cfg_dir / "watches").mkdir(parents=True)
    shutil.copy2(repo_cfg / "settings.example.yaml", cfg_dir / "settings.yaml")
    shutil.copy2(
        repo_cfg / "watches" / "example-watch.yaml.example",
        cfg_dir / "watches" / "example-watch.yaml",
    )

    store = ConfigStore(cfg_dir)
    settings = store.load_settings()
    assert settings.notifications.waha.url == "http://waha.docker"
    assert settings.notifications.waha.session == "pricewatcher"
    assert "primary" in settings.notifications.recipients
    assert "universal_deals" in settings.source_packs

    watches = store.load_watches()
    assert len(watches) == 1
    watch = store.get_watch("example-watch")
    assert watch is not None
    assert watch.rules.price.target == 3450
    assert watch.rules.extractors["ram_gb"].min == 64
    assert len(watch.sources) >= 6


def test_load_settings_falls_back_to_example_when_missing(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    repo_cfg = Path(__file__).resolve().parent.parent / "config"
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir(parents=True)
    shutil.copy2(repo_cfg / "settings.example.yaml", cfg_dir / "settings.example.yaml")

    store = ConfigStore(cfg_dir)
    assert not store.settings_path.exists()

    with caplog.at_level(logging.WARNING, logger="pricewatcher.config"):
        settings = store.load_settings()

    assert "primary" in settings.notifications.recipients
    assert "universal_deals" in settings.source_packs
    assert any("falling back" in rec.message.lower() for rec in caplog.records)


def test_example_configs_contain_no_personal_data() -> None:
    repo_cfg = Path(__file__).resolve().parent.parent / "config"
    settings_text = (repo_cfg / "settings.example.yaml").read_text(encoding="utf-8")
    watch_text = (repo_cfg / "watches" / "example-watch.yaml.example").read_text(encoding="utf-8")
    raw_settings = yaml.safe_load(settings_text)
    recipients = raw_settings["notifications"]["recipients"]
    assert set(recipients.keys()) == {"primary", "partner", "family_group"}
    for rec in recipients.values():
        if rec.get("email"):
            assert rec["email"].endswith("@example.com")
        if rec.get("whatsapp", "").endswith("@c.us"):
            assert rec["whatsapp"].startswith("1555")
    assert "@gmail.com" not in settings_text.lower()
    assert "@gmail.com" not in watch_text.lower()


def test_sanitize_watch_id_and_traversal_blocking() -> None:
    assert ConfigStore.sanitize_slug("Mac Studio M5 Max!") == "mac-studio-m5-max"
    assert ConfigStore.sanitize_watch_id("Mac Studio M5 Max!") == "mac-studio-m5-max"
    assert ConfigStore.sanitize_watch_id("aventon_level_2") == "aventon_level_2"
    assert ConfigStore.sanitize_watch_id == ConfigStore.sanitize_slug

    for bad in ("", " ", "../secret", "foo/bar", "a\\b", "a\x00b", "x"):
        with pytest.raises(ValueError):
            ConfigStore.sanitize_watch_id(bad)


def test_atomic_save_reload_and_delete(tmp_path: Path) -> None:
    cfg_dir = tmp_path / "config"
    (cfg_dir / "watches").mkdir(parents=True)
    shutil.copy2(
        Path(__file__).resolve().parent.parent / "config" / "settings.example.yaml",
        cfg_dir / "settings.yaml",
    )

    store = ConfigStore(cfg_dir)
    watch = WatchConfig(
        id="aventon-level-2",
        name="Aventon Level.2 E-Bike",
        enabled=True,
        query="Aventon Level.2",
        schedule=ScheduleConfig(interval_minutes=60, jitter_seconds=30, duration_days=30),
        rules=RulesConfig(
            include_keyword_groups=[["Aventon"], ["Level.2", "Level 2"]],
            exclude_keywords=["Battery Only", "Rack"],
            price=PriceRulesConfig(min=800, max=2000, target=1499),
        ),
        alerts=AlertsConfig(recipients=["primary"], delivery="waha_with_email_fallback"),
        sources=[
            SourceConfig(
                name="Slickdeals Aventon",
                adapter="rss",
                url="https://slickdeals.net/newsearch.php?q=Aventon+Level+2&rss=1",
            )
        ],
    )
    saved_path = store.save_watch(watch)
    assert saved_path.exists()
    assert saved_path.name == "aventon-level-2.yaml"
    assert not list((cfg_dir / "watches").glob("*.tmp"))

    loaded = store.get_watch("aventon-level-2")
    assert loaded is not None
    assert loaded.name == "Aventon Level.2 E-Bike"
    assert loaded.rules.price.target == 1499
    assert len(loaded.sources) == 1

    assert store.delete_watch("aventon-level-2") is True
    assert store.get_watch("aventon-level-2") is None
    assert store.delete_watch("aventon-level-2") is False


def test_schedule_status_and_expiry() -> None:
    now = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
    active = WatchConfig(
        id="active-watch",
        name="Active",
        enabled=True,
        schedule=ScheduleConfig(start_at=now - timedelta(days=2), duration_days=14),
    )
    is_expired, days_left = active.schedule.status_info(now=now)
    assert is_expired is False
    assert days_left == 12.0
    assert active.effective_status(now=now) == "active"

    paused = active.model_copy(update={"enabled": False})
    assert paused.effective_status(now=now) == "paused"

    expired = active.model_copy(
        update={
            "schedule": ScheduleConfig(
                start_at=now - timedelta(days=15),
                duration_days=14,
            )
        }
    )
    exp_flag, exp_days = expired.schedule.status_info(now=now)
    assert exp_flag is True
    assert exp_days == 0.0
    assert expired.effective_status(now=now) == "expired"


def test_invalid_extractor_regex_rejected() -> None:
    with pytest.raises(ValidationError):
        ExtractorConfig(pattern="[unclosed", type="int")

    ok = ExtractorConfig(pattern="a" * 256, type="str")
    assert len(ok.pattern) == 256
    with pytest.raises(ValidationError):
        ExtractorConfig(pattern="a" * 257, type="str")


def test_server_config_limits() -> None:
    srv = ServerConfig()
    assert srv.retention_days == 180
    assert srv.fetch_concurrency == 4

    with pytest.raises(ValidationError):
        ServerConfig(retention_days=0)
    with pytest.raises(ValidationError):
        ServerConfig(fetch_concurrency=0)
    with pytest.raises(ValidationError):
        ServerConfig(fetch_concurrency=17)


def test_config_store_mtime_caching_and_invalidation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_cfg = Path(__file__).resolve().parent.parent / "config"
    cfg_dir = tmp_path / "config"
    (cfg_dir / "watches").mkdir(parents=True)
    shutil.copy2(repo_cfg / "settings.example.yaml", cfg_dir / "settings.yaml")
    shutil.copy2(
        repo_cfg / "watches" / "example-watch.yaml.example",
        cfg_dir / "watches" / "example-watch.yaml",
    )

    store = ConfigStore(cfg_dir)
    parse_calls = 0
    real_safe_load = yaml.safe_load

    def counting_safe_load(stream: str) -> object:
        nonlocal parse_calls
        parse_calls += 1
        return real_safe_load(stream)

    monkeypatch.setattr(yaml, "safe_load", counting_safe_load)

    # Settings cached across repeated reads & returned copies don't poison cache
    s1 = store.load_settings()
    s1.server.port = 9999
    s2 = store.load_settings()
    assert s2.server.port == 8080
    assert parse_calls == 1

    # save_settings invalidates cache
    s2.server.port = 8181
    store.save_settings(s2)
    assert store.load_settings().server.port == 8181
    assert parse_calls == 2

    # External disk edit detected via mtime/size
    settings_txt = store.settings_path.read_text(encoding="utf-8").replace("8181", "8282")
    store.settings_path.write_text(settings_txt, encoding="utf-8")
    st = store.settings_path.stat()
    os.utime(store.settings_path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))
    assert store.load_settings().server.port == 8282
    assert parse_calls == 3

    # Watches cached across repeated reads
    parse_calls = 0
    w1 = store.load_watches()
    assert len(w1) == 1
    w1[0].name = "Mutated In Memory"
    w2 = store.load_watches()
    assert w2[0].name != "Mutated In Memory"
    assert parse_calls == 1

    # save_watch invalidates watches cache
    w_new = w2[0].model_copy(update={"id": "second-watch", "name": "Second Watch"})
    store.save_watch(w_new)
    assert len(store.load_watches()) == 2
    assert parse_calls == 3  # 2 watch files parsed

    # External edit to watch file invalidates watches cache
    second_path = store.watches_dir / "second-watch.yaml"
    second_path.write_text(
        second_path.read_text(encoding="utf-8").replace("Second Watch", "Second Watch Edited"),
        encoding="utf-8",
    )
    st_w = second_path.stat()
    os.utime(second_path, ns=(st_w.st_atime_ns, st_w.st_mtime_ns + 1_000_000))
    loaded_second = store.get_watch("second-watch")
    assert loaded_second is not None
    assert loaded_second.name == "Second Watch Edited"
    assert any(w.name == "Second Watch Edited" for w in store.load_watches())

    # delete_watch invalidates watches cache
    assert store.delete_watch("second-watch") is True
    assert [w.id for w in store.load_watches()] == ["example-watch"]


def test_env_session_override_and_docker_path_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PRICEWATCHER_CONFIG_DIR", "/app/config")
    monkeypatch.setenv("WAHA_SESSION", "CustomSession")
    store = ConfigStore()
    if not Path("/app/config").exists():
        assert store.config_dir == Path("config")
    cfg = store.load_settings().notifications.waha
    assert cfg.effective_session() == "CustomSession"


def test_source_template_make_model_render_and_save_settings(tmp_path: Path) -> None:
    cfg_dir = tmp_path / "config"
    (cfg_dir / "watches").mkdir(parents=True)
    shutil.copy2(
        Path(__file__).resolve().parent.parent / "config" / "settings.example.yaml",
        cfg_dir / "settings.yaml",
    )
    store = ConfigStore(cfg_dir)
    settings = store.load_settings()

    tmpl = SourceTemplateConfig(
        name="TrueCar Used ({query})",
        adapter="html_css",
        url_template="https://www.truecar.com/used-cars-for-sale/listings/{make}/{model}/",
    )
    rendered = tmpl.render("Toyota Tundra Pickup")
    assert rendered.url == "https://www.truecar.com/used-cars-for-sale/listings/toyota/tundra/"

    classic_tmpl = SourceTemplateConfig(
        name="Classic.com ({query})",
        adapter="html_css",
        url_template="https://www.classic.com/search?q={query_encoded}",
    )
    assert (
        classic_tmpl.render("volkswagen combi").url
        == "https://www.classic.com/search?q=volkswagen+Kombi"
    )

    settings.source_packs["custom_test"] = SourcePackConfig(
        label="Custom Test Pack",
        description="Test pack",
        sources=[classic_tmpl],
    )
    store.save_settings(settings)
    reloaded = store.load_settings()
    assert "custom_test" in reloaded.source_packs
    assert reloaded.source_packs["custom_test"].label == "Custom Test Pack"
    assert not list(cfg_dir.glob("*.tmp"))


def test_builtin_packs_match_example_and_sync_non_destructively(tmp_path: Path) -> None:
    from pricewatcher.config import (
        SettingsConfig,
        load_builtin_source_packs,
        sync_builtin_source_packs,
    )

    builtin = load_builtin_source_packs()
    for key in (
        "universal_deals",
        "apple_hardware",
        "electronics_tech",
        "home_furniture_appliances",
        "tools_diy",
        "automotive_vehicles",
        "classic_collector_cars",
        "bikes_outdoor_sports",
    ):
        assert key in builtin

    import yaml

    raw_example = yaml.safe_load(Path("config/settings.example.yaml").read_text(encoding="utf-8"))
    example_settings = SettingsConfig.model_validate(raw_example)
    assert set(builtin.keys()) == set(example_settings.source_packs.keys())
    for pack_id, pack in builtin.items():
        assert pack.model_dump(mode="json") == example_settings.source_packs[pack_id].model_dump(
            mode="json"
        )

    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    store = ConfigStore(cfg_dir)
    initial = SettingsConfig(
        source_packs={
            "custom_only": SourcePackConfig(label="Custom Only", description="Keep me", sources=[]),
            "universal_deals": SourcePackConfig(
                label="Universal",
                description="Partial",
                sources=[builtin["universal_deals"].sources[0].model_copy(deep=True)],
            ),
        }
    )
    store.save_settings(initial)

    packs_added, sources_added, synced = sync_builtin_source_packs(store)
    assert "tools_diy" in packs_added
    assert "apple_hardware" in packs_added
    assert sources_added > 0
    assert "custom_only" in synced.source_packs
    assert len(synced.source_packs["universal_deals"].sources) == len(
        builtin["universal_deals"].sources
    )


def test_concurrent_update_settings_no_lost_updates(tmp_path: Path) -> None:
    repo_cfg = Path(__file__).resolve().parent.parent / "config"
    cfg_dir = tmp_path / "config"
    (cfg_dir / "watches").mkdir(parents=True)
    shutil.copy2(repo_cfg / "settings.example.yaml", cfg_dir / "settings.yaml")

    store = ConfigStore(cfg_dir)
    workers = 12
    barrier = threading.Barrier(workers)

    def _add_recipient(idx: int) -> str:
        barrier.wait(timeout=5)
        key = f"concurrent-{idx}"

        def _mutate(settings: SettingsConfig) -> str:
            time.sleep(0.002)
            settings.notifications.recipients[key] = RecipientConfig(
                name=f"Concurrent {idx}",
                email=f"concurrent-{idx}@example.com",
            )
            return key

        return store.update_settings(_mutate)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(_add_recipient, range(workers)))

    assert results == [f"concurrent-{idx}" for idx in range(workers)]
    reloaded = store.load_settings()
    for idx in range(workers):
        key = f"concurrent-{idx}"
        assert key in reloaded.notifications.recipients
        assert reloaded.notifications.recipients[key].email == f"concurrent-{idx}@example.com"
    assert {"primary", "partner", "family_group"}.issubset(reloaded.notifications.recipients.keys())

    # Exception inside update_settings callback skips save_settings
    before_bytes = store.settings_path.read_bytes()

    def _abort(_settings: SettingsConfig) -> None:
        raise KeyError("missing")

    with pytest.raises(KeyError):
        store.update_settings(_abort)
    assert store.settings_path.read_bytes() == before_bytes


def test_concurrent_update_watch_and_duplicate_slot_allocation(tmp_path: Path) -> None:
    cfg_dir = tmp_path / "config"
    (cfg_dir / "watches").mkdir(parents=True)
    store = ConfigStore(cfg_dir)
    store.save_watch(
        WatchConfig(
            id="race-watch",
            name="Race Watch",
            enabled=True,
            query="Race Watch",
            rules=RulesConfig(exclude_keywords=[]),
        )
    )

    assert store.update_watch("missing-watch", lambda w: w) is None

    workers = 12
    barrier = threading.Barrier(workers)

    def _append_keyword(idx: int) -> WatchConfig | None:
        barrier.wait(timeout=5)

        def _mutate(watch: WatchConfig) -> WatchConfig | None:
            time.sleep(0.002)
            watch.rules.exclude_keywords.append(f"kw-{idx}")
            return watch if idx % 2 == 0 else None

        return store.update_watch("race-watch", _mutate)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        updated = list(pool.map(_append_keyword, range(workers)))

    assert all(w is not None and w.id == "race-watch" for w in updated)
    reloaded = store.get_watch("race-watch")
    assert reloaded is not None
    assert sorted(reloaded.rules.exclude_keywords) == sorted(f"kw-{idx}" for idx in range(workers))

    # Concurrent duplicate-style slot allocation must yield unique copy IDs
    dup_workers = 8
    dup_barrier = threading.Barrier(dup_workers)

    def _duplicate_slot(_idx: int) -> str:
        dup_barrier.wait(timeout=5)

        def _allocate(watch: WatchConfig) -> WatchConfig:
            time.sleep(0.002)
            for suffix_idx in range(1, 100):
                suffix = "-copy" if suffix_idx == 1 else f"-copy-{suffix_idx}"
                attempt = f"{watch.id}{suffix}"
                if store.get_watch(attempt) is None:
                    return watch.model_copy(
                        deep=True,
                        update={"id": attempt, "name": f"{watch.name} (Copy)", "enabled": False},
                    )
            raise RuntimeError("No free duplicate slot")

        cloned = store.update_watch("race-watch", _allocate)
        assert cloned is not None
        return cloned.id

    with ThreadPoolExecutor(max_workers=dup_workers) as pool:
        dup_ids = list(pool.map(_duplicate_slot, range(dup_workers)))

    assert len(set(dup_ids)) == dup_workers
    expected_ids = {"race-watch-copy"} | {f"race-watch-copy-{i}" for i in range(2, dup_workers + 1)}
    assert set(dup_ids) == expected_ids
    assert store.get_watch("race-watch") is not None
    for dup_id in dup_ids:
        assert store.get_watch(dup_id) is not None


def test_concurrent_http_api_updates_no_lost_updates(
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
    orig_load_settings = store.load_settings
    orig_get_watch = store.get_watch

    def _delayed_load_settings() -> SettingsConfig:
        settings = orig_load_settings()
        time.sleep(0.002)
        return settings

    def _delayed_get_watch(watch_id: str) -> WatchConfig | None:
        watch = orig_get_watch(watch_id)
        time.sleep(0.002)
        return watch

    monkeypatch.setattr(store, "load_settings", _delayed_load_settings)
    monkeypatch.setattr(store, "get_watch", _delayed_get_watch)

    db = Database(tmp_path / "prices.db")
    try:
        app = create_app(store=store, db=db, start_scheduler=False)

        def _csrf_client() -> tuple[TestClient, str]:
            client = TestClient(app)
            page = client.get("/")
            assert page.status_code == 200
            match = re.search(r'<meta\s+name="csrf-token"\s+content="([^"]*)"', page.text)
            assert match is not None
            return client, match.group(1)

        # 12 concurrent recipient saves via HTTP API
        workers = 12
        rec_barrier = threading.Barrier(workers)

        def _post_recipient(idx: int) -> int:
            client, csrf = _csrf_client()
            try:
                rec_barrier.wait(timeout=5)
                resp = client.post(
                    f"/api/recipients/user-{idx}",
                    json={
                        "name": f"User {idx}",
                        "email": f"user-{idx}@example.com",
                    },
                    headers={"X-CSRF-Token": csrf},
                )
                return resp.status_code
            finally:
                client.close()

        with ThreadPoolExecutor(max_workers=workers) as pool:
            rec_statuses = list(pool.map(_post_recipient, range(workers)))

        assert rec_statuses == [200] * workers
        saved_recipients = orig_load_settings().notifications.recipients
        for idx in range(workers):
            assert f"user-{idx}" in saved_recipients

        # 8 concurrent source pack saves via HTTP API
        pack_workers = 8
        pack_barrier = threading.Barrier(pack_workers)

        def _post_pack(idx: int) -> int:
            client, csrf = _csrf_client()
            try:
                pack_barrier.wait(timeout=5)
                resp = client.post(
                    f"/api/source-packs/custom-pack-{idx}",
                    json={
                        "label": f"Custom Pack {idx}",
                        "description": "Concurrent pack",
                        "sources": [
                            {
                                "name": "Slickdeals ({query})",
                                "adapter": "rss",
                                "url_template": "https://slickdeals.net/newsearch.php?q={query_encoded}&rss=1",
                            }
                        ],
                    },
                    headers={"X-CSRF-Token": csrf},
                )
                return resp.status_code
            finally:
                client.close()

        with ThreadPoolExecutor(max_workers=pack_workers) as pool:
            pack_statuses = list(pool.map(_post_pack, range(pack_workers)))

        assert pack_statuses == [200] * pack_workers
        saved_packs = orig_load_settings().source_packs
        for idx in range(pack_workers):
            assert f"custom-pack-{idx}" in saved_packs

        # 11 concurrent toggles on enabled=True watch must end with enabled=False
        toggle_workers = 11
        toggle_barrier = threading.Barrier(toggle_workers)

        def _post_toggle(_idx: int) -> int:
            client, csrf = _csrf_client()
            try:
                toggle_barrier.wait(timeout=5)
                resp = client.post(
                    "/api/watches/example-watch/toggle",
                    headers={"Accept": "application/json", "X-CSRF-Token": csrf},
                )
                return resp.status_code
            finally:
                client.close()

        with ThreadPoolExecutor(max_workers=toggle_workers) as pool:
            toggle_statuses = list(pool.map(_post_toggle, range(toggle_workers)))

        assert toggle_statuses == [200] * toggle_workers
        toggled_watch = orig_get_watch("example-watch")
        assert toggled_watch is not None
        assert toggled_watch.enabled is False

        # 6 concurrent duplicate requests via HTTP API must allocate 6 unique copies
        dup_workers = 6
        dup_barrier = threading.Barrier(dup_workers)

        def _post_duplicate(_idx: int) -> tuple[int, str]:
            client, csrf = _csrf_client()
            try:
                dup_barrier.wait(timeout=5)
                resp = client.post(
                    "/api/watches/example-watch/duplicate",
                    headers={"Accept": "application/json", "X-CSRF-Token": csrf},
                )
                return resp.status_code, resp.json()["watch"]["id"]
            finally:
                client.close()

        with ThreadPoolExecutor(max_workers=dup_workers) as pool:
            dup_results = list(pool.map(_post_duplicate, range(dup_workers)))

        assert all(status == 200 for status, _ in dup_results)
        dup_ids = [watch_id for _, watch_id in dup_results]
        assert len(set(dup_ids)) == dup_workers
        for dup_id in dup_ids:
            assert orig_get_watch(dup_id) is not None

        # Delete missing recipient / pack returns 404 without clobbering existing entries
        client, csrf = _csrf_client()
        try:
            assert (
                client.delete(
                    "/api/recipients/no-such-user",
                    headers={"X-CSRF-Token": csrf},
                ).status_code
                == 404
            )
            assert (
                client.delete(
                    "/api/source-packs/no-such-pack",
                    headers={"X-CSRF-Token": csrf},
                ).status_code
                == 404
            )
            for idx in range(workers):
                assert f"user-{idx}" in orig_load_settings().notifications.recipients

            # Exhaust all 99 duplicate suffixes -> 409 Conflict
            for suffix_idx in range(1, 100):
                suffix = "-copy" if suffix_idx == 1 else f"-copy-{suffix_idx}"
                attempt = f"example-watch{suffix}"
                path = store.watches_dir / f"{attempt}.yaml"
                if not path.exists():
                    path.write_text(f"id: {attempt}\nname: Copy\n", encoding="utf-8")
            conflict = client.post(
                "/api/watches/example-watch/duplicate",
                headers={"Accept": "application/json", "X-CSRF-Token": csrf},
            )
            assert conflict.status_code == 409
        finally:
            client.close()
    finally:
        db.close()
