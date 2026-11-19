"""Tests for Pydantic v2 config models and atomic YAML persistence."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import logging
import os
from pathlib import Path
import shutil

from pydantic import ValidationError
import pytest
import yaml

from pricewatcher.config import (
    AlertsConfig,
    ConfigStore,
    ExtractorConfig,
    PriceRulesConfig,
    RulesConfig,
    ScheduleConfig,
    ServerConfig,
    SourceConfig,
    SourcePackConfig,
    SourceTemplateConfig,
    WatchConfig,
)


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
