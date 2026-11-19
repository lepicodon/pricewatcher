"""Pydantic v2 configuration models and atomic YAML persistence."""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime, timedelta
import logging
import os
from pathlib import Path
import re
import tempfile
import threading
from typing import Any, Literal
from urllib.parse import quote_plus

from dotenv import find_dotenv, load_dotenv
from pydantic import BaseModel, ConfigDict, Field, field_validator
import regex
import yaml

logger = logging.getLogger("pricewatcher.config")

WATCH_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,62}$")


_LOADED_ENV_FILES: set[Path] = set()


def _load_env_once(path: Path) -> None:
    resolved = path.resolve()
    if resolved in _LOADED_ENV_FILES:
        return
    _LOADED_ENV_FILES.add(resolved)
    load_dotenv(resolved, override=False)


def _load_env_file() -> None:
    """Load .env from cwd or parent project root once without overriding real env vars."""
    cwd_env = Path.cwd() / ".env"
    if cwd_env.is_file():
        _load_env_once(cwd_env)
        return
    discovered = find_dotenv(usecwd=True)
    if discovered:
        _load_env_once(Path(discovered))
        return
    repo_env = Path(__file__).resolve().parents[2] / ".env"
    if repo_env.is_file():
        _load_env_once(repo_env)


_load_env_file()


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _ensure_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


class ServerConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    port: int = 8080
    timezone: str = "America/New_York"
    retention_days: int = Field(default=180, ge=1)
    fetch_concurrency: int = Field(default=4, ge=1, le=16)


class WahaConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    url: str = "http://waha.docker"
    api_key_env: str = "WAHA_API_KEY"
    session: str = "pricewatcher"

    def effective_url(self) -> str:
        env_url = os.environ.get("WAHA_URL", "").strip()
        return (env_url or self.url).rstrip("/")

    def effective_session(self) -> str:
        env_session = os.environ.get("WAHA_SESSION", "").strip()
        return env_session or self.session

    def effective_api_key(self) -> str:
        return os.environ.get(self.api_key_env, "").strip()


class EmailConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    enabled: bool = False
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    use_tls: bool = True
    user_env: str = "SMTP_USER"
    pass_env: str = "SMTP_PASS"  # noqa: S105 - env var name, not a secret
    from_addr: str = "pricewatcher@example.com"

    def effective_credentials(self) -> tuple[str, str]:
        return (
            os.environ.get(self.user_env, "").strip(),
            os.environ.get(self.pass_env, "").strip(),
        )


class RecipientConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    waha_chat_id: str | None = None
    email: str | None = None


class SourceConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    adapter: Literal["rss", "json_api", "html_css", "appleinsider"]
    url: str
    enabled: bool = True
    render_js: bool = False
    options: dict[str, Any] = Field(default_factory=dict)


GENERIC_CATEGORY_WORDS = {
    "pickup",
    "truck",
    "car",
    "suv",
    "sedan",
    "coupe",
    "van",
    "vehicle",
    "auto",
    "automobile",
    "motorcycle",
    "bike",
    "bicycle",
    "ebike",
    "chair",
    "desk",
    "sofa",
    "couch",
    "table",
    "phone",
    "smartphone",
    "cellphone",
    "laptop",
    "computer",
    "notebook",
    "desktop",
    "monitor",
    "tv",
    "television",
    "camera",
    "watch",
    "headphones",
    "earbuds",
    "speaker",
    "appliance",
    "tool",
}

QUERY_SYNONYM_GROUPS: dict[str, list[str]] = {
    "combi": [
        "Kombi",
        "Combi",
        "Type 2",
        "Microbus",
        "Transporter",
        "Westfalia",
        "Vanagon",
        "Bus",
    ],
    "kombi": [
        "Kombi",
        "Combi",
        "Type 2",
        "Microbus",
        "Transporter",
        "Westfalia",
        "Vanagon",
        "Bus",
    ],
    "volkswagen": ["Volkswagen", "VW"],
    "vw": ["VW", "Volkswagen"],
    "chevrolet": ["Chevrolet", "Chevy"],
    "chevy": ["Chevy", "Chevrolet"],
    "mercedes": ["Mercedes", "Mercedes-Benz"],
}

_SEARCH_SYNONYM_REPLACEMENTS: dict[str, str] = {
    "combi": "Kombi",
}

VEHICLE_MAKES: dict[str, str] = {
    "toyota": "toyota",
    "honda": "honda",
    "ford": "ford",
    "chevrolet": "chevrolet",
    "chevy": "chevrolet",
    "gmc": "gmc",
    "ram": "ram",
    "jeep": "jeep",
    "subaru": "subaru",
    "mazda": "mazda",
    "nissan": "nissan",
    "hyundai": "hyundai",
    "kia": "kia",
    "volkswagen": "volkswagen",
    "vw": "volkswagen",
    "bmw": "bmw",
    "mercedes-benz": "mercedes-benz",
    "mercedes": "mercedes-benz",
    "audi": "audi",
    "lexus": "lexus",
    "acura": "acura",
    "porsche": "porsche",
    "tesla": "tesla",
    "rivian": "rivian",
    "lucid": "lucid",
    "volvo": "volvo",
    "dodge": "dodge",
    "chrysler": "chrysler",
    "cadillac": "cadillac",
    "buick": "buick",
    "lincoln": "lincoln",
    "infiniti": "infiniti",
    "genesis": "genesis",
    "mitsubishi": "mitsubishi",
    "mini": "mini",
    "land-rover": "land-rover",
    "jaguar": "jaguar",
}

_TWO_WORD_VEHICLE_MODELS = {
    ("grand", "cherokee"),
    ("grand", "wagoneer"),
    ("grand", "highlander"),
    ("land", "cruiser"),
    ("santa", "fe"),
    ("santa", "cruz"),
    ("bronco", "sport"),
    ("mustang", "mach-e"),
    ("model", "3"),
    ("model", "s"),
    ("model", "x"),
    ("model", "y"),
    ("civic", "type"),
    ("corolla", "cross"),
    ("crown", "signia"),
    ("range", "rover"),
}


def extract_core_query_tokens(query: str) -> list[str]:
    """Extract search tokens while stripping generic category suffixes unless nothing else remains."""
    raw_tokens = [tok for tok in re.findall(r"[A-Za-z0-9.+-]+", query) if len(tok) >= 2]
    filtered = [tok for tok in raw_tokens if tok.lower() not in GENERIC_CATEGORY_WORDS]
    return filtered if filtered else raw_tokens


def normalize_search_query(query: str) -> str:
    """Normalize a query for vendor search endpoints (strips generic suffixes & regional spelling)."""
    tokens = extract_core_query_tokens(query)
    if not tokens:
        return " ".join(query.strip().split())
    normalized = [_SEARCH_SYNONYM_REPLACEMENTS.get(tok.lower(), tok) for tok in tokens]
    return " ".join(normalized)


def expand_include_keyword_groups(query: str) -> list[list[str]]:
    """Convert a product query into AND-groups, expanding recognized synonyms into OR-alternatives."""
    groups: list[list[str]] = []
    for tok in extract_core_query_tokens(query):
        syns = QUERY_SYNONYM_GROUPS.get(tok.lower())
        groups.append(list(syns) if syns else [tok])
    return groups


def detect_vehicle_make_model(query: str) -> tuple[str, str] | None:
    """Detect (make_slug, model_slug) from a vehicle query like '2024 Toyota Tundra Pickup'."""
    tokens = [
        tok for tok in extract_core_query_tokens(query) if not re.fullmatch(r"(?:19|20)\d{2}", tok)
    ]
    lowered = [_SEARCH_SYNONYM_REPLACEMENTS.get(tok.lower(), tok).lower() for tok in tokens]
    for idx, tok in enumerate(lowered):
        make_slug: str | None = None
        model_start = idx + 1
        if idx + 1 < len(lowered) and (tok, lowered[idx + 1]) in (
            ("land", "rover"),
            ("mercedes", "benz"),
        ):
            make_slug = f"{tok}-{lowered[idx + 1]}"
            model_start = idx + 2
        elif tok in VEHICLE_MAKES:
            make_slug = VEHICLE_MAKES[tok]

        if not make_slug or model_start >= len(lowered):
            continue

        m1 = re.sub(r"[^a-z0-9-]+", "-", lowered[model_start]).strip("-")
        if not m1:
            continue
        if model_start + 1 < len(lowered):
            m2 = re.sub(r"[^a-z0-9-]+", "-", lowered[model_start + 1]).strip("-")
            if (m1, m2) in _TWO_WORD_VEHICLE_MODELS:
                return (make_slug, f"{m1}-{m2}")
        return (make_slug, m1)
    return None


class SourceTemplateConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    adapter: Literal["rss", "json_api", "html_css", "appleinsider"]
    url_template: str
    render_js: bool = False
    options: dict[str, Any] = Field(default_factory=dict)

    def render(self, query: str) -> SourceConfig:
        clean_query = normalize_search_query(query) or query.strip()
        encoded = quote_plus(clean_query)
        vehicle = detect_vehicle_make_model(clean_query)
        make_slug, model_slug = vehicle if vehicle else ("", "")
        return SourceConfig(
            name=self.name.format(
                query=clean_query,
                query_encoded=encoded,
                make=make_slug,
                model=model_slug,
            ),
            adapter=self.adapter,
            url=self.url_template.format(
                query=clean_query,
                query_encoded=encoded,
                make=make_slug,
                model=model_slug,
            ),
            enabled=True,
            render_js=self.render_js,
            options=dict(self.options),
        )


class SourcePackConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    label: str
    description: str = ""
    sources: list[SourceTemplateConfig] = Field(default_factory=list)


class NotificationsConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    waha: WahaConfig = Field(default_factory=WahaConfig)
    email: EmailConfig = Field(default_factory=EmailConfig)
    recipients: dict[str, RecipientConfig] = Field(default_factory=dict)


class SettingsConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    server: ServerConfig = Field(default_factory=ServerConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)
    source_packs: dict[str, SourcePackConfig] = Field(default_factory=dict)


class ExtractorConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    pattern: str = Field(max_length=256)
    type: Literal["int", "float", "str", "storage_gb"] = "int"
    min: float | None = None
    max: float | None = None
    required: bool = True

    @field_validator("pattern")
    @classmethod
    def _validate_regex(cls, value: str) -> str:
        if len(value) > 256:
            raise ValueError("Extractor regex pattern must be at most 256 characters")
        try:
            regex.compile(value, regex.IGNORECASE)
        except regex.error as exc:
            raise ValueError(f"Invalid extractor regex {value!r}: {exc}") from exc
        return value


class PriceRulesConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    min: float = 0.0
    max: float = 999999.0
    target: float | None = None
    msrp: float | None = None
    min_drop_delta: float = 20.0
    cooldown_hours: float = 24.0


class RulesConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    include_keyword_groups: list[list[str]] = Field(default_factory=list)
    exclude_keywords: list[str] = Field(default_factory=list)
    extractors: dict[str, ExtractorConfig] = Field(default_factory=dict)
    conditions_allowed: list[str] = Field(
        default_factory=lambda: ["new", "refurbished", "open-box", "used"]
    )
    require_in_stock: bool = True
    price: PriceRulesConfig = Field(default_factory=PriceRulesConfig)
    tier_by: list[str] = Field(default_factory=list)


class ScheduleConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    interval_minutes: int = 30
    jitter_seconds: int = 180
    start_at: datetime | None = None
    duration_days: int | None = 14
    stop_after: datetime | None = None

    def status_info(self, now: datetime | None = None) -> tuple[bool, float | None]:
        current = _ensure_aware(now or _utcnow())
        end_at: datetime | None = None
        if self.stop_after is not None:
            end_at = _ensure_aware(self.stop_after)
        elif self.duration_days is not None:
            if self.start_at is not None:
                end_at = _ensure_aware(self.start_at) + timedelta(days=self.duration_days)
            else:
                return (False, float(self.duration_days))

        if end_at is None:
            return (False, None)

        remaining_days = (end_at - current).total_seconds() / 86400.0
        is_expired = remaining_days <= 0.0
        return (is_expired, round(max(0.0, remaining_days), 1))


class AlertsConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    recipients: list[str] = Field(default_factory=list)
    delivery: Literal["waha_only", "email_only", "waha_with_email_fallback", "all"] = (
        "waha_with_email_fallback"
    )
    send_startup_summary: bool = True


class WatchConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str
    name: str
    enabled: bool = True
    query: str = ""
    schedule: ScheduleConfig = Field(default_factory=ScheduleConfig)
    rules: RulesConfig = Field(default_factory=RulesConfig)
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)
    sources: list[SourceConfig] = Field(default_factory=list)

    @field_validator("id")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        if not WATCH_ID_RE.match(value):
            raise ValueError(f"Invalid watch id {value!r}: must match {WATCH_ID_RE.pattern}")
        return value

    def effective_status(
        self, now: datetime | None = None
    ) -> Literal["active", "paused", "expired"]:
        is_expired, _ = self.schedule.status_info(now=now)
        if is_expired:
            return "expired"
        if not self.enabled:
            return "paused"
        return "active"


class ConfigStore:
    """Thread-safe / atomic YAML reader & writer for settings and watches."""

    def __init__(self, config_dir: Path | str | None = None) -> None:
        if config_dir is None:
            _load_env_file()
        if config_dir is not None:
            raw_dir: Path | str = config_dir
        else:
            env_dir = os.environ.get("PRICEWATCHER_CONFIG_DIR", "").strip()
            if env_dir == "/app/config" and not Path("/app/config").exists():
                raw_dir = "config"
            else:
                raw_dir = env_dir or "config"
        self.config_dir = Path(raw_dir)
        self.settings_path = self.config_dir / "settings.yaml"
        self.settings_example_path = self.config_dir / "settings.example.yaml"
        self.watches_dir = self.config_dir / "watches"
        self._cache_lock = threading.RLock()
        self._settings_cache: tuple[tuple[str, int, int], SettingsConfig] | None = None
        self._watches_cache: tuple[tuple[tuple[str, int, int], ...], list[WatchConfig]] | None = (
            None
        )
        self._watch_file_cache: dict[str, tuple[tuple[str, int, int], WatchConfig]] = {}

    @classmethod
    def sanitize_slug(cls, raw: str) -> str:
        text = raw.strip()
        if not text or ".." in text or "/" in text or "\\" in text or "\x00" in text:
            raise ValueError(f"Unsafe or empty watch id: {raw!r}")
        slug = re.sub(r"[^a-z0-9_-]+", "-", text.lower()).strip("-_")
        slug = re.sub(r"-{2,}", "-", slug)[:63].strip("-_")
        if not WATCH_ID_RE.match(slug):
            raise ValueError(f"Watch id {raw!r} could not be normalized into a valid identifier")
        return slug

    sanitize_watch_id = sanitize_slug

    def invalidate_cache(self) -> None:
        with self._cache_lock:
            self._settings_cache = None
            self._watches_cache = None
            self._watch_file_cache.clear()

    def _safe_watch_path(self, watch_id: str) -> Path:
        if not WATCH_ID_RE.match(watch_id):
            raise ValueError(f"Invalid watch id: {watch_id!r}")
        base = self.watches_dir.resolve()
        candidate = (base / f"{watch_id}.yaml").resolve()
        if candidate.parent != base:
            raise ValueError(f"Path traversal blocked for watch id: {watch_id!r}")
        return candidate

    def _settings_cache_key(self) -> tuple[str, int, int, Path | None]:
        try:
            st = self.settings_path.stat()
            return ("settings", st.st_mtime_ns, st.st_size, self.settings_path)
        except FileNotFoundError:
            pass
        try:
            st = self.settings_example_path.stat()
            return ("example", st.st_mtime_ns, st.st_size, self.settings_example_path)
        except FileNotFoundError:
            return ("default", 0, 0, None)

    def load_settings(self) -> SettingsConfig:
        with self._cache_lock:
            source_kind, mtime_ns, size, path = self._settings_cache_key()
            cache_key = (source_kind, mtime_ns, size)
            if self._settings_cache is not None and self._settings_cache[0] == cache_key:
                return self._settings_cache[1].model_copy(deep=True)

            if path is not None:
                if source_kind == "example":
                    logger.warning(
                        "settings.yaml not found at %s; falling back to %s",
                        self.settings_path,
                        self.settings_example_path,
                    )
                raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                settings = SettingsConfig.model_validate(raw)
            else:
                settings = SettingsConfig()

            self._settings_cache = (cache_key, settings)
            return settings.model_copy(deep=True)

    def load_watches(self) -> list[WatchConfig]:
        with self._cache_lock:
            if not self.watches_dir.exists():
                self._watches_cache = ((), [])
                return []

            entries: list[tuple[Path, os.stat_result]] = []
            for path in sorted(self.watches_dir.glob("*.y*ml")):
                if path.suffix.lower() not in (".yaml", ".yml"):
                    continue
                try:
                    st = path.stat()
                except FileNotFoundError:
                    continue
                entries.append((path, st))

            cache_key = tuple((path.name, st.st_mtime_ns, st.st_size) for path, st in entries)
            if self._watches_cache is not None and self._watches_cache[0] == cache_key:
                return [w.model_copy(deep=True) for w in self._watches_cache[1]]

            watches: list[WatchConfig] = []
            seen_ids: set[str] = set()
            for path, _ in entries:
                try:
                    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                except FileNotFoundError:
                    continue
                if not isinstance(raw, dict):
                    continue
                if "id" not in raw:
                    raw["id"] = self.sanitize_watch_id(path.stem)
                watch = WatchConfig.model_validate(raw)
                if watch.id not in seen_ids:
                    seen_ids.add(watch.id)
                    watches.append(watch)

            self._watches_cache = (cache_key, watches)
            return [w.model_copy(deep=True) for w in watches]

    def get_watch(self, watch_id: str) -> WatchConfig | None:
        target = self._safe_watch_path(watch_id)
        with self._cache_lock:
            path: Path | None = None
            st: os.stat_result | None = None
            for candidate in (target, target.with_suffix(".yml")):
                try:
                    st = candidate.stat()
                    path = candidate
                    break
                except FileNotFoundError:
                    continue
            if path is None or st is None:
                self._watch_file_cache.pop(watch_id, None)
                return None

            cache_key = (path.name, st.st_mtime_ns, st.st_size)
            cached = self._watch_file_cache.get(watch_id)
            if cached is not None and cached[0] == cache_key:
                return cached[1].model_copy(deep=True)

            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            watch = WatchConfig.model_validate(raw)
            self._watch_file_cache[watch_id] = (cache_key, watch)
            return watch.model_copy(deep=True)

    def _atomic_write_yaml(self, target: Path, payload: dict[str, Any], *, prefix: str) -> Path:
        target.parent.mkdir(parents=True, exist_ok=True)
        rendered = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)

        fd, tmp_name = tempfile.mkstemp(
            dir=str(target.parent),
            prefix=prefix,
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(rendered)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, target)
        except Exception:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
            raise
        return target

    def save_settings(self, settings: SettingsConfig) -> Path:
        payload = settings.model_dump(mode="json")
        with self._cache_lock:
            path = self._atomic_write_yaml(
                self.settings_path, payload, prefix=f".{self.settings_path.stem}-"
            )
            self._settings_cache = None
            return path

    def save_watch(self, watch: WatchConfig) -> Path:
        target = self._safe_watch_path(watch.id)
        payload = watch.model_dump(mode="json")
        with self._cache_lock:
            path = self._atomic_write_yaml(target, payload, prefix=f".{watch.id}-")
            self._watches_cache = None
            self._watch_file_cache.pop(watch.id, None)
            return path

    def delete_watch(self, watch_id: str) -> bool:
        target = self._safe_watch_path(watch_id)
        with self._cache_lock:
            deleted = False
            for candidate in (target, target.with_suffix(".yml")):
                if candidate.exists():
                    candidate.unlink()
                    deleted = True
            self._watches_cache = None
            self._watch_file_cache.pop(watch_id, None)
            return deleted
