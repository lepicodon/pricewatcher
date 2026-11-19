"""FastAPI HTML and JSON API router aggregator and shared route helpers for PriceWatcher."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError

from pricewatcher.adapters import get_adapter
from pricewatcher.config import (
    AlertsConfig,
    ConfigStore,
    RulesConfig,
    ScheduleConfig,
    WatchConfig,
    load_builtin_source_packs,
    sync_builtin_source_packs,
)
from pricewatcher.discovery import probe_url, search_vendors_for_query
from pricewatcher.http_client import validate_outbound_url
from pricewatcher.notifiers.base import NotificationDispatcher
from pricewatcher.notifiers.waha import WahaClient
from pricewatcher.web.auth import prefers_json, safe_url

logger = logging.getLogger("pricewatcher.web")

DEFAULT_EXCLUDE_KEYWORDS = [
    "Case",
    "Cover",
    "Screen Protector",
    "Protector",
    "Tempered Glass",
    "Skin",
    "Mount",
    "Stand",
    "Cable",
    "Strap",
    "Hot Wheels",
    "Diecast",
    "1:64",
    "Key Fob",
    "Floor Mat",
    "Seat Cover",
    "Bumper",
]

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"


def _template_context(request: Request) -> dict[str, Any]:
    return {
        "csrf_token": getattr(request.state, "csrf_token", ""),
        "is_authenticated": bool(getattr(request.state, "authenticated", False)),
    }


def _format_validation_error(exc: Exception) -> str:
    if isinstance(exc, ValidationError):
        errors = exc.errors()
        if errors:
            loc = ".".join(str(part) for part in errors[0].get("loc", ()))
            msg = str(errors[0].get("msg", "Invalid input"))
            return f"{loc}: {msg}" if loc else msg
        return "Validation error."
    return str(exc)


async def _parse_json_object(
    request: Request,
    *,
    include_ok: bool = False,
    error_key: str = "error",
) -> tuple[dict[str, Any] | None, JSONResponse | None]:
    def _err(message: str) -> JSONResponse:
        body: dict[str, Any] = {error_key: message}
        if include_ok:
            body["ok"] = False
        return JSONResponse(body, status_code=400)

    try:
        payload = await request.json()
    except ValueError:
        return None, _err("Invalid JSON body")
    if not isinstance(payload, dict):
        return None, _err("JSON body must be an object")
    return payload, None


templates = Jinja2Templates(directory=str(TEMPLATES_DIR), context_processors=[_template_context])
templates.env.filters["safe_url"] = safe_url
router = APIRouter()


def _prefers_json(request: Request) -> bool:
    return prefers_json(request)


def _wake_scheduler(request: Request) -> None:
    wakeup = getattr(request.app.state, "wakeup_event", None)
    if wakeup is not None:
        wakeup.set()


def _manage_redirect(
    *,
    edit: str | None = None,
    flash: str | None = None,
    flash_ok: bool = True,
) -> RedirectResponse:
    params: dict[str, str] = {}
    if edit:
        params["edit"] = edit
    if flash:
        params["flash"] = flash
        params["flash_ok"] = "true" if flash_ok else "false"
    qs = f"?{urlencode(params)}" if params else ""
    return RedirectResponse(url=f"/manage{qs}", status_code=303)


def _blank_watch(default_recipients: list[str]) -> WatchConfig:
    return WatchConfig.model_construct(
        id="",
        name="",
        enabled=True,
        query="",
        schedule=ScheduleConfig(),
        rules=RulesConfig(),
        alerts=AlertsConfig(recipients=default_recipients),
        sources=[],
    )


def _manage_context(
    request: Request,
    store: ConfigStore,
    *,
    editing: WatchConfig | None = None,
    is_edit: bool = False,
    flash: str | None = None,
    flash_ok: bool = True,
) -> dict[str, Any]:
    settings = store.load_settings()
    watches = store.load_watches()
    default_recipients = list(settings.notifications.recipients.keys())[:1]
    target = editing if editing is not None else _blank_watch(default_recipients)

    include_groups_text = "\n".join(
        ", ".join(group) for group in target.rules.include_keyword_groups
    )
    exclude_keywords_text = ", ".join(target.rules.exclude_keywords)
    extractors_json = (
        json.dumps(
            {k: v.model_dump(exclude_none=True) for k, v in target.rules.extractors.items()},
            indent=2,
        )
        if target.rules.extractors
        else ""
    )
    return {
        "request": request,
        "active_page": "manage",
        "settings": settings,
        "watches": watches,
        "editing": target,
        "is_edit": is_edit,
        "flash": flash,
        "flash_ok": flash_ok,
        "include_groups_text": include_groups_text,
        "exclude_keywords_text": exclude_keywords_text,
        "extractors_json": extractors_json,
    }


from pricewatcher.web.routes import (  # noqa: E402
    auth_router,
    pages_router,
    settings_router,
    watches_router,
)

router.include_router(auth_router)
router.include_router(pages_router)
router.include_router(watches_router)
router.include_router(settings_router)

__all__ = [
    "DEFAULT_EXCLUDE_KEYWORDS",
    "STATIC_DIR",
    "TEMPLATES_DIR",
    "ConfigStore",
    "NotificationDispatcher",
    "WahaClient",
    "auth_router",
    "get_adapter",
    "load_builtin_source_packs",
    "pages_router",
    "probe_url",
    "router",
    "search_vendors_for_query",
    "settings_router",
    "sync_builtin_source_packs",
    "templates",
    "validate_outbound_url",
    "watches_router",
]
