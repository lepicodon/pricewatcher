"""FastAPI HTML and JSON API routes for PriceWatcher."""

from __future__ import annotations

import asyncio
from dataclasses import asdict
from datetime import UTC, datetime
import inspect
import json
import logging
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlencode

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError

from pricewatcher.adapters import get_adapter
from pricewatcher.config import (
    WATCH_ID_RE,
    AlertsConfig,
    ConfigStore,
    PriceRulesConfig,
    RecipientConfig,
    RulesConfig,
    ScheduleConfig,
    SourceConfig,
    SourcePackConfig,
    SourceTemplateConfig,
    WatchConfig,
    detect_vehicle_make_model,
    expand_include_keyword_groups,
    load_builtin_source_packs,
    sync_builtin_source_packs,
)
from pricewatcher.discovery import (
    build_vendor_search_sources,
    probe_url,
    search_vendors_for_query,
)
from pricewatcher.http_client import SSRFBlockedError, validate_outbound_url
from pricewatcher.notifiers.base import NotificationDispatcher
from pricewatcher.notifiers.waha import WahaClient
from pricewatcher.web.auth import (
    AuthManager,
    prefers_json,
    safe_next_path,
    safe_url,
)

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


def _derive_include_groups(query: str) -> list[list[str]]:
    return expand_include_keyword_groups(query)


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


def _parse_float(raw: Any, default: float | None = None) -> float | None:
    text = str(raw or "").strip()
    if not text:
        return default
    return float(text)


def _parse_int(raw: Any, default: int | None = None) -> int | None:
    text = str(raw or "").strip()
    if not text:
        return default
    return int(text)


def _parse_watch_from_form(form: Any) -> WatchConfig:
    raw_id = str(form.get("id", "")).strip() or str(form.get("name", "")).strip()
    watch_id = ConfigStore.sanitize_slug(raw_id)
    name = str(form.get("name", "")).strip()
    if not name:
        raise ValueError("Watch name is required.")
    query = str(form.get("query", "")).strip() or name

    include_groups: list[list[str]] = []
    for line in str(form.get("include_groups_text", "")).splitlines():
        terms = [t.strip() for t in line.split(",") if t.strip()]
        if terms:
            include_groups.append(terms)
    if not include_groups:
        include_groups = _derive_include_groups(query)

    exclude_keywords = [
        t.strip()
        for t in re.split(r"[,\n]+", str(form.get("exclude_keywords_text", "")))
        if t.strip()
    ]
    if not exclude_keywords:
        exclude_keywords = list(DEFAULT_EXCLUDE_KEYWORDS)

    tier_by = [t.strip() for t in str(form.get("tier_by_text", "")).split(",") if t.strip()]

    raw_extractors = str(form.get("extractors_json", "")).strip()
    extractors: dict[str, Any] = {}
    if raw_extractors:
        parsed_extractors = json.loads(raw_extractors)
        if not isinstance(parsed_extractors, dict):
            raise ValueError("Spec Extractors JSON must be a JSON object mapping field names.")
        extractors = parsed_extractors

    duration_days = _parse_int(form.get("duration_days"), None)
    start_at_raw = str(form.get("start_at", "")).strip()
    start_at = datetime.fromisoformat(start_at_raw) if start_at_raw else None
    if duration_days is not None and start_at is None:
        start_at = datetime.now(UTC)

    schedule = ScheduleConfig(
        interval_minutes=_parse_int(form.get("interval_minutes"), 30) or 30,
        jitter_seconds=_parse_int(form.get("jitter_seconds"), 180) or 0,
        duration_days=duration_days,
        start_at=start_at,
    )

    conditions_allowed = [
        str(c).strip() for c in form.getlist("conditions_allowed") if str(c).strip()
    ]

    price_min = _parse_float(form.get("price_min"), 0.0) or 0.0
    price_max = _parse_float(form.get("price_max"), 999999.0) or 999999.0
    price_target = _parse_float(form.get("price_target"), None)
    if price_min == 0.0:
        if price_target is not None and price_target >= 100.0:
            price_min = round(price_target * 0.3, 2)
        elif 250.0 <= price_max < 999999.0:
            price_min = round(price_max * 0.25, 2)

    price_rules = PriceRulesConfig(
        min=price_min,
        max=price_max,
        target=price_target,
        msrp=_parse_float(form.get("price_msrp"), None),
        min_drop_delta=_parse_float(form.get("min_drop_delta"), 20.0) or 0.0,
        cooldown_hours=_parse_float(form.get("cooldown_hours"), 24.0) or 0.0,
    )

    rules = RulesConfig(
        include_keyword_groups=include_groups,
        exclude_keywords=exclude_keywords,
        extractors=extractors,
        conditions_allowed=conditions_allowed,
        require_in_stock=str(form.get("require_in_stock", "")).lower() == "true",
        price=price_rules,
        tier_by=tier_by,
    )

    delivery = str(form.get("delivery", "waha_with_email_fallback")).strip()
    alerts = AlertsConfig(
        recipients=[str(r).strip() for r in form.getlist("alert_recipients") if str(r).strip()],
        delivery=delivery,  # type: ignore[arg-type]
        send_startup_summary=str(form.get("send_startup_summary", "")).lower() == "true",
    )

    names = form.getlist("source_name")
    adapters = form.getlist("source_adapter")
    urls = form.getlist("source_url")
    options_list = form.getlist("source_options_json")
    render_js_list = form.getlist("source_render_js")

    sources: list[SourceConfig] = []
    for idx, raw_url in enumerate(urls):
        url_str = str(raw_url).strip()
        if not url_str:
            continue
        src_name = str(names[idx] if idx < len(names) else "").strip() or f"Source {idx + 1}"
        adapter = str(adapters[idx] if idx < len(adapters) else "rss").strip()
        opts_raw = str(options_list[idx] if idx < len(options_list) else "{}").strip()
        options = json.loads(opts_raw) if opts_raw else {}
        if not isinstance(options, dict):
            raise ValueError(f"Source {src_name!r} options must be a JSON object.")
        render_js = (
            str(render_js_list[idx] if idx < len(render_js_list) else "false").lower() == "true"
        )
        sources.append(
            SourceConfig(
                name=src_name,
                adapter=adapter,  # type: ignore[arg-type]
                url=url_str,
                enabled=True,
                render_js=render_js,
                options=options,
            )
        )

    if not sources:
        sources = build_vendor_search_sources(query, include_reddit_all=False)

    return WatchConfig(
        id=watch_id,
        name=name,
        enabled=str(form.get("enabled", "")).lower() == "true",
        query=query,
        schedule=schedule,
        rules=rules,
        alerts=alerts,
        sources=sources,
    )


@router.get("/healthz")
async def healthz(request: Request) -> JSONResponse:
    store: ConfigStore = request.app.state.store
    db = request.app.state.db
    watches = store.load_watches()
    db.get_alerts(limit=1)
    return JSONResponse({"status": "ok", "watches": len(watches), "db": "ok"})


@router.get("/login", response_model=None)
async def login_page(request: Request, next: str = "/") -> HTMLResponse | RedirectResponse:
    auth: AuthManager = request.app.state.auth
    next_url = safe_next_path(next, default="/")
    if auth.mode == "insecure_no_auth" or getattr(request.state, "authenticated", False):
        return RedirectResponse(url=next_url, status_code=303)
    return templates.TemplateResponse(
        request,
        "login.html",
        {"request": request, "hide_nav": True, "next_url": next_url, "error": None},
    )


@router.post("/login", response_model=None)
async def login_submit(request: Request) -> HTMLResponse | JSONResponse | RedirectResponse:
    auth: AuthManager = request.app.state.auth
    if auth.mode == "insecure_no_auth":
        return RedirectResponse(url="/", status_code=303)

    if "application/json" in request.headers.get("content-type", ""):
        try:
            payload = await request.json()
        except ValueError:
            return JSONResponse({"ok": False, "error": "Invalid JSON body"}, status_code=400)
        if not isinstance(payload, dict):
            return JSONResponse({"ok": False, "error": "Invalid JSON body"}, status_code=400)
        password = str(payload.get("password", ""))
        next_url = safe_next_path(str(payload.get("next", "/")), default="/")
    else:
        form = await request.form()
        password = str(form.get("password", ""))
        next_url = safe_next_path(str(form.get("next", "/")), default="/")

    client_ip = auth.client_ip(request)
    retry_after = auth.rate_limiter.check_blocked(client_ip)
    if retry_after is not None:
        headers = {"Retry-After": str(retry_after)}
        if _prefers_json(request):
            return JSONResponse(
                {"ok": False, "error": "Too many failed login attempts. Try again later."},
                status_code=429,
                headers=headers,
            )
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "request": request,
                "hide_nav": True,
                "next_url": next_url,
                "error": f"Too many failed login attempts. Try again in {retry_after} seconds.",
            },
            status_code=429,
            headers=headers,
        )

    if not auth.verify_admin_password(password):
        auth.rate_limiter.record_failure(client_ip)
        if _prefers_json(request):
            return JSONResponse({"ok": False, "error": "Invalid password."}, status_code=401)
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "request": request,
                "hide_nav": True,
                "next_url": next_url,
                "error": "Invalid password.",
            },
            status_code=401,
        )

    auth.rate_limiter.reset(client_ip)
    session_token, sid = auth.create_session_token()
    csrf_token = auth.create_csrf_token(sub=sid)
    response = RedirectResponse(url=next_url, status_code=303)
    auth.set_session_cookies(
        response,
        request,
        session_token=session_token,
        csrf_token=csrf_token,
    )
    return response


@router.post("/logout", response_model=None)
async def logout_submit(request: Request) -> RedirectResponse:
    auth: AuthManager = request.app.state.auth
    response = RedirectResponse(url="/login", status_code=303)
    auth.clear_session_cookies(response, request)
    return response


@router.get("/favicon.ico", include_in_schema=False)
async def favicon() -> Response:
    return Response(status_code=204)


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    store: ConfigStore = request.app.state.store
    db = request.app.state.db
    watches = await asyncio.to_thread(store.load_watches)
    summary = await asyncio.to_thread(db.get_dashboard_summary, [w.id for w in watches])
    watches_summary = summary.get("watches", {})
    cards: list[dict[str, Any]] = []
    for watch in watches:
        status = watch.effective_status()
        _, days_remaining = watch.schedule.status_info()
        watch_summary = watches_summary.get(watch.id, {})
        runtime = watch_summary.get("runtime")
        last_run_at = runtime["last_run_at"] if runtime else None
        msrp = watch.rules.price.msrp
        tiers: list[dict[str, Any]] = []
        for row in watch_summary.get("tier_states", []):
            tier = dict(row)
            best_price = tier.get("best_price")
            tier["savings_vs_msrp"] = (
                round(msrp - float(best_price), 2)
                if (msrp is not None and best_price is not None)
                else None
            )
            tiers.append(tier)
        cards.append(
            {
                "watch": watch,
                "status": status,
                "days_remaining": days_remaining,
                "last_run_at": last_run_at,
                "tiers": tiers,
            }
        )
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {"request": request, "active_page": "dashboard", "cards": cards},
    )


@router.get("/watches/{watch_id}", response_class=HTMLResponse)
async def watch_detail(
    request: Request,
    watch_id: str,
    q: str = "",
    sort_by: str = "observed_at",
    sort_dir: str = "desc",
) -> HTMLResponse:
    store: ConfigStore = request.app.state.store
    db = request.app.state.db
    try:
        clean_id = ConfigStore.sanitize_slug(watch_id)
    except ValueError:
        return HTMLResponse("Invalid watch id", status_code=404)

    watch = await asyncio.to_thread(store.get_watch, clean_id)
    if watch is None:
        return HTMLResponse("Watch not found", status_code=404)

    status = watch.effective_status()
    _, days_remaining = watch.schedule.status_info()

    def _load_detail_data() -> tuple[
        list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]
    ]:
        return (
            db.get_tier_states(watch.id),
            db.get_observations(
                watch.id,
                sort_by=sort_by,
                sort_dir=sort_dir,
                search_query=q.strip() or None,
            ),
            db.get_source_health(watch.id),
            db.get_alerts(watch_id=watch.id, limit=50),
        )

    tiers, observations, source_health, alerts = await asyncio.to_thread(_load_detail_data)

    return templates.TemplateResponse(
        request,
        "watch_detail.html",
        {
            "request": request,
            "active_page": "dashboard",
            "watch": watch,
            "status": status,
            "days_remaining": days_remaining,
            "tiers": tiers,
            "observations": observations,
            "source_health": source_health,
            "alerts": alerts,
            "q": q,
            "sort_by": sort_by,
            "sort_dir": sort_dir,
        },
    )


@router.get("/manage", response_class=HTMLResponse)
async def manage_watches(
    request: Request,
    edit: str | None = None,
    new: bool = False,
    flash: str | None = None,
    flash_ok: bool = True,
) -> HTMLResponse:
    store: ConfigStore = request.app.state.store
    editing: WatchConfig | None = None
    is_edit = False
    resolved_flash = flash
    resolved_ok = flash_ok

    if edit and not new:
        try:
            clean_id = ConfigStore.sanitize_slug(edit)
            found = store.get_watch(clean_id)
            if found is not None:
                editing = found
                is_edit = True
            else:
                resolved_flash = f"Watch {edit!r} was not found."
                resolved_ok = False
        except ValueError as exc:
            resolved_flash = str(exc)
            resolved_ok = False

    ctx = _manage_context(
        request,
        store,
        editing=editing,
        is_edit=is_edit,
        flash=resolved_flash,
        flash_ok=resolved_ok,
    )
    return templates.TemplateResponse(request, "manage.html", ctx)


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request) -> HTMLResponse:
    store: ConfigStore = request.app.state.store
    settings = store.load_settings()
    waha_health = await WahaClient(settings.notifications.waha).check_health()
    waha_key_set = bool(settings.notifications.waha.effective_api_key())
    user, pwd = settings.notifications.email.effective_credentials()
    smtp_creds_set = bool(user and pwd)
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "request": request,
            "active_page": "settings",
            "settings": settings,
            "waha_health": waha_health,
            "waha_key_set": waha_key_set,
            "smtp_creds_set": smtp_creds_set,
        },
    )


@router.get("/packs", response_class=HTMLResponse)
async def packs_page(request: Request) -> HTMLResponse:
    store: ConfigStore = request.app.state.store
    settings = store.load_settings()
    builtin_pack_ids = sorted(load_builtin_source_packs().keys())
    return templates.TemplateResponse(
        request,
        "packs.html",
        {
            "request": request,
            "active_page": "packs",
            "settings": settings,
            "builtin_pack_ids": builtin_pack_ids,
        },
    )


@router.get("/api/watches")
async def api_list_watches(request: Request) -> JSONResponse:
    store: ConfigStore = request.app.state.store
    watches = store.load_watches()
    return JSONResponse({"watches": [w.model_dump(mode="json") for w in watches]})


@router.post("/api/watches", response_model=None)
async def api_save_watch(request: Request) -> JSONResponse | HTMLResponse | RedirectResponse:
    store: ConfigStore = request.app.state.store
    if "application/json" in request.headers.get("content-type", ""):
        try:
            payload = await request.json()
            if isinstance(payload, dict) and payload.get("id"):
                payload["id"] = ConfigStore.sanitize_slug(str(payload["id"]))
            watch = WatchConfig.model_validate(payload)
        except (ValueError, ValidationError) as exc:
            return JSONResponse(
                {"ok": False, "error": _format_validation_error(exc)}, status_code=422
            )
        store.save_watch(watch)
        _wake_scheduler(request)
        return JSONResponse({"ok": True, "watch": watch.model_dump(mode="json")})

    form = await request.form()
    is_edit = str(form.get("is_edit", "false")).lower() == "true"
    try:
        watch = _parse_watch_from_form(form)
    except (ValueError, ValidationError, json.JSONDecodeError) as exc:
        raw_id = str(form.get("id", "")).strip()
        existing = store.get_watch(raw_id) if raw_id and WATCH_ID_RE.match(raw_id) else None
        ctx = _manage_context(
            request,
            store,
            editing=existing,
            is_edit=is_edit and existing is not None,
            flash=f"Validation error: {_format_validation_error(exc)}",
            flash_ok=False,
        )
        return templates.TemplateResponse(request, "manage.html", ctx, status_code=422)

    store.save_watch(watch)
    _wake_scheduler(request)
    return _manage_redirect(
        edit=watch.id,
        flash=f"Saved config/watches/{watch.id}.yaml",
        flash_ok=True,
    )


@router.post("/api/watches/{watch_id}/toggle", response_model=None)
async def api_toggle_watch(request: Request, watch_id: str) -> JSONResponse | RedirectResponse:
    store: ConfigStore = request.app.state.store
    try:
        clean_id = ConfigStore.sanitize_slug(watch_id)
    except ValueError:
        return JSONResponse({"ok": False, "error": "Invalid watch id"}, status_code=404)

    watch = store.get_watch(clean_id)
    if watch is None:
        return JSONResponse({"ok": False, "error": "Watch not found"}, status_code=404)

    watch.enabled = not watch.enabled
    store.save_watch(watch)
    _wake_scheduler(request)
    if _prefers_json(request):
        return JSONResponse({"ok": True, "id": watch.id, "enabled": watch.enabled})
    state_lbl = "enabled" if watch.enabled else "paused"
    return _manage_redirect(flash=f"Watch {watch.id} {state_lbl}.", flash_ok=True)


@router.post("/api/watches/{watch_id}/duplicate", response_model=None)
async def api_duplicate_watch(request: Request, watch_id: str) -> JSONResponse | RedirectResponse:
    store: ConfigStore = request.app.state.store
    try:
        clean_id = ConfigStore.sanitize_slug(watch_id)
    except ValueError:
        return JSONResponse({"ok": False, "error": "Invalid watch id"}, status_code=404)

    watch = store.get_watch(clean_id)
    if watch is None:
        return JSONResponse({"ok": False, "error": "Watch not found"}, status_code=404)

    candidate_id = ""
    for suffix_idx in range(1, 100):
        suffix = "-copy" if suffix_idx == 1 else f"-copy-{suffix_idx}"
        base = watch.id[: 63 - len(suffix)].rstrip("-_")
        attempt = f"{base}{suffix}"
        if store.get_watch(attempt) is None:
            candidate_id = attempt
            break
    if not candidate_id:
        return JSONResponse(
            {"ok": False, "error": "Could not allocate unique duplicate watch id"},
            status_code=409,
        )

    cloned = watch.model_copy(
        deep=True,
        update={
            "id": candidate_id,
            "name": f"{watch.name} (Copy)",
            "enabled": False,
        },
    )
    store.save_watch(cloned)
    _wake_scheduler(request)
    if _prefers_json(request):
        return JSONResponse({"ok": True, "watch": cloned.model_dump(mode="json")})
    return _manage_redirect(
        edit=cloned.id,
        flash=f"Duplicated {watch.id} as {cloned.id} (paused).",
        flash_ok=True,
    )


@router.delete("/api/watches/{watch_id}")
async def api_delete_watch(request: Request, watch_id: str) -> JSONResponse:
    store: ConfigStore = request.app.state.store
    try:
        clean_id = ConfigStore.sanitize_slug(watch_id)
    except ValueError:
        return JSONResponse({"ok": False, "error": "Invalid watch id"}, status_code=404)

    if not store.delete_watch(clean_id):
        return JSONResponse({"ok": False, "error": "Watch not found"}, status_code=404)
    _wake_scheduler(request)
    return JSONResponse({"ok": True, "deleted": clean_id})


@router.post("/api/watches/{watch_id}/delete", response_model=None)
async def form_delete_watch(request: Request, watch_id: str) -> JSONResponse | RedirectResponse:
    store: ConfigStore = request.app.state.store
    try:
        clean_id = ConfigStore.sanitize_slug(watch_id)
    except ValueError:
        if _prefers_json(request):
            return JSONResponse({"ok": False, "error": "Invalid watch id"}, status_code=404)
        return _manage_redirect(flash="Invalid watch id.", flash_ok=False)

    deleted = store.delete_watch(clean_id)
    _wake_scheduler(request)
    if _prefers_json(request):
        status = 200 if deleted else 404
        return JSONResponse({"ok": deleted, "deleted": clean_id}, status_code=status)
    if deleted:
        return _manage_redirect(flash=f"Deleted {clean_id}.yaml.", flash_ok=True)
    return _manage_redirect(flash=f"Watch {clean_id} not found.", flash_ok=False)


@router.post("/api/watches/{watch_id}/run")
async def api_run_watch(request: Request, watch_id: str) -> JSONResponse:
    store: ConfigStore = request.app.state.store
    engine = request.app.state.engine
    try:
        clean_id = ConfigStore.sanitize_slug(watch_id)
    except ValueError:
        return JSONResponse({"ok": False, "error": "Invalid watch id"}, status_code=404)

    watch = store.get_watch(clean_id)
    if watch is None:
        return JSONResponse({"ok": False, "error": "Watch not found"}, status_code=404)

    report = await engine.poll_watch(watch, force=True)
    return JSONResponse({"ok": True, "report": asdict(report)})


@router.post("/api/probe")
async def api_probe_source(request: Request) -> JSONResponse:
    payload, err_resp = await _parse_json_object(request)
    if err_resp is not None or payload is None:
        return err_resp or JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    url = str(payload.get("url", "")).strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        return JSONResponse(
            {"error": "URL must start with http:// or https://"},
            status_code=400,
        )
    try:
        await asyncio.to_thread(validate_outbound_url, url)
    except SSRFBlockedError as exc:
        return JSONResponse({"error": f"Blocked outbound URL: {exc}"}, status_code=422)

    http_ctx = getattr(request.app.state, "http_ctx", None)
    if http_ctx is not None and "http_ctx" in inspect.signature(probe_url).parameters:
        result = await probe_url(url, http_ctx=http_ctx)
    else:
        result = await probe_url(url)
    if result.format_detected == "ssrf_blocked":
        detail = result.notes[0] if result.notes else "Blocked outbound destination"
        return JSONResponse({"error": detail}, status_code=422)
    return JSONResponse(result.model_dump(mode="json"))


@router.post("/api/vendors/search")
async def api_vendor_search(request: Request) -> JSONResponse:
    payload, err_resp = await _parse_json_object(request)
    if err_resp is not None or payload is None:
        return err_resp or JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    query = str(payload.get("query", "")).strip()
    if len(query) < 2:
        return JSONResponse(
            {"error": "Please enter an item name or search query (at least 2 characters)."},
            status_code=400,
        )
    http_ctx = getattr(request.app.state, "http_ctx", None)
    if (
        http_ctx is not None
        and "http_ctx" in inspect.signature(search_vendors_for_query).parameters
    ):
        result = await search_vendors_for_query(query, http_ctx=http_ctx)
    else:
        result = await search_vendors_for_query(query)
    return JSONResponse(result.model_dump(mode="json"))


@router.get("/api/source-packs")
async def api_list_source_packs(request: Request) -> JSONResponse:
    store: ConfigStore = request.app.state.store
    settings = store.load_settings()
    return JSONResponse(
        {
            "source_packs": {
                pid: pack.model_dump(mode="json") for pid, pack in settings.source_packs.items()
            }
        }
    )


@router.post("/api/source-packs/sync")
async def api_sync_source_packs(request: Request) -> JSONResponse:
    store: ConfigStore = request.app.state.store
    packs_added, sources_added, settings = sync_builtin_source_packs(store)
    return JSONResponse(
        {
            "ok": True,
            "packs_added": packs_added,
            "sources_added": sources_added,
            "source_packs": {
                pid: pack.model_dump(mode="json") for pid, pack in settings.source_packs.items()
            },
        }
    )


@router.post("/api/source-packs/render")
async def api_render_source_pack(request: Request) -> JSONResponse:
    store: ConfigStore = request.app.state.store
    payload, err_resp = await _parse_json_object(request)
    if err_resp is not None or payload is None:
        return err_resp or JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    pack_id = str(payload.get("pack_id", "")).strip()
    query = str(payload.get("query", "")).strip() or "Mac Studio"
    settings = store.load_settings()
    pack = settings.source_packs.get(pack_id)
    if pack is None:
        return JSONResponse({"error": f"Unknown source pack {pack_id!r}"}, status_code=404)

    has_vehicle = detect_vehicle_make_model(query) is not None
    rendered = [
        tmpl.render(query).model_dump(mode="json")
        for tmpl in pack.sources
        if has_vehicle or ("{make}" not in tmpl.url_template and "{model}" not in tmpl.url_template)
    ]
    return JSONResponse({"pack_id": pack_id, "query": query, "sources": rendered})


@router.post("/api/source-packs/test-source")
async def api_test_source_template(request: Request) -> JSONResponse:
    payload, err_resp = await _parse_json_object(request, include_ok=True)
    if err_resp is not None or payload is None:
        return err_resp or JSONResponse(
            {"ok": False, "error": "Invalid JSON body"}, status_code=400
        )

    url_template = str(payload.get("url_template", "")).strip()
    if not (url_template.startswith("http://") or url_template.startswith("https://")):
        return JSONResponse(
            {"ok": False, "error": "URL template must start with http:// or https://"},
            status_code=400,
        )

    needs_make_model = "{make}" in url_template or "{model}" in url_template
    test_query = str(payload.get("query", "")).strip() or (
        "Toyota Tundra" if needs_make_model else "Mac Studio"
    )
    if needs_make_model and detect_vehicle_make_model(test_query) is None:
        return JSONResponse(
            {
                "ok": False,
                "error": "Enter a vehicle Make + Model sample query (e.g. Toyota Tundra) to test {make}/{model} templates.",
            },
            status_code=400,
        )

    raw_opts = payload.get("options") or {}
    if isinstance(raw_opts, str):
        try:
            raw_opts = json.loads(raw_opts) if raw_opts.strip() else {}
        except ValueError as exc:
            return JSONResponse(
                {"ok": False, "error": f"Invalid options JSON: {exc}"}, status_code=400
            )
    if not isinstance(raw_opts, dict):
        return JSONResponse(
            {"ok": False, "error": "Options must be a JSON object."}, status_code=400
        )

    try:
        tmpl = SourceTemplateConfig(
            name=str(payload.get("name", "Test Source")).strip() or "Test Source",
            adapter=str(payload.get("adapter", "rss")).strip(),  # type: ignore[arg-type]
            url_template=url_template,
            render_js=bool(payload.get("render_js", False)),
            options=raw_opts,
        )
        src = tmpl.render(test_query)
    except ValidationError as exc:
        return JSONResponse({"ok": False, "error": exc.errors()[0]["msg"]}, status_code=422)
    except KeyError, IndexError, ValueError:
        return JSONResponse(
            {"ok": False, "error": "Invalid placeholder in URL template."}, status_code=422
        )

    try:
        await asyncio.to_thread(validate_outbound_url, src.url)
    except SSRFBlockedError as exc:
        return JSONResponse({"ok": False, "error": f"Blocked outbound URL: {exc}"}, status_code=422)

    adapter = get_adapter(src.adapter)
    http_ctx = getattr(request.app.state, "http_ctx", None)
    if http_ctx is not None and "http_ctx" in inspect.signature(adapter.fetch).parameters:
        outcome = await adapter.fetch(src, http_ctx=http_ctx)
    else:
        outcome = await adapter.fetch(src)
    groups = expand_include_keyword_groups(test_query)
    min_hits = len(groups) if len(groups) <= 2 else max(2, (len(groups) + 1) // 2)

    matched = [
        item
        for item in outcome.listings
        if not groups
        or sum(1 for g in groups if any(alt.lower() in item.title.lower() for alt in g)) >= min_hits
    ]
    preview_pool = matched if matched else outcome.listings
    preview = [
        {
            "title": item.title,
            "price": item.price,
            "merchant": item.merchant,
            "condition": item.condition,
            "url": item.url,
        }
        for item in preview_pool[:5]
    ]

    return JSONResponse(
        {
            "ok": outcome.error is None,
            "query": test_query,
            "rendered_url": src.url,
            "http_status": outcome.http_status,
            "latency_ms": outcome.latency_ms,
            "item_count": len(outcome.listings),
            "matching_count": len(matched),
            "preview_items": preview,
            "error": outcome.error,
        }
    )


@router.post("/api/source-packs/{pack_id}")
async def api_save_source_pack(request: Request, pack_id: str) -> JSONResponse:
    store: ConfigStore = request.app.state.store
    try:
        clean_id = ConfigStore.sanitize_slug(pack_id)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=422)

    payload, err_resp = await _parse_json_object(request, include_ok=True)
    if err_resp is not None or payload is None:
        return err_resp or JSONResponse(
            {"ok": False, "error": "Invalid JSON body"}, status_code=400
        )

    try:
        raw_sources = payload.get("sources") or []
        if not isinstance(raw_sources, list):
            return JSONResponse(
                {"ok": False, "error": "sources must be a JSON array"}, status_code=422
            )
        templates_list: list[SourceTemplateConfig] = []
        for idx, item in enumerate(raw_sources):
            if not isinstance(item, dict):
                return JSONResponse(
                    {"ok": False, "error": "Each source entry must be a JSON object"},
                    status_code=422,
                )
            opts = item.get("options") or {}
            if isinstance(opts, str):
                opts = json.loads(opts) if opts.strip() else {}
            url_tpl = str(item.get("url_template", "")).strip()
            if not url_tpl:
                continue
            templates_list.append(
                SourceTemplateConfig(
                    name=str(item.get("name", "")).strip() or f"Source {idx + 1}",
                    adapter=str(item.get("adapter", "rss")).strip(),  # type: ignore[arg-type]
                    url_template=url_tpl,
                    render_js=bool(item.get("render_js", False)),
                    options=opts if isinstance(opts, dict) else {},
                )
            )
        label = str(payload.get("label", "")).strip() or clean_id
        desc = str(payload.get("description", "")).strip()
        pack = SourcePackConfig(label=label, description=desc, sources=templates_list)
    except (ValidationError, ValueError, TypeError) as exc:
        return JSONResponse({"ok": False, "error": _format_validation_error(exc)}, status_code=422)

    settings = store.load_settings()
    settings.source_packs[clean_id] = pack
    store.save_settings(settings)
    return JSONResponse({"ok": True, "pack_id": clean_id, "pack": pack.model_dump(mode="json")})


@router.delete("/api/source-packs/{pack_id}")
async def api_delete_source_pack(request: Request, pack_id: str) -> JSONResponse:
    store: ConfigStore = request.app.state.store
    try:
        clean_id = ConfigStore.sanitize_slug(pack_id)
    except ValueError:
        return JSONResponse({"ok": False, "error": "Invalid pack id"}, status_code=404)

    settings = store.load_settings()
    if clean_id not in settings.source_packs:
        return JSONResponse(
            {"ok": False, "error": f"Unknown source pack {clean_id!r}"}, status_code=404
        )

    del settings.source_packs[clean_id]
    store.save_settings(settings)
    return JSONResponse({"ok": True, "deleted": clean_id})


@router.post("/api/recipients/{recipient_key}")
async def api_save_recipient(request: Request, recipient_key: str) -> JSONResponse:
    store: ConfigStore = request.app.state.store
    try:
        clean_key = ConfigStore.sanitize_slug(recipient_key)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=422)

    payload, err_resp = await _parse_json_object(request, include_ok=True)
    if err_resp is not None or payload is None:
        return err_resp or JSONResponse(
            {"ok": False, "error": "Invalid JSON body"}, status_code=400
        )

    name = str(payload.get("name", "")).strip() or clean_key
    waha_chat_id = str(payload.get("waha_chat_id") or "").strip() or None
    email = str(payload.get("email") or "").strip() or None

    try:
        rec = RecipientConfig(name=name, waha_chat_id=waha_chat_id, email=email)
    except (ValidationError, ValueError) as exc:
        return JSONResponse({"ok": False, "error": _format_validation_error(exc)}, status_code=422)

    settings = store.load_settings()
    settings.notifications.recipients[clean_key] = rec
    store.save_settings(settings)
    return JSONResponse(
        {"ok": True, "recipient_key": clean_key, "recipient": rec.model_dump(mode="json")}
    )


@router.delete("/api/recipients/{recipient_key}")
async def api_delete_recipient(request: Request, recipient_key: str) -> JSONResponse:
    store: ConfigStore = request.app.state.store
    try:
        clean_key = ConfigStore.sanitize_slug(recipient_key)
    except ValueError:
        return JSONResponse({"ok": False, "error": "Invalid user key"}, status_code=404)

    settings = store.load_settings()
    if clean_key not in settings.notifications.recipients:
        return JSONResponse({"ok": False, "error": f"Unknown user {clean_key!r}"}, status_code=404)

    del settings.notifications.recipients[clean_key]
    store.save_settings(settings)
    return JSONResponse({"ok": True, "deleted": clean_key})


@router.post("/api/test-alert")
async def api_test_alert(request: Request) -> JSONResponse:
    store: ConfigStore = request.app.state.store
    db = request.app.state.db
    payload, err_resp = await _parse_json_object(request, include_ok=True, error_key="summary")
    if err_resp is not None or payload is None:
        return err_resp or JSONResponse(
            {"ok": False, "summary": "Invalid JSON body"}, status_code=400
        )

    recipient_key = str(payload.get("recipient_key", "")).strip()
    settings = store.load_settings()
    if recipient_key not in settings.notifications.recipients:
        return JSONResponse(
            {"ok": False, "summary": f"Unknown recipient {recipient_key!r}"},
            status_code=404,
        )

    dispatcher = NotificationDispatcher(settings)
    test_watch = WatchConfig(
        id="test-alert",
        name="PriceWatcher Test Alert",
        alerts=AlertsConfig(
            recipients=[recipient_key],
            delivery="waha_with_email_fallback",
            send_startup_summary=False,
        ),
    )
    results = await dispatcher.dispatch(
        watch=test_watch,
        tier_key="test",
        alert_type="test_alert",
        subject="[PriceWatcher] Test Notification",
        message="[PriceWatcher] Test alert — WAHA/Email delivery verification.",
        db=db,
    )
    delivered = [r for r in results if r.ok]
    if delivered:
        channels = ", ".join(r.channel for r in delivered)
        summary = f"Sent via {channels}"
    else:
        errors = "; ".join(f"{r.channel}: {r.error}" for r in results)
        summary = f"Failed ({errors})"

    return JSONResponse(
        {
            "ok": bool(delivered),
            "summary": summary,
            "results": [asdict(r) for r in results],
        }
    )
