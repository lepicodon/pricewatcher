"""Watch CRUD, manual polling, URL probing, and vendor search API routes."""

from __future__ import annotations

import asyncio
from dataclasses import asdict
from datetime import UTC, datetime
import inspect
import json
import re
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import ValidationError

from pricewatcher.config import (
    WATCH_ID_RE,
    AlertsConfig,
    ConfigStore,
    PriceRulesConfig,
    RulesConfig,
    ScheduleConfig,
    SourceConfig,
    WatchConfig,
    expand_include_keyword_groups,
)
from pricewatcher.discovery import build_vendor_search_sources
from pricewatcher.http_client import SSRFBlockedError

watches_router = APIRouter()


class _DuplicateConflictError(Exception):
    """Raised when no unique duplicate watch identifier is available."""


def _derive_include_groups(query: str) -> list[list[str]]:
    return expand_include_keyword_groups(query)


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
    """Parse and validate a WatchConfig instance from a /manage form submission."""
    import pricewatcher.web.router as router_mod

    raw_id = str(form.get("id", "")).strip() or str(form.get("name", "")).strip()
    watch_id = router_mod.ConfigStore.sanitize_slug(raw_id)
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
        exclude_keywords = list(router_mod.DEFAULT_EXCLUDE_KEYWORDS)

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


def _build_form_error_context(
    request: Request,
    store: ConfigStore,
    *,
    raw_id: str,
    is_edit: bool,
    flash: str,
) -> dict[str, Any]:
    """Assemble template context when watch form validation fails."""
    import pricewatcher.web.router as router_mod

    existing = store.get_watch(raw_id) if raw_id and WATCH_ID_RE.match(raw_id) else None
    return router_mod._manage_context(
        request,
        store,
        editing=existing,
        is_edit=is_edit and existing is not None,
        flash=flash,
        flash_ok=False,
    )


@watches_router.get("/api/watches")
async def api_list_watches(request: Request) -> JSONResponse:
    """List all configured watches as JSON."""
    store: ConfigStore = request.app.state.store
    watches = await asyncio.to_thread(store.load_watches)
    return JSONResponse({"watches": [w.model_dump(mode="json") for w in watches]})


@watches_router.post("/api/watches", response_model=None)
async def api_save_watch(request: Request) -> JSONResponse | HTMLResponse | RedirectResponse:
    """Create or update a watch from a JSON API payload or HTML form submission."""
    import pricewatcher.web.router as router_mod

    store: ConfigStore = request.app.state.store
    if "application/json" in request.headers.get("content-type", ""):
        try:
            payload = await request.json()
            if isinstance(payload, dict) and payload.get("id"):
                payload["id"] = router_mod.ConfigStore.sanitize_slug(str(payload["id"]))
            watch = WatchConfig.model_validate(payload)
        except (ValueError, ValidationError) as exc:
            return JSONResponse(
                {"ok": False, "error": router_mod._format_validation_error(exc)}, status_code=422
            )
        await asyncio.to_thread(store.save_watch, watch)
        router_mod._wake_scheduler(request)
        return JSONResponse({"ok": True, "watch": watch.model_dump(mode="json")})

    form = await request.form()
    is_edit = str(form.get("is_edit", "false")).lower() == "true"
    try:
        watch = _parse_watch_from_form(form)
    except (ValueError, ValidationError, json.JSONDecodeError) as exc:
        raw_id = str(form.get("id", "")).strip()
        ctx = await asyncio.to_thread(
            _build_form_error_context,
            request,
            store,
            raw_id=raw_id,
            is_edit=is_edit,
            flash=f"Validation error: {router_mod._format_validation_error(exc)}",
        )
        return router_mod.templates.TemplateResponse(request, "manage.html", ctx, status_code=422)

    await asyncio.to_thread(store.save_watch, watch)
    router_mod._wake_scheduler(request)
    return router_mod._manage_redirect(
        edit=watch.id,
        flash=f"Saved config/watches/{watch.id}.yaml",
        flash_ok=True,
    )


@watches_router.post("/api/watches/{watch_id}/toggle", response_model=None)
async def api_toggle_watch(request: Request, watch_id: str) -> JSONResponse | RedirectResponse:
    """Toggle a watch's enabled flag."""
    import pricewatcher.web.router as router_mod

    store: ConfigStore = request.app.state.store
    try:
        clean_id = router_mod.ConfigStore.sanitize_slug(watch_id)
    except ValueError:
        return JSONResponse({"ok": False, "error": "Invalid watch id"}, status_code=404)

    def _toggle(watch: WatchConfig) -> WatchConfig:
        watch.enabled = not watch.enabled
        return watch

    watch = await asyncio.to_thread(store.update_watch, clean_id, _toggle)
    if watch is None:
        return JSONResponse({"ok": False, "error": "Watch not found"}, status_code=404)

    router_mod._wake_scheduler(request)
    if router_mod._prefers_json(request):
        return JSONResponse({"ok": True, "id": watch.id, "enabled": watch.enabled})
    state_lbl = "enabled" if watch.enabled else "paused"
    return router_mod._manage_redirect(flash=f"Watch {watch.id} {state_lbl}.", flash_ok=True)


@watches_router.post("/api/watches/{watch_id}/duplicate", response_model=None)
async def api_duplicate_watch(request: Request, watch_id: str) -> JSONResponse | RedirectResponse:
    """Duplicate an existing watch under a new paused copy identifier."""
    import pricewatcher.web.router as router_mod

    store: ConfigStore = request.app.state.store
    try:
        clean_id = router_mod.ConfigStore.sanitize_slug(watch_id)
    except ValueError:
        return JSONResponse({"ok": False, "error": "Invalid watch id"}, status_code=404)

    source_id = clean_id

    def _duplicate(watch: WatchConfig) -> WatchConfig:
        nonlocal source_id
        source_id = watch.id
        candidate_id = ""
        for suffix_idx in range(1, 100):
            suffix = "-copy" if suffix_idx == 1 else f"-copy-{suffix_idx}"
            base = watch.id[: 63 - len(suffix)].rstrip("-_")
            attempt = f"{base}{suffix}"
            if store.get_watch(attempt) is None:
                candidate_id = attempt
                break
        if not candidate_id:
            raise _DuplicateConflictError()
        return watch.model_copy(
            deep=True,
            update={
                "id": candidate_id,
                "name": f"{watch.name} (Copy)",
                "enabled": False,
            },
        )

    try:
        cloned = await asyncio.to_thread(store.update_watch, clean_id, _duplicate)
    except _DuplicateConflictError:
        return JSONResponse(
            {"ok": False, "error": "Could not allocate unique duplicate watch id"},
            status_code=409,
        )

    if cloned is None:
        return JSONResponse({"ok": False, "error": "Watch not found"}, status_code=404)

    router_mod._wake_scheduler(request)
    if router_mod._prefers_json(request):
        return JSONResponse({"ok": True, "watch": cloned.model_dump(mode="json")})
    return router_mod._manage_redirect(
        edit=cloned.id,
        flash=f"Duplicated {source_id} as {cloned.id} (paused).",
        flash_ok=True,
    )


@watches_router.delete("/api/watches/{watch_id}")
async def api_delete_watch(request: Request, watch_id: str) -> JSONResponse:
    """Delete a watch configuration by ID."""
    import pricewatcher.web.router as router_mod

    store: ConfigStore = request.app.state.store
    try:
        clean_id = router_mod.ConfigStore.sanitize_slug(watch_id)
    except ValueError:
        return JSONResponse({"ok": False, "error": "Invalid watch id"}, status_code=404)

    if not await asyncio.to_thread(store.delete_watch, clean_id):
        return JSONResponse({"ok": False, "error": "Watch not found"}, status_code=404)
    router_mod._wake_scheduler(request)
    return JSONResponse({"ok": True, "deleted": clean_id})


@watches_router.post("/api/watches/{watch_id}/delete", response_model=None)
async def form_delete_watch(request: Request, watch_id: str) -> JSONResponse | RedirectResponse:
    """Delete a watch via HTML form POST or JSON API fallback."""
    import pricewatcher.web.router as router_mod

    store: ConfigStore = request.app.state.store
    try:
        clean_id = router_mod.ConfigStore.sanitize_slug(watch_id)
    except ValueError:
        if router_mod._prefers_json(request):
            return JSONResponse({"ok": False, "error": "Invalid watch id"}, status_code=404)
        return router_mod._manage_redirect(flash="Invalid watch id.", flash_ok=False)

    deleted = await asyncio.to_thread(store.delete_watch, clean_id)
    router_mod._wake_scheduler(request)
    if router_mod._prefers_json(request):
        status = 200 if deleted else 404
        return JSONResponse({"ok": deleted, "deleted": clean_id}, status_code=status)
    if deleted:
        return router_mod._manage_redirect(flash=f"Deleted {clean_id}.yaml.", flash_ok=True)
    return router_mod._manage_redirect(flash=f"Watch {clean_id} not found.", flash_ok=False)


@watches_router.post("/api/watches/{watch_id}/run")
async def api_run_watch(request: Request, watch_id: str) -> JSONResponse:
    """Trigger an immediate forced poll for a single watch."""
    import pricewatcher.web.router as router_mod

    store: ConfigStore = request.app.state.store
    engine = request.app.state.engine
    try:
        clean_id = router_mod.ConfigStore.sanitize_slug(watch_id)
    except ValueError:
        return JSONResponse({"ok": False, "error": "Invalid watch id"}, status_code=404)

    watch = await asyncio.to_thread(store.get_watch, clean_id)
    if watch is None:
        return JSONResponse({"ok": False, "error": "Watch not found"}, status_code=404)

    report = await engine.poll_watch(watch, force=True)
    return JSONResponse({"ok": True, "report": asdict(report)})


@watches_router.post("/api/probe")
async def api_probe_source(request: Request) -> JSONResponse:
    """Probe a candidate source URL after outbound SSRF validation."""
    import pricewatcher.web.router as router_mod

    payload, err_resp = await router_mod._parse_json_object(request)
    if err_resp is not None or payload is None:
        return err_resp or JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    url = str(payload.get("url", "")).strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        return JSONResponse(
            {"error": "URL must start with http:// or https://"},
            status_code=400,
        )
    try:
        await asyncio.to_thread(router_mod.validate_outbound_url, url)
    except SSRFBlockedError as exc:
        return JSONResponse({"error": f"Blocked outbound URL: {exc}"}, status_code=422)

    probe_fn = router_mod.probe_url
    http_ctx = getattr(request.app.state, "http_ctx", None)
    if http_ctx is not None and "http_ctx" in inspect.signature(probe_fn).parameters:
        result = await probe_fn(url, http_ctx=http_ctx)
    else:
        result = await probe_fn(url)
    if result.format_detected == "ssrf_blocked":
        detail = result.notes[0] if result.notes else "Blocked outbound destination"
        return JSONResponse({"error": detail}, status_code=422)
    return JSONResponse(result.model_dump(mode="json"))


@watches_router.post("/api/vendors/search")
async def api_vendor_search(request: Request) -> JSONResponse:
    """Discover candidate vendor feed/search sources for a product query."""
    import pricewatcher.web.router as router_mod

    payload, err_resp = await router_mod._parse_json_object(request)
    if err_resp is not None or payload is None:
        return err_resp or JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    query = str(payload.get("query", "")).strip()
    if len(query) < 2:
        return JSONResponse(
            {"error": "Please enter an item name or search query (at least 2 characters)."},
            status_code=400,
        )
    search_fn = router_mod.search_vendors_for_query
    http_ctx = getattr(request.app.state, "http_ctx", None)
    if http_ctx is not None and "http_ctx" in inspect.signature(search_fn).parameters:
        result = await search_fn(query, http_ctx=http_ctx)
    else:
        result = await search_fn(query)
    return JSONResponse(result.model_dump(mode="json"))
