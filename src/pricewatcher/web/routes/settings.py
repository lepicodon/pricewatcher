"""Source-pack CRUD/testing, notification recipients, and test-alert API routes."""

from __future__ import annotations

import asyncio
from dataclasses import asdict
import inspect
import json

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from pricewatcher.config import (
    AlertsConfig,
    ConfigStore,
    RecipientConfig,
    SettingsConfig,
    SourcePackConfig,
    SourceTemplateConfig,
    WatchConfig,
    detect_vehicle_make_model,
    expand_include_keyword_groups,
)
from pricewatcher.http_client import SSRFBlockedError

settings_router = APIRouter()


@settings_router.get("/api/source-packs")
async def api_list_source_packs(request: Request) -> JSONResponse:
    """List configured source packs."""
    store: ConfigStore = request.app.state.store
    settings = await asyncio.to_thread(store.load_settings)
    return JSONResponse(
        {
            "source_packs": {
                pid: pack.model_dump(mode="json") for pid, pack in settings.source_packs.items()
            }
        }
    )


@settings_router.post("/api/source-packs/sync")
async def api_sync_source_packs(request: Request) -> JSONResponse:
    """Merge built-in source packs into settings.yaml."""
    import pricewatcher.web.router as router_mod

    store: ConfigStore = request.app.state.store
    packs_added, sources_added, settings = await asyncio.to_thread(
        router_mod.sync_builtin_source_packs, store
    )
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


@settings_router.post("/api/source-packs/render")
async def api_render_source_pack(request: Request) -> JSONResponse:
    """Render a source pack's URL templates for a given product query."""
    import pricewatcher.web.router as router_mod

    store: ConfigStore = request.app.state.store
    payload, err_resp = await router_mod._parse_json_object(request)
    if err_resp is not None or payload is None:
        return err_resp or JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    pack_id = str(payload.get("pack_id", "")).strip()
    query = str(payload.get("query", "")).strip() or "Mac Studio"
    settings = await asyncio.to_thread(store.load_settings)
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


@settings_router.post("/api/source-packs/test-source")
async def api_test_source_template(request: Request) -> JSONResponse:
    """Render and live-fetch a source template with a sample query for previewing."""
    import pricewatcher.web.router as router_mod

    payload, err_resp = await router_mod._parse_json_object(request, include_ok=True)
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
        await asyncio.to_thread(router_mod.validate_outbound_url, src.url)
    except SSRFBlockedError as exc:
        return JSONResponse({"ok": False, "error": f"Blocked outbound URL: {exc}"}, status_code=422)

    adapter = router_mod.get_adapter(src.adapter)
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


@settings_router.post("/api/source-packs/{pack_id}")
async def api_save_source_pack(request: Request, pack_id: str) -> JSONResponse:
    """Create or update a source pack in settings.yaml."""
    import pricewatcher.web.router as router_mod

    store: ConfigStore = request.app.state.store
    try:
        clean_id = router_mod.ConfigStore.sanitize_slug(pack_id)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=422)

    payload, err_resp = await router_mod._parse_json_object(request, include_ok=True)
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
        return JSONResponse(
            {"ok": False, "error": router_mod._format_validation_error(exc)}, status_code=422
        )

    def _save_pack(settings: SettingsConfig) -> None:
        settings.source_packs[clean_id] = pack

    await asyncio.to_thread(store.update_settings, _save_pack)
    return JSONResponse({"ok": True, "pack_id": clean_id, "pack": pack.model_dump(mode="json")})


@settings_router.delete("/api/source-packs/{pack_id}")
async def api_delete_source_pack(request: Request, pack_id: str) -> JSONResponse:
    """Delete a source pack from settings.yaml."""
    import pricewatcher.web.router as router_mod

    store: ConfigStore = request.app.state.store
    try:
        clean_id = router_mod.ConfigStore.sanitize_slug(pack_id)
    except ValueError:
        return JSONResponse({"ok": False, "error": "Invalid pack id"}, status_code=404)

    def _delete_pack(settings: SettingsConfig) -> None:
        if clean_id not in settings.source_packs:
            raise KeyError(clean_id)
        del settings.source_packs[clean_id]

    try:
        await asyncio.to_thread(store.update_settings, _delete_pack)
    except KeyError:
        return JSONResponse(
            {"ok": False, "error": f"Unknown source pack {clean_id!r}"}, status_code=404
        )

    return JSONResponse({"ok": True, "deleted": clean_id})


@settings_router.post("/api/recipients/{recipient_key}")
async def api_save_recipient(request: Request, recipient_key: str) -> JSONResponse:
    """Create or update a notification recipient in settings.yaml."""
    import pricewatcher.web.router as router_mod

    store: ConfigStore = request.app.state.store
    try:
        clean_key = router_mod.ConfigStore.sanitize_slug(recipient_key)
    except ValueError as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=422)

    payload, err_resp = await router_mod._parse_json_object(request, include_ok=True)
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
        return JSONResponse(
            {"ok": False, "error": router_mod._format_validation_error(exc)}, status_code=422
        )

    def _save_recipient(settings: SettingsConfig) -> None:
        settings.notifications.recipients[clean_key] = rec

    await asyncio.to_thread(store.update_settings, _save_recipient)
    return JSONResponse(
        {"ok": True, "recipient_key": clean_key, "recipient": rec.model_dump(mode="json")}
    )


@settings_router.delete("/api/recipients/{recipient_key}")
async def api_delete_recipient(request: Request, recipient_key: str) -> JSONResponse:
    """Delete a notification recipient from settings.yaml."""
    import pricewatcher.web.router as router_mod

    store: ConfigStore = request.app.state.store
    try:
        clean_key = router_mod.ConfigStore.sanitize_slug(recipient_key)
    except ValueError:
        return JSONResponse({"ok": False, "error": "Invalid user key"}, status_code=404)

    def _delete_recipient(settings: SettingsConfig) -> None:
        if clean_key not in settings.notifications.recipients:
            raise KeyError(clean_key)
        del settings.notifications.recipients[clean_key]

    try:
        await asyncio.to_thread(store.update_settings, _delete_recipient)
    except KeyError:
        return JSONResponse({"ok": False, "error": f"Unknown user {clean_key!r}"}, status_code=404)

    return JSONResponse({"ok": True, "deleted": clean_key})


@settings_router.post("/api/test-alert")
async def api_test_alert(request: Request) -> JSONResponse:
    """Send a test notification to a configured recipient."""
    import pricewatcher.web.router as router_mod

    store: ConfigStore = request.app.state.store
    db = request.app.state.db
    payload, err_resp = await router_mod._parse_json_object(
        request, include_ok=True, error_key="summary"
    )
    if err_resp is not None or payload is None:
        return err_resp or JSONResponse(
            {"ok": False, "summary": "Invalid JSON body"}, status_code=400
        )

    recipient_key = str(payload.get("recipient_key", "")).strip()
    settings = await asyncio.to_thread(store.load_settings)
    if recipient_key not in settings.notifications.recipients:
        return JSONResponse(
            {"ok": False, "summary": f"Unknown recipient {recipient_key!r}"},
            status_code=404,
        )

    dispatcher = router_mod.NotificationDispatcher(settings)
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
