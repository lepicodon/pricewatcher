"""Server-rendered HTML page routes for the PriceWatcher Web UI."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from pricewatcher.config import ConfigStore, SettingsConfig, WatchConfig

pages_router = APIRouter()


def _build_manage_view(
    request: Request,
    store: ConfigStore,
    *,
    edit: str | None = None,
    new: bool = False,
    flash: str | None = None,
    flash_ok: bool = True,
) -> dict[str, Any]:
    """Assemble template context for the watch management view."""
    import pricewatcher.web.router as router_mod

    editing: WatchConfig | None = None
    is_edit = False
    resolved_flash = flash
    resolved_ok = flash_ok

    if edit and not new:
        try:
            clean_id = router_mod.ConfigStore.sanitize_slug(edit)
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

    return router_mod._manage_context(
        request,
        store,
        editing=editing,
        is_edit=is_edit,
        flash=resolved_flash,
        flash_ok=resolved_ok,
    )


def _load_packs_page_data(store: ConfigStore) -> tuple[SettingsConfig, list[str]]:
    """Load settings and built-in pack IDs off the event loop."""
    import pricewatcher.web.router as router_mod

    settings = store.load_settings()
    builtin_pack_ids = sorted(router_mod.load_builtin_source_packs().keys())
    return settings, builtin_pack_ids


@pages_router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    """Render the main watch summary dashboard."""
    import pricewatcher.web.router as router_mod

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
    return router_mod.templates.TemplateResponse(
        request,
        "dashboard.html",
        {"request": request, "active_page": "dashboard", "cards": cards},
    )


@pages_router.get("/watches/{watch_id}", response_class=HTMLResponse)
async def watch_detail(
    request: Request,
    watch_id: str,
    q: str = "",
    sort_by: str = "observed_at",
    sort_dir: str = "desc",
) -> HTMLResponse:
    """Render detailed tier states, observations, source health, and alerts for a watch."""
    import pricewatcher.web.router as router_mod

    store: ConfigStore = request.app.state.store
    db = request.app.state.db
    try:
        clean_id = router_mod.ConfigStore.sanitize_slug(watch_id)
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

    return router_mod.templates.TemplateResponse(
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


@pages_router.get("/manage", response_class=HTMLResponse)
async def manage_watches(
    request: Request,
    edit: str | None = None,
    new: bool = False,
    flash: str | None = None,
    flash_ok: bool = True,
) -> HTMLResponse:
    """Render the watch management editor and source discovery view."""
    import pricewatcher.web.router as router_mod

    store: ConfigStore = request.app.state.store
    ctx = await asyncio.to_thread(
        _build_manage_view,
        request,
        store,
        edit=edit,
        new=new,
        flash=flash,
        flash_ok=flash_ok,
    )
    return router_mod.templates.TemplateResponse(request, "manage.html", ctx)


@pages_router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request) -> HTMLResponse:
    """Render the notifications and recipient settings page."""
    import pricewatcher.web.router as router_mod

    store: ConfigStore = request.app.state.store
    settings = await asyncio.to_thread(store.load_settings)
    waha_health = await router_mod.WahaClient(settings.notifications.waha).check_health()
    waha_key_set = bool(settings.notifications.waha.effective_api_key())
    user, pwd = settings.notifications.email.effective_credentials()
    smtp_creds_set = bool(user and pwd)
    return router_mod.templates.TemplateResponse(
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


@pages_router.get("/packs", response_class=HTMLResponse)
async def packs_page(request: Request) -> HTMLResponse:
    """Render the source packs management and template tester page."""
    import pricewatcher.web.router as router_mod

    store: ConfigStore = request.app.state.store
    settings, builtin_pack_ids = await asyncio.to_thread(_load_packs_page_data, store)
    return router_mod.templates.TemplateResponse(
        request,
        "packs.html",
        {
            "request": request,
            "active_page": "packs",
            "settings": settings,
            "builtin_pack_ids": builtin_pack_ids,
        },
    )
