"""Authentication, healthcheck, and favicon routes."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from pricewatcher.web.auth import (
    SESSION_COOKIE_NAME,
    AuthManager,
    safe_next_path,
)

auth_router = APIRouter()


@auth_router.get("/healthz")
async def healthz() -> JSONResponse:
    """Return lightweight service health without touching disk or DB."""
    return JSONResponse({"status": "ok"})


@auth_router.get("/login", response_model=None)
async def login_page(request: Request, next: str = "/") -> HTMLResponse | RedirectResponse:
    """Render the login page or redirect already-authenticated sessions."""
    import pricewatcher.web.router as router_mod

    auth: AuthManager = request.app.state.auth
    next_url = safe_next_path(next, default="/")
    if auth.mode == "insecure_no_auth" or getattr(request.state, "authenticated", False):
        return RedirectResponse(url=next_url, status_code=303)
    return router_mod.templates.TemplateResponse(
        request,
        "login.html",
        {"request": request, "hide_nav": True, "next_url": next_url, "error": None},
    )


@auth_router.post("/login", response_model=None)
async def login_submit(request: Request) -> HTMLResponse | JSONResponse | RedirectResponse:
    """Authenticate an admin password submission and issue session cookies."""
    import pricewatcher.web.router as router_mod

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
        if router_mod._prefers_json(request):
            return JSONResponse(
                {"ok": False, "error": "Too many failed login attempts. Try again later."},
                status_code=429,
                headers=headers,
            )
        return router_mod.templates.TemplateResponse(
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
        if router_mod._prefers_json(request):
            return JSONResponse({"ok": False, "error": "Invalid password."}, status_code=401)
        return router_mod.templates.TemplateResponse(
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


@auth_router.post("/logout", response_model=None)
async def logout_submit(request: Request) -> RedirectResponse:
    """Revoke the current session token and clear authentication cookies."""
    auth: AuthManager = request.app.state.auth
    auth.revoke_session_token(request.cookies.get(SESSION_COOKIE_NAME))
    response = RedirectResponse(url="/login", status_code=303)
    auth.clear_session_cookies(response, request)
    return response


@auth_router.get("/favicon.ico", include_in_schema=False)
async def favicon() -> Response:
    """Return an empty 204 response for browser favicon requests."""
    return Response(status_code=204)
