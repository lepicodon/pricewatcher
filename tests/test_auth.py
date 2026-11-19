"""Tests for authentication, CSRF protection, XSS hardening, CSP, and S5/S8 controls."""

from __future__ import annotations

import base64
from http.cookies import SimpleCookie
import io
import logging
from pathlib import Path
import re
import shutil
from typing import Any

from fastapi.testclient import TestClient
import pytest

from pricewatcher.config import ConfigStore
from pricewatcher.main import cli, create_app
from pricewatcher.storage import Database
from pricewatcher.web import auth, router


def _extract_meta_csrf(html: str) -> str:
    match = re.search(r'<meta\s+name="csrf-token"\s+content="([^"]+)"', html)
    assert match is not None, "Missing <meta name='csrf-token'> in HTML"
    return match.group(1)


def _init_cfg_dir(base_dir: Path) -> Path:
    repo_cfg = Path(__file__).resolve().parent.parent / "config"
    cfg_dir = base_dir / "config"
    (cfg_dir / "watches").mkdir(parents=True, exist_ok=True)
    shutil.copy2(repo_cfg / "settings.example.yaml", cfg_dir / "settings.yaml")
    shutil.copy2(
        repo_cfg / "watches" / "example-watch.yaml.example",
        cfg_dir / "watches" / "example-watch.yaml",
    )
    return cfg_dir


def _make_auth_app(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    password: str | None = None,
    session_secret: str | None = None,
) -> tuple[Any, ConfigStore, Database]:
    pw_val = password if password is not None else "correct-horse-battery"
    secret_val = (
        session_secret if session_secret is not None else "test-session-secret-0123456789abcdef"
    )
    monkeypatch.setenv("PRICEWATCHER_ADMIN_PASSWORD_HASH", auth.hash_password(pw_val))
    monkeypatch.setenv("PRICEWATCHER_SESSION_SECRET", secret_val)
    monkeypatch.delenv("PRICEWATCHER_INSECURE_NO_AUTH", raising=False)
    monkeypatch.delenv("PRICEWATCHER_COOKIE_SECURE", raising=False)

    cfg_dir = _init_cfg_dir(tmp_path)
    store = ConfigStore(cfg_dir)
    db = Database(tmp_path / "prices.db")
    app = create_app(store=store, db=db, start_scheduler=False)
    return app, store, db


def _login_client(
    client: TestClient,
    password: str | None = None,
    *,
    next_path: str | None = None,
) -> tuple[str, Any]:
    pw_val = password if password is not None else "correct-horse-battery"
    url = "/login" if next_path is None else f"/login?next={next_path}"
    login_page = client.get(url)
    assert login_page.status_code == 200
    login_csrf = _extract_meta_csrf(login_page.text)
    data = {"password": pw_val, "csrf_token": login_csrf}
    if next_path is not None:
        data["next"] = next_path
    res = client.post("/login", data=data, follow_redirects=False)
    return res.headers.get("location", ""), res


def test_scrypt_hash_and_verify() -> None:
    hashed = auth.hash_password("s3cr3t-password!")
    assert "$" not in hashed
    parts = hashed.split(":")
    assert len(parts) == 6
    assert parts[0] == "scrypt"
    assert parts[1:4] == ["16384", "8", "1"]
    assert len(base64.urlsafe_b64decode(parts[4] + "==")) == 16
    assert len(base64.urlsafe_b64decode(parts[5] + "==")) == 32

    assert auth.verify_password("s3cr3t-password!", hashed) is True
    assert auth.verify_password("s3cr3t-password!", hashed.replace(":", "$")) is True
    assert auth.verify_password("s3cr3t-password!", hashed.replace(":", "$$")) is True
    assert auth.verify_password("wrong-password", hashed) is False
    assert auth.hash_password("same") != auth.hash_password("same")

    with pytest.raises(ValueError):
        auth.hash_password("")


@pytest.mark.parametrize(
    "bad_hash",
    [
        "",
        "plain-text",
        "bcrypt$12$abc$def",
        "scrypt:16384:8:1:onlyfive",
        "scrypt$16384$8$1$onlyfive",
        "scrypt:notint:8:1:AAAA:BBBB",
        "scrypt:16385:8:1:AAAA:BBBB",
        "scrypt:0:8:1:AAAA:BBBB",
        "scrypt:1073741824:8:1:AAAA:BBBB",
        "scrypt:16384:8:1:!!!:!!!",
        "scrypt:16384:8:1:AA:BB",
    ],
)
def test_verify_password_rejects_malformed_hashes_safely(bad_hash: str) -> None:
    assert auth.verify_password("anything", bad_hash) is False


def test_cli_hash_password_stdin_and_tty(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake_stdin = io.StringIO("cli-pass-123\n")
    monkeypatch.setattr(fake_stdin, "isatty", lambda: False)
    monkeypatch.setattr("sys.stdin", fake_stdin)

    rc = cli(["hash-password"])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert out.startswith("scrypt:16384:8:1:")
    assert auth.verify_password("cli-pass-123", out) is True

    empty_stdin = io.StringIO("\n")
    monkeypatch.setattr(empty_stdin, "isatty", lambda: False)
    monkeypatch.setattr("sys.stdin", empty_stdin)
    assert cli(["--hash-password"]) == 1

    tty_stdin = io.StringIO("")
    monkeypatch.setattr(tty_stdin, "isatty", lambda: True)
    monkeypatch.setattr("sys.stdin", tty_stdin)

    prompts = iter(["tty-secret", "tty-secret"])
    monkeypatch.setattr("getpass.getpass", lambda _prompt: next(prompts))
    assert cli(["hash-password"]) == 0
    tty_out = capsys.readouterr().out.strip()
    assert auth.verify_password("tty-secret", tty_out) is True

    mismatch_prompts = iter(["one", "two"])
    monkeypatch.setattr("getpass.getpass", lambda _prompt: next(mismatch_prompts))
    assert cli(["hash-password"]) == 1


def test_cli_default_host_is_loopback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    recorded: dict[str, Any] = {}

    def fake_run(app_obj: Any, **kwargs: Any) -> None:
        recorded["app"] = app_obj
        recorded["host"] = kwargs["host"]
        recorded["port"] = kwargs["port"]

    cfg_dir = _init_cfg_dir(tmp_path)
    monkeypatch.setattr("uvicorn.run", fake_run)
    monkeypatch.setenv("PRICEWATCHER_CONFIG_DIR", str(cfg_dir))
    monkeypatch.setenv("PRICEWATCHER_DB_PATH", str(tmp_path / "prices.db"))
    rc = cli([])
    try:
        assert rc == 0
        assert recorded["host"] == "127.0.0.1"
        assert recorded["port"] == 8080
    finally:
        if "app" in recorded:
            recorded["app"].state.db.close()


def test_fail_closed_setup_mode_503(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PRICEWATCHER_ADMIN_PASSWORD_HASH", raising=False)
    monkeypatch.delenv("PRICEWATCHER_INSECURE_NO_AUTH", raising=False)
    monkeypatch.setenv("PRICEWATCHER_SESSION_SECRET", "setup-secret")

    store = ConfigStore(_init_cfg_dir(tmp_path))
    db = Database(tmp_path / "prices.db")
    app = create_app(store=store, db=db, start_scheduler=False)

    try:
        with TestClient(app) as client:
            health = client.get("/healthz")
            assert health.status_code == 200
            assert health.json()["status"] == "ok"

            assert client.get("/static/styles.css").status_code == 200
            assert client.get("/static/theme.js").status_code == 200

            html_res = client.get("/", follow_redirects=False)
            assert html_res.status_code == 503
            assert "PRICEWATCHER_ADMIN_PASSWORD_HASH" in html_res.text
            assert "hash-password" in html_res.text
            assert html_res.headers["content-security-policy"] == auth.CSP_POLICY

            login_res = client.get("/login", follow_redirects=False)
            assert login_res.status_code == 503

            api_res = client.get("/api/watches")
            assert api_res.status_code == 503
            assert api_res.json()["ok"] is False

            mut_res = client.post("/api/watches/example-watch/run")
            assert mut_res.status_code == 503
    finally:
        db.close()


def test_insecure_no_auth_mode_logs_warning_and_enforces_csrf(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.delenv("PRICEWATCHER_ADMIN_PASSWORD_HASH", raising=False)
    monkeypatch.setenv("PRICEWATCHER_INSECURE_NO_AUTH", "1")
    monkeypatch.delenv("PRICEWATCHER_SESSION_SECRET", raising=False)

    store = ConfigStore(_init_cfg_dir(tmp_path))
    db = Database(tmp_path / "prices.db")

    with caplog.at_level(logging.WARNING, logger="pricewatcher.auth"):
        app = create_app(store=store, db=db, start_scheduler=False)

    assert any("PRICEWATCHER_INSECURE_NO_AUTH" in r.message for r in caplog.records)
    assert any("PRICEWATCHER_SESSION_SECRET" in r.message for r in caplog.records)

    try:
        with TestClient(app) as client:
            home = client.get("/")
            assert home.status_code == 200
            csrf = _extract_meta_csrf(home.text)

            no_csrf = client.post("/api/watches/example-watch/toggle")
            assert no_csrf.status_code == 403

            with_csrf = client.post(
                "/api/watches/example-watch/toggle",
                headers={"X-CSRF-Token": csrf, "Accept": "application/json"},
            )
            assert with_csrf.status_code == 200
            assert with_csrf.json()["ok"] is True
    finally:
        db.close()


def test_auth_redirects_and_api_401(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, _, db = _make_auth_app(tmp_path, monkeypatch)
    try:
        with TestClient(app) as client:
            assert client.get("/healthz").status_code == 200
            assert client.get("/static/app.js").status_code == 200
            assert client.get("/login").status_code == 200

            for path in ("/", "/manage", "/settings"):
                res = client.get(path, follow_redirects=False)
                assert res.status_code == 303
                assert res.headers["location"].startswith("/login?next=")

            assert client.get("/api/watches").status_code == 401
            assert client.post("/api/watches/example-watch/run").status_code == 401
            assert client.post("/logout").status_code == 401
    finally:
        db.close()


@pytest.mark.parametrize(
    ("raw_next", "expected"),
    [
        ("/manage?tab=1", "/manage?tab=1"),
        ("/watches/example-watch", "/watches/example-watch"),
        ("https://evil.com/phish", "/"),
        ("//evil.com", "/"),
        ("/\\evil.com", "/"),
        ("javascript:alert(1)", "/"),
        ("", "/"),
        (None, "/"),
    ],
)
def test_safe_next_path(raw_next: str | None, expected: str) -> None:
    assert auth.safe_next_path(raw_next) == expected


def test_login_cookie_flags_tamper_expiry_and_logout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, _, db = _make_auth_app(tmp_path, monkeypatch)
    try:
        with TestClient(app) as client:
            loc, login_res = _login_client(client, next_path="https://evil.com")
            assert login_res.status_code == 303
            assert loc == "/"

            raw_cookies = login_res.headers.get_list("set-cookie")
            parsed: dict[str, Any] = {}
            for header_val in raw_cookies:
                sc = SimpleCookie()
                sc.load(header_val)
                for k, morsel in sc.items():
                    parsed[k] = morsel

            assert auth.SESSION_COOKIE_NAME in parsed
            sess_morsel = parsed[auth.SESSION_COOKIE_NAME]
            assert bool(sess_morsel["httponly"]) is True
            assert sess_morsel["samesite"].lower() == "strict"
            assert sess_morsel["path"] == "/"
            assert sess_morsel["max-age"] == str(auth.SESSION_TTL_SECONDS)
            assert not sess_morsel["secure"]

            assert client.get("/api/watches").status_code == 200

            # Tampered signature fails verification.
            orig_tok = sess_morsel.value
            bad_tok = orig_tok[:-1] + ("A" if orig_tok[-1] != "A" else "B")
            with TestClient(app) as tampered_client:
                tampered_client.cookies.set(auth.SESSION_COOKIE_NAME, bad_tok)
                assert tampered_client.get("/api/watches").status_code == 401

            # Expired session fails verification.
            manager = auth.AuthManager.from_env()
            tok, _ = manager.create_session_token(now=1_000)
            assert (
                manager.verify_session_token(tok, now=1_000 + auth.SESSION_TTL_SECONDS - 1)
                is not None
            )
            assert (
                manager.verify_session_token(tok, now=1_000 + auth.SESSION_TTL_SECONDS + 1) is None
            )

            # Logout clears cookie and invalidates session usage.
            dash = client.get("/")
            csrf = _extract_meta_csrf(dash.text)
            logout_res = client.post(
                "/logout",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
            assert logout_res.status_code == 303
            assert logout_res.headers["location"] == "/login"
            assert client.get("/api/watches").status_code == 401
    finally:
        db.close()


def test_secure_cookie_flag_on_https_and_forwarded_proto(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, _, db = _make_auth_app(tmp_path, monkeypatch)
    try:
        with TestClient(app, base_url="https://pricewatcher.local") as https_client:
            _, res = _login_client(https_client)
            assert res.status_code == 303
            assert "Secure" in "\n".join(res.headers.get_list("set-cookie"))

        with TestClient(app) as proxy_client:
            login_page = proxy_client.get("/login")
            csrf = _extract_meta_csrf(login_page.text)
            res = proxy_client.post(
                "/login",
                data={"password": "correct-horse-battery", "csrf_token": csrf},
                headers={"X-Forwarded-Proto": "https"},
                follow_redirects=False,
            )
            assert res.status_code == 303
            assert "Secure" in "\n".join(res.headers.get_list("set-cookie"))
    finally:
        db.close()


def test_login_rate_limit_five_failures_then_429_and_reset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, _, db1 = _make_auth_app(tmp_path / "one", monkeypatch)
    try:
        with TestClient(app) as client:
            for _ in range(5):
                _, bad = _login_client(client, password="wrong")
                assert bad.status_code == 401

            # 6th attempt is blocked with 429 + Retry-After even with right password.
            _, blocked = _login_client(client, password="correct-horse-battery")
            assert blocked.status_code == 429
            assert int(blocked.headers["retry-after"]) >= 1
    finally:
        db1.close()

    # Verify reset on success: 4 failures, 1 success, then 4 more failures stays unblocked.
    app2, _, db2 = _make_auth_app(tmp_path / "reset", monkeypatch)
    try:
        with TestClient(app2) as client2:
            for _ in range(4):
                _, bad = _login_client(client2, password="wrong")
                assert bad.status_code == 401
            _, ok = _login_client(client2, password="correct-horse-battery")
            assert ok.status_code == 303
            dash = client2.get("/")
            client2.post(
                "/logout",
                data={"csrf_token": _extract_meta_csrf(dash.text)},
                follow_redirects=False,
            )
            for _ in range(4):
                _, bad = _login_client(client2, password="wrong")
                assert bad.status_code == 401
    finally:
        db2.close()


def test_csrf_enforcement_origins_headers_and_form_posts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, store, db = _make_auth_app(tmp_path, monkeypatch)
    try:
        with TestClient(app) as client:
            # Capture pre-session login CSRF token to verify cross-context rejection.
            login_html = client.get("/login").text
            pre_session_csrf = _extract_meta_csrf(login_html)
            _, login_res = _login_client(client)
            assert login_res.status_code == 303

            dash = client.get("/")
            csrf = _extract_meta_csrf(dash.text)

            # Missing CSRF header -> 403.
            assert client.post("/api/watches/example-watch/toggle").status_code == 403

            # Pre-session CSRF token cannot be reused after login -> 403.
            assert (
                client.post(
                    "/api/watches/example-watch/toggle",
                    headers={"X-CSRF-Token": pre_session_csrf},
                ).status_code
                == 403
            )

            # Cross-origin Origin / Referer -> 403.
            assert (
                client.post(
                    "/api/watches/example-watch/toggle",
                    headers={
                        "X-CSRF-Token": csrf,
                        "Origin": "https://evil.example",
                    },
                ).status_code
                == 403
            )
            assert (
                client.post(
                    "/api/watches/example-watch/toggle",
                    headers={
                        "X-CSRF-Token": csrf,
                        "Referer": "https://evil.example/csrf.html",
                    },
                ).status_code
                == 403
            )

            # Same-origin Origin passes.
            ok = client.post(
                "/api/watches/example-watch/toggle",
                headers={
                    "X-CSRF-Token": csrf,
                    "Origin": "http://testserver",
                    "Accept": "application/json",
                },
            )
            assert ok.status_code == 200

            # application/x-www-form-urlencoded POST passes CSRF middleware and
            # downstream request.form() parses all fields cleanly.
            form_payload = {
                "csrf_token": csrf,
                "is_edit": "false",
                "name": "Urlencoded Watch",
                "id": "urlencoded-watch",
                "query": "Urlencoded Watch",
                "interval_minutes": "30",
                "jitter_seconds": "10",
                "duration_days": "14",
                "include_groups_text": "Urlencoded",
                "exclude_keywords_text": "",
                "tier_by_text": "condition",
                "conditions_allowed": ["new"],
                "require_in_stock": "true",
                "enabled": "true",
                "price_min": "100",
                "price_max": "500",
                "price_target": "300",
                "price_msrp": "400",
                "min_drop_delta": "10",
                "cooldown_hours": "12",
                "delivery": "waha_with_email_fallback",
                "source_name": ["Dummy RSS"],
                "source_adapter": ["rss"],
                "source_url": ["https://example.com/feed.xml"],
                "source_options_json": ["{}"],
                "source_render_js": ["false"],
            }
            urlenc_res = client.post(
                "/api/watches",
                data=form_payload,
                follow_redirects=False,
            )
            assert urlenc_res.status_code == 303
            assert store.get_watch("urlencoded-watch") is not None

            # multipart/form-data POST passes CSRF middleware AND downstream
            # request.form() parses fields cleanly.
            mp_payload = dict(form_payload, id="multipart-watch", name="Multipart Watch")
            mp_res = client.post(
                "/api/watches",
                data=mp_payload,
                files={"_ignored": ("empty.txt", b"")},
                follow_redirects=False,
            )
            assert mp_res.status_code == 303
            assert store.get_watch("multipart-watch") is not None
    finally:
        db.close()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://example.com/item?a=1&b=2", "https://example.com/item?a=1&b=2"),
        ("http://localhost:8080/test", "http://localhost:8080/test"),
        ("/watches/example-watch", "/watches/example-watch"),
        ("javascript:alert(1)", "#"),
        ("JaVaScRiPt:alert(1)", "#"),
        ("java\nscript:alert(1)", "#"),
        ("\x00javascript:alert(1)", "#"),
        ("data:text/html,<script>alert(1)</script>", "#"),
        ("vbscript:msgbox(1)", "#"),
        ("file:///etc/passwd", "#"),
        ("//evil.com/path", "#"),
        ("/\\evil.com", "#"),
        ("", "#"),
        (None, "#"),
    ],
)
def test_safe_url_filter(raw: str | None, expected: str) -> None:
    assert auth.safe_url(raw) == expected
    assert router.templates.env.filters["safe_url"](raw) == expected


def test_xss_escaping_csp_headers_and_zero_inline_scripts_or_styles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, _, db = _make_auth_app(tmp_path, monkeypatch)
    xss_title = "<script>alert(1)</script>"
    xss_merchant = "<img src=x onerror=alert(2)>"
    db.record_observation(
        watch_id="example-watch",
        tier_key="64-512",
        source_name="evil-src",
        merchant=xss_merchant,
        title=xss_title,
        url="javascript:alert(1)",
        price=1500.0,
        currency="USD",
        condition="new",
        in_stock=True,
        promo_code="<script>p</script>",
        specs={},
    )
    db.upsert_tier_seen(
        watch_id="example-watch",
        tier_key="64-512",
        best_price=1500.0,
        best_merchant=xss_merchant,
        best_url="javascript:alert(1)",
        best_title=xss_title,
        best_promo_code="<script>p</script>",
    )

    try:
        with TestClient(app) as client:
            login_res = client.get("/login")
            assert login_res.headers["content-security-policy"] == auth.CSP_POLICY
            assert login_res.headers["x-content-type-options"] == "nosniff"
            assert login_res.headers["x-frame-options"] == "DENY"
            assert login_res.headers["referrer-policy"] == "no-referrer"
            assert login_res.headers["cache-control"] == "no-store"

            _login_client(client)

            for path in ("/", "/watches/example-watch", "/manage", "/settings"):
                res = client.get(path)
                assert res.status_code == 200
                assert res.headers["content-security-policy"] == auth.CSP_POLICY
                assert res.headers["x-content-type-options"] == "nosniff"
                assert res.headers["x-frame-options"] == "DENY"
                assert res.headers["referrer-policy"] == "no-referrer"
                assert res.headers["cache-control"] == "no-store"

                html = res.text
                assert "javascript:alert" not in html
                assert "<script>alert(1)</script>" not in html
                assert "<script>p</script>" not in html
                assert 'style="' not in html
                assert "style='" not in html

                script_tags = re.findall(r"<script\b[^>]*>", html, flags=re.IGNORECASE)
                assert script_tags
                for tag in script_tags:
                    assert 'src="/static/' in tag

                forms = re.findall(
                    r'<form\b[^>]*method="post"[^>]*>.*?</form>',
                    html,
                    flags=re.IGNORECASE | re.DOTALL,
                )
                for form_html in forms:
                    assert 'name="csrf_token"' in form_html

            app_js = Path(router.__file__).resolve().parent / "static" / "app.js"
            theme_js = Path(router.__file__).resolve().parent / "static" / "theme.js"
            for js_file in (app_js, theme_js):
                content = js_file.read_text(encoding="utf-8")
                assert ".style." not in content
                assert "innerHTML" not in content
    finally:
        db.close()


def test_unhandled_exception_sanitized_with_security_headers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    app, store, db = _make_auth_app(tmp_path, monkeypatch)
    try:
        with TestClient(app) as client:
            _login_client(client)

            def boom() -> Any:
                raise RuntimeError("/var/secret/config.yaml leaked traceback")

            monkeypatch.setattr(store, "load_watches", boom)
            with caplog.at_level(logging.ERROR):
                res = client.get("/api/watches")
            assert res.status_code == 500
            body = res.json()
            assert body == {"ok": False, "error": "Internal server error"}
            assert "/var/secret" not in res.text
            assert "RuntimeError" not in res.text
            assert res.headers["content-security-policy"] == auth.CSP_POLICY
            assert res.headers["x-content-type-options"] == "nosniff"
            assert res.headers["x-frame-options"] == "DENY"
    finally:
        db.close()


def test_sanitize_slug_helper() -> None:
    assert router.ConfigStore.sanitize_slug("My Watch! 2026") == "my-watch-2026"
    assert ConfigStore.sanitize_watch_id("My Watch! 2026") == "my-watch-2026"


def test_non_ascii_cookies_csrf_and_non_dict_json_return_4xx_not_500(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, _, db = _make_auth_app(tmp_path, monkeypatch)
    try:
        with TestClient(app) as client:
            _login_client(client)
            csrf_token = _extract_meta_csrf(client.get("/").text)
            assert "object-src 'none'" in auth.CSP_POLICY

            # Non-ASCII CSRF form field must return 403, not 500
            bad_csrf = client.post(
                "/api/watches",
                data={"csrf_token": "tokén-non-ascii", "name": "Bad"},
            )
            assert bad_csrf.status_code == 403

            # Non-dict JSON body must return 400, not 500
            non_dict = client.post(
                "/api/probe",
                json=["not-an-object"],
                headers={"X-CSRF-Token": csrf_token},
            )
            assert non_dict.status_code == 400

            # Non-ASCII token helpers and ISO-8859-1 raw cookie header fail safely (401/False)
            assert app.state.auth.verify_session_token("bad.tökén") is None
            assert app.state.auth.verify_csrf_token("bad.tökén", expected_sub="abc") is False
            with TestClient(app) as anon:
                api_res = anon.get(
                    "/api/watches",
                    headers=[
                        (b"cookie", f"{auth.SESSION_COOKIE_NAME}=bad.t\xe9".encode("latin-1"))
                    ],
                )
                assert api_res.status_code == 401
    finally:
        db.close()
