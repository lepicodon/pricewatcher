"""Tests for authentication, CSRF protection, XSS hardening, CSP, and S5/S8 controls."""

from __future__ import annotations

import base64
from http.cookies import SimpleCookie
import io
import ipaddress
import logging
from pathlib import Path
import re
import shutil
from typing import Any

from fastapi import Request
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
    headers: dict[str, str] | None = None,
) -> tuple[str, Any]:
    pw_val = password if password is not None else "correct-horse-battery"
    url = "/login" if next_path is None else f"/login?next={next_path}"
    login_page = client.get(url, headers=headers)
    assert login_page.status_code == 200
    login_csrf = _extract_meta_csrf(login_page.text)
    data = {"password": pw_val, "csrf_token": login_csrf}
    if next_path is not None:
        data["next"] = next_path
    res = client.post("/login", data=data, headers=headers, follow_redirects=False)
    return res.headers.get("location", ""), res


def _make_scope_request(
    *,
    client_host: str | None = "testclient",
    headers: list[tuple[bytes, bytes]] | None = None,
    scheme: str = "http",
) -> Request:
    scope: dict[str, Any] = {
        "type": "http",
        "scheme": scheme,
        "method": "POST",
        "path": "/login",
        "headers": headers or [],
    }
    if client_host is not None:
        scope["client"] = (client_host, 12345)
    return Request(scope)


def _parse_set_cookies(res: Any) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for header_val in res.headers.get_list("set-cookie"):
        sc = SimpleCookie()
        sc.load(header_val)
        for name, morsel in sc.items():
            parsed[name] = morsel
    return parsed


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


def test_cli_proxy_headers_configuration(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def _run_cli_with_env(sub_dir: Path, trusted_proxies: str | None) -> dict[str, Any]:
        recorded: dict[str, Any] = {}

        def fake_run(app_obj: Any, **kwargs: Any) -> None:
            recorded["app"] = app_obj
            recorded.update(kwargs)

        cfg_dir = _init_cfg_dir(sub_dir)
        monkeypatch.setattr("uvicorn.run", fake_run)
        monkeypatch.setenv("PRICEWATCHER_CONFIG_DIR", str(cfg_dir))
        monkeypatch.setenv("PRICEWATCHER_DB_PATH", str(sub_dir / "prices.db"))
        if trusted_proxies is None:
            monkeypatch.delenv("PRICEWATCHER_TRUSTED_PROXIES", raising=False)
        else:
            monkeypatch.setenv("PRICEWATCHER_TRUSTED_PROXIES", trusted_proxies)

        rc = cli([])
        try:
            assert rc == 0
            return recorded
        finally:
            if "app" in recorded:
                recorded["app"].state.db.close()

    unset_call = _run_cli_with_env(tmp_path / "unset", None)
    assert unset_call["proxy_headers"] is False
    assert unset_call["forwarded_allow_ips"] == "127.0.0.1"

    set_call = _run_cli_with_env(tmp_path / "set", "172.18.0.0/16")
    assert set_call["proxy_headers"] is True
    assert set_call["forwarded_allow_ips"] == "172.18.0.0/16"


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

            # Logout clears cookie, revokes session server-side, and rejects replay.
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

            with TestClient(app) as replay_client:
                replay_client.cookies.set(auth.SESSION_COOKIE_NAME, orig_tok)
                assert replay_client.get("/api/watches").status_code == 401
    finally:
        db.close()


def test_logout_revokes_session_server_side_and_prunes_expired(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, _, db = _make_auth_app(tmp_path, monkeypatch)
    try:
        with TestClient(app) as client:
            _, login_res = _login_client(client)
            assert login_res.status_code == 303
            cookies = _parse_set_cookies(login_res)
            captured_session = cookies[auth.SESSION_COOKIE_NAME].value

            # Captured cookie works from another client before logout.
            with TestClient(app) as second_client:
                second_client.cookies.set(auth.SESSION_COOKIE_NAME, captured_session)
                assert second_client.get("/api/watches").status_code == 200

            dash = client.get("/")
            csrf = _extract_meta_csrf(dash.text)
            logout_res = client.post(
                "/logout",
                data={"csrf_token": csrf},
                follow_redirects=False,
            )
            assert logout_res.status_code == 303
            assert logout_res.headers["location"] == "/login"

            # Replaying the captured session cookie after logout is rejected with 401.
            with TestClient(app) as replay_client:
                replay_client.cookies.set(auth.SESSION_COOKIE_NAME, captured_session)
                assert replay_client.get("/api/watches").status_code == 401
                browser_res = replay_client.get("/", follow_redirects=False)
                assert browser_res.status_code == 303
                assert browser_res.headers["location"].startswith("/login")

        # Unit test revocation & pruning on AuthManager.
        manager = auth.AuthManager.from_env()
        tok1, sid1 = manager.create_session_token(now=1_000)
        tok2, sid2 = manager.create_session_token(now=2_000)
        exp1 = 1_000 + auth.SESSION_TTL_SECONDS

        assert manager.revoke_session_token(None) is False
        assert manager.revoke_session_token("invalid.token") is False
        assert manager.revoke_session_token(tok1, now=exp1 + 1) is False
        assert sid1 not in manager._revoked_sessions

        assert manager.revoke_session_token(tok1, now=1_500) is True
        assert manager._revoked_sessions[sid1] == exp1
        assert manager.verify_session_token(tok1, now=1_500) is None

        # At exact expiry boundary (now == exp1), entry is kept and rejected.
        assert manager.verify_session_token(tok1, now=exp1) is None
        assert sid1 in manager._revoked_sessions

        # Once now > exp1, verifying another active token prunes the expired entry.
        assert manager.verify_session_token(tok2, now=exp1 + 1) is not None
        assert sid1 not in manager._revoked_sessions

        # Pruning also runs during revoke_session_token.
        tok3, sid3 = manager.create_session_token(now=3_000)
        assert manager.revoke_session_token(tok2, now=2_500) is True
        assert sid2 in manager._revoked_sessions
        assert manager.revoke_session_token(tok3, now=2_000 + auth.SESSION_TTL_SECONDS + 1) is True
        assert sid2 not in manager._revoked_sessions
        assert sid3 in manager._revoked_sessions
    finally:
        db.close()


def test_secure_cookie_flag_on_https_and_forwarded_proto(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PRICEWATCHER_TRUSTED_PROXIES", raising=False)
    app, _, db = _make_auth_app(tmp_path / "untrusted", monkeypatch)
    try:
        with TestClient(app, base_url="https://pricewatcher.local") as https_client:
            _, res = _login_client(https_client)
            assert res.status_code == 303
            cookies = _parse_set_cookies(res)
            assert bool(cookies[auth.SESSION_COOKIE_NAME]["secure"]) is True
            assert bool(cookies[auth.CSRF_COOKIE_NAME]["secure"]) is True

        # Untrusted X-Forwarded-Proto: https must NOT mark cookies Secure.
        with TestClient(app) as untrusted_client:
            login_page = untrusted_client.get("/login", headers={"X-Forwarded-Proto": "https"})
            login_cookies = _parse_set_cookies(login_page)
            assert not login_cookies[auth.CSRF_COOKIE_NAME]["secure"]

            csrf = _extract_meta_csrf(login_page.text)
            res = untrusted_client.post(
                "/login",
                data={"password": "correct-horse-battery", "csrf_token": csrf},
                headers={"X-Forwarded-Proto": "https"},
                follow_redirects=False,
            )
            assert res.status_code == 303
            post_cookies = _parse_set_cookies(res)
            assert not post_cookies[auth.SESSION_COOKIE_NAME]["secure"]
            assert not post_cookies[auth.CSRF_COOKIE_NAME]["secure"]
    finally:
        db.close()

    # Trusted proxy with X-Forwarded-Proto: https DOES mark cookies Secure.
    monkeypatch.setenv("PRICEWATCHER_TRUSTED_PROXIES", "testclient,172.16.0.0/12")
    trusted_app, _, trusted_db = _make_auth_app(tmp_path / "trusted", monkeypatch)
    try:
        with TestClient(trusted_app) as proxy_client:
            login_page = proxy_client.get("/login", headers={"X-Forwarded-Proto": "https"})
            login_cookies = _parse_set_cookies(login_page)
            assert bool(login_cookies[auth.CSRF_COOKIE_NAME]["secure"]) is True

            # Pass the Secure cookie via Cookie header to simulate the reverse proxy
            # forwarding browser cookies from TLS termination over plain HTTP backend.
            login_csrf_val = login_cookies[auth.CSRF_COOKIE_NAME].value
            csrf = _extract_meta_csrf(login_page.text)
            res = proxy_client.post(
                "/login",
                data={"password": "correct-horse-battery", "csrf_token": csrf},
                headers={
                    "X-Forwarded-Proto": "https",
                    "Cookie": f"{auth.CSRF_COOKIE_NAME}={login_csrf_val}",
                },
                follow_redirects=False,
            )
            assert res.status_code == 303
            post_cookies = _parse_set_cookies(res)
            assert bool(post_cookies[auth.SESSION_COOKIE_NAME]["secure"]) is True
            assert bool(post_cookies[auth.CSRF_COOKIE_NAME]["secure"]) is True

            sess_val = post_cookies[auth.SESSION_COOKIE_NAME].value
            csrf_val = post_cookies[auth.CSRF_COOKIE_NAME].value
            proxied_cookie_header = (
                f"{auth.SESSION_COOKIE_NAME}={sess_val}; {auth.CSRF_COOKIE_NAME}={csrf_val}"
            )
            dash = proxy_client.get(
                "/",
                headers={"X-Forwarded-Proto": "https", "Cookie": proxied_cookie_header},
            )
            assert dash.status_code == 200
            dash_csrf = _extract_meta_csrf(dash.text)
            logout_res = proxy_client.post(
                "/logout",
                data={"csrf_token": dash_csrf},
                headers={"X-Forwarded-Proto": "https", "Cookie": proxied_cookie_header},
                follow_redirects=False,
            )
            assert logout_res.status_code == 303
            logout_cookies = _parse_set_cookies(logout_res)
            assert bool(logout_cookies[auth.SESSION_COOKIE_NAME]["secure"]) is True
            assert bool(logout_cookies[auth.CSRF_COOKIE_NAME]["secure"]) is True
    finally:
        trusted_db.close()


def test_is_https_request_gates_forwarded_proto_on_trusted_proxies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted = auth.parse_trusted_proxies("testclient,172.16.0.0/12")

    # Direct HTTPS and cookie_secure_env always return True.
    assert (
        auth.is_https_request(
            _make_scope_request(
                scheme="https",
                headers=[(b"host", b"pricewatcher.local")],
            ),
            trusted_proxies=(),
        )
        is True
    )
    assert (
        auth.is_https_request(
            _make_scope_request(scheme="http", client_host="203.0.113.5"),
            cookie_secure_env=True,
            trusted_proxies=(),
        )
        is True
    )

    # X-Forwarded-Proto: https only honored when peer matches trusted_proxies.
    forwarded_headers = [(b"x-forwarded-proto", b"https, http")]
    assert (
        auth.is_https_request(
            _make_scope_request(client_host="203.0.113.5", headers=forwarded_headers),
            trusted_proxies=trusted,
        )
        is False
    )
    assert (
        auth.is_https_request(
            _make_scope_request(client_host=None, headers=forwarded_headers),
            trusted_proxies=("*",),
        )
        is False
    )
    assert (
        auth.is_https_request(
            _make_scope_request(client_host="172.18.0.10", headers=forwarded_headers),
            trusted_proxies=trusted,
        )
        is True
    )
    assert (
        auth.is_https_request(
            _make_scope_request(
                client_host="172.18.0.10", headers=[(b"x-forwarded-proto", b"http")]
            ),
            trusted_proxies=trusted,
        )
        is False
    )

    # Non-matching PRICEWATCHER_TRUSTED_PROXIES ignores spoofed X-Forwarded-Proto.
    monkeypatch.setenv("PRICEWATCHER_TRUSTED_PROXIES", "172.16.0.0/12")
    app, _, db = _make_auth_app(tmp_path, monkeypatch)
    try:
        with TestClient(app) as client:
            _, res = _login_client(client, headers={"X-Forwarded-Proto": "https"})
            assert res.status_code == 303
            cookies = _parse_set_cookies(res)
            assert not cookies[auth.SESSION_COOKIE_NAME]["secure"]
            assert not cookies[auth.CSRF_COOKIE_NAME]["secure"]
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


def test_trusted_proxy_parsing_and_client_ip_resolution() -> None:
    assert auth.parse_trusted_proxies(None) == ()
    assert auth.parse_trusted_proxies("") == ()
    assert auth.parse_trusted_proxies(" ,  , ") == ()

    parsed = auth.parse_trusted_proxies("TestClient, 172.16.0.0/12, 10.0.0.5, 2001:db8::/32")
    assert parsed == (
        "testclient",
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("10.0.0.5/32"),
        ipaddress.ip_network("2001:db8::/32"),
    )

    assert auth.is_trusted_proxy(None, parsed) is False
    assert auth.is_trusted_proxy("   ", ("*",)) is False
    assert auth.is_trusted_proxy("172.18.0.5", ()) is False
    assert auth.is_trusted_proxy("TESTCLIENT", parsed) is True
    assert auth.is_trusted_proxy("172.18.0.5", parsed) is True
    assert auth.is_trusted_proxy("10.0.0.5", parsed) is True
    assert auth.is_trusted_proxy("2001:db8::1", parsed) is True
    assert auth.is_trusted_proxy("198.51.100.1", parsed) is False
    assert auth.is_trusted_proxy("198.51.100.1", ("*",)) is True

    # Multi-hop X-Forwarded-For skips trailing trusted proxies and returns rightmost untrusted IP.
    multi_hop_req = _make_scope_request(
        client_host="testclient",
        headers=[(b"x-forwarded-for", b"198.51.100.9, 172.18.0.5")],
    )
    assert auth.get_client_ip(multi_hop_req, parsed) == "198.51.100.9"

    # Untrusted peer ignores X-Forwarded-For completely.
    untrusted_req = _make_scope_request(
        client_host="203.0.113.7",
        headers=[(b"x-forwarded-for", b"198.51.100.9")],
    )
    assert auth.get_client_ip(untrusted_req, parsed) == "203.0.113.7"

    # All-trusted hops fall back to parts[0]; empty/missing XFF falls back to peer.
    all_trusted_req = _make_scope_request(
        client_host="testclient",
        headers=[(b"x-forwarded-for", b"172.17.0.2, 172.18.0.5")],
    )
    assert auth.get_client_ip(all_trusted_req, parsed) == "172.17.0.2"

    comma_xff_req = _make_scope_request(
        client_host="testclient",
        headers=[(b"x-forwarded-for", b" , ")],
    )
    assert auth.get_client_ip(comma_xff_req, parsed) == "testclient"

    no_client_req = _make_scope_request(client_host=None)
    assert auth.get_client_ip(no_client_req, parsed) == "unknown"

    manager = auth.AuthManager(
        password_hash="",
        insecure_no_auth=False,
        session_secret=b"secret",
        trusted_proxies="testclient,172.16.0.0/12",
    )
    assert manager.trusted_proxies == (
        "testclient",
        ipaddress.ip_network("172.16.0.0/12"),
    )
    assert manager.client_ip(multi_hop_req) == "198.51.100.9"


def test_login_rate_limit_trusted_proxy_isolates_forwarded_ips(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PRICEWATCHER_TRUSTED_PROXIES", "testclient,172.16.0.0/12")
    app, _, db = _make_auth_app(tmp_path, monkeypatch)
    try:
        with TestClient(app) as client_one:
            for _ in range(5):
                _, bad = _login_client(
                    client_one,
                    password="wrong",
                    headers={"X-Forwarded-For": "198.51.100.1"},
                )
                assert bad.status_code == 401

            _, blocked = _login_client(
                client_one,
                password="correct-horse-battery",
                headers={"X-Forwarded-For": "198.51.100.1"},
            )
            assert blocked.status_code == 429
            assert int(blocked.headers["retry-after"]) >= 1

        # Distinct forwarded IP behind the same trusted proxy is NOT locked out.
        with TestClient(app) as client_two:
            _, ok = _login_client(
                client_two,
                password="correct-horse-battery",
                headers={"X-Forwarded-For": "198.51.100.2"},
            )
            assert ok.status_code == 303

        # Multi-hop X-Forwarded-For resolves to the rightmost untrusted client IP (198.51.100.9).
        with TestClient(app) as client_multi:
            for _ in range(5):
                _, bad = _login_client(
                    client_multi,
                    password="wrong",
                    headers={"X-Forwarded-For": "198.51.100.9, 172.18.0.5"},
                )
                assert bad.status_code == 401

            assert app.state.auth.rate_limiter.check_blocked("198.51.100.9") is not None
            assert app.state.auth.rate_limiter.check_blocked("172.18.0.5") is None

            _, blocked_direct = _login_client(
                client_multi,
                password="correct-horse-battery",
                headers={"X-Forwarded-For": "198.51.100.9"},
            )
            assert blocked_direct.status_code == 429
    finally:
        db.close()


@pytest.mark.parametrize("trusted_env", [None, ""])
def test_login_rate_limit_untrusted_proxy_ignores_spoofed_xff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    trusted_env: str | None,
) -> None:
    if trusted_env is None:
        monkeypatch.delenv("PRICEWATCHER_TRUSTED_PROXIES", raising=False)
    else:
        monkeypatch.setenv("PRICEWATCHER_TRUSTED_PROXIES", trusted_env)

    app, _, db = _make_auth_app(tmp_path, monkeypatch)
    try:
        with TestClient(app) as client:
            for idx in range(5):
                _, bad = _login_client(
                    client,
                    password="wrong",
                    headers={"X-Forwarded-For": f"198.51.100.{idx + 10}"},
                )
                assert bad.status_code == 401

            assert app.state.auth.rate_limiter.check_blocked("testclient") is not None

            _, blocked = _login_client(
                client,
                password="correct-horse-battery",
                headers={"X-Forwarded-For": "198.51.100.99"},
            )
            assert blocked.status_code == 429
            assert int(blocked.headers["retry-after"]) >= 1
    finally:
        db.close()


def test_login_rate_limiter_periodic_sweep_removes_unqueried_expired_keys() -> None:
    now = [0.0]
    limiter = auth.LoginRateLimiter(
        max_failures=3,
        window_seconds=60,
        max_keys=100,
        clock=lambda: now[0],
    )

    now[0] = 10.0
    limiter.record_failure("stale-1")
    limiter.record_failure("stale-2")
    assert set(limiter._failures) == {"stale-1", "stale-2"}

    # Advance past window_seconds without ever querying stale-1 or stale-2 again.
    now[0] = 75.0
    assert limiter.check_blocked("unrelated-ip") is None
    assert limiter._failures == {}

    # Periodic sweep also triggers from record_failure.
    now[0] = 80.0
    limiter.record_failure("stale-3")
    assert "stale-3" in limiter._failures

    now[0] = 145.0
    limiter.record_failure("fresh-ip")
    assert list(limiter._failures) == ["fresh-ip"]


def test_login_rate_limiter_bounds_distinct_keys_under_flood() -> None:
    with pytest.raises(ValueError):
        auth.LoginRateLimiter(max_keys=0)

    now = [0.0]
    limiter = auth.LoginRateLimiter(
        max_failures=5,
        window_seconds=900,
        max_keys=5,
        clock=lambda: now[0],
    )

    for idx in range(50):
        now[0] += 1.0
        limiter.record_failure(f"198.51.100.{idx}")
        assert len(limiter._failures) <= limiter.max_keys

    assert len(limiter._failures) == 5
    assert list(limiter._failures) == [f"198.51.100.{idx}" for idx in range(45, 50)]

    # Updating an existing key refreshes its recency and does not evict it prematurely.
    now_short = [0.0]
    bounded = auth.LoginRateLimiter(
        max_failures=5,
        window_seconds=60,
        max_keys=3,
        clock=lambda: now_short[0],
    )
    now_short[0] = 1.0
    bounded.record_failure("k1")
    now_short[0] = 2.0
    bounded.record_failure("k2")
    now_short[0] = 3.0
    bounded.record_failure("k3")
    now_short[0] = 4.0
    bounded.record_failure("k1")
    now_short[0] = 5.0
    bounded.record_failure("k4")
    assert list(bounded._failures) == ["k3", "k1", "k4"]

    # When max_keys is full and entries have expired (even within sweep interval),
    # record_failure sweeps expired entries before evicting fresh ones.
    now_short[0] = 50.0
    bounded.check_blocked("probe")  # updates _last_sweep to 50.0
    now_short[0] = 64.0  # k3 (t=3) and k1 (t=4) are expired (cutoff=4.0), k4 (t=5) is fresh
    bounded.record_failure("k5")
    assert list(bounded._failures) == ["k4", "k5"]
    assert len(bounded._failures) <= bounded.max_keys


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

            # Default port symmetry (:80 on http) and reverse-proxy X-Forwarded-Host pass.
            ok_port = client.post(
                "/api/watches/example-watch/toggle",
                headers={
                    "X-CSRF-Token": csrf,
                    "Origin": "http://testserver:80",
                    "Accept": "application/json",
                },
            )
            assert ok_port.status_code == 200

            ok_proxy = client.post(
                "/api/watches/example-watch/toggle",
                headers={
                    "X-CSRF-Token": csrf,
                    "Host": "pricewatcher:8080",
                    "X-Forwarded-Host": "pricewatcher.docker",
                    "Origin": "http://pricewatcher.docker",
                    "Accept": "application/json",
                },
            )
            assert ok_proxy.status_code == 200

            # Cross-origin Origin is still rejected even when X-Forwarded-Host is present.
            bad_proxy = client.post(
                "/api/watches/example-watch/toggle",
                headers={
                    "X-CSRF-Token": csrf,
                    "Host": "pricewatcher:8080",
                    "X-Forwarded-Host": "pricewatcher.docker",
                    "Origin": "https://evil.example",
                },
            )
            assert bad_proxy.status_code == 403

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
            assert login_res.headers["referrer-policy"] == "same-origin"
            assert login_res.headers["cache-control"] == "no-store"
            assert client.get("/favicon.ico", follow_redirects=False).status_code == 204

            _login_client(client)

            for path in ("/", "/watches/example-watch", "/manage", "/settings", "/packs"):
                res = client.get(path)
                assert res.status_code == 200
                assert res.headers["content-security-policy"] == auth.CSP_POLICY
                assert res.headers["x-content-type-options"] == "nosniff"
                assert res.headers["x-frame-options"] == "DENY"
                assert res.headers["referrer-policy"] == "same-origin"
                assert res.headers["cache-control"] == "no-store"

                html = res.text
                assert "javascript:alert" not in html
                assert "<script>alert(1)</script>" not in html
                assert "<script>p</script>" not in html
                assert 'style="' not in html
                assert "style='" not in html

                assert '<script src="/static/theme.js"></script>' in html
                assert '<script type="module" src="/static/app.js"></script>' in html

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

            static_dir = Path(router.__file__).resolve().parent / "static"
            js_files = sorted(static_dir.glob("*.js"))
            expected_modules = {
                "app.js",
                "utils.js",
                "ui.js",
                "manage.js",
                "settings.js",
                "theme.js",
            }
            assert expected_modules.issubset({js_file.name for js_file in js_files})
            for js_file in js_files:
                content = js_file.read_text(encoding="utf-8")
                assert ".style." not in content, f".style. found in {js_file.name}"
                assert "innerHTML" not in content, f"innerHTML found in {js_file.name}"
                static_res = client.get(f"/static/{js_file.name}")
                assert static_res.status_code == 200
                assert "javascript" in static_res.headers.get("content-type", "").lower()
                assert static_res.headers.get("content-security-policy") == auth.CSP_POLICY
                assert static_res.headers.get("x-content-type-options") == "nosniff"
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
