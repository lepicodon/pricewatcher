"""Unit tests for WAHA and Email notifier clients with mocked network/SMTP."""

from __future__ import annotations

import base64
from email.message import EmailMessage
import json
import smtplib
import socket
from typing import Any

import httpx
import pytest

from pricewatcher import http_client
from pricewatcher.config import EmailConfig, WahaConfig
from pricewatcher.notifiers.email import EmailClient
from pricewatcher.notifiers.waha import ChannelSendResult, WahaClient


def _mock_dns(monkeypatch: pytest.MonkeyPatch, mapping: dict[str, list[tuple[int, str]]]) -> None:
    """Mock socket.getaddrinfo so validate_outbound_url never performs real DNS lookups."""

    def fake_getaddrinfo(
        host: str,
        port: Any,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[tuple[Any, ...]]:
        del family, type, proto, flags
        key = str(host).lower()
        if key not in mapping:
            raise socket.gaierror(socket.EAI_NONAME, f"No mock DNS entry for {key}")
        entries: list[tuple[Any, ...]] = []
        for fam, ip in mapping[key]:
            sockaddr: tuple[Any, ...] = (
                (ip, int(port or 0), 0, 0) if fam == socket.AF_INET6 else (ip, int(port or 0))
            )
            entries.append((fam, socket.SOCK_STREAM, 6, "", sockaddr))
        return entries

    monkeypatch.setattr(http_client.socket, "getaddrinfo", fake_getaddrinfo)


def _clear_notifier_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("WAHA_URL", "WAHA_SESSION", "WAHA_API_KEY", "SMTP_USER", "SMTP_PASS"):
        monkeypatch.delenv(var, raising=False)


@pytest.mark.parametrize(
    ("payload", "expected_ok", "expected_status"),
    [
        ({"status": "WORKING"}, True, "WORKING"),
        ({"status": "CONNECTED"}, True, "CONNECTED"),
        ({"status": "READY"}, True, "READY"),
        ({"status": "STOPPED"}, False, "STOPPED"),
    ],
)
async def test_waha_check_health_session_statuses(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, str],
    expected_ok: bool,
    expected_status: str,
) -> None:
    _clear_notifier_env(monkeypatch)
    _mock_dns(monkeypatch, {"waha.docker": [(socket.AF_INET, "172.18.0.5")]})
    monkeypatch.setenv("WAHA_API_KEY", "secret-waha-token")

    seen_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_requests.append(request)
        return httpx.Response(200, json=payload)

    cfg = WahaConfig(url="http://waha.docker", session="pricewatcher")
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=False
    ) as client:
        res = await WahaClient(cfg, client=client).check_health()

    assert len(seen_requests) == 1
    assert str(seen_requests[0].url) == "http://waha.docker/api/sessions/pricewatcher"
    assert seen_requests[0].headers.get("X-Api-Key") == "secret-waha-token"
    assert res["ok"] is expected_ok
    assert res["status"] == expected_status
    assert res["url"] == "http://waha.docker"
    assert res["session"] == "pricewatcher"


async def test_waha_check_health_404_lists_available_sessions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_notifier_env(monkeypatch)
    _mock_dns(monkeypatch, {"waha.docker": [(socket.AF_INET, "172.18.0.5")]})

    requested_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        if request.url.path == "/api/sessions/pricewatcher":
            return httpx.Response(404, json={"error": "missing"})
        if request.url.path == "/api/sessions" and request.url.params.get("all") == "true":
            return httpx.Response(200, json=[{"name": "default"}, {"name": "alerts"}])
        return httpx.Response(500)

    cfg = WahaConfig(url="http://waha.docker", session="pricewatcher")
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=False
    ) as client:
        res = await WahaClient(cfg, client=client).check_health()

    assert requested_urls == [
        "http://waha.docker/api/sessions/pricewatcher",
        "http://waha.docker/api/sessions?all=true",
    ]
    assert res == {
        "ok": False,
        "status": "http_404",
        "url": "http://waha.docker",
        "session": "pricewatcher",
        "detail": "Session 'pricewatcher' not found (available: default, alerts)",
    }


async def test_waha_check_health_timeout_500_and_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_notifier_env(monkeypatch)
    _mock_dns(monkeypatch, {"waha.docker": [(socket.AF_INET, "172.18.0.5")]})
    cfg = WahaConfig(url="http://waha.docker", session="pricewatcher")

    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(timeout_handler), follow_redirects=False
    ) as client:
        timeout_res = await WahaClient(cfg, client=client).check_health()
    assert timeout_res["ok"] is False
    assert timeout_res["status"] == "unreachable"
    assert "ReadTimeout" in timeout_res["detail"]

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _r: httpx.Response(500, text="server error")),
        follow_redirects=False,
    ) as client:
        err_res = await WahaClient(cfg, client=client).check_health()
    assert err_res["ok"] is False
    assert err_res["status"] == "http_500"
    assert "HTTP 500" in err_res["detail"]

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _r: httpx.Response(302, headers={"Location": "http://169.254.169.254/"})
        ),
        follow_redirects=False,
    ) as client:
        redir_res = await WahaClient(cfg, client=client).check_health()
    assert redir_res["ok"] is False
    assert redir_res["status"] == "http_302"
    assert "redirects disabled" in redir_res["detail"]


async def test_waha_send_text_success_500_timeout_and_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_notifier_env(monkeypatch)
    _mock_dns(monkeypatch, {"waha.docker": [(socket.AF_INET, "172.18.0.5")]})
    monkeypatch.setenv("WAHA_API_KEY", "send-key-123")
    cfg = WahaConfig(url="http://waha.docker", session="pricewatcher")

    sent_requests: list[httpx.Request] = []

    def ok_handler(request: httpx.Request) -> httpx.Response:
        sent_requests.append(request)
        return httpx.Response(200, json={"id": "msg-1"})

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(ok_handler), follow_redirects=False
    ) as client:
        ok_res = await WahaClient(cfg, client=client).send_text("15551234567@c.us", "Deal alert!")

    assert ok_res == ChannelSendResult(ok=True, error=None)
    assert len(sent_requests) == 1
    assert str(sent_requests[0].url) == "http://waha.docker/api/sendText"
    assert sent_requests[0].headers.get("X-Api-Key") == "send-key-123"
    assert json.loads(sent_requests[0].content) == {
        "session": "pricewatcher",
        "chatId": "15551234567@c.us",
        "text": "Deal alert!",
    }

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _r: httpx.Response(500, text="backend failure")),
        follow_redirects=False,
    ) as client:
        err_res = await WahaClient(cfg, client=client).send_text("15551234567@c.us", "Deal alert!")
    assert err_res.ok is False
    assert err_res.error is not None and "500" in err_res.error

    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("read timed out", request=request)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(timeout_handler), follow_redirects=False
    ) as client:
        timeout_res = await WahaClient(cfg, client=client).send_text(
            "15551234567@c.us", "Deal alert!"
        )
    assert timeout_res.ok is False
    assert timeout_res.error is not None and "ReadTimeout" in timeout_res.error

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _r: httpx.Response(302, headers={"Location": "http://example.org/"})
        ),
        follow_redirects=False,
    ) as client:
        redir_res = await WahaClient(cfg, client=client).send_text(
            "15551234567@c.us", "Deal alert!"
        )
    assert redir_res.ok is False
    assert redir_res.error == "WAHA HTTP 302: redirects disabled"


async def test_email_client_disabled_and_missing_recipient(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_notifier_env(monkeypatch)

    def fail_if_called(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("smtplib.SMTP must not be called when disabled or recipient missing")

    monkeypatch.setattr(smtplib, "SMTP", fail_if_called)

    disabled_client = EmailClient(EmailConfig(enabled=False))
    disabled_res = await disabled_client.send_email("buyer@example.com", "Subj", "Body")
    assert disabled_res == ChannelSendResult(ok=False, error="Email notifications disabled")

    enabled_client = EmailClient(EmailConfig(enabled=True))
    missing_to_res = await enabled_client.send_email("", "Subj", "Body")
    assert missing_to_res == ChannelSendResult(ok=False, error="Recipient email not configured")


@pytest.mark.parametrize(
    ("use_tls", "set_credentials", "expected_calls"),
    [
        (True, True, ["ehlo", "starttls", "ehlo", "login", "send_message", "exit"]),
        (False, True, ["ehlo", "login", "send_message", "exit"]),
        (True, False, ["ehlo", "starttls", "ehlo", "send_message", "exit"]),
        (False, False, ["ehlo", "send_message", "exit"]),
    ],
)
async def test_email_client_success_tls_and_auth_combinations(
    monkeypatch: pytest.MonkeyPatch,
    use_tls: bool,
    set_credentials: bool,
    expected_calls: list[str],
) -> None:
    _clear_notifier_env(monkeypatch)
    if set_credentials:
        monkeypatch.setenv("SMTP_USER", "notifier@example.com")
        monkeypatch.setenv("SMTP_PASS", "app-pass-xyz")

    calls: list[str] = []
    init_args: list[tuple[str, int, Any]] = []
    login_args: list[tuple[str, str]] = []
    sent_messages: list[EmailMessage] = []

    class FakeSMTP:
        def __init__(self, host: str, port: int, timeout: Any = None) -> None:
            init_args.append((host, port, timeout))

        def __enter__(self) -> FakeSMTP:
            return self

        def __exit__(self, *_args: Any) -> None:
            calls.append("exit")

        def ehlo(self) -> None:
            calls.append("ehlo")

        def starttls(self) -> None:
            calls.append("starttls")

        def login(self, user: str, password: str) -> None:
            calls.append("login")
            login_args.append((user, password))

        def send_message(self, msg: EmailMessage) -> None:
            calls.append("send_message")
            sent_messages.append(msg)

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)

    cfg = EmailConfig(
        enabled=True,
        smtp_host="smtp.example.org",
        smtp_port=2525,
        use_tls=use_tls,
        from_addr="alerts@example.org",
    )
    res = await EmailClient(cfg).send_email(
        "buyer@example.com",
        "[PriceWatcher] Target Hit",
        "Mac Studio dropped to $3,399.00",
    )

    assert res == ChannelSendResult(ok=True, error=None)
    assert init_args == [("smtp.example.org", 2525, 15)]
    assert calls == expected_calls
    if set_credentials:
        assert login_args == [("notifier@example.com", "app-pass-xyz")]
    else:
        assert login_args == []

    assert len(sent_messages) == 1
    msg = sent_messages[0]
    assert msg["From"] == "alerts@example.org"
    assert msg["To"] == "buyer@example.com"
    assert msg["Subject"] == "[PriceWatcher] Target Hit"
    assert "Mac Studio dropped to $3,399.00" in msg.get_content()


@pytest.mark.parametrize("exc_kind", ["smtp", "oserror"])
async def test_email_client_error_redacts_smtp_user_and_password(
    monkeypatch: pytest.MonkeyPatch,
    exc_kind: str,
) -> None:
    _clear_notifier_env(monkeypatch)
    smtp_user = "smtp-user@example.com"
    smtp_pass = "super-secret-smtp-pass!"
    monkeypatch.setenv("SMTP_USER", smtp_user)
    monkeypatch.setenv("SMTP_PASS", smtp_pass)

    b64_pass = base64.b64encode(smtp_pass.encode()).decode("ascii")
    b64_plain = base64.b64encode(f"\x00{smtp_user}\x00{smtp_pass}".encode()).decode("ascii")

    class ErrorSMTP:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def __enter__(self) -> ErrorSMTP:
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

        def ehlo(self) -> None:
            return None

        def starttls(self) -> None:
            return None

        def login(self, user: str, password: str) -> None:
            if exc_kind == "smtp":
                raise smtplib.SMTPException(
                    f"SMTP login failed user={user} pass={password} b64={b64_pass} plain={b64_plain}"
                )
            raise OSError(f"Socket error while authenticating {user} with {password}")

        def send_message(self, _msg: EmailMessage) -> None:
            raise AssertionError("send_message should not be reached after login failure")

    monkeypatch.setattr(smtplib, "SMTP", ErrorSMTP)

    res = await EmailClient(EmailConfig(enabled=True, smtp_host="smtp.example.org")).send_email(
        "buyer@example.com", "Alert", "Body"
    )

    assert res.ok is False
    assert res.error is not None
    expected_prefix = "SMTPException:" if exc_kind == "smtp" else "OSError:"
    assert res.error.startswith(expected_prefix)
    assert "[REDACTED]" in res.error
    for leaked in (smtp_user, smtp_pass, b64_pass, b64_plain):
        assert leaked not in res.error
