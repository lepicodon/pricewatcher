"""Tests for HTTP client User-Agent configuration, redirects, body caps, and IP pinning."""

from __future__ import annotations

from collections.abc import AsyncIterator
import socket
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from pricewatcher import http_client


def test_reddit_user_agent_default_and_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PRICEWATCHER_CONTACT_URL", raising=False)
    assert http_client.DEFAULT_CONTACT_URL in http_client.get_reddit_user_agent()
    assert "your-username/pricewatcher" in http_client.get_reddit_user_agent()

    monkeypatch.setenv("PRICEWATCHER_CONTACT_URL", "https://example.org/custom-contact")
    ua = http_client.get_reddit_user_agent()
    assert "https://example.org/custom-contact" in ua
    assert "your-username" not in ua


async def test_polite_get_sends_configured_reddit_ua(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_headers: dict[str, str] = {}

    async def fake_send_get(url: str, *, headers: dict[str, str], timeout: float, client):
        captured_headers.update(headers)
        return http_client.HttpResponse(status_code=200, url=url, headers={}, text="ok")

    monkeypatch.setattr(http_client, "_send_get", fake_send_get)
    monkeypatch.setattr(http_client, "_LAST_REQUEST_AT", {})
    monkeypatch.setenv("PRICEWATCHER_CONTACT_URL", "https://example.com/pw")

    # Pass a tiny delay or mock sleep so test is instant
    async def no_sleep(_seconds: float) -> None:
        return None

    monkeypatch.setattr(http_client.asyncio, "sleep", no_sleep)
    await http_client.polite_get("https://www.reddit.com/r/appledeals/new/.rss")
    assert "https://example.com/pw" in captured_headers["User-Agent"]


async def test_http_context_shares_client_and_isolates_rate_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_clients: list[object] = []

    async def fake_send_get(url: str, *, headers: dict[str, str], timeout: float, client):
        captured_clients.append(client)
        return http_client.HttpResponse(status_code=200, url=url, headers={}, text="ok")

    monkeypatch.setattr(http_client, "_send_get", fake_send_get)
    sleeps: list[float] = []
    now = 50.0

    monkeypatch.setattr(http_client.time, "monotonic", lambda: now)

    async def fake_sleep(seconds: float) -> None:
        nonlocal now
        sleeps.append(seconds)
        now += seconds

    monkeypatch.setattr(http_client.asyncio, "sleep", fake_sleep)

    async with http_client.HttpContext() as ctx:
        await http_client.polite_get("https://example.com/a", http_ctx=ctx)
        await http_client.polite_get("https://example.com/b", http_ctx=ctx)

    assert captured_clients == [ctx.client, ctx.client]
    assert sleeps == [pytest.approx(1.5)]


def _mock_dns(monkeypatch: pytest.MonkeyPatch, mapping: dict[str, list[tuple[int, str]]]) -> None:
    """Mock socket.getaddrinfo so outbound validation never touches real DNS."""

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


async def test_redirect_revalidation_public_host_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PRICEWATCHER_ALLOW_PRIVATE_HOSTS", raising=False)
    monkeypatch.delenv("PRICEWATCHER_MAX_RESPONSE_BYTES", raising=False)
    _mock_dns(
        monkeypatch,
        {
            "origin.example.com": [(socket.AF_INET, "93.184.216.34")],
            "dest.example.com": [(socket.AF_INET, "93.184.216.35")],
        },
    )

    seen_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_hosts.append(request.headers["host"])
        if request.headers["host"] == "origin.example.com":
            return httpx.Response(302, headers={"Location": "https://dest.example.com/deals/final"})
        return httpx.Response(200, text="final-payload")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        resp = await http_client.polite_get(
            "https://origin.example.com/start",
            min_interval_s=0.0,
            client=client,
        )

    assert seen_hosts == ["origin.example.com", "dest.example.com"]
    assert resp.status_code == 200
    assert resp.url == "https://dest.example.com/deals/final"
    assert resp.text == "final-payload"


@pytest.mark.parametrize(
    "blocked_location",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:8080/internal",
    ],
)
async def test_redirect_to_private_or_metadata_ip_raises_ssrf_blocked(
    monkeypatch: pytest.MonkeyPatch,
    blocked_location: str,
) -> None:
    monkeypatch.delenv("PRICEWATCHER_ALLOW_PRIVATE_HOSTS", raising=False)
    _mock_dns(
        monkeypatch,
        {
            "public.example.com": [(socket.AF_INET, "93.184.216.34")],
            "169.254.169.254": [(socket.AF_INET, "169.254.169.254")],
            "127.0.0.1": [(socket.AF_INET, "127.0.0.1")],
        },
    )

    requested_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_hosts.append(request.headers["host"])
        return httpx.Response(302, headers={"Location": blocked_location})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(http_client.SSRFBlockedError):
            await http_client.polite_get(
                "https://public.example.com/redirect",
                min_interval_s=0.0,
                client=client,
            )

    assert requested_hosts == ["public.example.com"]


async def test_redirect_chain_exceeding_max_hops_raises_too_many_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PRICEWATCHER_ALLOW_PRIVATE_HOSTS", raising=False)
    _mock_dns(monkeypatch, {"hop.example.com": [(socket.AF_INET, "93.184.216.34")]})

    def too_many_hops_handler(request: httpx.Request) -> httpx.Response:
        idx = int(request.url.path.removeprefix("/r"))
        return httpx.Response(302, headers={"Location": f"/r{idx + 1}"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(too_many_hops_handler)) as client:
        with pytest.raises(httpx.TooManyRedirects):
            await http_client.polite_get(
                "https://hop.example.com/r0",
                min_interval_s=0.0,
                client=client,
            )

    def max_allowed_handler(request: httpx.Request) -> httpx.Response:
        idx = int(request.url.path.removeprefix("/ok"))
        if idx < http_client.MAX_REDIRECT_HOPS:
            return httpx.Response(302, headers={"Location": f"/ok{idx + 1}"})
        return httpx.Response(200, text="at-hop-limit")

    async with httpx.AsyncClient(transport=httpx.MockTransport(max_allowed_handler)) as client:
        ok_resp = await http_client.polite_get(
            "https://hop.example.com/ok0",
            min_interval_s=0.0,
            client=client,
        )
    assert ok_resp.text == "at-hop-limit"
    assert ok_resp.url == f"https://hop.example.com/ok{http_client.MAX_REDIRECT_HOPS}"


async def test_body_size_cap_content_length_streaming_and_within_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PRICEWATCHER_ALLOW_PRIVATE_HOSTS", raising=False)
    monkeypatch.delenv("PRICEWATCHER_MAX_RESPONSE_BYTES", raising=False)
    _mock_dns(monkeypatch, {"cap.example.com": [(socket.AF_INET, "93.184.216.34")]})

    # 1. Content-Length > max_response_bytes fails immediately without reading stream
    stream_read = False

    class GuardStream(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            nonlocal stream_read
            stream_read = True
            yield b"should-not-be-read"

    def cl_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Length": "200"}, stream=GuardStream())

    async with httpx.AsyncClient(transport=httpx.MockTransport(cl_handler)) as client:
        with pytest.raises(http_client.ResponseTooLargeError, match="Content-Length"):
            await http_client.polite_get(
                "https://cap.example.com/header",
                min_interval_s=0.0,
                max_response_bytes=64,
                client=client,
            )
    assert stream_read is False

    # 2. Streaming chunks without Content-Length exceeding max_response_bytes aborts early
    chunks_sent = 0

    class MultiChunkStream(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            nonlocal chunks_sent
            for _ in range(10):
                chunks_sent += 1
                yield b"a" * 30

    def stream_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=MultiChunkStream())

    async with httpx.AsyncClient(transport=httpx.MockTransport(stream_handler)) as client:
        with pytest.raises(http_client.ResponseTooLargeError, match="exceeded limit"):
            await http_client.polite_get(
                "https://cap.example.com/stream",
                min_interval_s=0.0,
                max_response_bytes=50,
                client=client,
            )
    assert chunks_sent == 2

    # 3. Body exactly within max_response_bytes succeeds
    payload = b"x" * 50

    class ExactStream(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield payload[:25]
            yield payload[25:]

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _r: httpx.Response(200, stream=ExactStream()))
    ) as client:
        ok_resp = await http_client.polite_get(
            "https://cap.example.com/ok",
            min_interval_s=0.0,
            max_response_bytes=50,
            client=client,
        )
    assert ok_resp.raw_body == payload
    assert ok_resp.text == "x" * 50


@pytest.mark.parametrize("raw_val", ["not-an-int", "0", "-1", "3.14"])
def test_invalid_max_response_bytes_env_raises_value_error(
    monkeypatch: pytest.MonkeyPatch,
    raw_val: str,
) -> None:
    monkeypatch.setenv("PRICEWATCHER_MAX_RESPONSE_BYTES", raw_val)
    with pytest.raises(ValueError, match="PRICEWATCHER_MAX_RESPONSE_BYTES"):
        http_client.get_max_response_bytes()


def test_valid_and_default_max_response_bytes_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PRICEWATCHER_MAX_RESPONSE_BYTES", raising=False)
    assert http_client.get_max_response_bytes() == http_client.DEFAULT_MAX_RESPONSE_BYTES

    monkeypatch.setenv("PRICEWATCHER_MAX_RESPONSE_BYTES", "4096")
    assert http_client.get_max_response_bytes() == 4096


async def test_pinned_anyio_backend_connect_tcp_matches_host_and_port_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connect_calls: list[tuple[str, int]] = []
    sentinel_stream = object()

    async def fake_super_connect_tcp(
        _self: Any,
        host: str,
        port: int,
        **_kwargs: Any,
    ) -> Any:
        connect_calls.append((host, port))
        return sentinel_stream

    monkeypatch.setattr(
        http_client.httpcore.AnyIOBackend,
        "connect_tcp",
        fake_super_connect_tcp,
    )

    backend = http_client._PinnedAnyIOBackend()

    # Without ContextVar set, host is untouched
    assert await backend.connect_tcp("shop.example.com", 443) is sentinel_stream

    token = http_client._PINNED_TARGET_CTX.set(("shop.example.com", 443, "93.184.216.34"))
    try:
        # Case-insensitive matching host + matching port substitutes pinned IP
        assert await backend.connect_tcp("Shop.Example.COM", 443) is sentinel_stream
        # Unmatched host leaves host unchanged
        assert await backend.connect_tcp("other.example.com", 443) is sentinel_stream
        # Unmatched port leaves host unchanged
        assert await backend.connect_tcp("shop.example.com", 80) is sentinel_stream
    finally:
        http_client._PINNED_TARGET_CTX.reset(token)

    assert connect_calls == [
        ("shop.example.com", 443),
        ("93.184.216.34", 443),
        ("other.example.com", 443),
        ("shop.example.com", 80),
    ]


async def test_non_pinned_and_pinned_client_polite_get_behavior(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PRICEWATCHER_ALLOW_PRIVATE_HOSTS", raising=False)
    _mock_dns(monkeypatch, {"store.example.com": [(socket.AF_INET, "93.184.216.34")]})

    captured_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(200, text="ok")

    # Non-pinned client rewrites URL to pinned_url, sets Host header, and sets SNI for HTTPS
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as plain_client:
        await http_client.polite_get(
            "https://store.example.com:8443/catalog?p=1",
            min_interval_s=0.0,
            client=plain_client,
        )
        await http_client.polite_get(
            "http://store.example.com/catalog",
            min_interval_s=0.0,
            client=plain_client,
        )

    https_req, http_req = captured_requests
    assert str(https_req.url) == "https://93.184.216.34:8443/catalog?p=1"
    assert https_req.headers["host"] == "store.example.com:8443"
    assert https_req.extensions["sni_hostname"] == "store.example.com"

    assert str(http_req.url) == "http://93.184.216.34/catalog"
    assert http_req.headers["host"] == "store.example.com"
    assert "sni_hostname" not in http_req.extensions

    # Backend-pinned client keeps real hostname in URL and populates _PINNED_TARGET_CTX during call
    seen_ctx_during_request: list[tuple[str, int, str] | None] = []
    pinned_urls: list[str] = []

    def pinned_handler(request: httpx.Request) -> httpx.Response:
        pinned_urls.append(str(request.url))
        seen_ctx_during_request.append(http_client._PINNED_TARGET_CTX.get())
        return httpx.Response(200, text="pinned")

    async with httpx.AsyncClient(transport=httpx.MockTransport(pinned_handler)) as pinned_client:
        pinned_client._transport._pool = SimpleNamespace(  # type: ignore[attr-defined]
            _network_backend=http_client._PinnedAnyIOBackend()
        )
        await http_client.polite_get(
            "https://store.example.com:8443/catalog",
            min_interval_s=0.0,
            client=pinned_client,
        )

    assert pinned_urls == ["https://store.example.com:8443/catalog"]
    assert seen_ctx_during_request == [("store.example.com", 8443, "93.184.216.34")]
    assert http_client._PINNED_TARGET_CTX.get() is None
