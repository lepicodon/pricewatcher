"""Tests for SSRF protection, DNS pinning, redirect validation, streaming caps, and notifier hardening."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import AsyncIterator
import logging
import smtplib
import socket
import sys
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from pricewatcher import http_client
from pricewatcher.adapters.appleinsider import parse_appleinsider_html
from pricewatcher.adapters.base import sanitize_listing_url
from pricewatcher.adapters.html_css import HtmlCssAdapter, parse_html_css
from pricewatcher.adapters.json_api import parse_json_api_payload
from pricewatcher.adapters.rss import RssAdapter, parse_rss_feed
from pricewatcher.config import (
    AlertsConfig,
    EmailConfig,
    NotificationsConfig,
    RecipientConfig,
    SettingsConfig,
    SourceConfig,
    WahaConfig,
    WatchConfig,
)
from pricewatcher.discovery import probe_url
from pricewatcher.http_client import (
    HttpContext,
    ResponseTooLargeError,
    SSRFBlockedError,
    polite_get,
    validate_outbound_url,
)
from pricewatcher.notifiers.base import NotificationDispatcher
from pricewatcher.notifiers.email import EmailClient
from pricewatcher.notifiers.waha import WahaClient, _describe_missing_session


def _mock_dns(monkeypatch: pytest.MonkeyPatch, mapping: dict[str, list[tuple[int, str]]]) -> None:
    """Mock socket.getaddrinfo with a deterministic hostname -> [(family, ip), ...] mapping."""

    def fake_getaddrinfo(
        host: str,
        port: Any,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[tuple[Any, ...]]:
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


@pytest.mark.parametrize(
    "blocked_url",
    [
        "http://127.0.0.1/admin",
        "http://127.255.0.1:8080/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://172.31.255.254/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://100.64.0.1/",
        "http://100.127.255.254/",
        "http://0.0.0.0/",
        "http://0.1.2.3/",
        "http://224.0.0.1/",
        "http://255.255.255.255/",
        "http://[::1]/",
        "http://[::]/",
        "http://[fc00::1]/",
        "http://[fd12:3456::1]/",
        "http://[fe80::1]/",
        "http://[fe80::1%eth0]/",
        "http://[fe80::1%25eth0]/",
        "http://[fec0::1]/",
        "http://[ff02::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[::ffff:169.254.169.254]/",
        "http://[::ffff:100.64.0.1]/",
        "file:///etc/passwd",
        "ftp://example.com/resource",
        "gopher://example.com/1",
        "javascript:alert(1)",
        "data:text/html,<h1>hi</h1>",
        "https://user:pass@example.com/",
        "https://user@example.com/",
        "https://@example.com/",
        "https:///missing-host",
    ],
)
def test_validate_outbound_url_blocks_ssrf_targets(blocked_url: str) -> None:
    with pytest.raises(SSRFBlockedError):
        validate_outbound_url(blocked_url)


def test_validate_outbound_url_blocks_dns_to_private_and_mixed_ips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_dns(
        monkeypatch,
        {
            "rebind.example.com": [(socket.AF_INET, "10.20.30.40")],
            "mixed.example.com": [
                (socket.AF_INET, "93.184.216.34"),
                (socket.AF_INET, "127.0.0.1"),
            ],
            "empty.example.com": [],
        },
    )
    with pytest.raises(SSRFBlockedError):
        validate_outbound_url("https://rebind.example.com/deals")
    with pytest.raises(SSRFBlockedError):
        validate_outbound_url("https://mixed.example.com/deals")
    with pytest.raises(SSRFBlockedError):
        validate_outbound_url("https://empty.example.com/deals")
    with pytest.raises(SSRFBlockedError):
        validate_outbound_url("https://missing.example.invalid/deals")


def test_validate_outbound_url_allow_private_hosts_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_dns(
        monkeypatch,
        {
            "internal.local": [(socket.AF_INET, "192.168.50.10")],
            "127.0.0.1": [(socket.AF_INET, "127.0.0.1")],
            "169.254.169.254": [(socket.AF_INET, "169.254.169.254")],
        },
    )
    monkeypatch.setenv("PRICEWATCHER_ALLOW_PRIVATE_HOSTS", "127.0.0.1, internal.local")

    t1 = validate_outbound_url("http://127.0.0.1:8080/health")
    assert t1.pinned_ip == "127.0.0.1"
    assert t1.host_header == "127.0.0.1:8080"

    t2 = validate_outbound_url("https://internal.local/api")
    assert t2.pinned_ip == "192.168.50.10"
    assert t2.host_header == "internal.local"
    assert t2.sni_hostname == "internal.local"

    with pytest.raises(SSRFBlockedError):
        validate_outbound_url("http://169.254.169.254/latest/meta-data/")


def test_validate_outbound_url_pins_public_ipv4_and_ipv6(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_dns(
        monkeypatch,
        {
            "shop.example.com": [(socket.AF_INET, "93.184.216.34")],
            "v6only.example.com": [
                (socket.AF_INET6, "2606:2800:220:1:248:1893:25c8:1946"),
            ],
        },
    )
    t4 = validate_outbound_url("https://shop.example.com:8443/products.json?page=1")
    assert t4.pinned_ip == "93.184.216.34"
    assert t4.pinned_url == "https://93.184.216.34:8443/products.json?page=1"
    assert t4.host_header == "shop.example.com:8443"
    assert t4.sni_hostname == "shop.example.com"

    t6 = validate_outbound_url("https://v6only.example.com/deals")
    assert t6.pinned_ip == "2606:2800:220:1:248:1893:25c8:1946"
    assert t6.pinned_url == "https://[2606:2800:220:1:248:1893:25c8:1946]/deals"
    assert t6.host_header == "v6only.example.com"
    assert t6.sni_hostname == "v6only.example.com"


async def test_dns_pinning_prevents_rebinding_and_preserves_host_sni(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def flaky_rebinding_getaddrinfo(
        host: str,
        port: Any,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[tuple[Any, ...]]:
        nonlocal calls
        calls += 1
        ip = "93.184.216.34" if calls == 1 else "127.0.0.1"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, int(port or 443)))]

    monkeypatch.setattr(http_client.socket, "getaddrinfo", flaky_rebinding_getaddrinfo)

    seen_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_requests.append(request)
        return httpx.Response(200, text="pinned-ok")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        resp = await polite_get(
            "https://rebind-target.example.com/deals",
            min_interval_s=0.0,
            client=client,
        )

    assert calls == 1
    assert resp.text == "pinned-ok"
    assert resp.url == "https://rebind-target.example.com/deals"
    assert len(seen_requests) == 1
    req = seen_requests[0]
    assert req.url.host == "93.184.216.34"
    assert req.headers["host"] == "rebind-target.example.com"
    assert req.extensions["sni_hostname"] == "rebind-target.example.com"


async def test_redirect_chain_blocks_metadata_and_enforces_max_hops(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_dns(
        monkeypatch,
        {
            "start.example.com": [(socket.AF_INET, "93.184.216.34")],
            "hop.example.com": [(socket.AF_INET, "93.184.216.35")],
            "169.254.169.254": [(socket.AF_INET, "169.254.169.254")],
        },
    )

    requested_hosts: list[str] = []

    def metadata_redirect_handler(request: httpx.Request) -> httpx.Response:
        requested_hosts.append(request.headers["host"])
        if request.headers["host"] == "start.example.com":
            return httpx.Response(
                302,
                headers={"Location": "http://169.254.169.254/latest/meta-data/iam/"},
            )
        raise AssertionError("Should never send request to metadata IP")

    async with HttpContext(
        min_interval_s=0.0,
        client=httpx.AsyncClient(transport=httpx.MockTransport(metadata_redirect_handler)),
    ) as ctx:
        with pytest.raises(SSRFBlockedError):
            await polite_get("https://start.example.com/deal", http_ctx=ctx)
    assert requested_hosts == ["start.example.com"]

    # Relative + cross-host valid redirects update Host & SNI cleanly up to 5 hops; 6th fails
    hop_records: list[tuple[str, str, str]] = []

    def multi_hop_handler(request: httpx.Request) -> httpx.Response:
        hop_records.append(
            (
                request.url.host,
                request.headers["host"],
                str(request.extensions.get("sni_hostname", "")),
            )
        )
        path = request.url.path
        if path == "/step0":
            return httpx.Response(302, headers={"Location": "/step1"})
        if path == "/step1":
            return httpx.Response(302, headers={"Location": "https://hop.example.com/step2"})
        if path.startswith("/step"):
            step_num = int(path.removeprefix("/step"))
            if step_num < 6:
                return httpx.Response(302, headers={"Location": f"/step{step_num + 1}"})
        return httpx.Response(200, text="done")

    async with HttpContext(
        min_interval_s=0.0,
        client=httpx.AsyncClient(transport=httpx.MockTransport(multi_hop_handler)),
    ) as ctx:
        # 2 hops: /step0 -> /step1 -> hop.example.com/step2 -> if we want 2 hops, use 5-hop limit test
        with pytest.raises(httpx.TooManyRedirects):
            await polite_get("https://start.example.com/step0", http_ctx=ctx)

    assert hop_records[0] == ("93.184.216.34", "start.example.com", "start.example.com")
    assert hop_records[1] == ("93.184.216.34", "start.example.com", "start.example.com")
    assert hop_records[2] == ("93.184.216.35", "hop.example.com", "hop.example.com")
    assert len(hop_records) == 6  # initial + 5 hops, 6th redirect rejected

    # Exactly 5 redirects succeeds
    def five_hops_handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/h0":
            return httpx.Response(302, headers={"Location": "/h1"})
        if path.startswith("/h"):
            n = int(path.removeprefix("/h"))
            if n < 5:
                return httpx.Response(302, headers={"Location": f"/h{n + 1}"})
        return httpx.Response(200, text="five-hops-ok")

    async with HttpContext(
        min_interval_s=0.0,
        client=httpx.AsyncClient(transport=httpx.MockTransport(five_hops_handler)),
    ) as ctx:
        five_resp = await polite_get("https://start.example.com/h0", http_ctx=ctx)
    assert five_resp.text == "five-hops-ok"
    assert five_resp.url == "https://start.example.com/h5"


async def test_streaming_response_size_cap_header_and_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_dns(monkeypatch, {"big.example.com": [(socket.AF_INET, "93.184.216.34")]})
    monkeypatch.setenv("PRICEWATCHER_MAX_RESPONSE_BYTES", "100")

    # 1. Oversized Content-Length header rejected before consuming body
    def cl_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Length": "500"}, content=b"small")

    async with HttpContext(
        min_interval_s=0.0,
        client=httpx.AsyncClient(transport=httpx.MockTransport(cl_handler)),
    ) as ctx:
        with pytest.raises(ResponseTooLargeError):
            await polite_get("https://big.example.com/cl", http_ctx=ctx)

    # 2. Streaming response without Content-Length stops as soon as limit exceeded
    chunks_yielded = 0

    class ChunkedStream(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            nonlocal chunks_yielded
            for _ in range(100):
                chunks_yielded += 1
                yield b"x" * 40

    def stream_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=ChunkedStream())

    async with HttpContext(
        min_interval_s=0.0,
        client=httpx.AsyncClient(transport=httpx.MockTransport(stream_handler)),
    ) as ctx:
        with pytest.raises(ResponseTooLargeError):
            await polite_get("https://big.example.com/stream", http_ctx=ctx)

    # Stopped at chunk 3 (120 bytes > 100), never read all 100 chunks
    assert chunks_yielded == 3

    # 3. Adapter & discovery surface ResponseTooLargeError and SSRFBlockedError cleanly
    async with HttpContext(
        min_interval_s=0.0,
        client=httpx.AsyncClient(transport=httpx.MockTransport(cl_handler)),
    ) as ctx:
        outcome = await RssAdapter().fetch(
            SourceConfig(name="Big RSS", adapter="rss", url="https://big.example.com/feed.xml"),
            http_ctx=ctx,
        )
        assert outcome.error is not None
        assert "ResponseTooLargeError" in outcome.error

        probe_big = await probe_url("https://big.example.com/feed.xml", http_ctx=ctx)
        assert probe_big.classification == "ERROR"
        assert probe_big.format_detected == "response_too_large"

        probe_ssrf = await probe_url("http://169.254.169.254/latest/meta-data/", http_ctx=ctx)
        assert probe_ssrf.classification == "ERROR"
        assert probe_ssrf.format_detected == "ssrf_blocked"


async def test_http_context_pool_limits_reuse_and_politeness_timing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_dns(
        monkeypatch,
        {
            "shop.example.com": [(socket.AF_INET, "93.184.216.34")],
            "www.reddit.com": [(socket.AF_INET, "151.101.1.140")],
        },
    )

    now = 100.0
    slept: list[float] = []

    def fake_monotonic() -> float:
        return now

    async def fake_sleep(seconds: float) -> None:
        nonlocal now
        slept.append(seconds)
        now += seconds

    monkeypatch.setattr(http_client.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(http_client.asyncio, "sleep", fake_sleep)

    async def ok_handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    async with HttpContext() as default_ctx:
        assert default_ctx.client.follow_redirects is False
        assert default_ctx.min_interval_s == 1.5
        pool = default_ctx.client._transport._pool  # type: ignore[attr-defined]
        assert pool._max_connections == 20
        assert pool._max_keepalive_connections == 10

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(ok_handler))
    async with HttpContext(client=mock_client) as ctx:
        await polite_get("https://shop.example.com/1", http_ctx=ctx)
        now += 0.2
        await polite_get("https://shop.example.com/2", http_ctx=ctx)
        assert len(slept) == 1
        assert slept[0] == pytest.approx(1.3, abs=1e-6)

        await polite_get("https://www.reddit.com/r/deals/new/.rss", http_ctx=ctx)
        now += 0.5
        await polite_get("https://www.reddit.com/r/appledeals/new/.rss", http_ctx=ctx)
        assert len(slept) == 2
        assert slept[1] == pytest.approx(1.5, abs=1e-6)
    await mock_client.aclose()


async def test_playwright_ssrf_route_interception_and_truncation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_dns(
        monkeypatch,
        {
            "spa.example.com": [(socket.AF_INET, "93.184.216.34")],
            "cdn.example.com": [(socket.AF_INET, "93.184.216.35")],
        },
    )
    monkeypatch.setenv("PRICEWATCHER_MAX_RESPONSE_BYTES", "25")

    launched = False
    route_decisions: list[tuple[str, str]] = []

    class FakeRoute:
        def __init__(self, req_url: str, *, method: str = "GET") -> None:
            self.request = SimpleNamespace(url=req_url, method=method)

        async def abort(self) -> None:
            route_decisions.append((self.request.url, "abort"))

        async def continue_(self) -> None:
            route_decisions.append((self.request.url, "continue"))

        async def fulfill(
            self, *, status: int = 200, headers: Any = None, body: Any = None
        ) -> None:
            del headers
            payload = body if isinstance(body, (bytes, str)) else b""
            route_decisions.append((self.request.url, f"fulfill:{status}:{len(payload)}"))

    class FakePage:
        def __init__(self) -> None:
            self.url = "about:blank"
            self._handler: Any = None

        async def route(self, _pattern: str, handler: Any) -> None:
            self._handler = handler

        async def goto(self, target_url: str, **_kwargs: Any) -> None:
            self.url = target_url
            for sub_url, method in (
                ("https://cdn.example.com/bundle.js", "GET"),
                ("https://cdn.example.com/redir-ssrf", "GET"),
                ("https://cdn.example.com/exfil", "POST"),
                ("http://169.254.169.254/latest/meta-data/", "GET"),
                ("http://127.0.0.1:8080/internal", "GET"),
                ("file:///etc/passwd", "GET"),
                ("chrome://settings", "GET"),
                ("data:text/html,<script>alert(1)</script>", "GET"),
                ("data:image/png;base64,AAAA", "GET"),
                ("about:blank", "GET"),
            ):
                await self._handler(FakeRoute(sub_url, method=method))

        async def content(self) -> str:
            return "<html><body>0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ</body></html>"

    class FakeBrowser:
        async def new_page(self, **_kwargs: Any) -> FakePage:
            return FakePage()

        async def close(self) -> None:
            return None

    class FakePlaywrightCtx:
        def __init__(self) -> None:
            self.chromium = SimpleNamespace(launch=self._launch)

        async def _launch(self, **_kwargs: Any) -> FakeBrowser:
            nonlocal launched
            launched = True
            return FakeBrowser()

        async def __aenter__(self) -> FakePlaywrightCtx:
            return self

        async def __aexit__(self, *_args: Any) -> None:
            return None

    fake_module = SimpleNamespace(async_playwright=lambda: FakePlaywrightCtx())
    monkeypatch.setitem(sys.modules, "playwright", SimpleNamespace(async_api=fake_module))
    monkeypatch.setitem(sys.modules, "playwright.async_api", fake_module)

    # 1. Blocked initial URL never launches Playwright
    bad_outcome = await HtmlCssAdapter().fetch(
        SourceConfig(
            name="Blocked SPA",
            adapter="html_css",
            url="http://127.0.0.1/secret",
            render_js=True,
        )
    )
    assert launched is False
    assert bad_outcome.error is not None
    assert "SSRFBlockedError" in bad_outcome.error

    # 2. Allowed initial URL fulfills subrequests via polite_get (blocking 302 redirects & POSTs)
    from pricewatcher.adapters.html_css import _fetch_with_playwright

    def pw_subresource_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/redir-ssrf":
            return httpx.Response(
                302, headers={"Location": "http://169.254.169.254/latest/meta-data/"}
            )
        return httpx.Response(200, content=b"console.log(1)")

    async with HttpContext(
        min_interval_s=0.0,
        client=httpx.AsyncClient(transport=httpx.MockTransport(pw_subresource_handler)),
    ) as pw_ctx:
        rendered = await _fetch_with_playwright("https://spa.example.com/deals", http_ctx=pw_ctx)
    assert launched is True
    assert len(rendered.encode("utf-8")) <= 25
    decisions_map = dict(route_decisions)
    assert decisions_map["https://cdn.example.com/bundle.js"] == "fulfill:200:14"
    assert decisions_map["https://cdn.example.com/redir-ssrf"] == "abort"
    assert decisions_map["https://cdn.example.com/exfil"] == "abort"
    assert decisions_map["data:image/png;base64,AAAA"] == "continue"
    assert decisions_map["about:blank"] == "continue"
    assert decisions_map["http://169.254.169.254/latest/meta-data/"] == "abort"
    assert decisions_map["http://127.0.0.1:8080/internal"] == "abort"
    assert decisions_map["file:///etc/passwd"] == "abort"
    assert decisions_map["chrome://settings"] == "abort"
    assert decisions_map["data:text/html,<script>alert(1)</script>"] == "abort"

    # 3. Post-navigation page.url to private IP is blocked cleanly
    class RedirectingPage(FakePage):
        async def goto(self, _target_url: str, **_kwargs: Any) -> None:
            self.url = "http://169.254.169.254/latest/meta-data/"

    class RedirectingBrowser:
        async def new_page(self, **_kwargs: Any) -> RedirectingPage:
            return RedirectingPage()

        async def close(self) -> None:
            return None

    class RedirectingPlaywrightCtx(FakePlaywrightCtx):
        async def _launch(self, **_kwargs: Any) -> Any:
            return RedirectingBrowser()

    redirect_mod = SimpleNamespace(async_playwright=lambda: RedirectingPlaywrightCtx())
    monkeypatch.setitem(sys.modules, "playwright", SimpleNamespace(async_api=redirect_mod))
    monkeypatch.setitem(sys.modules, "playwright.async_api", redirect_mod)

    post_nav_outcome = await HtmlCssAdapter().fetch(
        SourceConfig(
            name="Redirected SPA",
            adapter="html_css",
            url="https://spa.example.com/deals",
            render_js=True,
        )
    )
    assert post_nav_outcome.error is not None
    assert "SSRFBlockedError" in post_nav_outcome.error


def test_sanitize_listing_url_across_all_four_adapters() -> None:
    assert sanitize_listing_url("https://example.com/deal") == "https://example.com/deal"
    assert sanitize_listing_url("http://example.com/deal") == "http://example.com/deal"
    assert sanitize_listing_url("javascript:alert(1)") == ""
    assert sanitize_listing_url("data:text/html,<script>alert(1)</script>") == ""
    assert sanitize_listing_url("vbscript:msgbox(1)") == ""
    assert sanitize_listing_url("file:///etc/passwd") == ""
    assert sanitize_listing_url("https:///no-netloc") == ""
    assert sanitize_listing_url(None) == ""

    # 1. RSS
    rss_xml = """<?xml version="1.0"?>
    <rss version="2.0"><channel><title>Deals</title>
      <item><title>Mac Studio M5 Max - $3,499</title><link>javascript:alert(1)</link></item>
      <item><title>Mac Studio M5 Max - $3,399</title><link>data:text/html,xss</link></item>
    </channel></rss>"""
    rss_listings = parse_rss_feed(
        rss_xml, SourceConfig(name="RSS", adapter="rss", url="https://deals.example.com/rss")
    )
    assert len(rss_listings) == 2
    assert all(item.url == "" for item in rss_listings)

    # 2. JSON API (Shopify suggest + Apple refurb + generic JSON)
    suggest_json = (
        '{"resources":{"results":{"products":['
        '{"title":"Mac Studio M5 Max","price":"3499","url":"javascript:alert(1)"}'
        "]}}}"
    )
    suggest_listings = parse_json_api_payload(
        suggest_json,
        SourceConfig(name="JSON", adapter="json_api", url="https://shop.example.com/suggest.json"),
    )
    assert len(suggest_listings) == 1
    assert suggest_listings[0].url == ""

    refurb_html = (
        "<script>window.REFURB_GRID_BOOTSTRAP = "
        '{"tiles":[{"title":"Refurbished Mac Studio","price":{"currentPrice":{"raw_amount":"2999"}},'
        '"productDetailsUrl":"data:text/html,evil"}]};</script>'
    )
    refurb_listings = parse_json_api_payload(
        refurb_html,
        SourceConfig(
            name="Refurb",
            adapter="json_api",
            url="https://www.apple.com/shop/refurbished/mac",
            options={"mode": "apple_refurb"},
        ),
    )
    assert len(refurb_listings) == 1
    assert refurb_listings[0].url == ""

    generic_json = '[{"title":"Mac Studio M5 Max","price":3299,"url":"javascript:void(0)"}]'
    generic_listings = parse_json_api_payload(
        generic_json,
        SourceConfig(name="Generic", adapter="json_api", url="https://api.example.com/items.json"),
    )
    assert len(generic_listings) == 1
    assert generic_listings[0].url == ""

    # 3. HTML/CSS (CSS selectors + JSON-LD + Abt)
    css_html = (
        '<div class="item">'
        '<a class="title" href="javascript:alert(1)">Mac Studio M5 Max</a>'
        '<span class="price">$3,199</span>'
        "</div>"
    )
    css_listings = parse_html_css(
        css_html,
        SourceConfig(
            name="CSS",
            adapter="html_css",
            url="https://store.example.com/list",
            options={
                "item_selector": ".item",
                "title_selector": ".title",
                "price_selector": ".price",
            },
        ),
    )
    assert len(css_listings) == 1
    assert css_listings[0].url == ""

    jsonld_html = (
        '<script type="application/ld+json">'
        '{"@type":"Product","name":"Mac Studio M5 Max","offers":{"price":"3199","url":"data:text/html,bad"}}'
        "</script>"
    )
    jsonld_listings = parse_html_css(
        jsonld_html,
        SourceConfig(name="LD", adapter="html_css", url="https://store.example.com/p"),
    )
    assert len(jsonld_listings) == 1
    assert jsonld_listings[0].url == ""

    # 4. AppleInsider
    ai_html = (
        '<script type="application/ld+json">'
        '{"@type":"Product","name":"Mac Studio M5 Max","offers":[{"price":"3299","url":"javascript:alert(9)"}]}'
        "</script>"
    )
    ai_listings = parse_appleinsider_html(
        ai_html,
        SourceConfig(
            name="AI",
            adapter="appleinsider",
            url="https://prices.appleinsider.com/mac-studio-m5-max",
        ),
    )
    assert len(ai_listings) == 1
    assert ai_listings[0].url == ""


async def test_waha_follow_redirects_false_and_no_secret_leaks(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret_key = "super-secret-waha-api-key-98765"
    monkeypatch.setenv("WAHA_API_KEY", secret_key)
    monkeypatch.delenv("WAHA_URL", raising=False)
    monkeypatch.delenv("WAHA_SESSION", raising=False)
    _mock_dns(monkeypatch, {"waha.docker": [(socket.AF_INET, "172.18.0.5")]})

    # 1. Verify AsyncClient is created with follow_redirects=False and rejects 302 redirects
    captured_client_kwargs: list[dict[str, Any]] = []
    real_async_client = httpx.AsyncClient

    def tracking_async_client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        captured_client_kwargs.append(dict(kwargs))
        return real_async_client(
            *args,
            transport=httpx.MockTransport(
                lambda _req: httpx.Response(
                    302,
                    headers={"Location": "http://169.254.169.254/steal"},
                )
            ),
            **kwargs,
        )

    monkeypatch.setattr(http_client_mod := httpx, "AsyncClient", tracking_async_client)
    assert http_client_mod is httpx

    waha_cfg = WahaConfig(url="http://waha.docker", session="pricewatcher")
    waha = WahaClient(waha_cfg)
    with caplog.at_level(logging.DEBUG):
        redirect_res = await waha.send_text("15550001@c.us", "hello")
        redirect_health = await waha.check_health()

    assert len(captured_client_kwargs) == 2
    assert all(kw.get("follow_redirects") is False for kw in captured_client_kwargs)
    assert redirect_res.ok is False
    assert "302" in (redirect_res.error or "")
    assert redirect_health["ok"] is False

    # 2. Failure body/exception echoing X-Api-Key must NEVER leak into errors, DeliveryResult, or logs
    monkeypatch.setattr(httpx, "AsyncClient", real_async_client)

    def failing_echo_handler(request: httpx.Request) -> httpx.Response:
        echoed = request.headers.get("X-Api-Key", "")
        return httpx.Response(
            500,
            text=f"Upstream failed with X-Api-Key: {echoed} raw={secret_key}",
        )

    echo_client = real_async_client(transport=httpx.MockTransport(failing_echo_handler))
    waha_echo = WahaClient(waha_cfg, client=echo_client)

    settings = SettingsConfig(
        notifications=NotificationsConfig(
            waha=waha_cfg,
            email=EmailConfig(enabled=False),
            recipients={
                "primary": RecipientConfig(name="Primary User", waha_chat_id="15550001@c.us")
            },
        )
    )
    watch = WatchConfig(
        id="waha-test",
        name="WAHA Test",
        alerts=AlertsConfig(recipients=["primary"], delivery="waha_only"),
    )
    dispatcher = NotificationDispatcher(settings, waha_client=waha_echo)
    with caplog.at_level(logging.DEBUG):
        results = await dispatcher.dispatch(
            watch=watch,
            tier_key="base",
            alert_type="target_hit",
            subject="subj",
            message="msg",
        )
    await echo_client.aclose()

    assert len(results) == 1
    assert results[0].ok is False
    assert results[0].error is not None
    assert secret_key not in results[0].error
    assert "[REDACTED]" in results[0].error
    assert secret_key not in caplog.text

    # 3. Exception containing secret is also redacted
    def raising_handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"Failed connecting with X-Api-Key={secret_key}")

    exc_client = real_async_client(transport=httpx.MockTransport(raising_handler))
    waha_exc = WahaClient(waha_cfg, client=exc_client)
    with caplog.at_level(logging.DEBUG):
        exc_res = await waha_exc.send_text("15550001@c.us", "hello")
        exc_health = await waha_exc.check_health()
    await exc_client.aclose()

    assert exc_res.ok is False
    assert exc_res.error is not None and secret_key not in exc_res.error
    assert exc_health["ok"] is False
    assert secret_key not in exc_health["detail"]
    assert secret_key not in caplog.text

    # 4. Embedded credentials or bad scheme in WAHA URL rejected cleanly
    bad_waha = WahaClient(WahaConfig(url="http://admin:waha-pass@waha.docker"))
    bad_send = await bad_waha.send_text("15550001@c.us", "hello")
    bad_health = await bad_waha.check_health()
    assert bad_send.ok is False
    assert "SSRFBlockedError" in (bad_send.error or "")
    assert "waha-pass" not in (bad_send.error or "")
    assert bad_health["ok"] is False
    assert "waha-pass" not in bad_health["url"]


async def test_waha_check_health_404_describes_sessions_and_logs_list_failures(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _mock_dns(monkeypatch, {"waha.docker": [(socket.AF_INET, "172.18.0.5")]})
    monkeypatch.delenv("WAHA_API_KEY", raising=False)
    monkeypatch.delenv("WAHA_URL", raising=False)
    monkeypatch.delenv("WAHA_SESSION", raising=False)

    waha_cfg = WahaConfig(url="http://waha.docker", session="pricewatcher")

    # 1. 404 on session + 200 on session list works for both injected and ephemeral clients
    def listing_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/sessions/pricewatcher":
            return httpx.Response(404, json={"error": "not found"})
        if request.url.path == "/api/sessions" and request.url.params.get("all") == "true":
            return httpx.Response(200, json=[{"name": "default"}, {"name": "backup"}])
        return httpx.Response(500)

    async with httpx.AsyncClient(transport=httpx.MockTransport(listing_handler)) as injected_client:
        health_injected = await WahaClient(waha_cfg, client=injected_client).check_health()
        direct_detail = await _describe_missing_session(
            injected_client,
            "http://waha.docker",
            "pricewatcher",
        )

    assert health_injected["ok"] is False
    assert health_injected["status"] == "http_404"
    assert health_injected["detail"] == (
        "Session 'pricewatcher' not found (available: default, backup)"
    )
    assert direct_detail == health_injected["detail"]

    real_async_client = httpx.AsyncClient
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda *args, **kwargs: real_async_client(
            *args,
            transport=httpx.MockTransport(listing_handler),
            **kwargs,
        ),
    )
    health_ephemeral = await WahaClient(waha_cfg).check_health()
    assert health_ephemeral == health_injected

    # 2. Failure while listing sessions is logged at DEBUG with exc_info (not swallowed)
    monkeypatch.setattr(httpx, "AsyncClient", real_async_client)

    def failing_list_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/sessions/pricewatcher":
            return httpx.Response(404)
        raise httpx.ConnectError("session-list-unavailable")

    async with real_async_client(transport=httpx.MockTransport(failing_list_handler)) as client:
        with caplog.at_level(logging.DEBUG, logger="pricewatcher.notifiers.waha"):
            health_list_err = await WahaClient(waha_cfg, client=client).check_health()

    assert health_list_err["ok"] is False
    assert health_list_err["status"] == "http_404"
    assert health_list_err["detail"] == "Session 'pricewatcher' not found (HTTP 404)"
    assert any(
        rec.name == "pricewatcher.notifiers.waha"
        and rec.levelno == logging.DEBUG
        and "Failed to list WAHA sessions" in rec.message
        and rec.exc_info is not None
        for rec in caplog.records
    )

    # 3. Secret embedded in a listing-session exception must never leak into debug logs
    secret_key = "super-secret-waha-list-key-54321"
    monkeypatch.setenv("WAHA_API_KEY", secret_key)
    caplog.clear()

    def secret_failing_list_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/sessions/pricewatcher":
            return httpx.Response(404)
        raise httpx.ConnectError(f"Failed with X-Api-Key={secret_key}")

    async with real_async_client(
        transport=httpx.MockTransport(secret_failing_list_handler)
    ) as secret_client:
        with caplog.at_level(logging.DEBUG, logger="pricewatcher.notifiers.waha"):
            health_secret_err = await WahaClient(waha_cfg, client=secret_client).check_health()

    assert health_secret_err["status"] == "http_404"
    assert health_secret_err["detail"] == "Session 'pricewatcher' not found (HTTP 404)"
    assert secret_key not in caplog.text
    assert "[REDACTED]" in caplog.text


async def test_email_client_redacts_smtp_credentials_on_failure(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    smtp_user = "alerts-sender@example.com"
    smtp_pass = "ultra-secret-smtp-password-4321"
    monkeypatch.setenv("SMTP_USER", smtp_user)
    monkeypatch.setenv("SMTP_PASS", smtp_pass)

    b64_pass = base64.b64encode(smtp_pass.encode()).decode("ascii")

    class FailingSMTP:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def __enter__(self) -> FailingSMTP:
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

        def ehlo(self) -> None:
            return None

        def starttls(self) -> None:
            return None

        def login(self, user: str, password: str) -> None:
            raise smtplib.SMTPAuthenticationError(
                535,
                f"5.7.8 Auth failed for {user} secret={password} b64={b64_pass}".encode(),
            )

    monkeypatch.setattr(smtplib, "SMTP", FailingSMTP)

    email_client = EmailClient(EmailConfig(enabled=True, smtp_host="smtp.example.com"))
    with caplog.at_level(logging.DEBUG):
        res = await email_client.send_email("dest@example.com", "Alert", "Body")

    assert res.ok is False
    assert res.error is not None
    assert smtp_pass not in res.error
    assert b64_pass not in res.error
    assert smtp_user not in res.error
    assert "[REDACTED]" in res.error
    assert smtp_pass not in caplog.text


async def test_http_context_fallback_works_across_multiple_event_loops(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_dns(monkeypatch, {"loop.example.com": [(socket.AF_INET, "93.184.216.34")]})

    def run_in_fresh_loop() -> str:
        async def _inner() -> str:
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(lambda _r: httpx.Response(200, text="loop-ok"))
            ) as client:
                resp = await polite_get(
                    "https://loop.example.com/item",
                    min_interval_s=0.05,
                    client=client,
                )
                return resp.text

        return asyncio.run(_inner())

    assert await asyncio.to_thread(run_in_fresh_loop) == "loop-ok"
    assert await asyncio.to_thread(run_in_fresh_loop) == "loop-ok"


async def test_shared_http_context_isolates_pool_origins_and_cookies_per_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_dns(
        monkeypatch,
        {
            "site-a.example.com": [(socket.AF_INET, "93.184.216.34")],
            "site-b.example.com": [(socket.AF_INET, "93.184.216.34")],
        },
    )

    recorded_connects: list[tuple[str, int]] = []
    recorded_urls: list[str] = []
    recorded_cookies: list[str | None] = []

    async with HttpContext(min_interval_s=0.0) as ctx:
        assert ctx.client.trust_env is False
        pool = ctx.client._transport._pool  # type: ignore[attr-defined]
        assert isinstance(pool._network_backend, http_client._PinnedAnyIOBackend)

        # Verify cookie jar rejects all cookies (never persists Set-Cookie across hosts sharing an IP)
        async def fake_connect_tcp(
            _self: Any,
            host: str,
            port: int,
            **_kwargs: Any,
        ) -> Any:
            recorded_connects.append((host, port))
            raise OSError("synthetic-stop")

        # Test via cookie policy directly and via pool request URL handling
        async def cookie_echo_handler(request: httpx.Request) -> httpx.Response:
            recorded_urls.append(str(request.url))
            recorded_cookies.append(request.headers.get("cookie"))
            return httpx.Response(
                200,
                text="ok",
                headers={"Set-Cookie": "session=leaked-cookie; Path=/"},
            )

        # Simulate two hosts sharing an IP with an AsyncClient sharing the same _RejectAllCookiePolicy
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(cookie_echo_handler),
            cookies=http_client._new_isolated_cookies(),
            trust_env=False,
        ) as isolated_client:
            # Pretend backend is pinned so real hostnames stay in request.url
            pool_transport = isolated_client._transport
            pool_transport._pool = SimpleNamespace(  # type: ignore[attr-defined]
                _network_backend=http_client._PinnedAnyIOBackend()
            )
            async with HttpContext(min_interval_s=0.0, client=isolated_client) as test_ctx:
                await polite_get("https://site-a.example.com/1", http_ctx=test_ctx)
                await polite_get("https://site-b.example.com/2", http_ctx=test_ctx)

        assert recorded_urls == [
            "https://site-a.example.com/1",
            "https://site-b.example.com/2",
        ]
        assert recorded_cookies == [None, None]

        # Also verify _PinnedAnyIOBackend substitutes the ContextVar-pinned IP at connect_tcp
        monkeypatch.setattr(
            http_client.httpcore.AnyIOBackend,
            "connect_tcp",
            fake_connect_tcp,
        )
        token = http_client._PINNED_TARGET_CTX.set(("site-a.example.com", 443, "93.184.216.34"))
        try:
            with pytest.raises(OSError, match="synthetic-stop"):
                await pool._network_backend.connect_tcp("site-a.example.com", 443)
        finally:
            http_client._PINNED_TARGET_CTX.reset(token)
        assert recorded_connects == [("93.184.216.34", 443)]
