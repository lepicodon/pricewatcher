"""Tests for HTTP client User-Agent configuration."""

from __future__ import annotations

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
