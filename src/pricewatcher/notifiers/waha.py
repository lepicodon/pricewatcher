"""WAHA (WhatsApp HTTP API) client using dedicated PriceWatcher session."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from pricewatcher.config import WahaConfig
from pricewatcher.http_client import SSRFBlockedError, validate_outbound_url

_API_KEY_HEADER_RE = re.compile(r"(?i)(x-api-key[\"']?\s*[:=]\s*[\"']?)([^\"'\s,;}\]]+)")


def _redact_waha_secret(text: str, api_key: str) -> str:
    redacted = text
    if api_key:
        redacted = redacted.replace(api_key, "[REDACTED]")
    return _API_KEY_HEADER_RE.sub(r"\1[REDACTED]", redacted)


def _sanitize_url_for_display(raw_url: str) -> str:
    try:
        sp = urlsplit(raw_url.strip())
    except ValueError:
        return "<invalid-url>"
    if "@" in sp.netloc:
        _, _, hostport = sp.netloc.rpartition("@")
        return urlunsplit((sp.scheme, hostport, sp.path, "", ""))
    return raw_url


@dataclass
class ChannelSendResult:
    ok: bool
    error: str | None = None


class WahaClient:
    """Client for a WAHA session behind Traefik (or LAN/localhost)."""

    def __init__(
        self,
        config: WahaConfig,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.config = config
        self._client = client

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        api_key = self.config.effective_api_key()
        if api_key:
            headers["X-Api-Key"] = api_key
        return headers

    async def check_health(self) -> dict[str, Any]:
        base_url = self.config.effective_url()
        session = self.config.effective_session()
        api_key = self.config.effective_api_key()
        try:
            validate_outbound_url(base_url, allow_private=True)
        except SSRFBlockedError as exc:
            return {
                "ok": False,
                "status": "invalid_url",
                "url": _sanitize_url_for_display(base_url),
                "session": session,
                "detail": _redact_waha_secret(f"{type(exc).__name__}: {exc}", api_key),
            }

        endpoint = f"{base_url}/api/sessions/{session}"
        try:
            if self._client is not None:
                resp = await self._client.get(
                    endpoint,
                    headers=self._headers(),
                    timeout=8.0,
                    follow_redirects=False,
                )
                if resp.status_code == 404:
                    detail = f"Session {session!r} not found (HTTP 404)"
                    try:
                        list_resp = await self._client.get(
                            f"{base_url}/api/sessions?all=true",
                            headers=self._headers(),
                            timeout=8.0,
                            follow_redirects=False,
                        )
                        if list_resp.status_code == 200 and isinstance(list_resp.json(), list):
                            names = [
                                str(item.get("name"))
                                for item in list_resp.json()
                                if isinstance(item, dict) and item.get("name")
                            ]
                            if names:
                                detail = (
                                    f"Session {session!r} not found (available: {', '.join(names)})"
                                )
                    except Exception:
                        pass
                    return {
                        "ok": False,
                        "status": "http_404",
                        "url": base_url,
                        "session": session,
                        "detail": detail,
                    }
            else:
                async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
                    resp = await client.get(endpoint, headers=self._headers())
                    if resp.status_code == 404:
                        detail = f"Session {session!r} not found (HTTP 404)"
                        try:
                            list_resp = await client.get(
                                f"{base_url}/api/sessions?all=true",
                                headers=self._headers(),
                            )
                            if list_resp.status_code == 200 and isinstance(list_resp.json(), list):
                                names = [
                                    str(item.get("name"))
                                    for item in list_resp.json()
                                    if isinstance(item, dict) and item.get("name")
                                ]
                                if names:
                                    detail = (
                                        f"Session {session!r} not found "
                                        f"(available: {', '.join(names)})"
                                    )
                        except Exception:
                            pass
                        return {
                            "ok": False,
                            "status": "http_404",
                            "url": base_url,
                            "session": session,
                            "detail": detail,
                        }
        except Exception as exc:
            return {
                "ok": False,
                "status": "unreachable",
                "url": base_url,
                "session": session,
                "detail": _redact_waha_secret(f"{type(exc).__name__}: {exc}", api_key),
            }

        if 300 <= resp.status_code < 400:
            return {
                "ok": False,
                "status": f"http_{resp.status_code}",
                "url": base_url,
                "session": session,
                "detail": f"WAHA returned HTTP {resp.status_code} (redirects disabled)",
            }

        if resp.status_code >= 400:
            return {
                "ok": False,
                "status": f"http_{resp.status_code}",
                "url": base_url,
                "session": session,
                "detail": f"WAHA returned HTTP {resp.status_code}",
            }

        try:
            data = resp.json()
        except ValueError:
            data = {}

        session_status = str(data.get("status") or "UNKNOWN").upper()
        ok = session_status in ("WORKING", "CONNECTED", "READY")
        return {
            "ok": ok,
            "status": session_status,
            "url": base_url,
            "session": session,
            "detail": f"Session {session!r} status: {session_status}",
        }

    async def send_text(self, chat_id: str, text: str) -> ChannelSendResult:
        base_url = self.config.effective_url()
        session = self.config.effective_session()
        api_key = self.config.effective_api_key()
        try:
            validate_outbound_url(base_url, allow_private=True)
        except SSRFBlockedError as exc:
            return ChannelSendResult(
                ok=False,
                error=_redact_waha_secret(f"{type(exc).__name__}: {exc}", api_key),
            )

        endpoint = f"{base_url}/api/sendText"
        payload = {
            "session": session,
            "chatId": chat_id,
            "text": text,
        }
        try:
            if self._client is not None:
                resp = await self._client.post(
                    endpoint,
                    json=payload,
                    headers=self._headers(),
                    timeout=15.0,
                    follow_redirects=False,
                )
            else:
                async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
                    resp = await client.post(endpoint, json=payload, headers=self._headers())
        except Exception as exc:
            return ChannelSendResult(
                ok=False,
                error=_redact_waha_secret(f"{type(exc).__name__}: {exc}", api_key),
            )

        if 300 <= resp.status_code < 400:
            return ChannelSendResult(
                ok=False,
                error=f"WAHA HTTP {resp.status_code}: redirects disabled",
            )

        if resp.status_code >= 400:
            safe_text = _redact_waha_secret(resp.text, api_key)[:200]
            return ChannelSendResult(
                ok=False,
                error=f"WAHA HTTP {resp.status_code}: {safe_text}",
            )
        return ChannelSendResult(ok=True)
