"""Shared HTTP/1.1 client with SSRF protection, response size caps, and politeness.

Implements:
- Outbound URL validation blocking non-HTTP(S) schemes, embedded credentials,
  and non-routable IPv4/IPv6 ranges (respecting ``PRICEWATCHER_ALLOW_PRIVATE_HOSTS``).
- DNS rebinding protection via ContextVar-scoped TCP IP pinning inside
  ``_PinnedAnyIOBackend`` (keeping pooled TLS origins isolated per hostname).
- Manual 5-hop redirect loop re-validating every ``Location`` target.
- Bounded response streaming capped by ``PRICEWATCHER_MAX_RESPONSE_BYTES`` (default 5 MiB)
  and per-domain politeness rate limiting via ``HttpContext``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable
from contextvars import ContextVar
from dataclasses import dataclass
from http.cookiejar import Cookie, CookiePolicy, DefaultCookiePolicy
import ipaddress
import os
import socket
import time
from types import TracebackType
from typing import Any
from urllib.parse import urljoin, urlsplit
from urllib.request import Request as CookieRequest
import weakref

import httpcore
import httpx

BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)
DEFAULT_CONTACT_URL = "https://github.com/your-username/pricewatcher"
DEFAULT_MAX_RESPONSE_BYTES = 5_242_880
MAX_REDIRECT_HOPS = 5
DEFAULT_MIN_INTERVAL_S = 1.5
REDDIT_MIN_INTERVAL_S = 2.0

_BLOCKED_IPV4_NETWORKS = (
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("100.64.0.0/10"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)

_BLOCKED_IPV6_NETWORKS = (
    ipaddress.IPv6Network("::/128"),
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("fc00::/7"),
    ipaddress.IPv6Network("fe80::/10"),
    ipaddress.IPv6Network("ff00::/8"),
)


class SSRFBlockedError(ValueError):
    """Raised when an outbound URL resolves to or targets a blocked destination."""


class ResponseTooLargeError(ValueError):
    """Raised when an HTTP response exceeds the configured byte limit."""


@dataclass(frozen=True)
class ValidatedTarget:
    """Validated outbound target with pinned IP, Host header, and TLS SNI hostname."""

    url: str
    scheme: str
    hostname: str
    sni_hostname: str
    port: int
    pinned_ip: str
    pinned_url: str
    host_header: str
    resolved_ips: tuple[str, ...]


def get_reddit_user_agent() -> str:
    """Build the Reddit User-Agent string with a configurable contact URL."""
    contact_url = os.environ.get("PRICEWATCHER_CONTACT_URL", "").strip() or DEFAULT_CONTACT_URL
    return f"PriceWatcher/1.0 (self-hosted deal monitor; +{contact_url})"


def get_max_response_bytes() -> int:
    """Return max allowed response size in bytes from PRICEWATCHER_MAX_RESPONSE_BYTES."""
    raw = os.environ.get("PRICEWATCHER_MAX_RESPONSE_BYTES", "").strip()
    if not raw:
        return DEFAULT_MAX_RESPONSE_BYTES
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"Invalid PRICEWATCHER_MAX_RESPONSE_BYTES: {raw!r}") from exc
    if value <= 0:
        raise ValueError(f"PRICEWATCHER_MAX_RESPONSE_BYTES must be positive, got {value}")
    return value


def _get_allowed_private_hosts() -> set[str]:
    raw = os.environ.get("PRICEWATCHER_ALLOW_PRIVATE_HOSTS", "")
    allowed: set[str] = set()
    for part in raw.split(","):
        item = part.strip().lower()
        if not item:
            continue
        if item.startswith("[") and item.endswith("]"):
            item = item[1:-1]
        if item:
            allowed.add(item)
    return allowed


def _is_ip_globally_routable(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True only if ip_obj (and any IPv4-mapped address) is globally routable."""
    if (
        not ip_obj.is_global
        or ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    ):
        return False

    if isinstance(ip_obj, ipaddress.IPv4Address):
        return not any(ip_obj in net for net in _BLOCKED_IPV4_NETWORKS)

    if ip_obj.is_site_local or any(ip_obj in net for net in _BLOCKED_IPV6_NETWORKS):
        return False

    if ip_obj.ipv4_mapped is not None:
        return _is_ip_globally_routable(ip_obj.ipv4_mapped)
    return True


def _validate_url_syntax(url: str) -> tuple[str, str, str, int, httpx.URL]:
    """Validate scheme, absence of embedded credentials, hostname, and port without DNS."""
    if not isinstance(url, str):
        raise SSRFBlockedError("URL must be a string")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in url):
        raise SSRFBlockedError("URL contains control characters")

    cleaned = url.strip()
    if not cleaned:
        raise SSRFBlockedError("Empty URL")

    sp = urlsplit(cleaned)
    scheme = sp.scheme.lower()
    if scheme not in {"http", "https"}:
        raise SSRFBlockedError(f"Blocked URL scheme: {scheme or '<empty>'}")

    if sp.username is not None or sp.password is not None or "@" in sp.netloc:
        raise SSRFBlockedError("URL must not contain embedded credentials")
    if "\\" in sp.netloc:
        raise SSRFBlockedError("URL authority contains invalid backslash")

    try:
        hx_url = httpx.URL(cleaned)
    except httpx.InvalidURL as exc:
        raise SSRFBlockedError(f"Malformed URL: {exc}") from exc

    if hx_url.userinfo:
        raise SSRFBlockedError("URL must not contain embedded credentials")

    hostname = (sp.hostname or "").lower()
    hx_host = (hx_url.host or "").lower()
    if not hostname or not hx_host or hostname != hx_host:
        raise SSRFBlockedError("URL missing or ambiguous hostname")
    if "%" in hostname:
        raise SSRFBlockedError("IPv6 zone IDs are not allowed")

    try:
        parsed_port = sp.port
    except ValueError as exc:
        raise SSRFBlockedError(f"Invalid port in URL: {exc}") from exc

    if parsed_port is not None and not (1 <= parsed_port <= 65535):
        raise SSRFBlockedError(f"Port out of range: {parsed_port}")

    port = parsed_port if parsed_port is not None else (443 if scheme == "https" else 80)
    return cleaned, scheme, hostname, port, hx_url


def validate_outbound_url(url: str, *, allow_private: bool = False) -> ValidatedTarget:
    """Validate an outbound HTTP(S) URL against SSRF rules and resolve/pin its IP."""
    cleaned, scheme, hostname, port, hx_url = _validate_url_syntax(url)
    allowlist = _get_allowed_private_hosts()
    is_allowed = allow_private or (hostname in allowlist)

    try:
        addrinfo = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        if allow_private:
            pinned_url = str(hx_url.copy_with(fragment=None))
            return ValidatedTarget(
                url=cleaned,
                scheme=scheme,
                hostname=hostname,
                sni_hostname=hx_url.raw_host.decode("ascii"),
                port=port,
                pinned_ip="",
                pinned_url=pinned_url,
                host_header=hx_url.netloc.decode("ascii"),
                resolved_ips=(),
            )
        raise SSRFBlockedError(f"DNS resolution failed for {hostname}: {exc}") from exc

    if not addrinfo:
        raise SSRFBlockedError(f"DNS resolved no addresses for {hostname}")

    resolved_ips: list[str] = []
    seen_ips: set[str] = set()
    first_ipv4: str | None = None

    for entry in addrinfo:
        sockaddr = entry[4]
        raw_ip = str(sockaddr[0])
        if "%" in raw_ip:
            raise SSRFBlockedError(f"Zone ID in resolved address is not allowed: {raw_ip}")
        try:
            ip_obj = ipaddress.ip_address(raw_ip)
        except ValueError as exc:
            raise SSRFBlockedError(f"Invalid resolved IP address: {raw_ip}") from exc

        if not is_allowed and not _is_ip_globally_routable(ip_obj):
            raise SSRFBlockedError(f"Blocked non-public IP address {ip_obj} for host {hostname}")

        canonical_ip = str(ip_obj)
        if canonical_ip not in seen_ips:
            seen_ips.add(canonical_ip)
            resolved_ips.append(canonical_ip)
            if first_ipv4 is None and ip_obj.version == 4:
                first_ipv4 = canonical_ip

    pinned_ip = first_ipv4 or resolved_ips[0]
    pinned_url = str(hx_url.copy_with(host=pinned_ip, fragment=None))
    return ValidatedTarget(
        url=cleaned,
        scheme=scheme,
        hostname=hostname,
        sni_hostname=hx_url.raw_host.decode("ascii"),
        port=port,
        pinned_ip=pinned_ip,
        pinned_url=pinned_url,
        host_header=hx_url.netloc.decode("ascii"),
        resolved_ips=tuple(resolved_ips),
    )


_PINNED_TARGET_CTX: ContextVar[tuple[str, int, str] | None] = ContextVar(
    "_PINNED_TARGET_CTX", default=None
)


class _RejectAllCookiePolicy(DefaultCookiePolicy):
    """CookiePolicy rejecting all Set-Cookie storage and Cookie header transmission."""

    def set_ok(self, cookie: Cookie, request: CookieRequest) -> bool:
        return False

    def return_ok(self, cookie: Cookie, request: CookieRequest) -> bool:
        return False

    def domain_return_ok(self, domain: str, request: CookieRequest) -> bool:
        return False

    def path_return_ok(self, path: str, request: CookieRequest) -> bool:
        return False


def _new_isolated_cookies() -> httpx.Cookies:
    cookies = httpx.Cookies()
    policy: CookiePolicy = _RejectAllCookiePolicy()
    cookies.jar.set_policy(policy)
    return cookies


class _PinnedAnyIOBackend(httpcore.AnyIOBackend):
    """Network backend that pins TCP connections to the ContextVar-validated IP per request."""

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        pinned = _PINNED_TARGET_CTX.get()
        connect_host = host
        if pinned is not None:
            expected_host, expected_port, pinned_ip = pinned
            if pinned_ip and host.lower() == expected_host and port == expected_port:
                connect_host = pinned_ip
        return await super().connect_tcp(
            connect_host,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )


def _build_pinned_async_client(
    *, timeout: float, limits: httpx.Limits | None = None
) -> httpx.AsyncClient:
    resolved_limits = limits if limits is not None else httpx.Limits()
    transport = httpx.AsyncHTTPTransport(
        http1=True,
        http2=False,
        limits=resolved_limits,
        trust_env=False,
    )
    pool = getattr(transport, "_pool", None)
    if pool is not None and hasattr(pool, "_network_backend"):
        pool._network_backend = _PinnedAnyIOBackend()
    return httpx.AsyncClient(
        http2=False,
        follow_redirects=False,
        timeout=timeout,
        limits=resolved_limits,
        transport=transport,
        cookies=_new_isolated_cookies(),
        trust_env=False,
    )


def _uses_pinned_network_backend(client: httpx.AsyncClient) -> bool:
    transport = getattr(client, "_transport", None)
    pool = getattr(transport, "_pool", None)
    backend = getattr(pool, "_network_backend", None)
    return isinstance(backend, _PinnedAnyIOBackend)


class HttpContext:
    """Async context manager holding a pooled HTTP/1.1 client and per-host rate limits."""

    def __init__(
        self,
        *,
        min_interval_s: float = DEFAULT_MIN_INTERVAL_S,
        timeout: float = 20.0,
        max_response_bytes: int | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.min_interval_s = min_interval_s
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self._owns_client = client is None
        self._pool_limits = httpx.Limits(max_connections=20, max_keepalive_connections=10)
        self.client: httpx.AsyncClient = (
            client
            if client is not None
            else _build_pinned_async_client(timeout=timeout, limits=self._pool_limits)
        )
        self._domain_locks: dict[str, asyncio.Lock] = {}
        self._last_request_at: dict[str, float] = {}

    async def __aenter__(self) -> HttpContext:
        if self._owns_client:
            if self.client.is_closed:
                self.client = _build_pinned_async_client(
                    timeout=self.timeout, limits=self._pool_limits
                )
            await self.client.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None = None,
        exc_val: BaseException | None = None,
        exc_tb: TracebackType | None = None,
    ) -> None:
        if self._owns_client:
            await self.client.__aexit__(exc_type, exc_val, exc_tb)

    async def aclose(self) -> None:
        if self._owns_client:
            await self.client.aclose()


_DOMAIN_LOCKS_BY_LOOP: weakref.WeakKeyDictionary[
    asyncio.AbstractEventLoop, dict[str, asyncio.Lock]
] = weakref.WeakKeyDictionary()
_LAST_REQUEST_AT: dict[str, float] = {}
_MAX_RESPONSE_BYTES_CTX: ContextVar[int | None] = ContextVar(
    "_MAX_RESPONSE_BYTES_CTX", default=None
)


def _get_fallback_lock(host: str) -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    locks = _DOMAIN_LOCKS_BY_LOOP.get(loop)
    if locks is None:
        locks = {}
        _DOMAIN_LOCKS_BY_LOOP[loop] = locks
    return locks.setdefault(host, asyncio.Lock())


@dataclass
class HttpResponse:
    status_code: int
    url: str
    headers: dict[str, str]
    text: str
    raw_body: bytes = b""


async def polite_get(
    url: str,
    *,
    accept: str | None = None,
    politeness_delay_seconds: float | None = None,
    min_interval_s: float | None = None,
    timeout: float | None = None,
    client: httpx.AsyncClient | None = None,
    http_ctx: HttpContext | None = None,
    max_response_bytes: int | None = None,
) -> HttpResponse:
    """Perform an SSRF-validated HTTP/1.1 GET with per-domain rate limiting."""
    cleaned, _, host, _, _ = _validate_url_syntax(url)
    is_reddit = host == "reddit.com" or host.endswith(".reddit.com")

    ua = get_reddit_user_agent() if is_reddit else BROWSER_UA
    default_accept = (
        "application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.8"
        if (".rss" in cleaned or "rss=1" in cleaned)
        else "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    )
    headers = {
        "User-Agent": ua,
        "Accept": accept or default_accept,
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
    }

    if min_interval_s is not None:
        base_delay = min_interval_s
    elif politeness_delay_seconds is not None and politeness_delay_seconds > 0:
        base_delay = politeness_delay_seconds
    elif http_ctx is not None:
        base_delay = http_ctx.min_interval_s
    else:
        base_delay = DEFAULT_MIN_INTERVAL_S

    if is_reddit and min_interval_s is None and base_delay > 0:
        delay = max(base_delay, REDDIT_MIN_INTERVAL_S)
    else:
        delay = base_delay

    effective_timeout = (
        timeout if timeout is not None else (http_ctx.timeout if http_ctx is not None else 20.0)
    )
    active_client = (
        client if client is not None else (http_ctx.client if http_ctx is not None else None)
    )
    effective_max_bytes = (
        max_response_bytes
        if max_response_bytes is not None
        else (http_ctx.max_response_bytes if http_ctx is not None else None)
    )

    token = _MAX_RESPONSE_BYTES_CTX.set(effective_max_bytes)
    try:
        if delay > 0:
            if http_ctx is not None:
                lock = http_ctx._domain_locks.setdefault(host, asyncio.Lock())
                last_request_at = http_ctx._last_request_at
            else:
                lock = _get_fallback_lock(host)
                last_request_at = _LAST_REQUEST_AT

            async with lock:
                last = last_request_at.get(host)
                if last is not None:
                    wait_for = delay - (time.monotonic() - last)
                    if wait_for > 0:
                        await asyncio.sleep(wait_for)
                try:
                    resp = await _send_get(
                        cleaned,
                        headers=headers,
                        timeout=effective_timeout,
                        client=active_client,
                    )
                except SSRFBlockedError:
                    raise
                except Exception:
                    last_request_at[host] = time.monotonic()
                    raise
                last_request_at[host] = time.monotonic()
                return resp

        return await _send_get(
            cleaned,
            headers=headers,
            timeout=effective_timeout,
            client=active_client,
        )
    finally:
        _MAX_RESPONSE_BYTES_CTX.reset(token)


async def _read_bounded_body(resp: httpx.Response, max_bytes: int) -> tuple[str, bytes]:
    raw_cl = resp.headers.get("content-length")
    if raw_cl is not None:
        try:
            content_length = int(raw_cl.strip())
        except ValueError:
            content_length = None
        if content_length is not None and content_length > max_bytes:
            raise ResponseTooLargeError(
                f"Response Content-Length {content_length} exceeds limit of {max_bytes} bytes"
            )

    chunk_size = max(1, min(65536, max_bytes + 1))
    chunks: list[bytes] = []
    total_bytes = 0
    async for chunk in resp.aiter_bytes(chunk_size=chunk_size):
        total_bytes += len(chunk)
        if total_bytes > max_bytes:
            raise ResponseTooLargeError(f"Response body exceeded limit of {max_bytes} bytes")
        chunks.append(chunk)

    body = b"".join(chunks)
    if not body:
        return "", b""
    encoding = resp.encoding or "utf-8"
    try:
        return body.decode(encoding, errors="replace"), body
    except LookupError:
        return body.decode("utf-8", errors="replace"), body


async def _perform_pinned_get(
    url: str,
    *,
    headers: dict[str, str],
    timeout: float,
    client: httpx.AsyncClient,
    max_bytes: int,
) -> HttpResponse:
    use_backend_pin = _uses_pinned_network_backend(client)
    current_url = url
    for hop in range(MAX_REDIRECT_HOPS + 1):
        target = validate_outbound_url(current_url)
        pin_token = None
        req_kwargs: dict[str, Any] = {
            "timeout": timeout,
            "follow_redirects": False,
        }
        if use_backend_pin:
            # Keep real hostname in request.url so httpcore isolates pooled TLS sockets by origin,
            # while _PinnedAnyIOBackend pins TCP connect_tcp() to the pre-validated IP.
            request_target_url = target.url
            req_kwargs["headers"] = httpx.Headers(headers)
            pin_token = _PINNED_TARGET_CTX.set(
                (target.sni_hostname.lower(), target.port, target.pinned_ip)
            )
        else:
            req_headers = httpx.Headers(headers)
            req_headers["Host"] = target.host_header
            extensions = {"sni_hostname": target.sni_hostname} if target.scheme == "https" else {}
            request_target_url = target.pinned_url
            req_kwargs["headers"] = req_headers
            req_kwargs["extensions"] = extensions

        try:
            async with client.stream("GET", request_target_url, **req_kwargs) as resp:
                if resp.has_redirect_location:
                    if hop >= MAX_REDIRECT_HOPS:
                        raise httpx.TooManyRedirects(
                            f"Exceeded maximum redirect hops ({MAX_REDIRECT_HOPS})",
                            request=resp.request,
                        )
                    location = resp.headers["location"]
                    current_url = urljoin(current_url, location)
                    continue

                text, raw_body = await _read_bounded_body(resp, max_bytes)
                return HttpResponse(
                    status_code=resp.status_code,
                    url=current_url,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    text=text,
                    raw_body=raw_body,
                )
        finally:
            if pin_token is not None:
                _PINNED_TARGET_CTX.reset(pin_token)

    raise httpx.TooManyRedirects(f"Exceeded maximum redirect hops ({MAX_REDIRECT_HOPS})")


async def _send_get(
    url: str,
    *,
    headers: dict[str, str],
    timeout: float,
    client: httpx.AsyncClient | None,
) -> HttpResponse:
    ctx_limit = _MAX_RESPONSE_BYTES_CTX.get()
    max_bytes = ctx_limit if ctx_limit is not None else get_max_response_bytes()

    if client is not None:
        return await _perform_pinned_get(
            url,
            headers=headers,
            timeout=timeout,
            client=client,
            max_bytes=max_bytes,
        )

    # Phase 1 proved AppleInsider and several stores require HTTP/1.1
    async with _build_pinned_async_client(timeout=timeout) as owned_client:
        return await _perform_pinned_get(
            url,
            headers=headers,
            timeout=timeout,
            client=owned_client,
            max_bytes=max_bytes,
        )
