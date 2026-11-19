"""Authentication, session cookies, CSRF protection, safe URLs, and security headers.

Implements:
- Fail-closed admin authentication backed by stdlib ``hashlib.scrypt`` hashes
  (``PRICEWATCHER_ADMIN_PASSWORD_HASH``) or explicit local dev opt-in
  (``PRICEWATCHER_INSECURE_NO_AUTH=1``).
- HMAC-SHA256 signed ``HttpOnly; SameSite=Strict`` session cookies
  (``PRICEWATCHER_SESSION_SECRET``) with per-IP login rate limiting.
- Double-submit session-bound CSRF validation + ``Origin``/``Referer`` checks.
- Strict Content-Security-Policy (no inline scripts/styles) and ``safe_url`` filtering.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import time
from typing import Any, Literal
from urllib.parse import urlencode, urlsplit

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response
from starlette.types import ASGIApp

logger = logging.getLogger("pricewatcher.auth")

SESSION_COOKIE_NAME = "pw_session"
CSRF_COOKIE_NAME = "pw_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"  # noqa: S105 - HTTP header name, not a credential
CSRF_FORM_FIELD = "csrf_token"  # noqa: S105 - HTML form field name, not a credential

SESSION_TTL_SECONDS = 12 * 60 * 60  # 43200s (12 hours)
SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 64 * 1024 * 1024
SCRYPT_DKLEN = 32

LOGIN_RATE_LIMIT_MAX_FAILURES = 5
LOGIN_RATE_LIMIT_WINDOW_SECONDS = 15 * 60
LOGIN_RATE_LIMIT_MAX_KEYS = 4096

CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "object-src 'none'; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_STD_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_URL_B64_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_MUTATING_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})

AuthMode = Literal["setup", "insecure_no_auth", "auth"]
TrustedProxyEntry = ipaddress.IPv4Network | ipaddress.IPv6Network | str


def _decode_b64_strict(encoded: str) -> bytes | None:
    if not encoded:
        return None
    if _STD_B64_RE.fullmatch(encoded) and len(encoded) % 4 == 0:
        try:
            return base64.b64decode(encoded, validate=True)
        except binascii.Error:
            return None
    if _URL_B64_RE.fullmatch(encoded) and len(encoded) % 4 != 1:
        padded = encoded + ("=" * (-len(encoded) % 4))
        try:
            return base64.urlsafe_b64decode(padded.encode("ascii"))
        except binascii.Error, ValueError:
            return None
    return None


def hash_password(password: str) -> str:
    """Hash a plaintext password using stdlib scrypt (N=16384, r=8, p=1, dklen=32)."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password must not be empty.")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        maxmem=SCRYPT_MAXMEM,
        dklen=SCRYPT_DKLEN,
    )
    salt_b64 = base64.b64encode(salt).decode("ascii")
    digest_b64 = base64.b64encode(digest).decode("ascii")
    return f"scrypt:{SCRYPT_N}:{SCRYPT_R}:{SCRYPT_P}:{salt_b64}:{digest_b64}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a plaintext password against a stored scrypt:N:r:p:salt:digest (or legacy $) hash."""
    if not isinstance(password, str) or not isinstance(stored_hash, str):
        return False
    if not password or not stored_hash:
        return False

    raw = stored_hash.strip()
    if raw.startswith("scrypt:"):
        parts = raw.split(":")
    else:
        raw = raw.replace("$$", "$")
        parts = raw.split("$")
    if len(parts) != 6 or parts[0] != "scrypt":
        return False

    n_str, r_str, p_str, salt_b64, digest_b64 = parts[1:]
    if not (
        n_str.isascii()
        and n_str.isdigit()
        and len(n_str) <= 10
        and r_str.isascii()
        and r_str.isdigit()
        and len(r_str) <= 5
        and p_str.isascii()
        and p_str.isdigit()
        and len(p_str) <= 5
    ):
        return False

    n = int(n_str)
    r = int(r_str)
    p = int(p_str)
    if n < 2 or (n & (n - 1)) != 0 or n > 1048576:
        return False
    if r < 1 or r > 64 or p < 1 or p > 16:
        return False
    if 128 * n * r > SCRYPT_MAXMEM:
        return False

    salt = _decode_b64_strict(salt_b64)
    expected = _decode_b64_strict(digest_b64)
    if salt is None or expected is None or len(salt) < 8 or not (16 <= len(expected) <= 128):
        return False

    try:
        derived = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            maxmem=SCRYPT_MAXMEM,
            dklen=len(expected),
        )
    except ValueError:
        return False

    return secrets.compare_digest(derived, expected)


def safe_url(value: Any) -> str:
    """Allow only http(s) URLs with netloc or single-slash relative paths; return '#' otherwise."""
    raw = str(value or "").strip()
    if not raw or _CONTROL_CHAR_RE.search(raw):
        return "#"

    parsed = urlsplit(raw)
    if parsed.scheme:
        if (
            parsed.scheme.lower() in {"http", "https"}
            and parsed.netloc
            and "\\" not in parsed.netloc
        ):
            return raw
        return "#"

    if parsed.netloc:
        return "#"
    if raw.startswith("/") and not raw.startswith("//") and not raw.startswith("/\\"):
        return raw
    return "#"


def safe_next_path(raw: str | None, default: str = "/") -> str:
    """Validate an internal post-login redirect target."""
    if not raw:
        return default
    text = raw.strip()
    if not text or _CONTROL_CHAR_RE.search(text) or "\\" in text:
        return default
    if not text.startswith("/") or text.startswith("//") or text.startswith("/\\"):
        return default
    parsed = urlsplit(text)
    if parsed.scheme or parsed.netloc:
        return default
    if parsed.path in {"/login", "/logout"}:
        return default
    return text


def prefers_json(request: Request) -> bool:
    """Return True when the request targets the JSON API or prefers JSON."""
    accept = request.headers.get("accept", "")
    content_type = request.headers.get("content-type", "")
    return "application/json" in accept or "application/json" in content_type


def is_https_request(
    request: Request,
    *,
    cookie_secure_env: bool = False,
    trusted_proxies: tuple[TrustedProxyEntry, ...] = (),
) -> bool:
    """Detect whether cookies should be marked Secure for this request."""
    if cookie_secure_env:
        return True
    if request.url.scheme.lower() == "https":
        return True
    peer_ip = request.client.host if request.client and request.client.host else None
    if is_trusted_proxy(peer_ip, trusted_proxies):
        forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
        return forwarded_proto == "https"
    return False


def parse_trusted_proxies(raw: str | None) -> tuple[TrustedProxyEntry, ...]:
    """Parse comma-separated trusted proxy IPs, CIDRs, hostnames, or '*'."""
    if not raw:
        return ()
    entries: list[TrustedProxyEntry] = []
    for chunk in raw.split(","):
        item = chunk.strip()
        if not item:
            continue
        if item == "*":
            entries.append("*")
            continue
        try:
            entries.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            entries.append(item.lower())
    return tuple(entries)


def is_trusted_proxy(host: str | None, trusted_proxies: tuple[TrustedProxyEntry, ...]) -> bool:
    """Return True when host matches any configured trusted proxy entry."""
    if not host or not trusted_proxies:
        return False
    normalized = host.strip().lower()
    if not normalized:
        return False
    if "*" in trusted_proxies or normalized in trusted_proxies:
        return True
    try:
        ip_obj = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return any(
        isinstance(entry, (ipaddress.IPv4Network, ipaddress.IPv6Network)) and ip_obj in entry
        for entry in trusted_proxies
    )


def get_client_ip(request: Request, trusted_proxies: tuple[TrustedProxyEntry, ...] = ()) -> str:
    """Resolve client IP from peer host or rightmost untrusted X-Forwarded-For hop."""
    peer_ip = request.client.host if request.client and request.client.host else "unknown"
    if is_trusted_proxy(peer_ip, trusted_proxies):
        xff = request.headers.get("x-forwarded-for", "").strip()
        if xff:
            parts = [part.strip() for part in xff.split(",") if part.strip()]
            if parts:
                for part in reversed(parts):
                    if not is_trusted_proxy(part, trusted_proxies):
                        return part
                return parts[0]
    return peer_ip


def _urlsafe_b64_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _urlsafe_b64_decode(encoded: str) -> bytes | None:
    if not encoded or not _URL_B64_RE.fullmatch(encoded) or len(encoded) % 4 == 1:
        return None
    padded = encoded + ("=" * (-len(encoded) % 4))
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except binascii.Error, ValueError:
        return None


class LoginRateLimiter:
    """In-memory sliding-window login failure tracker per client IP."""

    def __init__(
        self,
        *,
        max_failures: int = LOGIN_RATE_LIMIT_MAX_FAILURES,
        window_seconds: int = LOGIN_RATE_LIMIT_WINDOW_SECONDS,
        max_keys: int = LOGIN_RATE_LIMIT_MAX_KEYS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_keys < 1:
            raise ValueError("max_keys must be at least 1.")
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._clock = clock
        self._failures: dict[str, list[float]] = {}
        self._last_sweep: float = clock()

    def _sweep_expired(self, now: float) -> None:
        cutoff = now - self.window_seconds
        stale_keys: list[str] = []
        for key, timestamps in self._failures.items():
            fresh = [ts for ts in timestamps if ts > cutoff]
            if fresh:
                self._failures[key] = fresh
            else:
                stale_keys.append(key)
        for key in stale_keys:
            del self._failures[key]
        self._last_sweep = now

    def _prune(self, key: str, now: float) -> list[float]:
        cutoff = now - self.window_seconds
        bucket = [ts for ts in self._failures.get(key, []) if ts > cutoff]
        if bucket:
            self._failures[key] = bucket
        else:
            self._failures.pop(key, None)
        return bucket

    def check_blocked(self, key: str) -> int | None:
        """Return Retry-After seconds if blocked, or None if permitted."""
        now = self._clock()
        if now - self._last_sweep >= self.window_seconds or len(self._failures) >= self.max_keys:
            self._sweep_expired(now)
        bucket = self._prune(key, now)
        if len(bucket) >= self.max_failures:
            retry_after = math.ceil((bucket[0] + self.window_seconds) - now)
            return max(1, retry_after)
        return None

    def record_failure(self, key: str) -> None:
        now = self._clock()
        swept = False
        if now - self._last_sweep >= self.window_seconds or len(self._failures) >= self.max_keys:
            self._sweep_expired(now)
            swept = True
        bucket = self._prune(key, now)
        if key not in self._failures and len(self._failures) >= self.max_keys:
            if not swept:
                self._sweep_expired(now)
            while len(self._failures) >= self.max_keys and self._failures:
                del self._failures[next(iter(self._failures))]
        bucket.append(now)
        # Re-insert to keep dict order aligned with recency for O(1) eviction.
        self._failures.pop(key, None)
        self._failures[key] = bucket

    def reset(self, key: str) -> None:
        self._failures.pop(key, None)


class AuthManager:
    """Manages auth mode, HMAC-signed session cookies, CSRF tokens, and login rate limiting."""

    def __init__(
        self,
        *,
        password_hash: str,
        insecure_no_auth: bool,
        session_secret: bytes,
        cookie_secure_env: bool = False,
        session_ttl: int = SESSION_TTL_SECONDS,
        rate_limiter: LoginRateLimiter | None = None,
        trusted_proxies: tuple[TrustedProxyEntry, ...] | str = (),
    ) -> None:
        self.password_hash = password_hash
        self.insecure_no_auth = insecure_no_auth
        self.session_secret = session_secret
        self.cookie_secure_env = cookie_secure_env
        self.session_ttl = session_ttl
        self.rate_limiter = rate_limiter or LoginRateLimiter()
        self.trusted_proxies: tuple[TrustedProxyEntry, ...] = (
            parse_trusted_proxies(trusted_proxies)
            if isinstance(trusted_proxies, str)
            else tuple(trusted_proxies)
        )
        self._revoked_sessions: dict[str, int] = {}

    @classmethod
    def from_env(cls) -> AuthManager:
        """Build an AuthManager from current environment variables."""
        password_hash = os.environ.get("PRICEWATCHER_ADMIN_PASSWORD_HASH", "").strip()
        insecure_no_auth = os.environ.get("PRICEWATCHER_INSECURE_NO_AUTH", "").strip() == "1"
        cookie_secure_env = os.environ.get("PRICEWATCHER_COOKIE_SECURE", "").strip() == "1"
        trusted_proxies = parse_trusted_proxies(os.environ.get("PRICEWATCHER_TRUSTED_PROXIES", ""))

        raw_secret = os.environ.get("PRICEWATCHER_SESSION_SECRET", "").strip()
        if not raw_secret:
            raw_secret = secrets.token_urlsafe(32)
            logger.warning(
                "PRICEWATCHER_SESSION_SECRET is not set; generated an ephemeral session secret. "
                "Existing sessions will be invalidated on restart."
            )

        manager = cls(
            password_hash=password_hash,
            insecure_no_auth=insecure_no_auth,
            session_secret=raw_secret.encode("utf-8"),
            cookie_secure_env=cookie_secure_env,
            trusted_proxies=trusted_proxies,
        )
        if manager.mode == "insecure_no_auth":
            logger.warning(
                "PRICEWATCHER_INSECURE_NO_AUTH=1 is active with no admin password hash; "
                "all routes are accessible without authentication!"
            )
        elif manager.mode == "setup":
            logger.warning(
                "PRICEWATCHER_ADMIN_PASSWORD_HASH is not configured; web UI is locked in 503 setup mode."
            )
        return manager

    def client_ip(self, request: Request) -> str:
        """Resolve the effective client IP for this request."""
        return get_client_ip(request, self.trusted_proxies)

    @property
    def mode(self) -> AuthMode:
        if self.password_hash:
            return "auth"
        if self.insecure_no_auth:
            return "insecure_no_auth"
        return "setup"

    def verify_admin_password(self, password: str) -> bool:
        if not self.password_hash:
            return False
        return verify_password(password, self.password_hash)

    def _sign(self, message: str) -> str:
        sig = hmac.new(self.session_secret, message.encode("ascii"), hashlib.sha256).digest()
        return _urlsafe_b64_encode(sig)

    def create_session_token(self, *, now: int | None = None) -> tuple[str, str]:
        """Create a signed session cookie value and return (token, sid)."""
        issued_at = int(time.time()) if now is None else now
        sid = secrets.token_urlsafe(16)
        payload = {"sid": sid, "iat": issued_at, "exp": issued_at + self.session_ttl}
        payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        payload_b64 = _urlsafe_b64_encode(payload_bytes)
        sig_b64 = self._sign(payload_b64)
        return f"{payload_b64}.{sig_b64}", sid

    def verify_session_token(
        self, token: str | None, *, now: int | None = None
    ) -> dict[str, Any] | None:
        """Verify an HMAC-signed session cookie and return its payload, or None."""
        if not token or not token.isascii() or "." not in token:
            return None
        parts = token.split(".")
        if len(parts) != 2:
            return None
        payload_b64, sig_b64 = parts
        if not payload_b64 or not sig_b64:
            return None

        expected_sig = self._sign(payload_b64)
        if not secrets.compare_digest(sig_b64, expected_sig):
            return None

        raw_payload = _urlsafe_b64_decode(payload_b64)
        if raw_payload is None:
            return None
        try:
            data = json.loads(raw_payload.decode("utf-8"))
        except UnicodeDecodeError, json.JSONDecodeError:
            return None

        if not isinstance(data, dict):
            return None
        sid = data.get("sid")
        iat = data.get("iat")
        exp = data.get("exp")
        if not isinstance(sid, str) or not sid or not sid.isascii():
            return None
        if isinstance(iat, bool) or not isinstance(iat, int):
            return None
        if isinstance(exp, bool) or not isinstance(exp, int):
            return None

        current_ts = int(time.time()) if now is None else now
        if current_ts > exp or iat > current_ts + 60:
            return None
        self._prune_revoked_sessions(current_ts)
        if sid in self._revoked_sessions:
            return None
        return data

    def _prune_revoked_sessions(self, now: int) -> None:
        """Remove revoked session IDs whose expiration time has passed."""
        expired = [sid for sid, exp in self._revoked_sessions.items() if exp < now]
        for sid in expired:
            del self._revoked_sessions[sid]

    def revoke_session_token(self, token: str | None, *, now: int | None = None) -> bool:
        """Verify and revoke an active session token in memory until its expiry."""
        current_ts = int(time.time()) if now is None else now
        payload = self.verify_session_token(token, now=current_ts)
        if payload is None:
            return False
        self._prune_revoked_sessions(current_ts)
        self._revoked_sessions[str(payload["sid"])] = int(payload["exp"])
        return True

    def create_csrf_token(self, *, sub: str) -> str:
        """Create an HMAC-signed CSRF token bound to subject `sub`."""
        nonce = _urlsafe_b64_encode(secrets.token_bytes(16))
        sig = self._sign(f"csrf:{sub}:{nonce}")
        return f"{nonce}.{sig}"

    def verify_csrf_token(self, token: str | None, *, expected_sub: str) -> bool:
        """Verify a CSRF token's signature and binding to `expected_sub`."""
        if not token or not token.isascii() or not expected_sub.isascii() or "." not in token:
            return False
        parts = token.split(".")
        if len(parts) != 2:
            return False
        nonce, sig = parts
        if not nonce or not sig:
            return False
        expected_sig = self._sign(f"csrf:{expected_sub}:{nonce}")
        return secrets.compare_digest(sig, expected_sig)

    def set_session_cookies(
        self,
        response: Response,
        request: Request,
        *,
        session_token: str,
        csrf_token: str,
    ) -> None:
        """Attach HttpOnly SameSite=strict session and session-bound CSRF cookies."""
        secure = is_https_request(
            request,
            cookie_secure_env=self.cookie_secure_env,
            trusted_proxies=self.trusted_proxies,
        )
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=session_token,
            max_age=self.session_ttl,
            path="/",
            secure=secure,
            httponly=True,
            samesite="strict",
        )
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=csrf_token,
            max_age=self.session_ttl,
            path="/",
            secure=secure,
            httponly=True,
            samesite="strict",
        )

    def set_csrf_cookie(self, response: Response, request: Request, *, csrf_token: str) -> None:
        """Attach HttpOnly SameSite=strict CSRF cookie."""
        secure = is_https_request(
            request,
            cookie_secure_env=self.cookie_secure_env,
            trusted_proxies=self.trusted_proxies,
        )
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=csrf_token,
            max_age=self.session_ttl,
            path="/",
            secure=secure,
            httponly=True,
            samesite="strict",
        )

    def clear_session_cookies(self, response: Response, request: Request) -> None:
        """Delete session and CSRF cookies."""
        secure = is_https_request(
            request,
            cookie_secure_env=self.cookie_secure_env,
            trusted_proxies=self.trusted_proxies,
        )
        for name in (SESSION_COOKIE_NAME, CSRF_COOKIE_NAME):
            response.delete_cookie(
                key=name,
                path="/",
                secure=secure,
                httponly=True,
                samesite="strict",
            )


def _normalize_netloc(netloc: str, scheme: str) -> str:
    val = netloc.strip().lower()
    if scheme == "http" and val.endswith(":80"):
        return val[:-3]
    if scheme == "https" and val.endswith(":443"):
        return val[:-4]
    return val


def _hosts_match(candidate_netloc: str, candidate_scheme: str, host_header: str) -> bool:
    cand = _normalize_netloc(candidate_netloc, candidate_scheme)
    host = _normalize_netloc(host_header, candidate_scheme)
    return bool(cand and host and cand == host)


def _request_target_hosts(request: Request) -> list[str]:
    hosts: list[str] = []
    host = (request.headers.get("host") or "").strip()
    if host:
        hosts.append(host)
    raw_xfh = (request.headers.get("x-forwarded-host") or "").strip()
    if raw_xfh:
        first_xfh = raw_xfh.split(",", 1)[0].strip()
        if first_xfh and first_xfh not in hosts:
            hosts.append(first_xfh)
    return hosts


def _validate_same_origin(request: Request) -> bool:
    """Validate Origin (if present) or Referer (if Origin absent) matches Host/X-Forwarded-Host."""
    target_hosts = _request_target_hosts(request)
    if not target_hosts:
        return False

    origin = request.headers.get("origin")
    if origin is not None:
        parsed = urlsplit(origin.strip())
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or parsed.username or parsed.password:
            return False
        return any(_hosts_match(parsed.netloc, scheme, target) for target in target_hosts)

    referer = request.headers.get("referer")
    if referer is not None:
        parsed = urlsplit(referer.strip())
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or parsed.username or parsed.password:
            return False
        return any(_hosts_match(parsed.netloc, scheme, target) for target in target_hosts)

    return True


def _is_public_asset_or_health(request: Request) -> bool:
    if request.method not in {"GET", "HEAD"}:
        return False
    path = request.url.path
    return path in {"/healthz", "/favicon.ico"} or path.startswith("/static/")


def _is_api_request(request: Request) -> bool:
    return request.url.path.startswith("/api/") or prefers_json(request)


async def _extract_submitted_csrf_token(request: Request) -> str:
    header_tok = request.headers.get(CSRF_HEADER_NAME, "").strip()
    if header_tok:
        return header_tok

    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type in {"application/x-www-form-urlencoded", "multipart/form-data"}:
        # Cache request._body before parsing form so downstream FastAPI request.form() still works.
        await request.body()
        form = await request.form()
        raw_val = form.get(CSRF_FORM_FIELD, "")
        return str(raw_val).strip()
    return ""


class AuthCsrfMiddleware(BaseHTTPMiddleware):
    """Enforces setup-mode lockdown, session auth, and CSRF verification."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        auth_manager: AuthManager,
        templates: Jinja2Templates,
    ) -> None:
        super().__init__(app)
        self.auth = auth_manager
        self.templates = templates

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request.state.authenticated = False
        request.state.session = None
        request.state.csrf_token = ""

        if _is_public_asset_or_health(request):
            return await call_next(request)

        mode = self.auth.mode
        path = request.url.path

        if mode == "setup":
            if _is_api_request(request) or request.method not in {"GET", "HEAD"}:
                return JSONResponse(
                    {
                        "ok": False,
                        "error": (
                            "Authentication is not configured. Set PRICEWATCHER_ADMIN_PASSWORD_HASH "
                            "or run pricewatcher hash-password."
                        ),
                    },
                    status_code=503,
                )
            return self.templates.TemplateResponse(
                request,
                "setup.html",
                {"request": request, "hide_nav": True},
                status_code=503,
            )

        csrf_sub = "anon"
        if mode == "auth":
            session_cookie = request.cookies.get(SESSION_COOKIE_NAME)
            session = self.auth.verify_session_token(session_cookie)
            is_login_route = path == "/login" and request.method in {"GET", "HEAD", "POST"}

            if session is not None:
                request.state.authenticated = True
                request.state.session = session
                csrf_sub = str(session["sid"])
            elif is_login_route:
                csrf_sub = "login"
            else:
                if request.method in {"GET", "HEAD"} and not _is_api_request(request):
                    raw_next = path + (f"?{request.url.query}" if request.url.query else "")
                    safe_target = safe_next_path(raw_next, default="/")
                    qs = urlencode({"next": safe_target})
                    return RedirectResponse(url=f"/login?{qs}", status_code=303)
                return JSONResponse(
                    {"ok": False, "error": "Authentication required."},
                    status_code=401,
                )

        existing_csrf = request.cookies.get(CSRF_COOKIE_NAME, "").strip()
        csrf_valid_cookie = self.auth.verify_csrf_token(existing_csrf, expected_sub=csrf_sub)
        minted_csrf: str | None = None

        if csrf_valid_cookie:
            request.state.csrf_token = existing_csrf
        else:
            minted_csrf = self.auth.create_csrf_token(sub=csrf_sub)
            request.state.csrf_token = minted_csrf

        if request.method in _MUTATING_METHODS:
            if not _validate_same_origin(request):
                logger.warning(
                    "Cross-origin %s %s rejected (origin=%r referer=%r host=%r x_forwarded_host=%r)",
                    request.method,
                    request.url.path,
                    request.headers.get("origin"),
                    request.headers.get("referer"),
                    request.headers.get("host"),
                    request.headers.get("x-forwarded-host"),
                )
                return JSONResponse(
                    {"ok": False, "error": "Cross-origin request rejected."},
                    status_code=403,
                )
            try:
                submitted = await _extract_submitted_csrf_token(request)
            except Exception:
                return JSONResponse(
                    {"ok": False, "error": "Invalid request payload."},
                    status_code=400,
                )
            if (
                not csrf_valid_cookie
                or not submitted
                or not submitted.isascii()
                or not existing_csrf.isascii()
                or not secrets.compare_digest(submitted, existing_csrf)
                or not self.auth.verify_csrf_token(submitted, expected_sub=csrf_sub)
            ):
                return JSONResponse(
                    {"ok": False, "error": "Invalid or missing CSRF token."},
                    status_code=403,
                )

        response = await call_next(request)
        if (
            minted_csrf is not None
            and request.method in {"GET", "HEAD"}
            and response.status_code < 400
            and CSRF_COOKIE_NAME not in _response_cookie_names(response)
        ):
            self.auth.set_csrf_cookie(response, request, csrf_token=minted_csrf)
        return response


def _response_cookie_names(response: Response) -> set[str]:
    names: set[str] = set()
    for header_val in response.headers.getlist("set-cookie"):
        cookie_part = header_val.split(";", 1)[0]
        if "=" in cookie_part:
            names.add(cookie_part.split("=", 1)[0].strip())
    return names


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attaches strict security headers and sanitizes unhandled exceptions."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        try:
            response = await call_next(request)
        except Exception:
            logger.exception(
                "Unhandled error while processing %s %s", request.method, request.url.path
            )
            if _is_api_request(request):
                response = JSONResponse(
                    {"ok": False, "error": "Internal server error"},
                    status_code=500,
                )
            else:
                response = HTMLResponse("Internal server error", status_code=500)

        response.headers["Content-Security-Policy"] = CSP_POLICY
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        if not request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        return response
