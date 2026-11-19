# Security Policy & Threat Model

PriceWatcher is a self-hosted price monitoring daemon and web administration dashboard designed for single-operator deployments on trusted NAS/homelab hosts behind an HTTPS reverse proxy or on local loopback (`127.0.0.1`).

## Threat Model & Defenses

### 1. Authentication & Brute-Force Protection ([auth.py](src/pricewatcher/web/auth.py))
- **Fail-Closed Default:** Unconfigured deployments (`PRICEWATCHER_ADMIN_PASSWORD_HASH` unset) return HTTP `503` for all UI and API routes except unauthenticated liveness (`GET /healthz`) and static assets (`/static/*`). Unauthenticated mode requires opting in explicitly via `PRICEWATCHER_INSECURE_NO_AUTH=1`.
- **Password Storage:** Admin passwords are hashed with stdlib `hashlib.scrypt` (`N=16384`, `r=8`, `p=1`, `dklen=32`, 16-byte random salt) generated via `pricewatcher hash-password` and verified in constant time with `secrets.compare_digest` after strict parameter validation.
- **Sessions & Cookies:** Sessions use HMAC-SHA256 signed cookies (`pw_session`, 12-hour TTL) backed by `PRICEWATCHER_SESSION_SECRET` (auto-generating a warning-logged ephemeral 32-byte key if unset). Cookies set `HttpOnly` and `SameSite=Strict`, plus `Secure` automatically when accessed via HTTPS / `X-Forwarded-Proto: https` or when `PRICEWATCHER_COOKIE_SECURE=1`.
- **Rate Limiting:** `POST /login` enforces an in-memory per-IP limit of 5 failed attempts per 15-minute window, returning HTTP `429` with `Retry-After`.
- **Loopback Default:** The CLI defaults to `--host 127.0.0.1`; containers pass `--host 0.0.0.0` explicitly.

### 2. Cross-Site Request Forgery (CSRF)
- Every `POST`, `PUT`, `DELETE`, and `PATCH` request (including `/login`, `/logout`, HTML form actions, and JSON `/api/*` endpoints) must pass:
  1. **Origin/Referer Check:** If `Origin` or `Referer` is present, its scheme/host/port must match the request `Host` header.
  2. **Session-Bound Token Check:** A double-submit HMAC-signed `pw_csrf` cookie paired with matching `X-CSRF-Token` header or `csrf_token` form field bound to the session ID (`sid`, `"login"`, or `"anon"`).

### 3. Cross-Site Scripting (XSS) & Content Security Policy
- **URL Validation:** Jinja's `safe_url` filter and client-side `safeUrl()` allow only `http://`, `https://`, and single-leading-`/` relative paths, stripping control characters and rewriting unsafe payloads (`javascript:`, `data:`, `//evil.com`, `/\evil.com`) to `#`.
- **Ingest Filtering:** All source adapters filter ingested `Listing.url` values with `sanitize_listing_url()` so unsafe schemes from external feeds are dropped before persistence.
- **Strict CSP & DOM Hygiene:** Zero inline `<script>` blocks, zero `style=` attributes, zero `.style.*` mutations, and zero `innerHTML` sinks. Every HTTP response carries:
  - `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Referrer-Policy: no-referrer`
  - `Cache-Control: no-store` on non-static responses.

### 4. Server-Side Request Forgery (SSRF) & DNS Rebinding ([http_client.py](src/pricewatcher/http_client.py))
- **Pre-Flight URL & DNS Check:** `validate_outbound_url()` blocks non-HTTP(S) schemes, embedded credentials (`user:pass@`), IPv6 zone IDs (`%`), parser ambiguities, failed DNS lookups, and any resolved IPv4/IPv6 address that is non-routable (loopback, RFC 1918 private, link-local / cloud metadata `169.254.0.0/16`, CGNAT `100.64.0.0/10`, `0.0.0.0/8`, multicast, reserved, unspecified, IPv6 ULA `fc00::/7`, site-local `fec0::/10`, link-local `fe80::/10`, and IPv4-mapped IPv6 equivalents), honoring explicit `PRICEWATCHER_ALLOW_PRIVATE_HOSTS` allowlist entries.
- **Connection Pinning Without Pool Collisions:** Outbound `httpx.AsyncClient` disables proxy env trust (`trust_env=False`), disables cross-site cookies (`_RejectAllCookiePolicy`), keeps real hostnames in request URLs so HTTP/TLS connection pools remain isolated per origin, and overrides TCP destination resolution in `_PinnedAnyIOBackend.connect_tcp` via a per-request `ContextVar`.
- **Redirect Hop Validation:** Auto-redirects are disabled (`follow_redirects=False`); up to 5 hops resolve relative `Location` headers and re-run `validate_outbound_url()` on every hop.
- **Playwright Guard ([html_css.py](src/pricewatcher/adapters/html_css.py)):** Browser page requests and subresources are intercepted via `page.route("**/*", ...)` — blocking non-`GET`/`HEAD` requests and fulfilling `http`/`https` requests through `polite_get()` instead of Chromium's native stack, preventing 302 redirect bypasses and unpinned DNS lookups.
- **API Endpoint Enforcement:** `/api/probe` and `/api/source-packs/test-source` explicitly run `validate_outbound_url()` and return HTTP `422` for blocked destinations.
- **Response Size Caps:** Streaming body reads enforce `PRICEWATCHER_MAX_RESPONSE_BYTES` (default `5242880` bytes) on both `Content-Length` pre-check and chunk iteration.

### 5. Notifiers, ReDoS, Path Traversal & Error Handling
- **Notifier Credential Hygiene ([waha.py](src/pricewatcher/notifiers/waha.py), [email.py](src/pricewatcher/notifiers/email.py)):** WAHA requests set `follow_redirects=False` and reject 3xx responses so `X-Api-Key` cannot be redirected; WAHA keys and SMTP usernames/passwords/PLAIN tokens are scrubbed before logging or error persistence.
- **ReDoS Prevention ([config.py](src/pricewatcher/config.py), [matcher.py](src/pricewatcher/matcher.py)):** Extractor regex patterns are capped at 256 characters and executed via the third-party `regex` engine with `timeout=0.05` (50 ms).
- **Path Traversal & Error Handling:** Resource IDs pass `ConfigStore.sanitize_slug` and parent-directory verification; unexpected server errors return generic `"Internal server error"` responses without internal paths or stack traces.

### 6. Container & Supply Chain Hardening ([Dockerfile](Dockerfile), [docker-publish.yml](.github/workflows/docker-publish.yml))
- Digest-pinned base image (`python:3.14-slim-bookworm@sha256:...`), pinned transitive runtime packages in [requirements.lock](requirements.lock) installed with `--no-deps`, and startup privilege drop to non-root `appuser` (`UID/GID 10001` or `PUID`/`PGID`) after preparing bind-mounted `/data` and `/app/config` ownership.
- CI workflow pins all GitHub Actions by 40-char commit SHA, restricts workflow permissions per job, and runs `ruff check`, `ruff format --check`, `mypy`, `pip-audit`, and `pytest` prior to image publishing.

## Reporting a Vulnerability

If you discover a security vulnerability in PriceWatcher:
1. Do **not** open a public issue containing exploit details against live services.
2. Open a private security advisory on GitHub (Security tab -> "Report a vulnerability") or contact the repository maintainer directly with reproduction steps, affected versions/commits, and impact.
3. Include a minimal test case or proof-of-concept using local/mocked targets where possible. Maintainers aim to acknowledge reports within 72 hours and coordinate a fix before public disclosure.
