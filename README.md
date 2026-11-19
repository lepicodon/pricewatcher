# PriceWatcher

A self-hosted, multi-source price monitoring service with per-watch YAML configuration (`config/watches/*.yaml`), hardened outbound HTTP scraping, SQLite observation deduplication, WAHA WhatsApp + SMTP email notifications, and a Light/Dark Web UI.

## Features

- **Per-Watch YAML Config (`config/watches/*.yaml`):** Keyword groups, exclusions, regex spec extractors (`ram_gb`, `ssd_gb`, etc.) with ReDoS bounds, min/max/target prices, cooldowns, auto-expiration (`duration_days` / `stop_after`), and per-watch recipients.
- **Hardened HTTP-First Adapters:** AppleInsider JSON-LD, Shopify JSON (`/products.json` & `/search/suggest.json`), Apple Certified Refurbished (`REFURB_GRID_BOOTSTRAP`), Server-Rendered HTML / JSON-LD / CSS (`Abt` preset + custom selectors), and RSS/Atom feeds using a shared HTTP/1.1 pool with SSRF validation, DNS pinning, redirect hop checks, and streaming byte caps. Optional Playwright rendering (`INSTALL_PLAYWRIGHT=true`) routes browser requests through the same outbound validator.
- **Live URL Discovery ("Probe Source"):** Paste any product, collection, or feed URL in the Web UI (`/manage`) or CLI (`--probe`) to detect RSS, Shopify JSON, JSON-LD, HTML, JS-required pages, or bot blocks before adding a watch.
- **WAHA + Email Alerts:** Configurable WAHA WhatsApp session (with `follow_redirects=False` and credential redaction) and SMTP email fallback.
- **Authenticated Light/Dark Web UI:** Deals dashboard (`/`), watch details & history (`/watches/{id}`), watch builder & probe tool (`/manage`), gateway health & test alerts (`/settings`), and fail-closed `scrypt` login (`/login`).

## Quickstart (Local Setup)

1. Clone the repository and copy the example environment and configuration templates (your personal `config/settings.yaml`, `config/watches/*.yaml`, `.env`, and `data/` are gitignored):

```bash
git clone https://github.com/lepicodon/pricewatcher.git
cd pricewatcher
cp .env.example .env
cp config/settings.example.yaml config/settings.yaml
cp config/watches/example-watch.yaml.example config/watches/example-watch.yaml
```

2. Create a Python 3.14 virtual environment and install dependencies:

```bash
uv venv --python python3.14
uv pip install -e ".[dev]"
```

*(Using standard `pip`: `python3.14 -m venv .venv && .venv/bin/pip install -e ".[dev]"`.)*

3. Edit `config/settings.yaml` (recipients, notification preferences, WAHA/SMTP settings) and customize `config/watches/*.yaml` for the items you want to track.

4. Generate an admin password hash and session secret in `.env`:

```bash
# Prints a scrypt:16384:8:1:... hash for PRICEWATCHER_ADMIN_PASSWORD_HASH
.venv/bin/python -m pricewatcher.main hash-password
# Generate a 32-byte cookie signing secret for PRICEWATCHER_SESSION_SECRET:
openssl rand -hex 32
```

Add both to `.env` (legacy `$`-delimited `scrypt$...` hashes also remain accepted, though Docker Compose `.env` requires `$$` escaping for `$` hashes):

```dotenv
PRICEWATCHER_ADMIN_PASSWORD_HASH=scrypt:16384:8:1:...
PRICEWATCHER_SESSION_SECRET=<64-hex-chars>
```

5. Run the test suite and start PriceWatcher locally on `127.0.0.1:8080`:

```bash
.venv/bin/pytest -v

# Run one dry-run poll cycle without sending alerts
PRICEWATCHER_CONFIG_DIR=./config PRICEWATCHER_DB_PATH=./data/prices.db \
  .venv/bin/python -m pricewatcher.main --once --dry-run

# Start the Web UI + background scheduler (binds 127.0.0.1:8080 by default)
PRICEWATCHER_CONFIG_DIR=./config PRICEWATCHER_DB_PATH=./data/prices.db \
  .venv/bin/python -m pricewatcher.main
```

Open `http://127.0.0.1:8080` and sign in with your admin password (note: `.env.example` sets `PRICEWATCHER_COOKIE_SECURE=1` for TLS deployments; if running plain-HTTP local dev without TLS and your client drops `Secure` cookies, override `PRICEWATCHER_COOKIE_SECURE=0` or leave it empty in `.env`). If `PRICEWATCHER_ADMIN_PASSWORD_HASH` is unset, PriceWatcher fails closed with HTTP `503` setup instructions unless `PRICEWATCHER_INSECURE_NO_AUTH=1` is explicitly set for local development.

## CLI Reference (`pricewatcher` / `python -m pricewatcher.main`)

| Flag / Subcommand | Description |
|---|---|
| `hash-password` / `--hash-password` | Generate a `scrypt:N:r:p:salt:digest` hash for `PRICEWATCHER_ADMIN_PASSWORD_HASH` and exit |
| `--once` | Run a single poll cycle across enabled watches and exit |
| `--dry-run` | With `--once`, record observations and simulate alerts without sending WAHA/email messages |
| `--watch <id>` | With `--once`, poll only the specified watch ID |
| `--probe <url>` | Probe a candidate URL through the SSRF-validated HTTP client and print detection JSON |
| `--host <addr>` | Web server bind address (defaults to `127.0.0.1`; pass `0.0.0.0` explicitly inside containers) |
| `--port <port>` | Web server port (defaults to `server.port` in settings or `8080`) |

## Environment Variables

| Variable | Default / Required | Purpose |
|---|---|---|
| `PRICEWATCHER_ADMIN_PASSWORD_HASH` | Required in production | Admin `scrypt` password hash (`scrypt:N:r:p:salt:digest` or legacy `$`-delimited); fails closed (`503`) when unset |
| `PRICEWATCHER_SESSION_SECRET` | Random ephemeral per boot (warns) | Secret key for HMAC-SHA256 signing of `pw_session` and `pw_csrf` cookies |
| `PRICEWATCHER_INSECURE_NO_AUTH` | Unset (`""`) | Set to `"1"` ONLY for local development to disable login checks (CSRF still enforced) |
| `PRICEWATCHER_COOKIE_SECURE` | `1` (`docker-compose.yml` / `.env.example`); unset otherwise | Marks `pw_session` and `pw_csrf` cookies `Secure` (enabled by default for TLS-terminated deployments; override to `0` or empty only for plain-HTTP local dev; also auto-enabled on HTTPS / `X-Forwarded-Proto: https`) |
| `PRICEWATCHER_TRUSTED_PROXIES` | Unset (`""`) | Comma-separated proxy IPs or CIDRs (e.g., Traefik subnet `172.18.0.0/16`) trusted when running behind a reverse proxy so per-client login rate limiting sees real client IPs |
| `PRICEWATCHER_ALLOW_PRIVATE_HOSTS` | Unset (`""`) | Comma-separated hostnames/IPs explicitly permitted past outbound SSRF IP checks |
| `PRICEWATCHER_CONTACT_URL` | `https://github.com/your-username/pricewatcher` | Contact URL included in the Reddit `User-Agent` header |
| `PRICEWATCHER_MAX_RESPONSE_BYTES` | `5242880` (5 MiB) | Maximum streamed HTTP response size allowed per fetch |
| `PRICEWATCHER_DB_PATH` | `data/prices.db` (`/data/prices.db` in Docker) | SQLite database file path |
| `PRICEWATCHER_CONFIG_DIR` | `config` (`/app/config` in Docker) | Directory containing `settings.yaml` and `watches/*.yaml` |
| `WAHA_URL` | `http://waha.docker` | WAHA gateway base URL |
| `WAHA_API_KEY` | `""` | WAHA API key sent via `X-Api-Key` header |
| `WAHA_SESSION` | `pricewatcher` (or `settings.yaml` value) | Override WAHA session name |
| `SMTP_USER` | `""` | SMTP username for email fallback alerts |
| `SMTP_PASS` | `""` | SMTP password / app password for email fallback alerts |
| `LOG_LEVEL` | `INFO` | Python logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `TZ` | `America/New_York` | Process/container timezone |

## Docker Deployment

Multi-arch images (`linux/amd64` and `linux/arm64`) are built from a digest-pinned Debian Bookworm Python 3.14 base image, install pinned dependencies from [requirements.lock](requirements.lock), run as non-root `USER 10001` (`appuser`) by default (ensure host bind mounts `./config` and `./data` are writable by UID/GID `10001`, e.g. `chown -R 10001:10001 ./config ./data`, or run with `--user 0:0` and `PUID`/`PGID` so `pricewatcher.main` adjusts ownership before dropping privileges), expose port `8080`, and include a `/healthz` `HEALTHCHECK`.

### Option A: Using Docker Compose (Build from Source or Pre-Built GHCR Image)

1. Create the external `traefik` network if routing behind Traefik (or remove/replace the `networks:` block in [docker-compose.yml](docker-compose.yml) for standalone bridge networking):

```bash
docker network create traefik  # omit if already present
```

2. Configure `.env`, `config/settings.yaml`, and `config/watches/*.yaml`, then start:

```bash
docker compose up -d --build
```

[docker-compose.yml](docker-compose.yml) binds `"127.0.0.1:8080:8080"` (loopback-only, avoiding plain-HTTP LAN exposure that would bypass Traefik TLS) and defaults `PRICEWATCHER_COOKIE_SECURE=1` (matching [.env.example](.env.example); override to `0` or empty only for plain-HTTP local dev). When routing behind Traefik or another reverse proxy, set `PRICEWATCHER_TRUSTED_PROXIES` (default empty/none) to the proxy subnet (e.g., `172.18.0.0/16`) so per-client login rate limiting sees real client IPs.

To pull the pre-built image published by [docker-publish.yml](.github/workflows/docker-publish.yml) instead of building locally, set `image: ghcr.io/lepicodon/pricewatcher:latest` in your Compose override and run `docker compose pull && docker compose up -d`.

To include optional headless Chromium / Playwright support for `render_js: true` watches:

```bash
docker compose build --build-arg INSTALL_PLAYWRIGHT=true
docker compose up -d
```

## Architecture & Security Model

- **Authentication & Bind Safety:** Local CLI defaults to `--host 127.0.0.1`. Authenticated sessions use `HttpOnly; SameSite=Strict` cookies (with `Secure` enabled by default via `PRICEWATCHER_COOKIE_SECURE=1` in [docker-compose.yml](docker-compose.yml) / [.env.example](.env.example) and behind HTTPS proxies), per-IP login rate limiting (5 failed logins per 15 minutes), and session-bound CSRF tokens + `Origin`/`Referer` checks on all state-changing requests. See [SECURITY.md](SECURITY.md) for the full threat model.
- **Reverse Proxy (HTTPS) Deployment:** Put TLS termination (Traefik, Caddy, or Nginx) in front of container port `8080` and forward `X-Forwarded-Proto: https`. [docker-compose.yml](docker-compose.yml) binds `"127.0.0.1:8080:8080"` (loopback-only, avoiding LAN HTTP exposure bypassing Traefik TLS) and enables `PRICEWATCHER_COOKIE_SECURE=1` by default (override to `0` or empty only for plain-HTTP local dev). Set `PRICEWATCHER_TRUSTED_PROXIES` (default empty/none) to your Traefik/proxy subnet (e.g., `172.18.0.0/16`) so per-client login rate limiting sees real client IPs.
- **Outbound SSRF & Privacy Controls:** All HTTP fetches resolve DNS via `socket.getaddrinfo`, block loopback/RFC1918/link-local/CGNAT/reserved/multicast IPv4 & IPv6 targets, pin the validated IP per TCP connection while keeping TLS SNI and connection-pool origins isolated by hostname, validate every redirect hop (max 5), and redact WAHA/SMTP credentials from logs and responses. If you intentionally poll an internal test endpoint, add its hostname to `PRICEWATCHER_ALLOW_PRIVATE_HOSTS`.
- **Engine & Storage:** Poll cycles fetch enabled sources concurrently (bounded semaphore, default 4), schedule active watches independently guarded by per-watch locks, deduplicate unchanged `(watch_id, source_name, url, tier_key)` observations within 24 hours in SQLite schema v2, prune rows older than `server.retention_days` (default 180), and bound regex extractors with `regex` `timeout=0.05` and 256-character max length.

See [SECURITY.md](SECURITY.md) and [CHANGELOG.md](CHANGELOG.md) for security policy details and release history.
