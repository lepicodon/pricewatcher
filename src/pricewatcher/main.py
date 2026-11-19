"""PriceWatcher entrypoint: FastAPI Web UI, async scheduler loop, and CLI."""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import AsyncIterator
import contextlib
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
import getpass
import json
import logging
import os
from pathlib import Path
import random
import sys
from typing import Any

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
import uvicorn

from pricewatcher.config import ConfigStore, SettingsConfig, WatchConfig
from pricewatcher.discovery import probe_url
from pricewatcher.engine import PollEngine
import pricewatcher.http_client as http_client_module
from pricewatcher.storage import Database
from pricewatcher.web.auth import (
    AuthCsrfMiddleware,
    AuthManager,
    SecurityHeadersMiddleware,
    hash_password,
)
from pricewatcher.web.router import STATIC_DIR, router, templates

logger = logging.getLogger("pricewatcher")

_RETENTION_INTERVAL = timedelta(hours=24)


async def _open_http_context(stack: AsyncExitStack) -> Any:
    http_ctx_cls = getattr(http_client_module, "HttpContext", None)
    if http_ctx_cls is None:
        return None
    candidate = http_ctx_cls()
    if hasattr(candidate, "__aenter__") and hasattr(candidate, "__aexit__"):
        return await stack.enter_async_context(candidate)
    if hasattr(candidate, "aclose"):
        stack.push_async_callback(candidate.aclose)
    elif hasattr(candidate, "close"):
        stack.callback(candidate.close)
    return candidate


def _compute_initial_due(last_run_at: str | None, interval_minutes: int) -> datetime:
    now = datetime.now(UTC)
    if not last_run_at:
        return now
    try:
        parsed = datetime.fromisoformat(last_run_at)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
    except ValueError:
        return now
    return parsed + timedelta(minutes=interval_minutes)


def _compute_next_due(watch: WatchConfig) -> datetime:
    jitter = (
        random.randint(0, watch.schedule.jitter_seconds) if watch.schedule.jitter_seconds > 0 else 0
    )
    return datetime.now(UTC) + timedelta(
        minutes=watch.schedule.interval_minutes,
        seconds=jitter,
    )


async def scheduler_loop(
    *,
    store: ConfigStore,
    db: Database,
    engine: PollEngine,
    wakeup_event: asyncio.Event,
    stop_event: asyncio.Event,
) -> None:
    """Continuously schedules active watches independently, reloading YAML config each pass."""
    next_due: dict[str, datetime] = {}
    active_tasks: dict[str, asyncio.Task[None]] = {}
    task_done_event = asyncio.Event()
    last_pruned_at: datetime | None = None

    async def _poll_watch_task(
        watch: WatchConfig, settings: SettingsConfig | None, poll_now: datetime
    ) -> None:
        logger.info("Polling watch %s (%s sources)", watch.id, len(watch.sources))
        try:
            report = await engine.poll_watch(watch, settings=settings, now=poll_now)
            if report.already_running:
                logger.info("Watch %s already running; skipped duplicate poll", watch.id)
            else:
                logger.info(
                    "Watch %s done: sources=%d/%d fetched=%d matched=%d alerts=%d/%d",
                    watch.id,
                    report.sources_ok,
                    report.sources_checked,
                    report.items_fetched,
                    report.items_matched,
                    report.alerts_delivered,
                    report.alerts_triggered,
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("Error polling watch %s: %s", watch.id, exc)
            next_due[watch.id] = _compute_next_due(watch)
        else:
            next_due[watch.id] = _compute_next_due(watch)
        finally:
            task_done_event.set()

    try:
        while not stop_event.is_set():
            wakeup_event.clear()
            task_done_event.clear()

            for wid, task in list(active_tasks.items()):
                if task.done():
                    active_tasks.pop(wid, None)
                    if not task.cancelled():
                        exc = task.exception()
                        if exc is not None:
                            logger.error("Watch task %s failed: %s", wid, exc)

            now = datetime.now(UTC)
            config_loaded = True
            try:
                watches = await asyncio.to_thread(store.load_watches)
                settings: SettingsConfig | None = await asyncio.to_thread(store.load_settings)
            except Exception as exc:
                logger.exception("Failed reloading config in scheduler loop: %s", exc)
                watches = []
                settings = None
                config_loaded = False

            active_watches: list[WatchConfig] = []
            if config_loaded:
                if last_pruned_at is None or (now - last_pruned_at) >= _RETENTION_INTERVAL:
                    retention_days = settings.server.retention_days if settings is not None else 180
                    try:
                        pruned = await asyncio.to_thread(db.prune_old_observations, retention_days)
                        if pruned:
                            logger.info(
                                "Pruned %d observation(s) older than %d days",
                                pruned,
                                retention_days,
                            )
                        last_pruned_at = now
                    except Exception as exc:
                        logger.exception("Failed pruning old observations: %s", exc)

                active_watches = [w for w in watches if w.effective_status(now=now) == "active"]
                active_ids = {w.id for w in active_watches}

                for stale_id in list(next_due):
                    if stale_id not in active_ids:
                        del next_due[stale_id]

                for stale_id, task in list(active_tasks.items()):
                    if stale_id not in active_ids:
                        if not task.done():
                            task.cancel()
                        active_tasks.pop(stale_id, None)

                for watch in active_watches:
                    if watch.id not in next_due:
                        runtime = await asyncio.to_thread(db.get_watch_runtime, watch.id)
                        next_due[watch.id] = _compute_initial_due(
                            runtime["last_run_at"] if runtime else None,
                            watch.schedule.interval_minutes,
                        )

                    if now >= next_due[watch.id] and watch.id not in active_tasks:
                        active_tasks[watch.id] = asyncio.create_task(
                            _poll_watch_task(watch, settings, now)
                        )

            wait_timeout = 15.0
            now_after_spawn = datetime.now(UTC)
            for watch in active_watches:
                if watch.id in active_tasks:
                    continue
                due_at = next_due.get(watch.id)
                if due_at is not None:
                    delta = (due_at - now_after_spawn).total_seconds()
                    wait_timeout = min(wait_timeout, max(0.05, delta))

            if stop_event.is_set():
                break

            wait_task = asyncio.create_task(wakeup_event.wait())
            stop_task = asyncio.create_task(stop_event.wait())
            done_task = asyncio.create_task(task_done_event.wait())
            try:
                await asyncio.wait(
                    {wait_task, stop_task, done_task},
                    timeout=wait_timeout,
                    return_when=asyncio.FIRST_COMPLETED,
                )
            finally:
                for waiter in (wait_task, stop_task, done_task):
                    if not waiter.done():
                        waiter.cancel()
    finally:
        pending = [task for task in active_tasks.values() if not task.done()]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        active_tasks.clear()


def create_app(
    store: ConfigStore | None = None,
    db: Database | None = None,
    engine: PollEngine | None = None,
    *,
    start_scheduler: bool = True,
) -> FastAPI:
    resolved_store = store or ConfigStore()
    resolved_db = db or Database()
    resolved_engine = engine or PollEngine(store=resolved_store, db=resolved_db)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        wakeup_event = asyncio.Event()
        stop_event = asyncio.Event()
        app.state.wakeup_event = wakeup_event
        bg_task: asyncio.Task[None] | None = None
        prev_http_ctx = getattr(resolved_engine, "http_ctx", None)
        assigned_http_ctx = False

        async with AsyncExitStack() as stack:
            http_ctx = await _open_http_context(stack)
            app.state.http_ctx = http_ctx
            if (
                http_ctx is not None
                and prev_http_ctx is None
                and hasattr(resolved_engine, "http_ctx")
            ):
                resolved_engine.http_ctx = http_ctx
                assigned_http_ctx = True

            if start_scheduler:
                bg_task = asyncio.create_task(
                    scheduler_loop(
                        store=resolved_store,
                        db=resolved_db,
                        engine=resolved_engine,
                        wakeup_event=wakeup_event,
                        stop_event=stop_event,
                    )
                )
            try:
                yield
            finally:
                stop_event.set()
                wakeup_event.set()
                if bg_task is not None:
                    try:
                        await asyncio.wait_for(bg_task, timeout=5.0)
                    except TimeoutError, asyncio.CancelledError:
                        bg_task.cancel()
                        await asyncio.gather(bg_task, return_exceptions=True)
                if assigned_http_ctx:
                    resolved_engine.http_ctx = None
                if db is None:
                    await asyncio.to_thread(resolved_db.close)

    app = FastAPI(title="PriceWatcher", version="0.1.0", lifespan=lifespan)
    app.state.store = resolved_store
    app.state.db = resolved_db
    app.state.engine = resolved_engine
    app.state.wakeup_event = asyncio.Event()
    app.state.http_ctx = None
    auth_manager = AuthManager.from_env()
    app.state.auth = auth_manager
    app.add_middleware(AuthCsrfMiddleware, auth_manager=auth_manager, templates=templates)
    app.add_middleware(SecurityHeadersMiddleware)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.include_router(router)
    return app


async def _run_once(*, dry_run: bool, watch_id: str | None) -> int:
    store = ConfigStore()
    db = Database()
    try:
        async with AsyncExitStack() as stack:
            http_ctx = await _open_http_context(stack)
            engine = PollEngine(store=store, db=db, http_ctx=http_ctx)
            settings = await asyncio.to_thread(store.load_settings)
            if watch_id:
                clean_id = ConfigStore.sanitize_watch_id(watch_id)
                watch = await asyncio.to_thread(store.get_watch, clean_id)
                if watch is None:
                    print(json.dumps({"error": f"Watch {watch_id!r} not found"}))
                    return 1
                reports = [await engine.poll_watch(watch, settings=settings, dry_run=dry_run)]
            else:
                reports = await engine.poll_all(dry_run=dry_run)
            print(json.dumps([asdict(r) for r in reports], indent=2))
            return 0
    finally:
        await asyncio.to_thread(db.close)


async def _run_probe(url: str) -> int:
    result = await probe_url(url)
    print(result.model_dump_json(indent=2))
    return 0 if result.classification != "ERROR" else 1


def _parse_non_negative_id(env_name: str, default: int) -> int:
    raw = os.environ.get(env_name, "").strip()
    if not raw:
        return default
    try:
        val = int(raw)
        if val >= 0:
            return val
    except ValueError:
        pass
    logger.warning("Invalid %s=%r; falling back to %d", env_name, raw, default)
    return default


def _chown_tree(root_dir: Path, uid: int, gid: int) -> None:
    """Recursively chown a non-symlink directory tree without following symlinks."""
    if not root_dir.exists() or root_dir.is_symlink():
        return
    with contextlib.suppress(OSError):
        os.chown(root_dir, uid, gid)
    for current, dirnames, filenames in os.walk(root_dir, followlinks=False):
        cur_path = Path(current)
        for name in (*dirnames, *filenames):
            entry = cur_path / name
            if entry.is_symlink():
                continue
            with contextlib.suppress(OSError):
                os.chown(entry, uid, gid)


def _ensure_volume_permissions_and_drop_privileges() -> None:
    """When launched as root in Docker, prepare bind-mount ownership and drop to appuser."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return

    uid = _parse_non_negative_id("PUID", 10001)
    gid = _parse_non_negative_id("PGID", 10001)

    env_db = os.environ.get("PRICEWATCHER_DB_PATH", "").strip()
    db_path = (
        Path("data/prices.db")
        if env_db == "/data/prices.db" and not Path("/data").exists()
        else Path(env_db or "data/prices.db")
    )
    env_cfg = os.environ.get("PRICEWATCHER_CONFIG_DIR", "").strip()
    cfg_dir = (
        Path("config")
        if env_cfg == "/app/config" and not Path("/app/config").exists()
        else Path(env_cfg or "config")
    )

    for target_dir in (db_path.parent, cfg_dir, cfg_dir / "watches"):
        if not target_dir.is_symlink():
            with contextlib.suppress(OSError):
                target_dir.mkdir(parents=True, exist_ok=True)

    _chown_tree(db_path.parent, uid, gid)
    _chown_tree(cfg_dir, uid, gid)
    home_dir = Path("/home/appuser")
    if home_dir.is_dir():
        _chown_tree(home_dir, uid, gid)
        os.environ["HOME"] = str(home_dir)

    if hasattr(os, "setgroups"):
        os.setgroups([])
    if hasattr(os, "setgid"):
        os.setgid(gid)
    if hasattr(os, "setuid"):
        os.setuid(uid)

    if os.geteuid() == 0:
        raise RuntimeError("Failed to drop root privileges before starting PriceWatcher")


def _run_hash_password() -> int:
    if sys.stdin.isatty():
        password = getpass.getpass("Admin password: ")
        confirm = getpass.getpass("Confirm admin password: ")
        if password != confirm:
            print("Error: passwords do not match.", file=sys.stderr)
            return 1
    else:
        password = sys.stdin.readline().rstrip("\r\n")

    if not password:
        print("Error: password must not be empty.", file=sys.stderr)
        return 1

    print(hash_password(password))
    return 0


def cli(argv: list[str] | None = None) -> int:
    args_list = sys.argv[1:] if argv is None else list(argv)
    if args_list == ["hash-password"]:
        return _run_hash_password()

    parser = argparse.ArgumentParser(description="PriceWatcher monitoring service")
    parser.add_argument("--once", action="store_true", help="Run one poll cycle and exit")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="With --once, record observations and simulate alerts without sending messages",
    )
    parser.add_argument("--watch", default=None, help="With --once, poll only this watch id")
    parser.add_argument("--probe", default=None, help="Probe a candidate URL and print result")
    parser.add_argument(
        "--hash-password",
        action="store_true",
        help="Generate a scrypt hash for PRICEWATCHER_ADMIN_PASSWORD_HASH and exit",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Web server bind host")
    parser.add_argument(
        "--port", type=int, default=None, help="Web server port (default from settings/8080)"
    )
    args = parser.parse_args(argv)

    if args.hash_password:
        return _run_hash_password()

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    _ensure_volume_permissions_and_drop_privileges()

    if args.probe:
        return asyncio.run(_run_probe(args.probe))

    if args.once:
        return asyncio.run(_run_once(dry_run=args.dry_run, watch_id=args.watch))

    store = ConfigStore()
    settings = store.load_settings()
    port = args.port or settings.server.port or 8080
    app = create_app(store=store)
    uvicorn.run(app, host=args.host, port=port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
