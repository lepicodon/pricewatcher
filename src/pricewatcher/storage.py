"""SQLite persistence layer for PriceWatcher observations, tier state, alerts, and health."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import sqlite3
import threading
from typing import Any

SCHEMA_VERSION = 2
_DEDUP_WINDOW = timedelta(hours=24)
_PRICE_MATCH_EPSILON = 0.005


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts)
        return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)
    except ValueError:
        return None


def _normalize_utc_iso(ts: str | None) -> str:
    if not ts:
        return _utcnow_iso()
    dt = _parse_iso(ts)
    if dt is None:
        return ts
    return dt.astimezone(UTC).isoformat()


class Database:
    """Thread-safe SQLite storage backend."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        if db_path is not None:
            raw_path: Path | str = db_path
        else:
            env_db = os.environ.get("PRICEWATCHER_DB_PATH", "").strip()
            if env_db == "/data/prices.db" and not Path("/data").exists():
                raw_path = "data/prices.db"
            else:
                raw_path = env_db or "data/prices.db"
        self.db_path = Path(raw_path)
        if str(self.db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._tx_depth = 0
        try:
            self._conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,
                timeout=15.0,
            )
        except sqlite3.OperationalError as exc:
            parent_dir = self.db_path.parent
            uid_gid = (
                f"{os.geteuid()}:{os.getegid()}"
                if hasattr(os, "geteuid") and hasattr(os, "getegid")
                else "unknown"
            )
            parent_info = "missing"
            if parent_dir.exists():
                try:
                    st = parent_dir.stat()
                    parent_info = f"mode={oct(st.st_mode & 0o777)} uid={st.st_uid} gid={st.st_gid}"
                except OSError:
                    parent_info = "unreadable"
            raise sqlite3.OperationalError(
                f"Unable to open SQLite database at {self.db_path} "
                f"(process uid:gid={uid_gid}, parent {parent_dir} {parent_info}): {exc}"
            ) from exc
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _maybe_commit(self) -> None:
        if self._tx_depth == 0:
            self._conn.commit()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Run a block in a single SQLite transaction (savepoint-backed when nested)."""
        with self._lock:
            depth = self._tx_depth
            if depth == 0:
                if not self._conn.in_transaction:
                    self._conn.execute("BEGIN")
            else:
                self._conn.execute(f"SAVEPOINT _pw_sp_{depth}")
            self._tx_depth = depth + 1
            try:
                yield
            except BaseException:
                self._tx_depth = depth
                if depth == 0:
                    if self._conn.in_transaction:
                        self._conn.rollback()
                else:
                    self._conn.execute(f"ROLLBACK TO SAVEPOINT _pw_sp_{depth}")
                    self._conn.execute(f"RELEASE SAVEPOINT _pw_sp_{depth}")
                raise
            else:
                self._tx_depth = depth
                if depth == 0:
                    if self._conn.in_transaction:
                        self._conn.commit()
                else:
                    self._conn.execute(f"RELEASE SAVEPOINT _pw_sp_{depth}")

    def _init_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute("PRAGMA synchronous=NORMAL;")
            cur.executescript(
                """
                CREATE TABLE IF NOT EXISTS observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    watch_id TEXT NOT NULL,
                    tier_key TEXT NOT NULL,
                    source_name TEXT NOT NULL,
                    merchant TEXT NOT NULL,
                    title TEXT NOT NULL,
                    url TEXT NOT NULL,
                    price REAL NOT NULL,
                    currency TEXT NOT NULL DEFAULT 'USD',
                    condition TEXT NOT NULL DEFAULT 'new',
                    in_stock INTEGER NOT NULL DEFAULT 1,
                    promo_code TEXT,
                    specs_json TEXT NOT NULL DEFAULT '{}',
                    observed_at TEXT NOT NULL,
                    last_seen_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_obs_watch_tier
                    ON observations (watch_id, tier_key, observed_at DESC);
                CREATE INDEX IF NOT EXISTS idx_obs_watch_price
                    ON observations (watch_id, price ASC);

                CREATE TABLE IF NOT EXISTS tier_state (
                    watch_id TEXT NOT NULL,
                    tier_key TEXT NOT NULL,
                    best_price REAL,
                    best_merchant TEXT,
                    best_url TEXT,
                    best_title TEXT,
                    best_promo_code TEXT,
                    last_seen_at TEXT,
                    last_alerted_price REAL,
                    last_alerted_at TEXT,
                    PRIMARY KEY (watch_id, tier_key)
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    watch_id TEXT NOT NULL,
                    tier_key TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    price REAL,
                    merchant TEXT,
                    message TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_watch_time
                    ON alerts (watch_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS source_health (
                    watch_id TEXT NOT NULL,
                    source_name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    http_status INTEGER,
                    item_count INTEGER NOT NULL DEFAULT 0,
                    matched_count INTEGER NOT NULL DEFAULT 0,
                    latency_ms INTEGER NOT NULL DEFAULT 0,
                    last_checked_at TEXT NOT NULL,
                    last_error TEXT,
                    PRIMARY KEY (watch_id, source_name)
                );

                CREATE TABLE IF NOT EXISTS watch_runtime (
                    watch_id TEXT PRIMARY KEY,
                    last_run_at TEXT,
                    startup_summary_sent_at TEXT,
                    last_status TEXT
                );

                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );
                """
            )

            user_version = int(cur.execute("PRAGMA user_version").fetchone()[0])
            obs_cols = {
                str(row["name"])
                for row in cur.execute("PRAGMA table_info(observations)").fetchall()
            }
            applied_versions = {
                int(row["version"])
                for row in cur.execute("SELECT version FROM schema_migrations").fetchall()
            }
            effective_version = max([user_version, *applied_versions], default=0)
            idx_exists = (
                cur.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'idx_observations_dedup'"
                ).fetchone()
                is not None
            )

            if (
                effective_version < SCHEMA_VERSION
                or "last_seen_at" not in obs_cols
                or not idx_exists
            ):
                if "last_seen_at" not in obs_cols:
                    cur.execute("ALTER TABLE observations ADD COLUMN last_seen_at TEXT;")
                cur.execute(
                    "UPDATE observations SET last_seen_at = observed_at WHERE last_seen_at IS NULL;"
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_observations_dedup
                        ON observations (watch_id, source_name, url, tier_key, observed_at DESC);
                    """
                )
                cur.execute(
                    "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (SCHEMA_VERSION, _utcnow_iso()),
                )
                cur.execute(f"PRAGMA user_version = {SCHEMA_VERSION};")

            self._normalize_observation_timestamps(cur)
            cur.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_obs_watch_seen
                    ON observations (watch_id, COALESCE(last_seen_at, observed_at));
                """
            )

            self._conn.commit()

    @staticmethod
    def _normalize_observation_timestamps(cur: sqlite3.Cursor) -> None:
        canon_sec = (
            "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]+00:00"
        )
        canon_us = (
            "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]"
            "T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]+00:00"
        )
        rows = cur.execute(
            """
            SELECT id, observed_at, last_seen_at
            FROM observations
            WHERE (observed_at NOT GLOB ? AND observed_at NOT GLOB ?)
               OR (
                   last_seen_at IS NOT NULL
                   AND last_seen_at NOT GLOB ?
                   AND last_seen_at NOT GLOB ?
               )
            """,
            (canon_sec, canon_us, canon_sec, canon_us),
        ).fetchall()
        updates: list[tuple[str, str | None, int]] = []
        for row in rows:
            obs_raw = str(row["observed_at"])
            seen_raw = row["last_seen_at"]
            obs_norm = _normalize_utc_iso(obs_raw)
            if seen_raw is None:
                seen_norm = None
            elif seen_raw == "":
                seen_norm = obs_norm
            else:
                seen_norm = _normalize_utc_iso(str(seen_raw))
            if obs_norm != obs_raw or seen_norm != seen_raw:
                updates.append((obs_norm, seen_norm, int(row["id"])))
        if updates:
            cur.executemany(
                "UPDATE observations SET observed_at = ?, last_seen_at = ? WHERE id = ?",
                updates,
            )

    def upsert_observation(
        self,
        *,
        watch_id: str,
        tier_key: str,
        source_name: str,
        merchant: str,
        title: str,
        url: str,
        price: float,
        currency: str,
        condition: str,
        in_stock: bool,
        promo_code: str | None,
        specs: dict[str, Any],
        observed_at: str | None = None,
    ) -> int:
        ts = _normalize_utc_iso(observed_at)
        current_dt = _parse_iso(ts)
        price_val = float(price)
        in_stock_bool = bool(in_stock)

        with self._lock:
            latest = self._conn.execute(
                """
                SELECT id, price, in_stock, observed_at, last_seen_at
                FROM observations
                WHERE watch_id = ? AND source_name = ? AND url = ? AND tier_key = ?
                ORDER BY observed_at DESC, id DESC
                LIMIT 1
                """,
                (watch_id, source_name, url, tier_key),
            ).fetchone()

            if latest is not None:
                prev_ts = latest["last_seen_at"] or latest["observed_at"]
                prev_dt = _parse_iso(prev_ts)
                same_price = abs(price_val - float(latest["price"])) < _PRICE_MATCH_EPSILON
                same_stock = in_stock_bool == bool(latest["in_stock"])
                within_window = (
                    current_dt is not None
                    and prev_dt is not None
                    and timedelta(0) <= (current_dt - prev_dt) <= _DEDUP_WINDOW
                )
                if same_price and same_stock and within_window:
                    row_id = int(latest["id"])
                    self._conn.execute(
                        "UPDATE observations SET last_seen_at = ? WHERE id = ?",
                        (ts, row_id),
                    )
                    self._maybe_commit()
                    return row_id

            cur = self._conn.execute(
                """
                INSERT INTO observations (
                    watch_id, tier_key, source_name, merchant, title, url,
                    price, currency, condition, in_stock, promo_code, specs_json,
                    observed_at, last_seen_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    watch_id,
                    tier_key,
                    source_name,
                    merchant,
                    title,
                    url,
                    price_val,
                    currency,
                    condition,
                    1 if in_stock_bool else 0,
                    promo_code,
                    json.dumps(specs, sort_keys=True),
                    ts,
                    ts,
                ),
            )
            self._maybe_commit()
            return int(cur.lastrowid or 0)

    def record_observation(
        self,
        *,
        watch_id: str,
        tier_key: str,
        source_name: str,
        merchant: str,
        title: str,
        url: str,
        price: float,
        currency: str,
        condition: str,
        in_stock: bool,
        promo_code: str | None,
        specs: dict[str, Any],
        observed_at: str | None = None,
    ) -> int:
        return self.upsert_observation(
            watch_id=watch_id,
            tier_key=tier_key,
            source_name=source_name,
            merchant=merchant,
            title=title,
            url=url,
            price=price,
            currency=currency,
            condition=condition,
            in_stock=in_stock,
            promo_code=promo_code,
            specs=specs,
            observed_at=observed_at,
        )

    def prune_old_observations(self, retention_days: int = 180) -> int:
        if retention_days < 0:
            raise ValueError(f"retention_days must be >= 0, got {retention_days}")
        cutoff_iso = (datetime.now(UTC) - timedelta(days=retention_days)).isoformat()
        with self._lock:
            cur = self._conn.execute(
                """
                DELETE FROM observations
                WHERE COALESCE(last_seen_at, observed_at) < ?
                """,
                (cutoff_iso,),
            )
            self._maybe_commit()
            return int(cur.rowcount) if cur.rowcount and cur.rowcount > 0 else 0

    def upsert_tier_seen(
        self,
        *,
        watch_id: str,
        tier_key: str,
        best_price: float,
        best_merchant: str,
        best_url: str,
        best_title: str,
        best_promo_code: str | None,
        seen_at: str | None = None,
    ) -> None:
        ts = _normalize_utc_iso(seen_at)
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO tier_state (
                    watch_id, tier_key, best_price, best_merchant, best_url,
                    best_title, best_promo_code, last_seen_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(watch_id, tier_key) DO UPDATE SET
                    best_price = excluded.best_price,
                    best_merchant = excluded.best_merchant,
                    best_url = excluded.best_url,
                    best_title = excluded.best_title,
                    best_promo_code = excluded.best_promo_code,
                    last_seen_at = excluded.last_seen_at
                """,
                (
                    watch_id,
                    tier_key,
                    float(best_price),
                    best_merchant,
                    best_url,
                    best_title,
                    best_promo_code,
                    ts,
                ),
            )
            self._maybe_commit()

    def mark_tier_alerted(
        self,
        *,
        watch_id: str,
        tier_key: str,
        alerted_price: float,
        alerted_at: str | None = None,
    ) -> None:
        ts = _normalize_utc_iso(alerted_at)
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO tier_state (
                    watch_id, tier_key, last_alerted_price, last_alerted_at
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(watch_id, tier_key) DO UPDATE SET
                    last_alerted_price = excluded.last_alerted_price,
                    last_alerted_at = excluded.last_alerted_at
                """,
                (watch_id, tier_key, float(alerted_price), ts),
            )
            self._maybe_commit()

    def get_tier_states(self, watch_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM tier_state
                WHERE watch_id = ?
                ORDER BY best_price ASC NULLS LAST, tier_key ASC
                """,
                (watch_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_tier_state(self, watch_id: str, tier_key: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM tier_state WHERE watch_id = ? AND tier_key = ?",
                (watch_id, tier_key),
            ).fetchone()
            return dict(row) if row else None

    def upsert_source_health(
        self,
        *,
        watch_id: str,
        source_name: str,
        url: str,
        http_status: int | None,
        item_count: int,
        matched_count: int,
        latency_ms: int,
        last_error: str | None,
        checked_at: str | None = None,
    ) -> None:
        ts = _normalize_utc_iso(checked_at)
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO source_health (
                    watch_id, source_name, url, http_status, item_count,
                    matched_count, latency_ms, last_checked_at, last_error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(watch_id, source_name) DO UPDATE SET
                    url = excluded.url,
                    http_status = excluded.http_status,
                    item_count = excluded.item_count,
                    matched_count = excluded.matched_count,
                    latency_ms = excluded.latency_ms,
                    last_checked_at = excluded.last_checked_at,
                    last_error = excluded.last_error
                """,
                (
                    watch_id,
                    source_name,
                    url,
                    http_status,
                    item_count,
                    matched_count,
                    latency_ms,
                    ts,
                    last_error,
                ),
            )
            self._maybe_commit()

    def get_source_health(self, watch_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM source_health
                WHERE watch_id = ?
                ORDER BY source_name ASC
                """,
                (watch_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def record_alert(
        self,
        *,
        watch_id: str,
        tier_key: str,
        alert_type: str,
        recipient: str,
        channel: str,
        price: float | None,
        merchant: str | None,
        message: str,
        status: str,
        error: str | None = None,
        created_at: str | None = None,
    ) -> int:
        ts = _normalize_utc_iso(created_at)
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO alerts (
                    watch_id, tier_key, alert_type, recipient, channel,
                    price, merchant, message, status, error, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    watch_id,
                    tier_key,
                    alert_type,
                    recipient,
                    channel,
                    price,
                    merchant,
                    message,
                    status,
                    error,
                    ts,
                ),
            )
            self._maybe_commit()
            return int(cur.lastrowid or 0)

    def get_alerts(self, watch_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            if watch_id:
                rows = self._conn.execute(
                    """
                    SELECT * FROM alerts
                    WHERE watch_id = ?
                    ORDER BY created_at DESC, id DESC
                    LIMIT ?
                    """,
                    (watch_id, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    """
                    SELECT * FROM alerts
                    ORDER BY created_at DESC, id DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            return [dict(r) for r in rows]

    def get_observations(
        self,
        watch_id: str,
        *,
        sort_by: str = "observed_at",
        sort_dir: str = "desc",
        tier_filter: str | None = None,
        search_query: str | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        allowed_cols = {
            "price": "price",
            "tier_key": "tier_key",
            "merchant": "merchant",
            "observed_at": "observed_at",
            "last_seen_at": "last_seen_at",
        }
        col = allowed_cols.get(sort_by, "observed_at")
        direction = "ASC" if sort_dir.lower() == "asc" else "DESC"

        clauses = ["watch_id = ?"]
        params: list[Any] = [watch_id]
        if tier_filter:
            clauses.append("tier_key = ?")
            params.append(tier_filter)
        if search_query:
            like = f"%{search_query.strip()}%"
            clauses.append(
                "(title LIKE ? OR merchant LIKE ? OR tier_key LIKE ? OR source_name LIKE ?)"
            )
            params.extend([like, like, like, like])

        where_sql = " AND ".join(clauses)
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT * FROM observations
                WHERE {where_sql}
                ORDER BY {col} {direction}, id DESC
                LIMIT ?
                """,  # noqa: S608 - col/direction allowlisted, where_sql uses static clauses
                params,
            ).fetchall()
            results = []
            for r in rows:
                item = dict(r)
                try:
                    item["specs"] = json.loads(item.get("specs_json") or "{}")
                except json.JSONDecodeError:
                    item["specs"] = {}
                results.append(item)
            return results

    def get_watch_runtime(self, watch_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM watch_runtime WHERE watch_id = ?",
                (watch_id,),
            ).fetchone()
            return dict(row) if row else None

    def update_watch_runtime(
        self,
        *,
        watch_id: str,
        last_run_at: str | None = None,
        last_status: str | None = None,
        mark_startup_sent: bool = False,
    ) -> None:
        now = _utcnow_iso()
        run_ts = _normalize_utc_iso(last_run_at) if last_run_at else now
        with self._lock:
            existing = self.get_watch_runtime(watch_id)
            startup_ts = (
                now
                if mark_startup_sent
                else (existing.get("startup_summary_sent_at") if existing else None)
            )
            self._conn.execute(
                """
                INSERT INTO watch_runtime (
                    watch_id, last_run_at, startup_summary_sent_at, last_status
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(watch_id) DO UPDATE SET
                    last_run_at = excluded.last_run_at,
                    startup_summary_sent_at = COALESCE(excluded.startup_summary_sent_at, watch_runtime.startup_summary_sent_at),
                    last_status = excluded.last_status
                """,
                (watch_id, run_ts, startup_ts, last_status),
            )
            self._maybe_commit()

    def get_dashboard_summary(
        self,
        watch_ids: list[str],
        *,
        history_days: int = 7,
        alert_limit: int = 20,
    ) -> dict[str, Any]:
        """Fetch dashboard state across watches using fixed batched SQL queries."""
        unique_ids = list(dict.fromkeys(watch_ids))
        if not unique_ids:
            return {"watches": {}, "recent_alerts": []}

        placeholders = ",".join("?" for _ in unique_ids)
        cutoff_iso = (datetime.now(UTC) - timedelta(days=max(1, history_days))).isoformat()

        with self._lock:
            runtime_rows = self._conn.execute(
                f"SELECT * FROM watch_runtime WHERE watch_id IN ({placeholders})",  # noqa: S608
                unique_ids,
            ).fetchall()
            runtime_by_watch: dict[str, dict[str, Any]] = {
                str(r["watch_id"]): dict(r) for r in runtime_rows
            }

            tier_rows = self._conn.execute(
                f"""
                SELECT * FROM tier_state
                WHERE watch_id IN ({placeholders})
                ORDER BY watch_id ASC, best_price ASC NULLS LAST, tier_key ASC
                """,  # noqa: S608
                unique_ids,
            ).fetchall()
            tiers_by_watch: dict[str, list[dict[str, Any]]] = {wid: [] for wid in unique_ids}
            for r in tier_rows:
                tiers_by_watch[str(r["watch_id"])].append(dict(r))

            health_rows = self._conn.execute(
                f"""
                SELECT * FROM source_health
                WHERE watch_id IN ({placeholders})
                ORDER BY watch_id ASC, source_name ASC
                """,  # noqa: S608
                unique_ids,
            ).fetchall()
            health_by_watch: dict[str, list[dict[str, Any]]] = {wid: [] for wid in unique_ids}
            for r in health_rows:
                health_by_watch[str(r["watch_id"])].append(dict(r))

            spark_rows = self._conn.execute(
                f"""
                SELECT
                    watch_id,
                    date(COALESCE(last_seen_at, observed_at)) AS day,
                    MIN(price) AS min_price,
                    COUNT(*) AS observation_count
                FROM observations
                WHERE watch_id IN ({placeholders})
                  AND COALESCE(last_seen_at, observed_at) >= ?
                GROUP BY watch_id, date(COALESCE(last_seen_at, observed_at))
                ORDER BY watch_id ASC, day ASC
                """,  # noqa: S608
                [*unique_ids, cutoff_iso],
            ).fetchall()
            sparkline_by_watch: dict[str, list[dict[str, Any]]] = {wid: [] for wid in unique_ids}
            for r in spark_rows:
                if r["day"] is not None:
                    sparkline_by_watch[str(r["watch_id"])].append(
                        {
                            "day": str(r["day"]),
                            "min_price": float(r["min_price"]),
                            "observation_count": int(r["observation_count"]),
                        }
                    )

            latest_obs_rows = self._conn.execute(
                f"""
                SELECT * FROM (
                    SELECT
                        *,
                        ROW_NUMBER() OVER (
                            PARTITION BY watch_id
                            ORDER BY COALESCE(last_seen_at, observed_at) DESC, id DESC
                        ) AS _rn
                    FROM observations
                    WHERE watch_id IN ({placeholders})
                )
                WHERE _rn <= 5
                ORDER BY watch_id ASC, _rn ASC
                """,  # noqa: S608
                unique_ids,
            ).fetchall()
            latest_obs_by_watch: dict[str, list[dict[str, Any]]] = {wid: [] for wid in unique_ids}
            for r in latest_obs_rows:
                item = dict(r)
                item.pop("_rn", None)
                try:
                    item["specs"] = json.loads(item.get("specs_json") or "{}")
                except json.JSONDecodeError:
                    item["specs"] = {}
                latest_obs_by_watch[str(item["watch_id"])].append(item)

            alert_rows = self._conn.execute(
                f"""
                SELECT * FROM alerts
                WHERE watch_id IN ({placeholders})
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,  # noqa: S608
                [*unique_ids, max(0, alert_limit)],
            ).fetchall()
            recent_alerts = [dict(r) for r in alert_rows]

        watches_summary: dict[str, dict[str, Any]] = {}
        for wid in unique_ids:
            sources = health_by_watch.get(wid, [])
            error_count = sum(1 for s in sources if s.get("last_error"))
            ok_count = len(sources) - error_count
            last_checked_at = max(
                (str(s["last_checked_at"]) for s in sources if s.get("last_checked_at")),
                default=None,
            )
            obs_list = latest_obs_by_watch.get(wid, [])
            watches_summary[wid] = {
                "watch_id": wid,
                "runtime": runtime_by_watch.get(wid),
                "tier_states": tiers_by_watch.get(wid, []),
                "latest_observations": obs_list,
                "latest_observation": obs_list[0] if obs_list else None,
                "sparkline": sparkline_by_watch.get(wid, []),
                "source_health": {
                    "total": len(sources),
                    "ok": ok_count,
                    "error": error_count,
                    "last_checked_at": last_checked_at,
                    "sources": sources,
                },
            }

        return {
            "watches": watches_summary,
            "recent_alerts": recent_alerts,
        }
