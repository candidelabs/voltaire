"""
Cache backends for PersistentFIFOCache.

The cache layer (cache.py) owns the in-memory hot tier, the bounded
write queue, batching, FIFO eviction policy, and the soft-fail
behavior that drops to memory-only on disk-tier errors. This module
owns the bytes-in/bytes-out cold tier. Two implementations:

- SQLiteBackend: one SQLite file per cache, sync sqlite3 under
  asyncio.to_thread. Mirrors the long-standing behavior; default for
  single-host operators with no external infra.

- PostgresBackend: one shared asyncpg pool across every cache, with
  one table per cache name. Native async I/O — no worker-thread hop.
  For multi-bundler deployments that already run Postgres.

Values stored by either backend are opaque bytes; the cache layer
handles JSON encoding/decoding. A malformed-payload error therefore
surfaces in the cache layer, not here.

Backends raise CacheBackendError to signal a failure the cache layer
should treat as fatal for the disk tier — at open time that means
fall through to memory-only; mid-flight it means call close() and
clear the backend reference.
"""
from __future__ import annotations

import abc
import asyncio
import logging
import re
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    import asyncpg
else:
    try:
        import asyncpg  # type: ignore[import-not-found]
    except ImportError:
        asyncpg = None  # type: ignore[assignment]


# Same gate the cache layer uses for cache names. Identifiers are
# interpolated into SQL via f-strings (parameterised queries can't
# bind table/sequence names), so anything that escapes a SQL
# identifier here is a code bug, not a runtime input.
_SAFE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class CacheBackendError(Exception):
    """Raised when a backend operation fails fatally enough to disable
    the disk tier. Callers should log, drop the backend reference, and
    keep serving from memory."""


# ----------------------------------------------------------------------
# Backend configuration
# ----------------------------------------------------------------------


@dataclass
class SQLiteConfig:
    """Configuration for SQLite backends. ``cache_dir`` is the directory
    that holds one ``{name}.sqlite`` file per cache."""
    cache_dir: Path
    cache_size_kb: int = 8_000


@dataclass
class PostgresConfig:
    """Configuration for Postgres backends.

    ``url`` is a standard libpq DSN (``postgresql://user:pass@host:port/db``).
    A single connection pool is shared across every cache.

    ``table_prefix`` is prepended to each cache name to form the table
    name. The prefix keeps the bundler's tables visually separated from
    anything else sharing the database. Set to an empty string for a
    dedicated database."""
    url: str
    min_pool_size: int = 1
    max_pool_size: int = 10
    table_prefix: str = "voltaire_cache_"


BackendConfig = SQLiteConfig | PostgresConfig


# ----------------------------------------------------------------------
# Abstract interface
# ----------------------------------------------------------------------


class CacheBackend(abc.ABC):
    """One backend per cache. Lifecycle: ``open`` → many reads/writes →
    ``close``. ``open`` may raise ``CacheBackendError``; the cache layer
    soft-fails to memory-only in that case. ``close`` is idempotent."""

    @abc.abstractmethod
    async def open(self) -> None: ...

    @abc.abstractmethod
    async def close(self) -> None: ...

    @abc.abstractmethod
    async def get(self, key: str) -> bytes | None: ...

    @abc.abstractmethod
    async def get_many(self, keys: list[str]) -> dict[str, bytes]: ...

    @abc.abstractmethod
    async def commit_batch(
        self, batch: list[tuple[str, bytes | None]],
    ) -> None:
        """Apply a batch atomically. Each entry is ``(key, bytes)`` for
        an upsert or ``(key, None)`` for a delete. Order is preserved —
        the last op for a given key wins, matching SQLite's
        ``INSERT OR REPLACE`` behavior."""

    @abc.abstractmethod
    async def load_recent(self, limit: int) -> list[tuple[str, bytes]]:
        """Return up to ``limit`` rows ordered OLDEST-first so the cache
        can preserve disk FIFO order when warming the OrderedDict."""

    @abc.abstractmethod
    async def evict_excess(self, max_rows: int) -> None:
        """Trim the cold tier to at most ``max_rows`` rows by deleting
        the lowest-seq rows first."""

    @abc.abstractmethod
    async def count_rows(self) -> int: ...


# ----------------------------------------------------------------------
# SQLite backend (port of the original on-disk path)
# ----------------------------------------------------------------------


class SQLiteBackend(CacheBackend):
    """One SQLite file per cache. Sync sqlite3 runs in a worker thread
    via ``asyncio.to_thread`` — the bundler's event loop never blocks on
    a SELECT or COMMIT.

    Two connections per backend: a write connection used only by the
    writer task path, and a read connection guarded by ``_read_lock``.
    The lock serialises close-vs-read so a malformed-row close can't
    yank the connection out from under an in-flight SELECT (see
    tests/test_cache_shutdown_race.py)."""

    def __init__(
        self,
        *,
        path: Path,
        table: str,
        cache_size_kb: int = 8_000,
    ) -> None:
        if not _SAFE_NAME.match(table):
            raise ValueError(
                f"table name must be a SQL identifier: {table!r}"
            )
        self._path = path
        self._table = table
        self._cache_size_kb = cache_size_kb
        self._write_conn: sqlite3.Connection | None = None
        self._read_conn: sqlite3.Connection | None = None
        # threading.Lock (not asyncio.Lock) because the readers run on
        # the asyncio default executor's worker threads — the contention
        # is between OS threads, not coroutines.
        self._read_lock = threading.Lock()

    async def open(self) -> None:
        try:
            await asyncio.to_thread(self._open_sync)
        except (OSError, sqlite3.Error) as exc:
            # _open_sync rolled back its own connections on failure.
            # Re-raise as the backend-neutral error type so the cache
            # layer can soft-fail uniformly.
            raise CacheBackendError(
                f"sqlite open at {self._path} failed: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

    def _open_sync(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            # isolation_level=None puts us in autocommit mode; the
            # writer task manages BEGIN/COMMIT explicitly.
            self._write_conn = sqlite3.connect(
                str(self._path),
                check_same_thread=False,
                isolation_level=None,
            )
            self._read_conn = sqlite3.connect(
                str(self._path),
                check_same_thread=False,
                isolation_level=None,
            )
            for conn in (self._write_conn, self._read_conn):
                # PRAGMAs are per-connection; both conns need them.
                conn.execute("PRAGMA journal_mode = WAL")
                conn.execute("PRAGMA synchronous  = NORMAL")
                conn.execute("PRAGMA temp_store   = MEMORY")
                conn.execute(
                    f"PRAGMA cache_size  = -{self._cache_size_kb}",
                )
                conn.execute("PRAGMA mmap_size    = 67108864")  # 64 MB
                # Multi-bundler safety: when another process on the
                # same chain shares this file and holds the WAL write
                # lock, wait up to 5 s rather than failing the commit.
                conn.execute("PRAGMA busy_timeout = 5000")

            self._write_conn.executescript(
                f"""
                CREATE TABLE IF NOT EXISTS {self._table} (
                    key   TEXT    PRIMARY KEY,
                    value BLOB    NOT NULL,
                    seq   INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS {self._table}_seq
                    ON {self._table} (seq);
                CREATE TABLE IF NOT EXISTS cache_meta (
                    table_name TEXT PRIMARY KEY,
                    next_seq   INTEGER NOT NULL
                );
                """
            )
        except Exception:
            # Roll back any partial state so the caller's soft-fail
            # path doesn't see a half-open backend.
            for attr in ("_write_conn", "_read_conn"):
                conn = getattr(self, attr, None)
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    setattr(self, attr, None)
            raise

    async def close(self) -> None:
        if self._write_conn is None and self._read_conn is None:
            return
        await asyncio.to_thread(self._close_sync)

    def _close_sync(self) -> None:
        try:
            if self._write_conn is not None:
                # Roll the WAL into the main DB so the next cold start
                # doesn't replay a large WAL.
                try:
                    self._write_conn.execute(
                        "PRAGMA wal_checkpoint(TRUNCATE)"
                    )
                except sqlite3.Error:
                    # Checkpoint is opportunistic; if the DB is being
                    # closed mid-flight we'd rather not raise.
                    pass
                self._write_conn.close()
        finally:
            # Hold _read_lock across the read-conn close+null so we
            # don't race a reader that already passed the None-check
            # and is about to execute a SELECT under the same lock.
            with self._read_lock:
                if self._read_conn is not None:
                    self._read_conn.close()
                self._write_conn = None
                self._read_conn = None

    async def get(self, key: str) -> bytes | None:
        return await asyncio.to_thread(self._get_sync, key)

    def _get_sync(self, key: str) -> bytes | None:
        # Check _read_conn INSIDE the lock — close_sync sets it to None
        # under the same lock, so a check outside would allow a stale
        # "not None" observation to ride a now-closed connection into
        # the SELECT below.
        with self._read_lock:
            if self._read_conn is None:
                return None
            cur = self._read_conn.execute(
                f"SELECT value FROM {self._table} WHERE key = ?",
                (key,),
            )
            row = cur.fetchone()
        return bytes(row[0]) if row else None

    async def get_many(self, keys: list[str]) -> dict[str, bytes]:
        return await asyncio.to_thread(self._get_many_sync, keys)

    def _get_many_sync(self, keys: list[str]) -> dict[str, bytes]:
        if not keys:
            return {}
        # SQLite has a SQLITE_LIMIT_VARIABLE_NUMBER ceiling. Real
        # callers pass a handful of keys; this guard catches accidental
        # misuse without imposing a chunking dance for the common case.
        if len(keys) > 500:
            raise ValueError(
                f"get_many: {len(keys)} keys exceeds the per-query limit"
            )
        placeholders = ",".join("?" * len(keys))
        with self._read_lock:
            if self._read_conn is None:
                return {}
            cur = self._read_conn.execute(
                f"SELECT key, value FROM {self._table} "
                f"WHERE key IN ({placeholders})",
                keys,
            )
            rows = cur.fetchall()
        return {k: bytes(v) for k, v in rows}

    async def commit_batch(
        self, batch: list[tuple[str, bytes | None]],
    ) -> None:
        await asyncio.to_thread(self._commit_batch_sync, batch)

    def _commit_batch_sync(
        self, batch: list[tuple[str, bytes | None]],
    ) -> None:
        if self._write_conn is None:
            # Disk tier disabled mid-flight; drop the batch.
            return
        cur = self._write_conn.cursor()
        # IMMEDIATE takes the write lock upfront so concurrent
        # bundlers serialise cleanly via busy_timeout rather than
        # getting partway through and hitting SQLITE_BUSY.
        cur.execute("BEGIN IMMEDIATE")
        try:
            # Read authoritative next_seq inside the write lock so a
            # second bundler that committed since our last batch
            # doesn't cause us to reuse its seq values.
            row = cur.execute(
                "SELECT next_seq FROM cache_meta WHERE table_name = ?",
                (self._table,),
            ).fetchone()
            next_seq = row[0] if row else 0
            for key, value in batch:
                if value is None:
                    cur.execute(
                        f"DELETE FROM {self._table} WHERE key = ?",
                        (key,),
                    )
                else:
                    cur.execute(
                        f"INSERT OR REPLACE INTO {self._table} "
                        f"(key, value, seq) VALUES (?, ?, ?)",
                        (key, value, next_seq),
                    )
                    next_seq += 1
            cur.execute(
                "INSERT OR REPLACE INTO cache_meta "
                "(table_name, next_seq) VALUES (?, ?)",
                (self._table, next_seq),
            )
            cur.execute("COMMIT")
        except Exception:
            cur.execute("ROLLBACK")
            raise

    async def load_recent(self, limit: int) -> list[tuple[str, bytes]]:
        return await asyncio.to_thread(self._load_recent_sync, limit)

    def _load_recent_sync(self, limit: int) -> list[tuple[str, bytes]]:
        with self._read_lock:
            if self._read_conn is None:
                return []
            cur = self._read_conn.execute(
                f"SELECT key, value FROM {self._table} "
                f"ORDER BY seq DESC LIMIT ?",
                (limit,),
            )
            rows = cur.fetchall()
        # Came back newest-first; flip so the caller sees oldest-first.
        return [(k, bytes(v)) for k, v in reversed(rows)]

    async def evict_excess(self, max_rows: int) -> None:
        await asyncio.to_thread(self._evict_excess_sync, max_rows)

    def _evict_excess_sync(self, max_rows: int) -> None:
        if self._write_conn is None:
            return
        cur = self._write_conn.cursor()
        cur.execute(f"SELECT COUNT(*) FROM {self._table}")
        count = cur.fetchone()[0]
        if count <= max_rows:
            return
        overflow = count - max_rows
        cur.execute("BEGIN")
        try:
            cur.execute(
                f"DELETE FROM {self._table} WHERE seq IN "
                f"(SELECT seq FROM {self._table} "
                f"ORDER BY seq LIMIT ?)",
                (overflow,),
            )
            cur.execute("COMMIT")
        except Exception:
            cur.execute("ROLLBACK")
            raise

    async def count_rows(self) -> int:
        return await asyncio.to_thread(self._count_rows_sync)

    def _count_rows_sync(self) -> int:
        with self._read_lock:
            if self._read_conn is None:
                return 0
            row = self._read_conn.execute(
                f"SELECT COUNT(*) FROM {self._table}",
            ).fetchone()
        return row[0] if row else 0


# ----------------------------------------------------------------------
# Postgres backend
# ----------------------------------------------------------------------


# Module-level shared pool. PersistentFIFOCache instances are
# module-level singletons created at import time; the pool is opened
# once at start_all() time and shared across every PostgresBackend.
_postgres_pool: "asyncpg.Pool | None" = None
_postgres_pool_lock = asyncio.Lock()


async def init_postgres_pool(config: PostgresConfig) -> None:
    """Open the shared asyncpg pool. Idempotent — repeat calls are
    no-ops once the pool is open. Raises CacheBackendError if asyncpg
    isn't installed or the pool can't open."""
    global _postgres_pool
    if asyncpg is None:
        raise CacheBackendError(
            "asyncpg not installed — install voltaire's postgres "
            "extras (poetry install) to use --cache_backend postgres"
        )
    async with _postgres_pool_lock:
        if _postgres_pool is not None:
            return
        try:
            _postgres_pool = await asyncpg.create_pool(
                dsn=config.url,
                min_size=config.min_pool_size,
                max_size=config.max_pool_size,
            )
        except Exception as exc:
            raise CacheBackendError(
                f"postgres pool open failed: "
                f"{type(exc).__name__}: {exc}"
            ) from exc


async def close_postgres_pool() -> None:
    """Close the shared pool. Idempotent."""
    global _postgres_pool
    async with _postgres_pool_lock:
        if _postgres_pool is None:
            return
        try:
            await _postgres_pool.close()
        finally:
            _postgres_pool = None


def _get_postgres_pool() -> "asyncpg.Pool":
    if _postgres_pool is None:
        raise CacheBackendError(
            "postgres pool is not initialised — "
            "call init_postgres_pool() before opening backends"
        )
    return _postgres_pool


class PostgresBackend(CacheBackend):
    """One table per cache, all sharing a single asyncpg pool. Uses a
    per-table SEQUENCE for FIFO ordering — concurrent inserts from
    multiple bundler processes get distinct seq values naturally, no
    SELECT FOR UPDATE dance needed."""

    def __init__(self, *, table: str, table_prefix: str = "") -> None:
        full_table = f"{table_prefix}{table}"
        if not _SAFE_NAME.match(full_table):
            raise ValueError(
                f"table name must be a SQL identifier: {full_table!r}"
            )
        self._table = full_table
        self._seq = f"{full_table}_seq"
        self._closed = False

    async def open(self) -> None:
        pool = _get_postgres_pool()
        try:
            async with pool.acquire() as conn:
                # CREATE SEQUENCE before the table so the DEFAULT can
                # reference it. Both are IF NOT EXISTS so reruns on an
                # existing DB are no-ops.
                await conn.execute(
                    f'CREATE SEQUENCE IF NOT EXISTS "{self._seq}"'
                )
                await conn.execute(
                    f'CREATE TABLE IF NOT EXISTS "{self._table}" ('
                    f'    key   TEXT   PRIMARY KEY,'
                    f'    value BYTEA  NOT NULL,'
                    f'    seq   BIGINT NOT NULL '
                    f'          DEFAULT nextval(\'"{self._seq}"\')'
                    f')'
                )
                await conn.execute(
                    f'CREATE INDEX IF NOT EXISTS "{self._table}_seq_idx" '
                    f'ON "{self._table}" (seq)'
                )
        except Exception as exc:
            if asyncpg is not None and isinstance(
                exc, asyncpg.PostgresError,
            ):
                raise CacheBackendError(
                    f"postgres open for {self._table} failed: "
                    f"{type(exc).__name__}: {exc}"
                ) from exc
            raise

    async def close(self) -> None:
        # The pool itself is owned by the module — see
        # close_postgres_pool. A backend just stops issuing queries.
        self._closed = True

    async def get(self, key: str) -> bytes | None:
        if self._closed:
            return None
        pool = _get_postgres_pool()
        try:
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    f'SELECT value FROM "{self._table}" WHERE key = $1',
                    key,
                )
        except Exception as exc:
            raise self._wrap(exc, "get") from exc
        return bytes(row["value"]) if row else None

    async def get_many(self, keys: list[str]) -> dict[str, bytes]:
        if not keys or self._closed:
            return {}
        pool = _get_postgres_pool()
        try:
            async with pool.acquire() as conn:
                rows = await conn.fetch(
                    f'SELECT key, value FROM "{self._table}" '
                    f'WHERE key = ANY($1::text[])',
                    keys,
                )
        except Exception as exc:
            raise self._wrap(exc, "get_many") from exc
        return {r["key"]: bytes(r["value"]) for r in rows}

    async def commit_batch(
        self, batch: list[tuple[str, bytes | None]],
    ) -> None:
        if not batch or self._closed:
            return
        pool = _get_postgres_pool()
        # Run the whole batch in a single transaction. Sequential
        # execution preserves insertion order so "set then delete then
        # set" for the same key ends in the set state, matching
        # SQLite's INSERT OR REPLACE semantics.
        try:
            async with pool.acquire() as conn:
                async with conn.transaction():
                    for key, value in batch:
                        if value is None:
                            await conn.execute(
                                f'DELETE FROM "{self._table}" '
                                f'WHERE key = $1',
                                key,
                            )
                        else:
                            # ON CONFLICT … nextval bumps seq on
                            # overwrite so the row moves to FIFO-newest
                            # position, matching the SQLite path.
                            await conn.execute(
                                f'INSERT INTO "{self._table}" '
                                f'(key, value, seq) VALUES '
                                f'($1, $2, nextval(\'"{self._seq}"\')) '
                                f'ON CONFLICT (key) DO UPDATE SET '
                                f'value = EXCLUDED.value, '
                                f'seq = nextval(\'"{self._seq}"\')',
                                key, value,
                            )
        except Exception as exc:
            raise self._wrap(exc, "commit_batch") from exc

    async def load_recent(self, limit: int) -> list[tuple[str, bytes]]:
        if self._closed:
            return []
        pool = _get_postgres_pool()
        try:
            async with pool.acquire() as conn:
                rows = await conn.fetch(
                    f'SELECT key, value FROM "{self._table}" '
                    f'ORDER BY seq DESC LIMIT $1',
                    limit,
                )
        except Exception as exc:
            raise self._wrap(exc, "load_recent") from exc
        # Came back newest-first; flip so the caller sees oldest-first.
        return [(r["key"], bytes(r["value"])) for r in reversed(rows)]

    async def evict_excess(self, max_rows: int) -> None:
        if self._closed:
            return
        pool = _get_postgres_pool()
        try:
            async with pool.acquire() as conn:
                async with conn.transaction():
                    count = await conn.fetchval(
                        f'SELECT COUNT(*) FROM "{self._table}"'
                    )
                    if count <= max_rows:
                        return
                    overflow = count - max_rows
                    await conn.execute(
                        f'DELETE FROM "{self._table}" WHERE seq IN ('
                        f'    SELECT seq FROM "{self._table}" '
                        f'    ORDER BY seq LIMIT $1'
                        f')',
                        overflow,
                    )
        except Exception as exc:
            raise self._wrap(exc, "evict_excess") from exc

    async def count_rows(self) -> int:
        if self._closed:
            return 0
        pool = _get_postgres_pool()
        try:
            async with pool.acquire() as conn:
                return await conn.fetchval(
                    f'SELECT COUNT(*) FROM "{self._table}"'
                ) or 0
        except Exception as exc:
            raise self._wrap(exc, "count_rows") from exc

    def _wrap(self, exc: Exception, op: str) -> Exception:
        if asyncpg is not None and isinstance(
            exc, (asyncpg.PostgresError, asyncpg.InterfaceError),
        ):
            return CacheBackendError(
                f"postgres {op} on {self._table} failed: "
                f"{type(exc).__name__}: {exc}"
            )
        return exc


# ----------------------------------------------------------------------
# Factory
# ----------------------------------------------------------------------


def make_backend(config: BackendConfig, name: str) -> CacheBackend:
    """Construct a backend for a cache. Pool initialisation for the
    Postgres path happens once in ``init_postgres_pool``; this just
    spins up a per-cache backend object."""
    if isinstance(config, SQLiteConfig):
        return SQLiteBackend(
            path=config.cache_dir / f"{name}.sqlite",
            table=name,
            cache_size_kb=config.cache_size_kb,
        )
    if isinstance(config, PostgresConfig):
        return PostgresBackend(
            table=name, table_prefix=config.table_prefix,
        )
    raise TypeError(f"unknown backend config: {type(config).__name__}")


__all__ = [
    "BackendConfig",
    "CacheBackend",
    "CacheBackendError",
    "PostgresBackend",
    "PostgresConfig",
    "SQLiteBackend",
    "SQLiteConfig",
    "close_postgres_pool",
    "init_postgres_pool",
    "make_backend",
]
