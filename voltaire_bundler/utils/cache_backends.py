"""
Postgres cache backend for PersistentFIFOCache.

The cache layer (cache.py) owns the in-memory hot tier, the bounded
write queue, batching, FIFO eviction policy, and the soft-fail
behavior that drops to memory-only on disk-tier errors. This module
owns the bytes-in/bytes-out cold tier — one shared asyncpg pool
across every cache, with one table per cache name.

Values stored by the backend are opaque bytes; the cache layer
handles JSON encoding/decoding. A malformed-payload error therefore
surfaces in the cache layer, not here.

The backend raises CacheBackendError to signal a failure the cache
layer should treat as fatal for the disk tier — at open time that
means fall through to memory-only; mid-flight it means call close()
and clear the backend reference.
"""
from __future__ import annotations

import abc
import asyncio
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    import asyncpg
else:
    try:
        import asyncpg  # type: ignore[import-not-found]
    except ImportError:
        asyncpg = None  # type: ignore[assignment]


# Gate the cache layer uses for cache names. Identifiers are
# interpolated into SQL via f-strings (parameterised queries can't
# bind table/sequence names), so anything that escapes a SQL
# identifier here is a code bug, not a runtime input.
_SAFE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class CacheBackendError(Exception):
    """Raised when a backend operation fails fatally enough to disable
    the disk tier. Callers should log, drop the backend reference, and
    keep serving from memory."""


@dataclass
class PostgresConfig:
    """Configuration for the Postgres backend.

    ``url`` is a standard libpq DSN (``postgresql://user:pass@host:port/db``).
    A single connection pool is shared across every cache.

    ``table_prefix`` is prepended to each cache name to form the table
    name. The prefix keeps the bundler's tables visually separated
    from anything else sharing the database. Set to an empty string
    for a dedicated database."""
    url: str
    min_pool_size: int = 1
    max_pool_size: int = 10
    table_prefix: str = "voltaire_cache_"


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
        an upsert or ``(key, None)`` for a delete. Order is preserved
        — the last op for a given key wins."""

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
# Shared pool lifecycle
# ----------------------------------------------------------------------


# PersistentFIFOCache instances are module-level singletons created
# at import time; the pool is opened once at start_all() time and
# shared across every PostgresBackend.
_postgres_pool: "asyncpg.Pool | None" = None
_postgres_pool_lock = asyncio.Lock()


async def init_postgres_pool(config: PostgresConfig) -> None:
    """Open the shared asyncpg pool. Idempotent — repeat calls are
    no-ops once the pool is open. Raises CacheBackendError if asyncpg
    isn't installed or the pool can't open."""
    global _postgres_pool
    if asyncpg is None:
        raise CacheBackendError(
            "asyncpg not installed — run `poetry install` to pull "
            "it in before enabling the persistent cache"
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


# ----------------------------------------------------------------------
# Postgres backend
# ----------------------------------------------------------------------


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
        # set" for the same key ends in the set state.
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
                            # position.
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


__all__ = [
    "CacheBackend",
    "CacheBackendError",
    "PostgresBackend",
    "PostgresConfig",
    "close_postgres_pool",
    "init_postgres_pool",
]
