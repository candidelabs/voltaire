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

    ``table_prefix`` is prepended to each cache name to form the
    table name. ``main.py`` builds this from the bundler's chain_id
    (``voltaire_cache_chain_{chain_id}_``) so a single Postgres can
    serve bundlers on multiple chains with clear per-chain table
    ownership for ops (decommissioning, autovacuum tuning, disk
    attribution). Override at construction time if you need
    different scoping (e.g. multi-tenant), or set to an empty string
    for a dedicated single-purpose database."""
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
    async def evict_expired(self, ttl_seconds: int) -> None:
        """Delete every row whose ``inserted_at`` is older than
        ``ttl_seconds``. A single indexed range delete — no COUNT,
        no full scan, cost proportional to the number of evicted rows
        rather than to total table size."""

    @abc.abstractmethod
    async def count_rows(self) -> int:
        """Approximate row count. Backends are free to use a cheap
        planner statistic rather than an exact COUNT — the value
        feeds the startup log line, where order-of-magnitude
        accuracy beats a multi-minute scan."""


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
    """One table per cache, all sharing a single asyncpg pool. FIFO
    ordering is derived from ``inserted_at`` (microsecond-resolution
    wall clock); we used to carry a separate ``seq`` column for
    strictly-monotonic ordering, but the warmup-load order is the
    only consumer of it and ``inserted_at DESC`` gives the same
    answer in practice. Dropping seq saves one column + one index
    per write and unblocks HOT updates when only ``value`` /
    ``inserted_at`` change."""

    def __init__(self, *, table: str, table_prefix: str = "") -> None:
        full_table = f"{table_prefix}{table}"
        if not _SAFE_NAME.match(full_table):
            raise ValueError(
                f"table name must be a SQL identifier: {full_table!r}"
            )
        self._table = full_table
        self._closed = False

    async def open(self) -> None:
        pool = _get_postgres_pool()
        try:
            async with pool.acquire() as conn:
                # ``inserted_at`` drives both TTL eviction and warmup
                # ordering. All statements idempotent so reruns are
                # no-ops; the ALTER handles upgrading tables created
                # before the column existed.
                #
                # Tables migrated from the seq era will still have a
                # ``seq`` column lingering — harmless, unused by any
                # current query. Operators wanting to reclaim the
                # space can ``ALTER TABLE … DROP COLUMN seq`` manually.
                await conn.execute(
                    f'CREATE TABLE IF NOT EXISTS "{self._table}" ('
                    f'    key         TEXT        PRIMARY KEY,'
                    f'    value       BYTEA       NOT NULL,'
                    f'    inserted_at TIMESTAMPTZ NOT NULL DEFAULT now()'
                    f')'
                )
                await conn.execute(
                    f'ALTER TABLE "{self._table}" '
                    f'ADD COLUMN IF NOT EXISTS '
                    f'inserted_at TIMESTAMPTZ NOT NULL DEFAULT now()'
                )
                await conn.execute(
                    f'CREATE INDEX IF NOT EXISTS '
                    f'"{self._table}_inserted_at_idx" '
                    f'ON "{self._table}" (inserted_at)'
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
        # Dedupe by key — last op wins, matching the previous
        # sequential-execution semantic ("set then delete then set"
        # for the same key ends in the set state). After this each
        # key appears in at most one of sets/deletes, so the order
        # we run the two ``executemany`` calls is irrelevant.
        last_op: dict[str, bytes | None] = {}
        for key, value in batch:
            last_op[key] = value
        sets = [(k, v) for k, v in last_op.items() if v is not None]
        deletes = [(k,) for k, v in last_op.items() if v is None]

        pool = _get_postgres_pool()
        try:
            async with pool.acquire() as conn:
                async with conn.transaction():
                    if deletes:
                        # asyncpg sends executemany as one extended
                        # protocol round-trip — N parameter sets
                        # against a single prepared statement, no
                        # per-row network latency.
                        await conn.executemany(
                            f'DELETE FROM "{self._table}" '
                            f'WHERE key = $1',
                            deletes,
                        )
                    if sets:
                        # ON CONFLICT refreshes inserted_at so an
                        # overwritten row resets the TTL clock —
                        # otherwise a frequently-touched key could
                        # still age out from its original insertion
                        # timestamp.
                        await conn.executemany(
                            f'INSERT INTO "{self._table}" '
                            f'(key, value) VALUES ($1, $2) '
                            f'ON CONFLICT (key) DO UPDATE SET '
                            f'value = EXCLUDED.value, '
                            f'inserted_at = now()',
                            sets,
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
                    f'ORDER BY inserted_at DESC LIMIT $1',
                    limit,
                )
        except Exception as exc:
            raise self._wrap(exc, "load_recent") from exc
        # Came back newest-first; flip so the caller sees oldest-first.
        return [(r["key"], bytes(r["value"])) for r in reversed(rows)]

    async def evict_expired(self, ttl_seconds: int) -> None:
        if self._closed:
            return
        pool = _get_postgres_pool()
        try:
            async with pool.acquire() as conn:
                # Single indexed range delete via the
                # inserted_at_idx — no COUNT, no full table scan,
                # cost proportional to the number of expired rows.
                await conn.execute(
                    f'DELETE FROM "{self._table}" WHERE '
                    f'inserted_at < now() - make_interval(secs => $1)',
                    ttl_seconds,
                )
        except Exception as exc:
            raise self._wrap(exc, "evict_expired") from exc

    async def count_rows(self) -> int:
        """Approximate row count from ``pg_class.reltuples``. The
        value is the planner's row estimate, updated by VACUUM /
        ANALYZE — accurate enough for the startup log line and
        constant-time regardless of table size (unlike COUNT(*),
        which would scan the full table). Freshly-created tables
        report ``-1`` until the first ANALYZE; clamp to 0 so the log
        doesn't surface a negative number."""
        if self._closed:
            return 0
        pool = _get_postgres_pool()
        try:
            async with pool.acquire() as conn:
                # to_regclass resolves the quoted identifier through
                # the search_path, returning NULL if the table is
                # missing (in which case fetchval returns None and we
                # fall back to 0).
                result = await conn.fetchval(
                    'SELECT GREATEST(0, reltuples::bigint)::bigint '
                    'FROM pg_class WHERE oid = to_regclass($1)',
                    f'"{self._table}"',
                )
        except Exception as exc:
            raise self._wrap(exc, "count_rows") from exc
        return result or 0

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
