"""
FIFO cache with an optional on-disk cold tier (Postgres).

Hot tier: ``OrderedDict`` capped at ``memory_capacity``. Strict FIFO —
overwrites of existing keys do NOT refresh insertion order.

Cold tier (enabled when ``start(backend=...)`` is called with a
non-None backend): a per-cache key-value store backed by
PostgresBackend (see ``cache_backends.py``). Writes are non-blocking
on the RPC path — ``set`` enqueues onto a bounded ``asyncio.Queue``
whose consumer is a background writer task that batches up to
``BATCH_MAX`` writes per backend commit.

Reads consult memory first; on miss, an async backend read runs.

When ``start`` is called without a backend (or never called), the
cache behaves as a memory-only FIFO: ``get`` is still async, but
never falls through to disk.

Eviction-order discrepancy on overwrites
----------------------------------------
The two tiers diverge on how they treat ``set(k, v)`` for a key
that's already present:

- The memory ``OrderedDict`` keeps the key in its **original**
  insertion slot (strict FIFO — overwrites do not refresh recency).
- The disk side bumps the seq on overwrite (Postgres'
  ``ON CONFLICT … nextval``), so the entry moves to the
  **FIFO-newest** position on disk.

After a restart, ``_warm_memory_from_disk`` loads ``memory_capacity``
rows by ``seq DESC`` — i.e. the disk view wins, and a key that was
"old" in the previous session's memory comes back as "newest" in
memory. This is intentional today because all current callers store
deterministic values (chain-immutable logs/receipts/txs, or
``seen_cache`` block hex where either bundler's value is correct),
so the eviction-priority flip is invisible. If you add a caller that
overwrites with different semantics, audit this.
"""
from __future__ import annotations

import asyncio
import json
import logging
from collections import OrderedDict
from typing import Any

from voltaire_bundler.utils.cache_backends import (
    CacheBackend,
    CacheBackendError,
    PostgresBackend,
    PostgresConfig,
    close_postgres_pool,
    init_postgres_pool,
)

logger = logging.getLogger(__name__)

# Sentinel used internally to represent a delete in the write queue.
# The writer task translates it into a backend delete (None payload).
# Distinct from a stored ``None`` value.
_TOMBSTONE: object = object()

# Tuning knobs — kept module-level so they're easy to find and
# override in tests.
BATCH_MAX = 100              # max writes coalesced into one backend commit
QUEUE_MAX = 10_000           # max disk-writes queued before we drop-oldest
EVICT_EVERY_N_WRITES = 1000  # how often the writer task prunes excess rows


class PersistentFIFOCache:
    # Process-wide registry so the bundler entry point can start/stop
    # all caches in one shot without threading them through every
    # constructor.
    _instances: list["PersistentFIFOCache"] = []

    def __init__(
        self,
        name: str,
        memory_capacity: int = 10_000,
        disk_capacity: int = 500_000,
    ) -> None:
        self.name = name
        self.memory_capacity = memory_capacity
        self.disk_capacity = disk_capacity

        self._memory: OrderedDict[str, Any] = OrderedDict()

        # Disk-tier state. None until start(backend=...) is called
        # with a non-None backend; cleared again on soft-fail.
        self._backend: CacheBackend | None = None
        self._write_queue: asyncio.Queue[tuple[str, Any]] | None = None
        self._writer_task: asyncio.Task[None] | None = None
        self._writes_since_evict: int = 0

        self._started: bool = False

        # Startup observability: how many rows _warm_memory_from_disk
        # pulled into memory. Free to capture (just len(rows)) so it
        # happens on the critical path. The matching on-disk row total
        # is fetched lazily by log_startup_status so the extra
        # COUNT(*) doesn't extend bundler startup.
        self._memory_loaded_at_start: int = 0

        PersistentFIFOCache._instances.append(self)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @property
    def persistent(self) -> bool:
        return self._backend is not None

    async def start(self, backend: CacheBackend | None = None) -> None:
        """Start the cache. With ``backend=None`` runs in memory-only
        mode. Idempotent — repeat calls are a no-op.

        If the disk tier is requested but the backend can't open
        (Postgres unreachable, auth failure, etc.), the cache
        soft-fails to memory-only with a warning. The bundler still
        runs; the next restart re-attempts the disk tier."""
        if self._started:
            return
        if backend is None:
            self._started = True
            return
        self._backend = backend
        try:
            await backend.open()
            # Preload the freshest entries from disk so the first
            # batch of RPCs after a restart get hot hits instead of
            # falling through to disk. Inside the same try/except as
            # open() — a corrupt or partially-readable backend can
            # fail at read time, and we'd rather degrade to
            # memory-only than abort start().
            await self._warm_memory_from_disk()
        except CacheBackendError as exc:
            logger.warning(
                "cache %s: disk tier disabled (%s); running "
                "memory-only. Check VOLTAIRE_CACHE_POSTGRES_URL or "
                "unset it to silence this warning.",
                self.name, exc,
            )
            try:
                await backend.close()
            except Exception:
                pass
            self._backend = None
            self._started = True
            return
        if self._backend is None:
            # _warm_memory_from_disk hit a fatal decode error and
            # cleared the backend; no point spinning up a writer that
            # has nothing to write to.
            self._started = True
            return
        self._write_queue = asyncio.Queue(maxsize=QUEUE_MAX)
        self._writer_task = asyncio.create_task(
            self._writer_loop(), name=f"cache-writer:{self.name}",
        )
        self._started = True

    async def aclose(self) -> None:
        if not self._started:
            return
        if self._write_queue is not None:
            # Wait for all enqueued writes to flush.
            await self._write_queue.join()
        if self._writer_task is not None:
            self._writer_task.cancel()
            try:
                await self._writer_task
            except asyncio.CancelledError:
                pass
            self._writer_task = None
        if self._backend is not None:
            try:
                await self._backend.close()
            except Exception:
                logger.exception("cache %s: backend close failed", self.name)
            self._backend = None
        self._started = False

    @classmethod
    def apply_capacity_multipliers(
        cls, memory_mult: float, disk_mult: float,
    ) -> None:
        """Scale every registered cache's capacities by the given
        multipliers. Must be called BEFORE ``start_all`` so warm-on-start
        observes the new memory cap and disk eviction uses the new disk
        cap."""
        if memory_mult <= 0 or disk_mult <= 0:
            raise ValueError("cache size multipliers must be positive")
        for cache in cls._instances:
            cache.memory_capacity = max(
                1, int(cache.memory_capacity * memory_mult),
            )
            cache.disk_capacity = max(
                1, int(cache.disk_capacity * disk_mult),
            )

    @classmethod
    async def start_all(
        cls, config: PostgresConfig | None = None,
    ) -> None:
        """Start every registered cache instance.

        ``config=None`` means memory-only mode for every cache;
        otherwise each cache gets a PostgresBackend that talks to a
        shared connection pool."""
        if config is None:
            for cache in cls._instances:
                await cache.start(backend=None)
            return
        try:
            await init_postgres_pool(config)
        except CacheBackendError as exc:
            logger.warning(
                "cache: postgres pool open failed (%s); "
                "running all caches memory-only", exc,
            )
            for cache in cls._instances:
                await cache.start(backend=None)
            return
        for cache in cls._instances:
            await cache.start(
                backend=PostgresBackend(
                    table=cache.name,
                    table_prefix=config.table_prefix,
                ),
            )

    @classmethod
    async def aclose_all(cls) -> None:
        for cache in cls._instances:
            try:
                await cache.aclose()
            except Exception:
                logger.exception("cache %s: aclose failed", cache.name)
        # Tear down the shared Postgres pool last — backends above
        # have already stopped issuing queries, so it's safe to close.
        try:
            await close_postgres_pool()
        except Exception:
            logger.exception("cache: postgres pool close failed")

    @classmethod
    def log_startup_status(cls) -> None:
        """Emit a one-shot summary of cache tier state after start_all.

        Two phases. The synchronous phase reports the persistent /
        memory-only flag and the count of caches that fell back. The
        async phase follows up with per-cache (on-disk rows, rows
        warmed into memory) figures once a COUNT(*) per cache lands;
        that work is scheduled AFTER start_all so it never blocks the
        event loop or extends bundler startup."""
        if not cls._instances:
            return
        persistent = [c for c in cls._instances if c.persistent]
        memory_only = [c for c in cls._instances if not c.persistent]

        if not persistent:
            logger.info(
                "RPC caches: memory-only mode (%d caches; persistence "
                "disabled or soft-failed to memory-only)",
                len(memory_only),
            )
            return

        total_loaded = sum(c._memory_loaded_at_start for c in persistent)
        logger.info(
            "RPC caches: persistent mode active (%d on-disk caches, "
            "%d rows warmed into memory at startup); per-cache on-disk "
            "row counts to follow",
            len(persistent), total_loaded,
        )
        if memory_only:
            logger.info(
                "  %d caches in memory-only fallback: %s",
                len(memory_only),
                ", ".join(c.name for c in memory_only),
            )

        asyncio.create_task(
            cls._log_disk_row_counts(persistent),
            name="cache-disk-row-count-report",
        )

    @classmethod
    async def _log_disk_row_counts(
        cls, caches: list["PersistentFIFOCache"],
    ) -> None:
        """COUNT(*) each persistent cache off the critical path and
        emit the per-cache (on-disk, warmed) breakdown. Best-effort:
        per-cache errors are swallowed so a single corrupt DB doesn't
        suppress the rest."""
        counts: dict[str, int] = {}
        for c in caches:
            if c._backend is None:
                continue
            try:
                counts[c.name] = await c._backend.count_rows()
            except Exception:
                logger.exception(
                    "cache %s: disk row count failed", c.name,
                )
        if not counts:
            return
        logger.info(
            "RPC caches: %d total rows on disk", sum(counts.values()),
        )
        for c in caches:
            if c.name not in counts:
                continue
            logger.info(
                "  cache %s: %d on disk, %d warmed into memory "
                "(memory_capacity=%d, disk_capacity=%d)",
                c.name, counts[c.name], c._memory_loaded_at_start,
                c.memory_capacity, c.disk_capacity,
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get(self, key: str) -> Any | None:
        # ``is not None`` is the hit/miss signal, so a cached ``None``
        # is indistinguishable from "not in cache" and triggers a
        # refetch. That's the right behavior for this codebase: every
        # key maps to chain-derived state that can change over time (a
        # userop hash with no log today may have one after the next
        # bundle), so there's no such thing as an authoritative cached
        # "no result". If you wire up a caller whose miss IS final,
        # this needs a sentinel-based signal instead.
        v = self._memory.get(key)
        if v is not None:
            return v
        if self._backend is None:
            return None
        # Cold tier fallback.
        raw = await self._backend_get(key)
        if raw is None:
            return None
        try:
            v = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning(
                "cache %s: malformed payload for key %s (%s); "
                "disabling disk tier and treating this lookup as a miss",
                self.name, key, exc,
            )
            await self._disable_disk_tier()
            return None
        # Promote so a follow-up read is a hot hit.
        self._memory[key] = v
        if len(self._memory) > self.memory_capacity:
            self._memory.popitem(last=False)
        return v

    async def get_many(self, keys: list[str]) -> dict[str, Any]:
        """Bulk lookup. Returns a dict mapping each key that's present
        (in either tier) to its value; keys absent from both tiers are
        absent from the result. Memory misses for all keys go to disk
        in a single backend round trip instead of one per key — the
        difference matters when a hot-path handler probes 4+ keys at
        once (e.g. seen-cache fan-out across entrypoint versions)."""
        if not keys:
            return {}
        found: dict[str, Any] = {}
        misses: list[str] = []
        for k in keys:
            v = self._memory.get(k)
            if v is not None:
                found[k] = v
            else:
                misses.append(k)
        if misses and self._backend is not None:
            raw_hits = await self._backend_get_many(misses)
            for k, raw in raw_hits.items():
                try:
                    v = json.loads(raw)
                except json.JSONDecodeError as exc:
                    logger.warning(
                        "cache %s: malformed payload for key %s (%s); "
                        "disabling disk tier and skipping the bad row",
                        self.name, k, exc,
                    )
                    await self._disable_disk_tier()
                    # Return whatever was already decoded — the caller
                    # treats absent keys as misses, which is the
                    # correct degradation.
                    return found
                found[k] = v
                self._memory[k] = v
                if len(self._memory) > self.memory_capacity:
                    self._memory.popitem(last=False)
        return found

    def set(self, key: str, value: Any) -> None:
        # Hot tier: insert (or overwrite in place — OrderedDict
        # preserves position on overwrite, keeping the FIFO order
        # pinned to the ORIGINAL insertion time).
        self._memory[key] = value
        if len(self._memory) > self.memory_capacity:
            self._memory.popitem(last=False)
        # Cold tier: hand off to the writer task. Sub-µs.
        self._enqueue_disk_write(key, value)

    def delete(self, key: str) -> None:
        self._memory.pop(key, None)
        self._enqueue_disk_write(key, _TOMBSTONE)

    def __contains__(self, key: str) -> bool:
        # Memory-only check; intentional, since async ``in`` doesn't
        # exist.
        return key in self._memory

    def __len__(self) -> int:
        return len(self._memory)

    # ------------------------------------------------------------------
    # Internal: backend wrappers (centralise the soft-fail try/except)
    # ------------------------------------------------------------------

    async def _backend_get(self, key: str) -> bytes | None:
        assert self._backend is not None
        try:
            return await self._backend.get(key)
        except CacheBackendError as exc:
            logger.warning(
                "cache %s: backend get failed (%s); "
                "disabling disk tier",
                self.name, exc,
            )
            await self._disable_disk_tier()
            return None

    async def _backend_get_many(
        self, keys: list[str],
    ) -> dict[str, bytes]:
        assert self._backend is not None
        try:
            return await self._backend.get_many(keys)
        except CacheBackendError as exc:
            logger.warning(
                "cache %s: backend get_many failed (%s); "
                "disabling disk tier",
                self.name, exc,
            )
            await self._disable_disk_tier()
            return {}

    # ------------------------------------------------------------------
    # Internal: write queue
    # ------------------------------------------------------------------

    def _enqueue_disk_write(self, key: str, value: Any) -> None:
        # Either branch means there's no disk tier to write to: queue
        # never built (memory-only start) or disk tier soft-failed and
        # cleared the backend mid-flight.
        if self._write_queue is None or self._backend is None:
            return
        try:
            self._write_queue.put_nowait((key, value))
            return
        except asyncio.QueueFull:
            pass
        # Drop the oldest queued write to make room. The dropped entry
        # stays in memory; it just won't be durable. Keeps the RPC
        # path non-blocking under pathological write bursts.
        try:
            self._write_queue.get_nowait()
            self._write_queue.task_done()
        except asyncio.QueueEmpty:
            pass
        try:
            self._write_queue.put_nowait((key, value))
        except asyncio.QueueFull:
            pass
        logger.warning(
            "cache %s: write queue full, dropped oldest", self.name,
        )

    async def _writer_loop(self) -> None:
        assert self._write_queue is not None
        # One-shot cleanup of any overage accumulated across previous
        # sessions. _writes_since_evict only triggers in-session
        # eviction after EVICT_EVERY_N_WRITES; a frequently-restarting
        # bundler that never crosses that threshold would otherwise
        # let the disk file drift past disk_capacity indefinitely.
        # Doing this in the writer task instead of in start() keeps
        # startup latency untouched.
        try:
            if self._backend is not None:
                await self._backend.evict_excess(self.disk_capacity)
        except CacheBackendError as exc:
            logger.warning(
                "cache %s: startup eviction failed (%s)", self.name, exc,
            )
        except Exception:
            logger.exception(
                "cache %s: startup eviction failed", self.name,
            )
        while True:
            first = await self._write_queue.get()
            batch: list[tuple[str, Any]] = [first]
            # Opportunistically drain more without awaiting — batches
            # grow under load, stay small under idle.
            try:
                while len(batch) < BATCH_MAX:
                    batch.append(self._write_queue.get_nowait())
            except asyncio.QueueEmpty:
                pass
            try:
                await self._commit_batch(batch)
                self._writes_since_evict += len(batch)
                if self._writes_since_evict >= EVICT_EVERY_N_WRITES:
                    if self._backend is not None:
                        try:
                            await self._backend.evict_excess(
                                self.disk_capacity,
                            )
                        except CacheBackendError as exc:
                            logger.warning(
                                "cache %s: eviction failed (%s)",
                                self.name, exc,
                            )
                    self._writes_since_evict = 0
            except Exception:
                logger.exception(
                    "cache %s: batch commit failed", self.name,
                )
            finally:
                for _ in batch:
                    self._write_queue.task_done()

    async def _commit_batch(
        self, batch: list[tuple[str, Any]],
    ) -> None:
        if self._backend is None:
            return
        # Encode in the cache layer; the backend stores opaque bytes.
        encoded: list[tuple[str, bytes | None]] = []
        for key, value in batch:
            if value is _TOMBSTONE:
                encoded.append((key, None))
            else:
                encoded.append((key, json.dumps(value).encode("utf-8")))
        try:
            await self._backend.commit_batch(encoded)
        except CacheBackendError as exc:
            # Unlike read-path errors, we don't auto-disable on write
            # errors — transient backend hiccups (e.g. brief Postgres
            # disconnect) shouldn't permanently demote the cache. Log
            # loudly; the loop will retry on the next batch.
            logger.warning(
                "cache %s: backend commit failed (%s); "
                "batch lost, disk tier remains active",
                self.name, exc,
            )

    # ------------------------------------------------------------------
    # Internal: warmup and disable
    # ------------------------------------------------------------------

    async def _warm_memory_from_disk(self) -> None:
        """Preload the most-recent ``memory_capacity`` rows into the hot
        tier so the first reads after a restart don't need disk
        fallback. The backend returns rows in oldest-first order so the
        OrderedDict's FIFO order mirrors on-disk insertion order
        (oldest first, newest last)."""
        if self._backend is None:
            return
        rows = await self._backend.load_recent(self.memory_capacity)
        loaded = 0
        for key, raw in rows:
            try:
                self._memory[key] = json.loads(raw)
            except json.JSONDecodeError as exc:
                logger.warning(
                    "cache %s: malformed payload for key %s during "
                    "warmup (%s); disabling disk tier and continuing "
                    "memory-only", self.name, key, exc,
                )
                await self._disable_disk_tier()
                break
            loaded += 1
        self._memory_loaded_at_start = loaded

    async def _disable_disk_tier(self) -> None:
        """Soft-fail the disk tier after an unrecoverable error
        (malformed payload, lost Postgres connection, etc.). Closes
        the backend and clears the reference so subsequent reads
        stay memory-only. Idempotent.

        The writer task lingers but its commits no-op once the
        backend is None; new ``set``/``delete`` calls also no-op
        (``_enqueue_disk_write`` checks the backend)."""
        if self._backend is None:
            return
        backend = self._backend
        self._backend = None
        try:
            await backend.close()
        except Exception:
            logger.exception(
                "cache %s: closing backend after disk-tier disable "
                "failed", self.name,
            )


# Re-export the backend types so callers only need to import from
# cache.py for typical usage. Used by main.py / cli_manager.py.
__all__ = [
    "PersistentFIFOCache",
    "PostgresConfig",
]
