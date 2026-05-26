"""
FIFO cache with an optional on-disk cold tier (SQLite).

Hot tier: ``OrderedDict`` capped at ``memory_capacity``. Strict FIFO —
overwrites of existing keys do NOT refresh insertion order.

Cold tier (enabled when ``start(sqlite_path=...)`` is called with a path):
a single SQLite table keyed by ``key``, with a monotonic ``seq`` column for
FIFO ordering. Writes are non-blocking on the RPC path — ``set`` enqueues
onto a bounded ``asyncio.Queue`` whose consumer is a background writer
task that batches up to ``BATCH_MAX`` writes per transaction and commits
via ``asyncio.to_thread``.

Reads consult memory first; on miss, a ``SELECT`` runs via
``asyncio.to_thread`` against a dedicated read connection. WAL mode is
enabled so readers never wait on the writer.

When ``start`` is called without a ``sqlite_path`` (or never called), the
cache behaves as a memory-only FIFO: ``get`` is still async, but never
falls through to disk.

Eviction-order discrepancy on overwrites
----------------------------------------
The two tiers diverge on how they treat ``set(k, v)`` for a key that's
already present:

- The memory ``OrderedDict`` keeps the key in its **original** insertion
  slot (strict FIFO — overwrites do not refresh recency).
- The disk side uses ``INSERT OR REPLACE``, which deletes the existing
  row and reinserts with a fresh ``seq``, so the entry moves to the
  **FIFO-newest** position on disk.

After a restart, ``warm_memory_from_disk`` loads ``memory_capacity``
rows by ``seq DESC`` — i.e. the disk view wins, and a key that was
"old" in the previous session's memory comes back as "newest" in
memory. This is intentional today because all current callers store
deterministic values (chain-immutable logs/receipts/txs, or
``seen_cache`` block hex where either bundler's value is correct), so
the eviction-priority flip is invisible. If you add a caller that
overwrites with different semantics, audit this.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import sqlite3
import threading
from collections import OrderedDict
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Sentinel used internally to represent a delete in the write queue. Translated
# to a SQL DELETE by the writer task. Distinct from a stored ``None`` value.
_TOMBSTONE: object = object()

# Tuning knobs — kept module-level so they're easy to find and override in tests.
BATCH_MAX = 100              # max writes coalesced into a single SQLite txn
QUEUE_MAX = 10_000           # max disk-writes queued before we drop-oldest
EVICT_EVERY_N_WRITES = 1000  # how often the writer task prunes excess rows

# A SQL identifier safe enough to interpolate into CREATE/SELECT/etc. The cache
# ``name`` is used as both the table name and a key in cache_meta.
_SAFE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class PersistentFIFOCache:
    # Process-wide registry so the bundler entry point can start/stop all
    # caches in one shot without threading them through every constructor.
    _instances: list["PersistentFIFOCache"] = []

    def __init__(
        self,
        name: str,
        memory_capacity: int = 10_000,
        disk_capacity: int = 500_000,
    ) -> None:
        if not _SAFE_NAME.match(name):
            # ``name`` is interpolated into SQL via f-strings; reject anything
            # that could escape an identifier.
            raise ValueError(f"cache name must be a SQL identifier: {name!r}")
        self.name = name
        self.memory_capacity = memory_capacity
        self.disk_capacity = disk_capacity

        self._memory: OrderedDict[str, Any] = OrderedDict()

        # Disk-tier state. None until start(sqlite_path=...) is called.
        self._sqlite_path: Path | None = None
        self._sqlite_cache_size_kb: int = 8_000
        self._write_conn: sqlite3.Connection | None = None
        self._read_conn: sqlite3.Connection | None = None
        self._read_lock = threading.Lock()
        self._write_queue: asyncio.Queue[tuple[str, Any]] | None = None
        self._writer_task: asyncio.Task[None] | None = None
        self._next_seq: int = 0
        self._writes_since_evict: int = 0

        self._started: bool = False

        # Startup observability: how many rows _warm_memory_from_disk
        # pulled into memory. Free to capture (just len(rows)) so it
        # happens on the critical path. The matching on-disk row total
        # is fetched lazily by log_startup_status so the extra COUNT(*)
        # doesn't extend bundler startup.
        self._memory_loaded_at_start: int = 0

        PersistentFIFOCache._instances.append(self)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @property
    def persistent(self) -> bool:
        return self._sqlite_path is not None

    async def start(
        self,
        sqlite_path: Path | None = None,
        sqlite_cache_size_kb: int = 8_000,
    ) -> None:
        """Start the cache. With ``sqlite_path=None``, runs in memory-only
        mode. Idempotent — repeat calls are a no-op.

        If the disk tier is requested but the SQLite file can't be opened
        (unwritable directory, full disk, corruption, etc.), the cache
        soft-fails to memory-only mode with a warning. The bundler still
        runs; the next restart re-attempts the disk tier."""
        if self._started:
            return
        if sqlite_path is None:
            self._started = True
            return
        self._sqlite_path = sqlite_path
        self._sqlite_cache_size_kb = sqlite_cache_size_kb
        try:
            await asyncio.to_thread(self._open_db)
            # Preload the freshest entries from disk so the first batch
            # of RPCs after a restart get hot hits instead of falling
            # through to disk. Keep this inside the same try/except as
            # _open_db: a corrupt or partially-readable DB can fail at
            # SELECT time, and we'd rather degrade to memory-only than
            # abort start().
            await asyncio.to_thread(self._warm_memory_from_disk)
        except (OSError, sqlite3.Error) as exc:
            # Most commonly: cache_dir isn't writable (container without a
            # writable HOME, hardened systemd unit, read-only filesystem),
            # the disk is full, or the existing DB file is corrupted. Log
            # and fall through to memory-only so we don't take the bundler
            # down for a non-load-bearing optimization.
            logger.warning(
                "cache %s: disk tier disabled (%s: %s); running memory-only. "
                "Set --cache_dir to a writable location, drop "
                "--enable_persistent_cache to silence, or "
                "--clear_cache to wipe a corrupted DB.",
                self.name, type(exc).__name__, exc,
            )
            # _open_db rolls back its own connections on failure, but a
            # warmup-time error leaves them open — close them here so the
            # memory-only path doesn't leak file handles.
            if self._write_conn is not None or self._read_conn is not None:
                try:
                    await asyncio.to_thread(self._close_conns)
                except Exception:
                    pass
            self._sqlite_path = None
            self._started = True
            return
        if self._sqlite_path is None:
            # _warm_memory_from_disk hit a fatal JSON decode error and
            # called _disable_disk_tier; no point spinning up a writer
            # that has nothing to write to.
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
            # Wait for all enqueued writes to be flushed.
            await self._write_queue.join()
        if self._writer_task is not None:
            self._writer_task.cancel()
            try:
                await self._writer_task
            except asyncio.CancelledError:
                pass
            self._writer_task = None
        if self._write_conn is not None:
            await asyncio.to_thread(self._close_conns)
        self._started = False

    @classmethod
    def apply_capacity_multipliers(
        cls, memory_mult: float, disk_mult: float,
    ) -> None:
        """Scale every registered cache's capacities by the given multipliers.
        Must be called BEFORE ``start_all`` so warm-on-start observes the
        new memory cap and disk eviction uses the new disk cap."""
        if memory_mult <= 0 or disk_mult <= 0:
            raise ValueError("cache size multipliers must be positive")
        for cache in cls._instances:
            cache.memory_capacity = max(1, int(cache.memory_capacity * memory_mult))
            cache.disk_capacity = max(1, int(cache.disk_capacity * disk_mult))

    @classmethod
    async def start_all(
        cls,
        cache_dir: Path | None,
        sqlite_cache_size_kb: int = 8_000,
    ) -> None:
        """Start every registered cache instance.

        ``cache_dir`` of ``None`` means memory-only mode; otherwise each
        cache opens ``{cache_dir}/{name}.sqlite``."""
        for cache in cls._instances:
            if cache_dir is None:
                await cache.start(sqlite_path=None)
            else:
                await cache.start(
                    sqlite_path=cache_dir / f"{cache.name}.sqlite",
                    sqlite_cache_size_kb=sqlite_cache_size_kb,
                )

    @classmethod
    async def aclose_all(cls) -> None:
        for cache in cls._instances:
            try:
                await cache.aclose()
            except Exception:
                logger.exception("cache %s: aclose failed", cache.name)

    @classmethod
    def log_startup_status(cls) -> None:
        """Emit a one-shot summary of cache tier state after start_all.

        Logged in two phases. The synchronous phase reports the
        persistent/memory-only flag plus the count of caches that fell
        back to memory-only (all free — no SQL). The async phase
        follows up with per-cache (on-disk rows, rows warmed into
        memory) figures once a COUNT(*) per cache lands; that work runs
        in a worker thread so it never blocks the event loop and is
        scheduled AFTER start_all so it doesn't extend bundler startup.
        Call from an async context (``asyncio.create_task`` needs a
        running loop)."""
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
        """Run COUNT(*) on each persistent cache off the event loop and
        emit the per-cache (on-disk, warmed) breakdown. Best-effort:
        per-cache errors are swallowed so a single corrupt DB doesn't
        suppress the rest."""
        counts: dict[str, int] = {}
        for c in caches:
            try:
                counts[c.name] = await asyncio.to_thread(c._count_disk_rows)
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
        # ``is not None`` is the hit/miss signal, so a cached ``None`` is
        # indistinguishable from "not in cache" and triggers a refetch.
        # That's the right behavior for this codebase: every key maps to
        # chain-derived state that can change over time (a userop hash
        # with no log today may have one after the next bundle), so
        # there's no such thing as an authoritative cached "no result".
        # If you wire up a caller whose miss IS final, this needs a
        # sentinel-based signal instead.
        # Memory first — the hot path.
        v = self._memory.get(key)
        if v is not None:
            return v
        # No disk tier configured: memory miss is a hard miss.
        if self._read_conn is None:
            return None
        # Cold tier fallback. Cheap if the page is hot in the SQLite cache or
        # the OS page cache (via mmap); a few hundred µs otherwise.
        v = await asyncio.to_thread(self._disk_get, key)
        if v is not None:
            # Promote so a follow-up read is a hot hit. Doesn't queue a disk
            # write — the entry is already durable.
            self._memory[key] = v
            if len(self._memory) > self.memory_capacity:
                self._memory.popitem(last=False)
        return v

    async def get_many(self, keys: list[str]) -> dict[str, Any]:
        """Bulk lookup. Returns a dict mapping each key that's present (in
        either tier) to its value; keys absent from both tiers are absent
        from the result. Memory misses for ALL keys go to disk in a single
        ``SELECT … WHERE key IN (…)`` instead of one round trip per key —
        the difference matters when a hot-path handler probes 4+ keys at
        once (e.g. the seen-cache fan-out across entrypoint versions)."""
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
        if misses and self._read_conn is not None:
            disk_hits = await asyncio.to_thread(self._disk_get_many, misses)
            for k, v in disk_hits.items():
                found[k] = v
                self._memory[k] = v
                if len(self._memory) > self.memory_capacity:
                    self._memory.popitem(last=False)
        return found

    def set(self, key: str, value: Any) -> None:
        # Hot tier: insert (or overwrite in place — OrderedDict preserves
        # position on overwrite, keeping the FIFO order pinned to the
        # ORIGINAL insertion time).
        self._memory[key] = value
        if len(self._memory) > self.memory_capacity:
            self._memory.popitem(last=False)
        # Cold tier: hand off to the writer task. Sub-µs.
        self._enqueue_disk_write(key, value)

    def delete(self, key: str) -> None:
        self._memory.pop(key, None)
        self._enqueue_disk_write(key, _TOMBSTONE)

    def __contains__(self, key: str) -> bool:
        # Memory-only check; intentional, since async ``in`` doesn't exist.
        return key in self._memory

    def __len__(self) -> int:
        return len(self._memory)

    # ------------------------------------------------------------------
    # Internal: write queue
    # ------------------------------------------------------------------

    def _enqueue_disk_write(self, key: str, value: Any) -> None:
        # Either branch means there's no disk tier to write to: queue
        # never built (memory-only start) or disk tier soft-failed and
        # cleared the path mid-flight.
        if self._write_queue is None or self._sqlite_path is None:
            return
        try:
            self._write_queue.put_nowait((key, value))
            return
        except asyncio.QueueFull:
            pass
        # Drop the oldest queued write to make room. The dropped entry stays
        # in memory; it just won't be durable. This keeps the RPC path
        # non-blocking under pathological write bursts.
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
        # sessions. ``_writes_since_evict`` only triggers in-session
        # eviction after 1000 writes; a frequently-restarting bundler
        # that never crosses that threshold would otherwise let the disk
        # file drift past disk_capacity indefinitely. Doing this here (in
        # the writer task) instead of in start() keeps startup latency
        # untouched — the writer task gets created at the end of start()
        # and the eviction runs in the background. Errors are logged and
        # swallowed; nothing here is load-bearing.
        try:
            await asyncio.to_thread(self._evict_oldest)
        except Exception:
            logger.exception(
                "cache %s: startup eviction failed", self.name,
            )
        while True:
            first = await self._write_queue.get()
            batch: list[tuple[str, Any]] = [first]
            # Opportunistically drain more without awaiting — batches grow
            # under load, stay small under idle.
            try:
                while len(batch) < BATCH_MAX:
                    batch.append(self._write_queue.get_nowait())
            except asyncio.QueueEmpty:
                pass
            try:
                await asyncio.to_thread(self._commit_batch, batch)
                self._writes_since_evict += len(batch)
                if self._writes_since_evict >= EVICT_EVERY_N_WRITES:
                    await asyncio.to_thread(self._evict_oldest)
                    self._writes_since_evict = 0
            except Exception:
                logger.exception(
                    "cache %s: batch commit failed", self.name,
                )
            finally:
                for _ in batch:
                    self._write_queue.task_done()

    # ------------------------------------------------------------------
    # Internal: SQLite (all runs in a worker thread via asyncio.to_thread)
    # ------------------------------------------------------------------

    def _open_db(self) -> None:
        assert self._sqlite_path is not None
        try:
            self._sqlite_path.parent.mkdir(parents=True, exist_ok=True)
            # isolation_level=None puts us in autocommit mode; transactions
            # are managed explicitly via BEGIN/COMMIT.
            self._write_conn = sqlite3.connect(
                str(self._sqlite_path),
                check_same_thread=False,
                isolation_level=None,
            )
            self._read_conn = sqlite3.connect(
                str(self._sqlite_path),
                check_same_thread=False,
                isolation_level=None,
            )
            for conn in (self._write_conn, self._read_conn):
                # PRAGMAs are per-connection; both conns need them.
                conn.execute("PRAGMA journal_mode = WAL")
                conn.execute("PRAGMA synchronous  = NORMAL")
                conn.execute("PRAGMA temp_store   = MEMORY")
                conn.execute(
                    f"PRAGMA cache_size  = -{self._sqlite_cache_size_kb}",
                )
                conn.execute("PRAGMA mmap_size    = 67108864")  # 64 MB virtual
                # Multi-bundler safety: when another process on the same
                # chain shares this file and holds the WAL write lock, wait
                # up to 5 s rather than failing the commit. Without this,
                # any concurrent write contention silently drops the batch.
                conn.execute("PRAGMA busy_timeout = 5000")

            self._write_conn.executescript(
                f"""
                CREATE TABLE IF NOT EXISTS {self.name} (
                    key   TEXT    PRIMARY KEY,
                    value BLOB    NOT NULL,
                    seq   INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS {self.name}_seq
                    ON {self.name} (seq);
                CREATE TABLE IF NOT EXISTS cache_meta (
                    table_name TEXT PRIMARY KEY,
                    next_seq   INTEGER NOT NULL
                );
                """
            )
            # next_seq is read inside _commit_batch under BEGIN IMMEDIATE so
            # concurrent bundlers sharing this SQLite file allocate disjoint
            # sequence ranges. Caching it here at startup was racy: two
            # processes would each load the same value and both advance an
            # in-memory copy, producing overlapping seq writes.
        except Exception:
            # Roll back any partial state so ``start``'s soft-fail path
            # doesn't see a half-open cache. Best-effort close — we're
            # about to re-raise, the warning will log the real cause.
            for conn_attr in ("_write_conn", "_read_conn"):
                conn = getattr(self, conn_attr, None)
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    setattr(self, conn_attr, None)
            raise

    def _close_conns(self) -> None:
        try:
            if self._write_conn is not None:
                # Roll the WAL into the main DB so a cold restart doesn't
                # have to replay a large WAL.
                self._write_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                self._write_conn.close()
        finally:
            # Hold _read_lock across the read-conn close+null so we don't
            # race a reader that already passed the None-check and is
            # about to (or currently is) executing a SELECT inside the
            # same lock. Without this, _disable_disk_tier on the
            # malformed-JSON path could close the connection while a
            # sibling _disk_get/_disk_get_many holds the lock, surfacing
            # as sqlite3.ProgrammingError("closed database").
            with self._read_lock:
                if self._read_conn is not None:
                    self._read_conn.close()
                self._write_conn = None
                self._read_conn = None

    def _commit_batch(self, batch: list[tuple[str, Any]]) -> None:
        # Disk tier may have been disabled mid-flight (e.g. by a fatal
        # JSON decode error in _disk_get). Drop the batch silently — the
        # data is still in memory; persistence is the only thing lost.
        if self._write_conn is None:
            return
        cur = self._write_conn.cursor()
        # IMMEDIATE takes the write lock upfront so concurrent bundlers
        # serialize cleanly via busy_timeout, rather than getting partway
        # through a deferred transaction and hitting SQLITE_BUSY on the
        # first INSERT.
        cur.execute("BEGIN IMMEDIATE")
        try:
            # Read the authoritative next_seq inside the write lock so a
            # second bundler that committed since our last batch doesn't
            # cause us to reuse its seq values. The in-memory _next_seq
            # is only a hint; this is the source of truth.
            row = cur.execute(
                "SELECT next_seq FROM cache_meta WHERE table_name = ?",
                (self.name,),
            ).fetchone()
            next_seq = row[0] if row else 0
            for key, value in batch:
                if value is _TOMBSTONE:
                    cur.execute(
                        f"DELETE FROM {self.name} WHERE key = ?", (key,),
                    )
                else:
                    # INSERT OR REPLACE bumps seq so the entry moves to the
                    # FIFO-newest position even on overwrite.
                    cur.execute(
                        f"INSERT OR REPLACE INTO {self.name} "
                        "(key, value, seq) VALUES (?, ?, ?)",
                        (
                            key,
                            json.dumps(value).encode("utf-8"),
                            next_seq,
                        ),
                    )
                    next_seq += 1
            cur.execute(
                "INSERT OR REPLACE INTO cache_meta (table_name, next_seq) "
                "VALUES (?, ?)",
                (self.name, next_seq),
            )
            cur.execute("COMMIT")
            self._next_seq = next_seq
        except Exception:
            cur.execute("ROLLBACK")
            raise

    def _disk_get(self, key: str) -> Any | None:
        # Check _read_conn INSIDE the lock — _close_conns sets it to None
        # under the same lock, so a check outside would allow a stale
        # "not None" observation to ride a now-closed connection into
        # the SELECT below.
        with self._read_lock:
            if self._read_conn is None:
                return None
            cur = self._read_conn.execute(
                f"SELECT value FROM {self.name} WHERE key = ?", (key,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        try:
            return json.loads(row[0])
        except json.JSONDecodeError as exc:
            logger.warning(
                "cache %s: malformed JSON for key %s (%s); "
                "disabling disk tier and treating this lookup as a miss",
                self.name, key, exc,
            )
            self._disable_disk_tier()
            return None

    def _disk_get_many(self, keys: list[str]) -> dict[str, Any]:
        # SQLite has a SQLITE_LIMIT_VARIABLE_NUMBER ceiling (default 999 on
        # older builds, 32766 on newer ones). Real callers pass a handful
        # of keys; this guard catches accidental misuse without imposing
        # a chunking dance for the common case.
        if len(keys) > 500:
            raise ValueError(
                f"get_many: {len(keys)} keys exceeds the per-query limit"
            )
        placeholders = ",".join("?" * len(keys))
        # Check _read_conn INSIDE the lock for the same reason as
        # _disk_get — _close_conns nulls it under the same lock.
        with self._read_lock:
            if self._read_conn is None:
                return {}
            cur = self._read_conn.execute(
                f"SELECT key, value FROM {self.name} "
                f"WHERE key IN ({placeholders})",
                keys,
            )
            rows = cur.fetchall()
        out: dict[str, Any] = {}
        for key, value in rows:
            try:
                out[key] = json.loads(value)
            except json.JSONDecodeError as exc:
                logger.warning(
                    "cache %s: malformed JSON for key %s (%s); "
                    "disabling disk tier and skipping the bad row",
                    self.name, key, exc,
                )
                self._disable_disk_tier()
                # Return whatever we already decoded — the caller treats
                # absent keys as misses, which is the correct degradation.
                return out
        return out

    def _warm_memory_from_disk(self) -> None:
        """Preload the most-recent ``memory_capacity`` rows into the hot
        tier so the first reads after a restart don't need disk fallback.
        Inserts in ascending seq order so the OrderedDict's FIFO order
        mirrors on-disk insertion order (oldest first, newest last)."""
        if self._read_conn is None:
            return
        with self._read_lock:
            cur = self._read_conn.execute(
                f"SELECT key, value FROM {self.name} "
                f"ORDER BY seq DESC LIMIT ?",
                (self.memory_capacity,),
            )
            rows = cur.fetchall()
        # rows came back newest-first; reverse so we insert oldest-first.
        loaded = 0
        for key, value in reversed(rows):
            try:
                self._memory[key] = json.loads(value)
            except json.JSONDecodeError as exc:
                logger.warning(
                    "cache %s: malformed JSON for key %s during warmup "
                    "(%s); disabling disk tier and continuing memory-only",
                    self.name, key, exc,
                )
                self._disable_disk_tier()
                break
            loaded += 1
        self._memory_loaded_at_start = loaded

    def _disable_disk_tier(self) -> None:
        """Soft-fail the disk tier after an unrecoverable error (e.g.
        malformed JSON in a row, which signals a corrupt DB file). Closes
        both SQLite connections and clears ``_sqlite_path`` so subsequent
        reads stay memory-only. Idempotent — safe to call from any
        worker thread, and from the writer task path.

        The writer task lingers but its commits no-op once
        ``_write_conn`` is None; new ``set``/``delete`` calls also no-op
        (``_enqueue_disk_write`` checks ``_sqlite_path``)."""
        if self._sqlite_path is None:
            return
        self._sqlite_path = None
        try:
            self._close_conns()
        except Exception:
            logger.exception(
                "cache %s: closing connections after disk-tier disable failed",
                self.name,
            )

    def _count_disk_rows(self) -> int:
        """Total on-disk row count. Used by log_startup_status; runs a
        full COUNT(*), so don't call on a hot path."""
        assert self._read_conn is not None
        with self._read_lock:
            row = self._read_conn.execute(
                f"SELECT COUNT(*) FROM {self.name}",
            ).fetchone()
        return row[0] if row else 0

    def _evict_oldest(self) -> None:
        if self._write_conn is None:
            return
        cur = self._write_conn.cursor()
        cur.execute(f"SELECT COUNT(*) FROM {self.name}")
        count = cur.fetchone()[0]
        if count <= self.disk_capacity:
            return
        overflow = count - self.disk_capacity
        cur.execute("BEGIN")
        try:
            # Delete the ``overflow`` oldest rows (lowest seq).
            cur.execute(
                f"DELETE FROM {self.name} WHERE seq IN "
                f"(SELECT seq FROM {self.name} ORDER BY seq LIMIT ?)",
                (overflow,),
            )
            cur.execute("COMMIT")
        except Exception:
            cur.execute("ROLLBACK")
            raise


