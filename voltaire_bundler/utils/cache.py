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
        mode. Idempotent — repeat calls are a no-op."""
        if self._started:
            return
        if sqlite_path is None:
            self._started = True
            return
        self._sqlite_path = sqlite_path
        self._sqlite_cache_size_kb = sqlite_cache_size_kb
        await asyncio.to_thread(self._open_db)
        # Preload the freshest entries from disk so the first batch of RPCs
        # after a restart get hot hits instead of falling through to disk.
        await asyncio.to_thread(self._warm_memory_from_disk)
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

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get(self, key: str) -> Any | None:
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
        if self._write_queue is None:
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
        self._sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        # isolation_level=None puts us in autocommit mode; transactions are
        # managed explicitly via BEGIN/COMMIT.
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
            conn.execute(f"PRAGMA cache_size  = -{self._sqlite_cache_size_kb}")
            conn.execute("PRAGMA mmap_size    = 67108864")  # 64 MB virtual

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
        row = self._write_conn.execute(
            "SELECT next_seq FROM cache_meta WHERE table_name = ?",
            (self.name,),
        ).fetchone()
        self._next_seq = row[0] if row else 0

    def _close_conns(self) -> None:
        try:
            if self._write_conn is not None:
                # Roll the WAL into the main DB so a cold restart doesn't
                # have to replay a large WAL.
                self._write_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                self._write_conn.close()
        finally:
            if self._read_conn is not None:
                self._read_conn.close()
            self._write_conn = None
            self._read_conn = None

    def _commit_batch(self, batch: list[tuple[str, Any]]) -> None:
        assert self._write_conn is not None
        cur = self._write_conn.cursor()
        cur.execute("BEGIN")
        try:
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
                            self._next_seq,
                        ),
                    )
                    self._next_seq += 1
            cur.execute(
                "INSERT OR REPLACE INTO cache_meta (table_name, next_seq) "
                "VALUES (?, ?)",
                (self.name, self._next_seq),
            )
            cur.execute("COMMIT")
        except Exception:
            cur.execute("ROLLBACK")
            raise

    def _disk_get(self, key: str) -> Any | None:
        assert self._read_conn is not None
        with self._read_lock:
            cur = self._read_conn.execute(
                f"SELECT value FROM {self.name} WHERE key = ?", (key,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return json.loads(row[0])

    def _warm_memory_from_disk(self) -> None:
        """Preload the most-recent ``memory_capacity`` rows into the hot
        tier so the first reads after a restart don't need disk fallback.
        Inserts in ascending seq order so the OrderedDict's FIFO order
        mirrors on-disk insertion order (oldest first, newest last)."""
        assert self._read_conn is not None
        with self._read_lock:
            cur = self._read_conn.execute(
                f"SELECT key, value FROM {self.name} "
                f"ORDER BY seq DESC LIMIT ?",
                (self.memory_capacity,),
            )
            rows = cur.fetchall()
        # rows came back newest-first; reverse so we insert oldest-first.
        for key, value in reversed(rows):
            self._memory[key] = json.loads(value)

    def _evict_oldest(self) -> None:
        assert self._write_conn is not None
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


