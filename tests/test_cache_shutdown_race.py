"""
Concurrency regression for SQLiteBackend close vs concurrent reads.

Earlier, the SQLite path closed self._read_conn and nulled it without
holding self._read_lock, while _get_sync / _get_many_sync checked
_read_conn outside the lock and used it inside. A reader that passed
the None-check while a sibling reader was in the malformed-JSON path
(which today triggers the cache layer's _disable_disk_tier, which
calls backend.close()) could then call .execute() on a now-closed
connection and surface a sqlite3.ProgrammingError("Cannot operate on
a closed database.").

The fix: _close_sync acquires _read_lock around the read-conn
close+null, and _get_sync / _get_many_sync do the None check INSIDE
the lock. This test stresses the race by running many concurrent
reader threads while one thread closes the backend, and asserts no
sqlite exception is raised.

After the cache refactor, the lock + close logic lives on
SQLiteBackend (not PersistentFIFOCache), so the test exercises the
backend directly. The JSON-decode-and-disable path that originally
triggered the close now lives in the cache layer; for this race we
just need a close racing with reads, so we trigger the close
explicitly.
"""

from __future__ import annotations

import asyncio
import sqlite3
import threading
import time
from pathlib import Path

import pytest

from voltaire_bundler.utils.cache_backends import SQLiteBackend


def _seed_rows(db_path: Path, table: str) -> None:
    """Side-channel insert of a couple of rows so the readers have
    something to fetch. Going via a separate sqlite3 connection means
    we don't have to drive the backend's write path."""
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            f"INSERT INTO {table} (key, value, seq) VALUES (?, ?, ?)",
            ("good", b'"hello"', 9000),
        )
        conn.execute(
            f"INSERT INTO {table} (key, value, seq) VALUES (?, ?, ?)",
            ("other", b'"world"', 9001),
        )
        conn.commit()
    finally:
        conn.close()


def _race_readers_against_close(
    backend: SQLiteBackend,
) -> list[BaseException]:
    """Spawn N reader threads hammering _get_sync / _get_many_sync,
    plus one thread that triggers _close_sync. Returns sqlite
    exceptions seen by any thread — must be empty for the test to
    pass."""
    errors: list[BaseException] = []
    stop = threading.Event()

    def hammer() -> None:
        while not stop.is_set():
            try:
                backend._get_sync("good")
                backend._get_many_sync(["good", "other", "missing"])
            except sqlite3.Error as exc:
                errors.append(exc)
                return

    def trigger_close() -> None:
        try:
            backend._close_sync()
        except sqlite3.Error as exc:
            errors.append(exc)

    readers = [
        threading.Thread(target=hammer, name=f"reader-{i}")
        for i in range(8)
    ]
    for t in readers:
        t.start()
    # Give readers a moment to start hammering before the close so the
    # close doesn't fire before any reader has even contended for the
    # lock.
    time.sleep(0.05)

    closer = threading.Thread(target=trigger_close, name="closer")
    closer.start()
    closer.join()

    # Let the readers race the shutdown for a bit longer so threads
    # that were blocked on the lock at close time get to wake up and
    # exercise the post-close path.
    time.sleep(0.1)
    stop.set()
    for t in readers:
        t.join()
    return errors


@pytest.mark.asyncio
async def test_close_does_not_race_with_concurrent_reads(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "race.sqlite"
    backend = SQLiteBackend(
        path=db_path, table="race_test", cache_size_kb=1_000,
    )
    await backend.open()
    try:
        assert backend._read_conn is not None
        _seed_rows(db_path, "race_test")
        errors = _race_readers_against_close(backend)
        assert not errors, (
            f"sqlite errors observed during shutdown: {errors!r}"
        )
        # Post-conditions: backend is fully torn down.
        assert backend._read_conn is None
        assert backend._write_conn is None
    finally:
        # Already closed by the race; second close is a no-op.
        await backend.close()


@pytest.mark.asyncio
async def test_close_acquires_read_lock(tmp_path: Path) -> None:
    """Direct, deterministic check that _close_sync waits on
    _read_lock. A reader holding _read_lock must block _close_sync
    until it releases. The stress test above can't catch every
    interleaving on every run; this one nails down the invariant."""
    db_path = tmp_path / "lock.sqlite"
    backend = SQLiteBackend(path=db_path, table="lock_test")
    await backend.open()
    try:
        assert backend._read_conn is not None

        reader_inside_lock = threading.Event()
        release_reader = threading.Event()

        def hold_read_lock() -> None:
            with backend._read_lock:
                reader_inside_lock.set()
                release_reader.wait(timeout=5.0)

        holder = threading.Thread(
            target=hold_read_lock, name="lock-holder",
        )
        holder.start()
        assert reader_inside_lock.wait(timeout=2.0)

        closer_done = threading.Event()

        def close_under_contention() -> None:
            backend._close_sync()
            closer_done.set()

        closer = threading.Thread(
            target=close_under_contention, name="closer",
        )
        closer.start()

        assert not closer_done.wait(timeout=0.2), (
            "_close_sync finished while _read_lock was held — "
            "lock is not being acquired on the close path"
        )

        release_reader.set()
        holder.join(timeout=2.0)
        assert closer_done.wait(timeout=2.0)
        closer.join(timeout=2.0)

        assert backend._read_conn is None
        assert backend._write_conn is None
    finally:
        await backend.close()


@pytest.mark.asyncio
async def test_cache_disable_on_malformed_payload(
    tmp_path: Path,
) -> None:
    """End-to-end check that the cache layer disables the disk tier
    on a malformed payload from the backend. This is the cache-level
    equivalent of the old race test — the JSON-decode-and-disable
    path moved from SQLiteBackend into PersistentFIFOCache as part of
    the refactor, and we want regression coverage that it still
    fires."""
    from voltaire_bundler.utils.cache import PersistentFIFOCache

    db_path = tmp_path / "decode.sqlite"
    cache = PersistentFIFOCache(name="decode_test", memory_capacity=4)
    backend = SQLiteBackend(path=db_path, table="decode_test")
    try:
        await cache.start(backend=backend)
        assert cache.persistent
        _seed_rows(db_path, "decode_test")
        # Corrupt the row so the cache's json.loads fails. Going via
        # a side-channel conn matches the seed pattern.
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute(
                "UPDATE decode_test SET value = ? WHERE key = ?",
                (b"not-valid-json", "good"),
            )
            conn.commit()
        finally:
            conn.close()

        # Memory miss + backend hit + decode failure → disable tier.
        result = await cache.get("good")
        assert result is None
        assert not cache.persistent
    finally:
        try:
            await cache.aclose()
        except Exception:
            pass
        if cache in PersistentFIFOCache._instances:
            PersistentFIFOCache._instances.remove(cache)


# Silence "imported but unused" — asyncio appears in fixtures that
# pytest-asyncio injects implicitly.
_ = asyncio
