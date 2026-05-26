"""
Concurrency regression for PersistentFIFOCache._close_conns.

Earlier, _close_conns / _disable_disk_tier closed self._read_conn and
nulled it without holding self._read_lock, while _disk_get and
_disk_get_many checked _read_conn outside the lock and used it inside.
A reader that passed the None-check while a sibling reader was in the
malformed-JSON path (which calls _disable_disk_tier after releasing the
lock) could then call .execute() on a now-closed connection and surface
a sqlite3.ProgrammingError("Cannot operate on a closed database.").

The fix: _close_conns acquires _read_lock around the read-conn
close+null, and _disk_get/_disk_get_many do the None check INSIDE the
lock. This test stresses the race by running many concurrent reader
threads while one of them dereferences a malformed-JSON row that
triggers _disable_disk_tier, and asserts no sqlite exception is raised.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

import pytest

from voltaire_bundler.utils.cache import PersistentFIFOCache


def _seed_rows(db_path: Path, table: str) -> None:
    """Side-channel insert of one decodable and one malformed-JSON row.

    Going via a separate sqlite3 connection (rather than cache.set) means
    the malformed row never passes through the writer task's JSON
    encoder; _warm_memory_from_disk has also already finished by the
    time we call this, so it won't decode the bad row and disable the
    tier before the race window opens."""
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            f"INSERT INTO {table} (key, value, seq) VALUES (?, ?, ?)",
            ("good", b'"hello"', 9000),
        )
        conn.execute(
            f"INSERT INTO {table} (key, value, seq) VALUES (?, ?, ?)",
            ("bad", b"not-valid-json", 9001),
        )
        conn.commit()
    finally:
        conn.close()


def _drop_from_registry(cache: PersistentFIFOCache) -> None:
    """Avoid leaking test instances into the class-level registry — other
    tests using start_all/aclose_all would otherwise pick them up."""
    if cache in PersistentFIFOCache._instances:
        PersistentFIFOCache._instances.remove(cache)


def _race_readers_against_disable(
    cache: PersistentFIFOCache,
) -> list[BaseException]:
    """Spawn N reader threads hammering _disk_get/_disk_get_many on
    "good", plus one thread that triggers _disable_disk_tier via the
    malformed "bad" row. Returns a list of sqlite exceptions seen by any
    thread — must be empty for the test to pass."""
    errors: list[BaseException] = []
    stop = threading.Event()

    def hammer_good() -> None:
        # Drive both code paths (single + bulk lookup) since each has
        # its own None-check / lock sequence to verify.
        while not stop.is_set():
            try:
                cache._disk_get("good")
                cache._disk_get_many(["good", "missing"])
            except sqlite3.Error as exc:
                errors.append(exc)
                return

    def trigger_disable() -> None:
        # Reading "bad" forces a JSONDecodeError inside _disk_get, which
        # calls _disable_disk_tier -> _close_conns. The buggy version
        # closes _read_conn without the lock, racing the readers above.
        try:
            cache._disk_get("bad")
        except sqlite3.Error as exc:
            errors.append(exc)

    readers = [
        threading.Thread(target=hammer_good, name=f"reader-{i}")
        for i in range(8)
    ]
    for t in readers:
        t.start()
    # Give readers a moment to start hammering before triggering the
    # shutdown — without this the disable can fire before any reader
    # has even contended for the lock.
    time.sleep(0.05)

    disabler = threading.Thread(target=trigger_disable, name="disabler")
    disabler.start()
    disabler.join()

    # Let the readers race the shutdown for a bit longer so threads that
    # were blocked on the lock at close time get to wake up and exercise
    # the post-close path.
    time.sleep(0.1)
    stop.set()
    for t in readers:
        t.join()
    return errors


@pytest.mark.asyncio
async def test_disable_disk_tier_does_not_race_with_concurrent_reads(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "race.sqlite"
    cache = PersistentFIFOCache(
        name="race_test", memory_capacity=4, disk_capacity=1000,
    )
    try:
        await cache.start(sqlite_path=db_path)
        # Sanity: the disk tier opened cleanly.
        assert cache._read_conn is not None
        assert cache._sqlite_path is not None

        _seed_rows(db_path, "race_test")
        errors = _race_readers_against_disable(cache)
        assert not errors, f"sqlite errors observed during shutdown: {errors!r}"
        # Post-conditions: disk tier is fully torn down.
        assert cache._read_conn is None
        assert cache._sqlite_path is None
    finally:
        try:
            await cache.aclose()
        except Exception:
            pass
        _drop_from_registry(cache)


@pytest.mark.asyncio
async def test_close_conns_acquires_read_lock(tmp_path: Path) -> None:
    """Direct, deterministic check that _close_conns waits on _read_lock.

    A reader holding _read_lock must block _close_conns until it
    releases. The stress test above can't catch every interleaving on
    every run; this one nails down the documented invariant."""
    db_path = tmp_path / "lock.sqlite"
    cache = PersistentFIFOCache(name="lock_test", memory_capacity=4)
    try:
        await cache.start(sqlite_path=db_path)
        assert cache._read_conn is not None

        reader_inside_lock = threading.Event()
        release_reader = threading.Event()

        def hold_read_lock() -> None:
            with cache._read_lock:
                reader_inside_lock.set()
                release_reader.wait(timeout=5.0)

        holder = threading.Thread(target=hold_read_lock, name="lock-holder")
        holder.start()
        # Wait until the reader actually owns the lock.
        assert reader_inside_lock.wait(timeout=2.0)

        closer_done = threading.Event()

        def close_under_contention() -> None:
            cache._close_conns()
            closer_done.set()

        closer = threading.Thread(target=close_under_contention, name="closer")
        closer.start()

        # _close_conns must not complete while the reader holds the lock.
        assert not closer_done.wait(timeout=0.2), (
            "_close_conns finished while _read_lock was held — "
            "lock is not being acquired on the close path"
        )

        release_reader.set()
        holder.join(timeout=2.0)
        assert closer_done.wait(timeout=2.0)
        closer.join(timeout=2.0)

        assert cache._read_conn is None
        assert cache._write_conn is None
    finally:
        try:
            await cache.aclose()
        except Exception:
            pass
        _drop_from_registry(cache)
