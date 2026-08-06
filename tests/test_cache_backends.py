"""
Behavior tests for the Postgres cache backend.

Skipped at collection time when ``VOLTAIRE_TEST_POSTGRES_URL`` is
unset so CI without Postgres infra still passes cleanly. Each test
scopes its tables under a random suffix so concurrent runs on a
shared Postgres instance don't collide.
"""

from __future__ import annotations

import asyncio
import os
import secrets

import pytest
import pytest_asyncio

from voltaire_bundler.utils.cache_backends import (
    PostgresBackend,
    PostgresConfig,
    _get_postgres_pool,
    close_postgres_pool,
    init_postgres_pool,
)


POSTGRES_URL = os.getenv("VOLTAIRE_TEST_POSTGRES_URL", "")

pytestmark = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="VOLTAIRE_TEST_POSTGRES_URL not set",
)


# Short prefix so the random-suffixed table name still fits within
# SQL identifier limits.
TEST_PREFIX = "t_"


@pytest_asyncio.fixture(scope="session", autouse=True, loop_scope="session")
async def _postgres_pool() -> "object":
    """Session-scoped pool init. Opens once per test session, tears
    down at the end. autouse so individual tests don't have to ask
    for it."""
    await init_postgres_pool(PostgresConfig(url=POSTGRES_URL))
    yield None
    await close_postgres_pool()


async def _make_backend() -> PostgresBackend:
    suffix = secrets.token_hex(4)
    backend = PostgresBackend(
        table=f"{TEST_PREFIX}{suffix}",
        table_prefix="",
    )
    await backend.open()
    return backend


async def _backdate(
    backend: PostgresBackend, keys: list[str], *, days: int,
) -> None:
    """Force ``inserted_at`` for the given keys to be ``days`` days
    in the past. Used to drive the TTL eviction tests without having
    to wait real time."""
    pool = _get_postgres_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            f'UPDATE "{backend._table}" SET '
            f'inserted_at = now() - make_interval(days => $1) '
            f'WHERE key = ANY($2::text[])',
            days, keys,
        )


@pytest.mark.asyncio(loop_scope="session")
async def test_set_get_roundtrip() -> None:
    backend = await _make_backend()
    try:
        await backend.commit_batch(
            [("k1", b"v1"), ("k2", b"v2")],
        )
        assert await backend.get("k1") == b"v1"
        assert await backend.get("k2") == b"v2"
        assert await backend.get("missing") is None

        bulk = await backend.get_many(["k1", "k2", "missing"])
        assert bulk == {"k1": b"v1", "k2": b"v2"}
    finally:
        await backend.close()


@pytest.mark.asyncio(loop_scope="session")
async def test_delete_via_none_payload() -> None:
    backend = await _make_backend()
    try:
        await backend.commit_batch([("k", b"v")])
        assert await backend.get("k") == b"v"
        await backend.commit_batch([("k", None)])
        assert await backend.get("k") is None
    finally:
        await backend.close()


@pytest.mark.asyncio(loop_scope="session")
async def test_commit_batch_dedup_last_op_wins() -> None:
    """``commit_batch`` dedupes by key before issuing the executemany
    calls, so a single batch containing multiple ops for the same key
    must end in the state of the LAST op. This is the load-bearing
    contract that makes the dedupe + two-executemany rewrite
    semantically equivalent to the old N-sequential-statements
    implementation."""
    backend = await _make_backend()
    try:
        # Three permutations of multi-op batches, each in its own
        # call so a previous batch can't influence the next.

        # set → delete → set: final value is the LAST set
        await backend.commit_batch(
            [("k", b"v1"), ("k", None), ("k", b"v2")],
        )
        assert await backend.get("k") == b"v2"

        # set → set → delete: row should end up deleted
        await backend.commit_batch(
            [("k", b"v3"), ("k", b"v4"), ("k", None)],
        )
        assert await backend.get("k") is None

        # Mixed keys, mixed ops: a ends set, b ends deleted
        await backend.commit_batch([("b", b"seed")])
        await backend.commit_batch(
            [
                ("a", b"x"),
                ("a", None),
                ("a", b"y"),
                ("b", None),
                ("b", b"z"),
                ("b", None),
            ],
        )
        assert await backend.get("a") == b"y"
        assert await backend.get("b") is None
    finally:
        await backend.close()


@pytest.mark.asyncio(loop_scope="session")
async def test_overwrite_refreshes_inserted_at() -> None:
    """Overwriting a key resets its inserted_at to now() so a
    frequently-touched key doesn't age out from its original
    insertion timestamp. Backdate both rows, overwrite one, evict
    with a short TTL, assert the overwritten row survives."""
    backend = await _make_backend()
    try:
        await backend.commit_batch([("a", b"1")])
        await backend.commit_batch([("b", b"2")])
        # Force both rows to look 10 days old.
        await _backdate(backend, ["a", "b"], days=10)
        # Overwrite a — refreshes its inserted_at to now().
        await backend.commit_batch([("a", b"3")])
        # TTL of 1 day: b (10 days old) is expired; a (just now) survives.
        await backend.evict_expired(ttl_seconds=86_400)
        assert await backend.get("a") == b"3"
        assert await backend.get("b") is None
    finally:
        await backend.close()


@pytest.mark.asyncio(loop_scope="session")
async def test_load_recent_returns_oldest_first() -> None:
    """The cache's warmup relies on oldest-first ordering so the
    OrderedDict preserves disk FIFO order."""
    backend = await _make_backend()
    try:
        for k, v in [("a", b"1"), ("b", b"2"), ("c", b"3")]:
            await backend.commit_batch([(k, v)])
        recent = await backend.load_recent(limit=10)
        assert [k for k, _ in recent] == ["a", "b", "c"]
    finally:
        await backend.close()


@pytest.mark.asyncio(loop_scope="session")
async def test_evict_expired_removes_old_rows() -> None:
    """Backdate a subset of rows past the TTL horizon and verify the
    DELETE picks them up while the fresh rows survive."""
    backend = await _make_backend()
    try:
        for i in range(10):
            await backend.commit_batch([(f"k{i}", str(i).encode())])
        # k0..k6 look 10 days old; k7..k9 are fresh.
        await _backdate(backend, [f"k{i}" for i in range(7)], days=10)
        await backend.evict_expired(ttl_seconds=86_400)
        survivors = await backend.get_many([f"k{i}" for i in range(10)])
        assert set(survivors.keys()) == {"k7", "k8", "k9"}
    finally:
        await backend.close()


@pytest.mark.asyncio(loop_scope="session")
async def test_count_rows_uses_planner_stats() -> None:
    """count_rows reads pg_class.reltuples — the planner statistic
    refreshed by VACUUM/ANALYZE — so it's constant-time but stale
    until the first ANALYZE on a new table. Force ANALYZE inside the
    test so the assertion is deterministic; in production autovacuum
    handles this in the background."""
    backend = await _make_backend()
    try:
        assert await backend.count_rows() == 0
        # Insert a batch big enough that the post-ANALYZE estimate
        # rounds to something stable.
        await backend.commit_batch(
            [(f"k{i}", str(i).encode()) for i in range(100)],
        )
        pool = _get_postgres_pool()
        async with pool.acquire() as conn:
            await conn.execute(f'ANALYZE "{backend._table}"')
        # reltuples is an estimate; 100 inserts in one batch lands
        # exactly at 100 in practice, but allow a small fuzz factor
        # in case PG ever rounds differently.
        approx = await backend.count_rows()
        assert 90 <= approx <= 110, f"expected ~100 rows, got {approx}"
    finally:
        await backend.close()


_ = asyncio
