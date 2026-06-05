"""
Cross-backend smoke + behavior tests for the cache cold tier.

Every test is parametrized over (sqlite, postgres). The Postgres
parametrization is dropped at collection time when
``VOLTAIRE_TEST_POSTGRES_URL`` is unset so CI without Postgres infra
runs the SQLite half cleanly.

Each test scopes its tables under a random suffix so concurrent runs
on a shared Postgres instance don't collide.
"""

from __future__ import annotations

import asyncio
import os
import secrets
from pathlib import Path

import pytest
import pytest_asyncio

from voltaire_bundler.utils.cache_backends import (
    CacheBackend,
    PostgresBackend,
    PostgresConfig,
    SQLiteBackend,
    close_postgres_pool,
    init_postgres_pool,
)


POSTGRES_URL = os.getenv("VOLTAIRE_TEST_POSTGRES_URL", "")

BACKENDS = ["sqlite"] + (["postgres"] if POSTGRES_URL else [])


# Short prefix so the random-suffixed table name still fits within
# SQL identifier limits.
TEST_PREFIX = "t_"


# Session-scoped pool init. Runs once per test session when Postgres
# tests are enabled; tears down at the end. autouse so individual
# tests don't have to ask for it.
@pytest_asyncio.fixture(scope="session", autouse=True)
async def _maybe_init_postgres_pool() -> "object":
    if not POSTGRES_URL:
        yield None
        return
    await init_postgres_pool(PostgresConfig(url=POSTGRES_URL))
    yield None
    await close_postgres_pool()


async def _make_backend(
    kind: str, tmp_path: Path,
) -> CacheBackend:
    suffix = secrets.token_hex(4)
    backend: CacheBackend
    if kind == "sqlite":
        backend = SQLiteBackend(
            path=tmp_path / f"{TEST_PREFIX}{suffix}.sqlite",
            table=f"{TEST_PREFIX}{suffix}",
        )
    elif kind == "postgres":
        backend = PostgresBackend(
            table=f"{TEST_PREFIX}{suffix}",
            table_prefix="",
        )
    else:
        raise ValueError(kind)
    await backend.open()
    return backend


@pytest.mark.parametrize("backend_kind", BACKENDS)
@pytest.mark.asyncio
async def test_set_get_roundtrip(
    backend_kind: str, tmp_path: Path,
) -> None:
    backend = await _make_backend(backend_kind, tmp_path)
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


@pytest.mark.parametrize("backend_kind", BACKENDS)
@pytest.mark.asyncio
async def test_delete_via_none_payload(
    backend_kind: str, tmp_path: Path,
) -> None:
    backend = await _make_backend(backend_kind, tmp_path)
    try:
        await backend.commit_batch([("k", b"v")])
        assert await backend.get("k") == b"v"
        await backend.commit_batch([("k", None)])
        assert await backend.get("k") is None
    finally:
        await backend.close()


@pytest.mark.parametrize("backend_kind", BACKENDS)
@pytest.mark.asyncio
async def test_overwrite_bumps_seq(
    backend_kind: str, tmp_path: Path,
) -> None:
    """Overwriting a key should move it to the FIFO-newest slot — the
    documented eviction-flip behavior. Verify by inserting a then b,
    overwriting a, then evicting down to 1 row. b had the lowest seq,
    so b is evicted; a survives with its new seq."""
    backend = await _make_backend(backend_kind, tmp_path)
    try:
        await backend.commit_batch([("a", b"1")])
        await backend.commit_batch([("b", b"2")])
        await backend.commit_batch([("a", b"3")])
        await backend.evict_excess(max_rows=1)
        assert await backend.get("a") == b"3"
        assert await backend.get("b") is None
    finally:
        await backend.close()


@pytest.mark.parametrize("backend_kind", BACKENDS)
@pytest.mark.asyncio
async def test_load_recent_returns_oldest_first(
    backend_kind: str, tmp_path: Path,
) -> None:
    """The cache's warmup relies on oldest-first ordering so the
    OrderedDict preserves disk FIFO order."""
    backend = await _make_backend(backend_kind, tmp_path)
    try:
        for k, v in [("a", b"1"), ("b", b"2"), ("c", b"3")]:
            await backend.commit_batch([(k, v)])
        recent = await backend.load_recent(limit=10)
        assert [k for k, _ in recent] == ["a", "b", "c"]
    finally:
        await backend.close()


@pytest.mark.parametrize("backend_kind", BACKENDS)
@pytest.mark.asyncio
async def test_evict_excess_trims_oldest(
    backend_kind: str, tmp_path: Path,
) -> None:
    backend = await _make_backend(backend_kind, tmp_path)
    try:
        for i in range(10):
            await backend.commit_batch([(f"k{i}", str(i).encode())])
        await backend.evict_excess(max_rows=3)
        survivors = await backend.get_many([f"k{i}" for i in range(10)])
        assert len(survivors) == 3
        assert set(survivors.keys()) == {"k7", "k8", "k9"}
    finally:
        await backend.close()


@pytest.mark.parametrize("backend_kind", BACKENDS)
@pytest.mark.asyncio
async def test_count_rows(
    backend_kind: str, tmp_path: Path,
) -> None:
    backend = await _make_backend(backend_kind, tmp_path)
    try:
        assert await backend.count_rows() == 0
        await backend.commit_batch([("k", b"v")])
        assert await backend.count_rows() == 1
    finally:
        await backend.close()


_ = asyncio
