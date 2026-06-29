"""Unit tests for the LatestBlockCache class.

The module-level facade (publish / get_or_fetch / warm) delegates to a
process-wide instance — these tests construct fresh instances so cases
don't bleed state into each other.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from voltaire_bundler.utils.latest_block_cache import LatestBlockCache


URLS = ["http://node-a"]


def _rpc_block_result(block_number: int) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "number": hex(block_number),
            "hash": "0xdead",
        },
    }


@pytest.mark.asyncio
async def test_publish_then_get_returns_cached_no_rpc():
    cache = LatestBlockCache(max_age_s=10.0)
    cache.publish(123)
    fake = AsyncMock()
    with patch(
        "voltaire_bundler.utils.latest_block_cache."
        "send_rpc_request_to_eth_client",
        fake,
    ):
        assert await cache.get_or_fetch(URLS) == 123
    fake.assert_not_called()


@pytest.mark.asyncio
async def test_cold_cache_fetches_via_rpc():
    cache = LatestBlockCache(max_age_s=10.0)
    fake = AsyncMock(return_value=_rpc_block_result(42))
    with patch(
        "voltaire_bundler.utils.latest_block_cache."
        "send_rpc_request_to_eth_client",
        fake,
    ):
        assert await cache.get_or_fetch(URLS) == 42
    assert fake.call_count == 1


@pytest.mark.asyncio
async def test_publish_accepts_reorg_backward():
    """Drop-the-only-move-forward fix: the most-recent publish wins
    even if its number is lower than the previous cached value, so a
    canonical reorg dropping the head from N+1 → N is reflected."""
    cache = LatestBlockCache()
    cache.publish(1000)
    cache.publish(999)
    fake = AsyncMock()
    with patch(
        "voltaire_bundler.utils.latest_block_cache."
        "send_rpc_request_to_eth_client",
        fake,
    ):
        assert await cache.get_or_fetch(URLS) == 999


@pytest.mark.asyncio
async def test_rpc_failure_returns_stale_cached_value():
    cache = LatestBlockCache(max_age_s=0.0)  # force every read to refetch
    cache.publish(500)
    fake = AsyncMock(side_effect=RuntimeError("upstream down"))
    with patch(
        "voltaire_bundler.utils.latest_block_cache."
        "send_rpc_request_to_eth_client",
        fake,
    ):
        # Stale + RPC failure → return cached, not None.
        assert await cache.get_or_fetch(URLS) == 500


@pytest.mark.asyncio
async def test_rpc_failure_with_empty_cache_returns_none():
    cache = LatestBlockCache()
    fake = AsyncMock(side_effect=RuntimeError("upstream down"))
    with patch(
        "voltaire_bundler.utils.latest_block_cache."
        "send_rpc_request_to_eth_client",
        fake,
    ):
        assert await cache.get_or_fetch(URLS) is None


@pytest.mark.asyncio
async def test_concurrent_misses_collapse_to_single_rpc():
    cache = LatestBlockCache(max_age_s=10.0)
    # Slow fake so all callers queue on the lock before the first
    # finishes; only one upstream call should fire.
    block = _rpc_block_result(777)

    async def slow(*args, **kwargs):
        await asyncio.sleep(0.05)
        return block

    fake = AsyncMock(side_effect=slow)
    with patch(
        "voltaire_bundler.utils.latest_block_cache."
        "send_rpc_request_to_eth_client",
        fake,
    ):
        results = await asyncio.gather(*[
            cache.get_or_fetch(URLS) for _ in range(10)
        ])
    assert all(r == 777 for r in results)
    assert fake.call_count == 1


@pytest.mark.asyncio
async def test_warm_raises_on_malformed_response():
    cache = LatestBlockCache()
    bad = AsyncMock(return_value={"jsonrpc": "2.0", "id": 1, "result": None})
    with patch(
        "voltaire_bundler.utils.latest_block_cache."
        "send_rpc_request_to_eth_client",
        bad,
    ):
        with pytest.raises(ValueError):
            await cache.warm(URLS)


@pytest.mark.asyncio
async def test_warm_populates_cache():
    cache = LatestBlockCache(max_age_s=10.0)
    fake = AsyncMock(return_value=_rpc_block_result(2026))
    with patch(
        "voltaire_bundler.utils.latest_block_cache."
        "send_rpc_request_to_eth_client",
        fake,
    ):
        await cache.warm(URLS)
        # Cached, no second RPC.
        assert await cache.get_or_fetch(URLS) == 2026
    assert fake.call_count == 1
