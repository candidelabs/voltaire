"""Behaviour tests for GasPriceCache.

The cache is refreshed only by its background loop; reads return the
cached value and never touch the network. These tests pin that contract
plus the failure handling around it:

- reads never trigger a fetch, even when the value is old
- a failed background refresh keeps the previous value
- the refresh walks the configured nodes, so a hanging primary falls
  through to the next node
- a read before any successful fetch raises GasPriceUnavailableError
"""
from __future__ import annotations

import asyncio
import time

import pytest

import voltaire_bundler.gas.gas_price_cache as gpc
from voltaire_bundler.gas.gas_price_cache import (
    GasPriceCache,
    GasPriceSnapshot,
    GasPriceUnavailableError,
)


class FakeRpc:
    """Stand-in for send_rpc_request_to_eth_client keyed by node URL.

    ``behaviour[url]`` is either a hex string to return, an Exception to
    raise, or the string "hang" to block until cancelled."""

    def __init__(self, behaviour: dict[str, object]):
        self.behaviour = behaviour
        self.calls: list[tuple[str, str]] = []

    async def __call__(self, nodes_urls, method, params=None,
                       flashbots=None, expected_key=None):
        url = nodes_urls[0]
        self.calls.append((url, method))
        action = self.behaviour[url]
        if action == "hang":
            await asyncio.sleep(3600)
        if isinstance(action, Exception):
            raise action
        return {"result": action}


@pytest.fixture
def fast_timeouts(monkeypatch):
    monkeypatch.setattr(gpc, "_PER_NODE_TIMEOUT_SECONDS", 0.05)


def _cache(urls: list[str], interval: float = 1.0) -> GasPriceCache:
    # Legacy mode: only eth_gasPrice is fetched, keeping call lists short.
    return GasPriceCache(urls, chain_id=1, is_legacy_mode=True,
                         refresh_interval_seconds=interval)


async def _run_for(cache: GasPriceCache, seconds: float) -> None:
    task = asyncio.create_task(cache.run())
    await asyncio.sleep(seconds)
    cache.stop()
    await task


@pytest.mark.asyncio
async def test_read_never_fetches_even_when_old(monkeypatch, fast_timeouts):
    rpc = FakeRpc({"http://a": "0x10"})
    monkeypatch.setattr(gpc, "send_rpc_request_to_eth_client", rpc)
    cache = _cache(["http://a"])
    cache._snapshot = GasPriceSnapshot(
        max_fee_per_gas=0x30, max_priority_fee_per_gas=None,
        fetched_at_monotonic=time.monotonic() - 600.0,
    )

    snap = await cache.get_snapshot()

    assert snap.max_fee_per_gas == 0x30
    assert rpc.calls == []


@pytest.mark.asyncio
async def test_read_before_first_fetch_raises(monkeypatch, fast_timeouts):
    rpc = FakeRpc({"http://a": "0x10"})
    monkeypatch.setattr(gpc, "send_rpc_request_to_eth_client", rpc)
    cache = _cache(["http://a"])

    with pytest.raises(GasPriceUnavailableError):
        await cache.get_snapshot()
    assert rpc.calls == []


@pytest.mark.asyncio
async def test_warm_populates_and_reads_are_free(monkeypatch, fast_timeouts):
    rpc = FakeRpc({"http://a": "0x60"})
    monkeypatch.setattr(gpc, "send_rpc_request_to_eth_client", rpc)
    cache = _cache(["http://a"])

    await cache.warm()
    snap = await cache.get_snapshot()

    assert snap.max_fee_per_gas == 0x60
    assert (await cache.get_snapshot()) is snap
    assert len(rpc.calls) == 1


@pytest.mark.asyncio
async def test_hanging_primary_falls_through_to_secondary(
    monkeypatch, fast_timeouts
):
    rpc = FakeRpc({"http://a": "hang", "http://b": "0x10"})
    monkeypatch.setattr(gpc, "send_rpc_request_to_eth_client", rpc)
    cache = _cache(["http://a", "http://b"])

    await cache.warm()

    assert (await cache.get_snapshot()).max_fee_per_gas == 0x10
    assert [u for u, _ in rpc.calls] == ["http://a", "http://b"]


@pytest.mark.asyncio
async def test_erroring_primary_falls_through_to_secondary(
    monkeypatch, fast_timeouts
):
    rpc = FakeRpc({"http://a": ValueError("boom"), "http://b": "0x20"})
    monkeypatch.setattr(gpc, "send_rpc_request_to_eth_client", rpc)
    cache = _cache(["http://a", "http://b"])

    await cache.warm()

    assert (await cache.get_snapshot()).max_fee_per_gas == 0x20


@pytest.mark.asyncio
async def test_warm_raises_when_all_nodes_fail(monkeypatch, fast_timeouts):
    rpc = FakeRpc({"http://a": "hang", "http://b": ValueError("down")})
    monkeypatch.setattr(gpc, "send_rpc_request_to_eth_client", rpc)
    cache = _cache(["http://a", "http://b"])

    with pytest.raises(ValueError, match="down"):
        await cache.warm()
    assert [u for u, _ in rpc.calls] == ["http://a", "http://b"]


@pytest.mark.asyncio
async def test_background_loop_refreshes_on_interval(
    monkeypatch, fast_timeouts
):
    rpc = FakeRpc({"http://a": "0x10"})
    monkeypatch.setattr(gpc, "send_rpc_request_to_eth_client", rpc)
    cache = _cache(["http://a"], interval=0.02)
    await cache.warm()
    rpc.behaviour["http://a"] = "0x11"

    await _run_for(cache, 0.1)

    assert (await cache.get_snapshot()).max_fee_per_gas == 0x11
    assert len(rpc.calls) >= 3


@pytest.mark.asyncio
async def test_background_failure_keeps_previous_value(
    monkeypatch, fast_timeouts
):
    rpc = FakeRpc({"http://a": "0x10"})
    monkeypatch.setattr(gpc, "send_rpc_request_to_eth_client", rpc)
    cache = _cache(["http://a"], interval=0.02)
    await cache.warm()
    before = await cache.get_snapshot()
    rpc.behaviour["http://a"] = "hang"

    await _run_for(cache, 0.2)

    assert (await cache.get_snapshot()) is before
    assert len(rpc.calls) >= 2, "loop should keep retrying"


@pytest.mark.asyncio
async def test_background_loop_populates_after_failed_warm(
    monkeypatch, fast_timeouts
):
    rpc = FakeRpc({"http://a": ValueError("down")})
    monkeypatch.setattr(gpc, "send_rpc_request_to_eth_client", rpc)
    cache = _cache(["http://a"], interval=0.02)
    with pytest.raises(ValueError):
        await cache.warm()
    rpc.behaviour["http://a"] = "0x70"

    await _run_for(cache, 0.1)

    assert (await cache.get_snapshot()).max_fee_per_gas == 0x70
