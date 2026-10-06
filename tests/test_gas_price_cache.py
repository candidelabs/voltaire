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


@pytest.mark.asyncio
async def test_failed_fee_rpc_cancels_its_sibling(monkeypatch, fast_timeouts):
    """When one of the two fee RPCs against a node fails, the other must be
    cancelled rather than left running against that node after the refresh
    has moved on to the next one."""
    monkeypatch.setattr(gpc, "_PER_NODE_TIMEOUT_SECONDS", 1.0)
    hanging: list[asyncio.Task] = []

    async def rpc(nodes_urls, method, params=None, flashbots=None,
                  expected_key=None):
        url = nodes_urls[0]
        if url == "http://a" and method == "eth_gasPrice":
            raise ValueError("boom")
        if url == "http://a":
            hanging.append(asyncio.current_task())
            await asyncio.sleep(3600)
        return {"result": "0x10"}

    monkeypatch.setattr(gpc, "send_rpc_request_to_eth_client", rpc)
    # Non-legacy mode on a chain with a priority fee: both RPCs are issued.
    cache = GasPriceCache(["http://a", "http://b"], chain_id=1,
                          is_legacy_mode=False, refresh_interval_seconds=1.0)

    await cache.warm()

    snap = await cache.get_snapshot()
    assert snap.max_fee_per_gas == 0x10
    assert snap.max_priority_fee_per_gas == 0x10
    assert len(hanging) == 1
    assert hanging[0].cancelled()


@pytest.mark.asyncio
async def test_malformed_primary_falls_through_to_secondary(
    monkeypatch, fast_timeouts
):
    """A node that answers but with an unparseable value (JSON null here,
    as some proxies return) counts as that node's failure, so the refresh
    moves on to the next node instead of aborting."""
    rpc = FakeRpc({"http://a": None, "http://b": "0x20"})
    monkeypatch.setattr(gpc, "send_rpc_request_to_eth_client", rpc)
    cache = _cache(["http://a", "http://b"])

    await cache.warm()

    assert (await cache.get_snapshot()).max_fee_per_gas == 0x20
    assert [u for u, _ in rpc.calls] == ["http://a", "http://b"]


@pytest.mark.asyncio
async def test_malformed_on_all_nodes_raises_value_error(
    monkeypatch, fast_timeouts
):
    rpc = FakeRpc({"http://a": "not-hex"})
    monkeypatch.setattr(gpc, "send_rpc_request_to_eth_client", rpc)
    cache = _cache(["http://a"])

    with pytest.raises(ValueError, match="malformed gas-price response"):
        await cache.warm()


# ------------------------------------------------------------ public nodes
# --gas_price_node_url mode: round-robin start plus outlier rejection.

def _public_cache(urls: list[str], interval: float = 1.0) -> GasPriceCache:
    return GasPriceCache(urls, chain_id=1, is_legacy_mode=True,
                         refresh_interval_seconds=interval,
                         public_nodes=True)


@pytest.mark.asyncio
async def test_default_mode_always_starts_at_primary(
    monkeypatch, fast_timeouts
):
    rpc = FakeRpc({"http://a": "0x10", "http://b": "0x10"})
    monkeypatch.setattr(gpc, "send_rpc_request_to_eth_client", rpc)
    cache = _cache(["http://a", "http://b"])

    for _ in range(3):
        await cache.warm()

    assert [u for u, _ in rpc.calls] == ["http://a"] * 3


@pytest.mark.asyncio
async def test_public_mode_round_robins_start_node(
    monkeypatch, fast_timeouts
):
    rpc = FakeRpc({"http://a": "0x10", "http://b": "0x10",
                   "http://c": "0x10"})
    monkeypatch.setattr(gpc, "send_rpc_request_to_eth_client", rpc)
    cache = _public_cache(["http://a", "http://b", "http://c"])

    for _ in range(4):
        await cache.warm()

    assert [u for u, _ in rpc.calls] == [
        "http://a", "http://b", "http://c", "http://a"]


@pytest.mark.asyncio
async def test_public_mode_fails_over_from_rotated_start(
    monkeypatch, fast_timeouts
):
    """Second refresh starts at b; b hangs, so it walks c then wraps to a.
    The rotation also advances past a failed start so the third refresh
    begins at c, not b again."""
    rpc = FakeRpc({"http://a": "0x10", "http://b": "hang",
                   "http://c": ValueError("down")})
    monkeypatch.setattr(gpc, "send_rpc_request_to_eth_client", rpc)
    cache = _public_cache(["http://a", "http://b", "http://c"])

    await cache.warm()  # a
    await cache.warm()  # b (hang) -> c (error) -> a
    await cache.warm()  # c (error) -> a

    assert [u for u, _ in rpc.calls] == [
        "http://a",
        "http://b", "http://c", "http://a",
        "http://c", "http://a",
    ]
    assert (await cache.get_snapshot()).max_fee_per_gas == 0x10


@pytest.mark.asyncio
async def test_public_mode_rejects_outlier_and_uses_next_node(
    monkeypatch, fast_timeouts
):
    """Node a reports a 256x price; it is treated as a's failure and b's
    sane value is served instead."""
    rpc = FakeRpc({"http://a": "0x100", "http://b": "0x110"})
    monkeypatch.setattr(gpc, "send_rpc_request_to_eth_client", rpc)
    cache = _public_cache(["http://a", "http://b"])
    await cache.warm()  # a -> 0x100 (first sample, always accepted)
    rpc.behaviour["http://a"] = "0x10000"

    await cache.warm()  # starts at b -> 0x110
    await cache.warm()  # starts at a -> outlier -> b -> 0x110

    assert (await cache.get_snapshot()).max_fee_per_gas == 0x110
    assert [u for u, _ in rpc.calls] == [
        "http://a", "http://b", "http://a", "http://b"]


@pytest.mark.asyncio
async def test_public_mode_rejects_outlier_in_both_directions(
    monkeypatch, fast_timeouts
):
    rpc = FakeRpc({"http://a": "0x1000", "http://b": "0x1000"})
    monkeypatch.setattr(gpc, "send_rpc_request_to_eth_client", rpc)
    cache = _public_cache(["http://a", "http://b"])
    await cache.warm()
    rpc.behaviour["http://b"] = "0x1"  # far too low

    await cache.warm()  # b -> outlier -> a -> 0x1000

    assert (await cache.get_snapshot()).max_fee_per_gas == 0x1000


@pytest.mark.asyncio
async def test_public_mode_accepts_jump_after_consecutive_confirmations(
    monkeypatch, fast_timeouts
):
    """A genuine market move beyond the ratio is accepted once three
    consecutive samples agree, so the cache can't get pinned at a stale
    price. With one node that takes three refreshes."""
    rpc = FakeRpc({"http://a": "0x100"})
    monkeypatch.setattr(gpc, "send_rpc_request_to_eth_client", rpc)
    cache = _public_cache(["http://a"])
    await cache.warm()
    rpc.behaviour["http://a"] = "0x10000"

    for _ in range(2):
        with pytest.raises(ValueError, match="outlier"):
            await cache.warm()
        assert (await cache.get_snapshot()).max_fee_per_gas == 0x100
    await cache.warm()  # third consecutive deviant sample: accepted

    assert (await cache.get_snapshot()).max_fee_per_gas == 0x10000


@pytest.mark.asyncio
async def test_public_mode_jump_confirmed_across_nodes_in_one_refresh(
    monkeypatch, fast_timeouts
):
    """With three nodes all reporting the jump, the walk within a single
    refresh collects the three confirmations and serves the new price."""
    rpc = FakeRpc({"http://a": "0x100", "http://b": "0x100",
                   "http://c": "0x100"})
    monkeypatch.setattr(gpc, "send_rpc_request_to_eth_client", rpc)
    cache = _public_cache(["http://a", "http://b", "http://c"])
    await cache.warm()
    for url in rpc.behaviour:
        rpc.behaviour[url] = "0x10000"

    await cache.warm()

    assert (await cache.get_snapshot()).max_fee_per_gas == 0x10000
    assert len(rpc.calls) == 4


@pytest.mark.asyncio
async def test_public_mode_sane_sample_resets_outlier_streak(
    monkeypatch, fast_timeouts
):
    """One persistently bad node can't accumulate confirmations on its own:
    the healthy node after it in the rotation resets the streak."""
    rpc = FakeRpc({"http://a": "0x100", "http://b": "0x100"})
    monkeypatch.setattr(gpc, "send_rpc_request_to_eth_client", rpc)
    cache = _public_cache(["http://a", "http://b"])
    await cache.warm()
    rpc.behaviour["http://a"] = "0x10000"

    for _ in range(10):
        await cache.warm()
        assert (await cache.get_snapshot()).max_fee_per_gas == 0x100


@pytest.mark.asyncio
async def test_default_mode_never_clamps(monkeypatch, fast_timeouts):
    rpc = FakeRpc({"http://a": "0x100"})
    monkeypatch.setattr(gpc, "send_rpc_request_to_eth_client", rpc)
    cache = _cache(["http://a"])
    await cache.warm()
    rpc.behaviour["http://a"] = "0x10000"

    await cache.warm()

    assert (await cache.get_snapshot()).max_fee_per_gas == 0x10000


@pytest.mark.asyncio
async def test_public_mode_clamps_priority_fee_too(
    monkeypatch, fast_timeouts
):
    """An inflated tip alone (sane eth_gasPrice) is still an outlier: the
    priority fee is what the bundler actually pays."""
    def rpc_for(prices: dict[str, dict[str, str]]):
        calls: list[tuple[str, str]] = []

        async def rpc(nodes_urls, method, params=None, flashbots=None,
                      expected_key=None):
            calls.append((nodes_urls[0], method))
            return {"result": prices[nodes_urls[0]][method]}
        return rpc, calls

    prices = {
        "http://a": {"eth_gasPrice": "0x100",
                     "eth_maxPriorityFeePerGas": "0x10"},
        "http://b": {"eth_gasPrice": "0x100",
                     "eth_maxPriorityFeePerGas": "0x10"},
    }
    rpc, calls = rpc_for(prices)
    monkeypatch.setattr(gpc, "send_rpc_request_to_eth_client", rpc)
    cache = GasPriceCache(["http://a", "http://b"], chain_id=1,
                          is_legacy_mode=False, refresh_interval_seconds=1.0,
                          public_nodes=True)
    await cache.warm()  # a
    prices["http://b"]["eth_maxPriorityFeePerGas"] = "0x1000"

    await cache.warm()  # b -> tip outlier -> a

    snap = await cache.get_snapshot()
    assert snap.max_priority_fee_per_gas == 0x10
    assert [u for u, _ in calls][-2:] == ["http://a", "http://a"]


def test_public_cache_rejects_empty_node_list():
    with pytest.raises(ValueError, match="at least one node"):
        _public_cache([])
