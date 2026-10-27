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
    """Stand-in for send_rpc_request_once keyed by node URL.

    ``behaviour[url]`` is either a hex string to return, an Exception to
    raise, or the string "hang" to block until cancelled. Mutate
    ``behaviour`` between refreshes to simulate a node going down or
    coming back."""

    def __init__(self, behaviour: dict[str, object]):
        self.behaviour = behaviour
        self.calls: list[tuple[str, str]] = []

    async def __call__(self, node_url, method, params=None):
        self.calls.append((node_url, method))
        action = self.behaviour[node_url]
        if action == "hang":
            await asyncio.sleep(3600)
        if isinstance(action, Exception):
            raise action
        return action


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
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
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
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _cache(["http://a"])

    with pytest.raises(GasPriceUnavailableError):
        await cache.get_snapshot()
    assert rpc.calls == []


@pytest.mark.asyncio
async def test_warm_populates_and_reads_are_free(monkeypatch, fast_timeouts):
    rpc = FakeRpc({"http://a": "0x60"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
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
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _cache(["http://a", "http://b"])

    await cache.warm()

    assert (await cache.get_snapshot()).max_fee_per_gas == 0x10
    assert [u for u, _ in rpc.calls] == ["http://a", "http://b"]


@pytest.mark.asyncio
async def test_erroring_primary_falls_through_to_secondary(
    monkeypatch, fast_timeouts
):
    rpc = FakeRpc({"http://a": ValueError("boom"), "http://b": "0x20"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _cache(["http://a", "http://b"])

    await cache.warm()

    assert (await cache.get_snapshot()).max_fee_per_gas == 0x20


@pytest.mark.asyncio
async def test_warm_raises_when_all_nodes_fail(monkeypatch, fast_timeouts):
    rpc = FakeRpc({"http://a": "hang", "http://b": ValueError("down")})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _cache(["http://a", "http://b"])

    with pytest.raises(ValueError, match="down"):
        await cache.warm()
    assert [u for u, _ in rpc.calls] == ["http://a", "http://b"]


@pytest.mark.asyncio
async def test_background_loop_refreshes_on_interval(
    monkeypatch, fast_timeouts
):
    rpc = FakeRpc({"http://a": "0x10"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
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
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
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
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
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

    async def rpc(url, method, params=None):
        if url == "http://a" and method == "eth_gasPrice":
            raise ValueError("boom")
        if url == "http://a":
            hanging.append(asyncio.current_task())
            await asyncio.sleep(3600)
        return "0x10"

    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
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
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _cache(["http://a", "http://b"])

    await cache.warm()

    assert (await cache.get_snapshot()).max_fee_per_gas == 0x20
    assert [u for u, _ in rpc.calls] == ["http://a", "http://b"]


@pytest.mark.asyncio
async def test_malformed_on_all_nodes_raises_value_error(
    monkeypatch, fast_timeouts
):
    rpc = FakeRpc({"http://a": "not-hex"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
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
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
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
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
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
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
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
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
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
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
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
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
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
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
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
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _public_cache(["http://a", "http://b"])
    await cache.warm()
    rpc.behaviour["http://a"] = "0x10000"

    for _ in range(10):
        await cache.warm()
        assert (await cache.get_snapshot()).max_fee_per_gas == 0x100


@pytest.mark.asyncio
async def test_default_mode_never_clamps(monkeypatch, fast_timeouts):
    rpc = FakeRpc({"http://a": "0x100"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
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

        async def rpc(url, method, params=None):
            calls.append((url, method))
            return prices[url][method]
        return rpc, calls

    prices = {
        "http://a": {"eth_gasPrice": "0x100",
                     "eth_maxPriorityFeePerGas": "0x10"},
        "http://b": {"eth_gasPrice": "0x100",
                     "eth_maxPriorityFeePerGas": "0x10"},
    }
    rpc, calls = rpc_for(prices)
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
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


# --------------------------------------------------------------------------
# Log volume: the loop ticks forever, so it must log on state changes, not
# on every tick (one warning when a node breaks, one info when it recovers,
# a reminder every _PROBLEM_HEARTBEAT_SECONDS in between, and nothing else,
# not even at debug level).
# --------------------------------------------------------------------------

def _records(caplog, level, needle):
    return [r for r in caplog.records
            if r.levelname == level and needle in r.getMessage()]


@pytest.mark.asyncio
async def test_failing_node_is_warned_about_once(
    monkeypatch, fast_timeouts, caplog
):
    rpc = FakeRpc({"http://a": ValueError("boom"), "http://b": "0x10"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _cache(["http://a", "http://b"])
    caplog.set_level("DEBUG")

    for _ in range(5):
        await cache._refresh()

    assert len(_records(caplog, "WARNING", "node 1/2 failed")) == 1
    # the other four ticks log nothing at any level
    assert len([r for r in caplog.records if "node 1/2" in r.getMessage()]) == 1
    assert _records(caplog, "WARNING", "node 2/2") == []


@pytest.mark.asyncio
async def test_failing_node_gets_a_reminder_after_heartbeat_interval(
    monkeypatch, fast_timeouts, caplog
):
    rpc = FakeRpc({"http://a": ValueError("boom"), "http://b": "0x10"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    monkeypatch.setattr(gpc, "_PROBLEM_HEARTBEAT_SECONDS", 0.0)
    cache = _cache(["http://a", "http://b"])
    caplog.set_level("DEBUG")

    for _ in range(3):
        await cache._refresh()

    assert len(_records(caplog, "WARNING", "node 1/2 failed")) == 1
    reminders = _records(caplog, "WARNING", "node 1/2 still failing")
    assert len(reminders) == 2
    assert "3 consecutive problems" in reminders[-1].getMessage()
    assert "trying next node" in reminders[-1].getMessage()


@pytest.mark.asyncio
async def test_node_recovery_is_logged_once_at_info(
    monkeypatch, fast_timeouts, caplog
):
    rpc = FakeRpc({"http://a": ValueError("boom"), "http://b": "0x10"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _cache(["http://a", "http://b"])
    caplog.set_level("DEBUG")

    await cache._refresh()
    await cache._refresh()
    rpc.behaviour["http://a"] = "0x11"
    await cache._refresh()
    await cache._refresh()

    recovered = _records(caplog, "INFO", "node 1/2 recovered")
    assert len(recovered) == 1
    assert "after 2 consecutive problems" in recovered[0].getMessage()
    assert (await cache.get_snapshot()).max_fee_per_gas == 0x11
    # a second outage starts a new run and is warned about again
    rpc.behaviour["http://a"] = ValueError("boom again")
    await cache._refresh()
    assert len(_records(caplog, "WARNING", "node 1/2 failed")) == 2


@pytest.mark.asyncio
async def test_repeated_outliers_from_one_node_are_warned_about_once(
    monkeypatch, fast_timeouts, caplog
):
    """Round-robin: the bad node's outlier is rejected every other tick,
    the sane node in between resets the confirmation streak, and the bad
    node's problem run stays open, so only its first outlier is a
    warning."""
    rpc = FakeRpc({"http://a": "0x10", "http://b": "0x10"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = GasPriceCache(["http://a", "http://b"], chain_id=1,
                          is_legacy_mode=True, refresh_interval_seconds=1.0,
                          public_nodes=True)
    caplog.set_level("DEBUG")
    await cache.warm()
    rpc.behaviour["http://a"] = "0x1000"  # 256x: outlier from now on

    for _ in range(6):
        await cache._refresh()

    assert len(_records(caplog, "WARNING", "node 1/2 returned an outlier")) == 1
    assert len([r for r in caplog.records if "outlier" in r.getMessage()]) == 1
    assert (await cache.get_snapshot()).max_fee_per_gas == 0x10


@pytest.mark.asyncio
async def test_total_outage_logs_first_failure_then_one_escalation(
    monkeypatch, fast_timeouts, caplog
):
    rpc = FakeRpc({"http://a": "0x10"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    # stale after 50 ms; the loop ticks every 10 ms
    monkeypatch.setattr(gpc, "_STALE_ERROR_AFTER_SECONDS", 0.05)
    cache = _cache(["http://a"], interval=0.01)
    caplog.set_level("DEBUG")
    await cache.warm()
    rpc.behaviour["http://a"] = ValueError("down")

    await _run_for(cache, 0.3)

    assert len(_records(caplog, "WARNING", "background refresh failed")) == 1
    escalations = _records(caplog, "ERROR", "refresh has failed")
    assert len(escalations) == 1
    assert "likely working from a wrong price" in escalations[0].getMessage()
    # no reminder within the heartbeat window, and nothing else at all
    assert _records(caplog, "WARNING", "refresh still failing") == []
    assert _records(caplog, "ERROR", "refresh still failing") == []
    assert len([r for r in caplog.records if "refresh" in r.getMessage()]) == 2
    # readers kept the last good value throughout
    assert (await cache.get_snapshot()).max_fee_per_gas == 0x10


@pytest.mark.asyncio
async def test_total_outage_reminders_use_error_level_once_stale(
    monkeypatch, fast_timeouts, caplog
):
    rpc = FakeRpc({"http://a": "0x10"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    monkeypatch.setattr(gpc, "_STALE_ERROR_AFTER_SECONDS", 0.0)
    monkeypatch.setattr(gpc, "_PROBLEM_HEARTBEAT_SECONDS", 0.0)
    cache = _cache(["http://a"], interval=0.01)
    caplog.set_level("DEBUG")
    await cache.warm()
    rpc.behaviour["http://a"] = ValueError("down")

    await _run_for(cache, 0.1)

    # already stale on the first failure: first line is the error, the
    # following ticks are reminders at error level, nothing at warning
    assert len(_records(caplog, "ERROR", "background refresh failed")) == 1
    assert len(_records(caplog, "ERROR", "refresh still failing")) >= 3
    assert _records(caplog, "WARNING", "refresh") == []


@pytest.mark.asyncio
async def test_total_outage_recovery_is_logged_once_at_info(
    monkeypatch, fast_timeouts, caplog
):
    rpc = FakeRpc({"http://a": "0x10"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _cache(["http://a"], interval=0.01)
    caplog.set_level("DEBUG")
    await cache.warm()
    rpc.behaviour["http://a"] = ValueError("down")
    task = asyncio.create_task(cache.run())
    await asyncio.sleep(0.1)
    rpc.behaviour["http://a"] = "0x20"
    await asyncio.sleep(0.1)
    cache.stop()
    await task

    recovered = _records(caplog, "INFO", "refresh recovered")
    assert len(recovered) == 1
    assert "consecutive failures" in recovered[0].getMessage()
    assert (await cache.get_snapshot()).max_fee_per_gas == 0x20
    # the single-node problem run closes with the same tick
    assert len(_records(caplog, "INFO", "node 1/1 recovered")) == 1


@pytest.mark.asyncio
async def test_successful_ticks_log_nothing(monkeypatch, fast_timeouts, caplog):
    rpc = FakeRpc({"http://a": "0x10"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _cache(["http://a"], interval=0.01)
    caplog.set_level("DEBUG")
    await cache.warm()

    await _run_for(cache, 0.1)

    assert len(rpc.calls) > 3
    assert [r for r in caplog.records if "GasPriceCache" in r.getMessage()] == []


# --------------------------------------------------------------------------
# Fallback to the bundler's own (trusted) node list when every public node
# fails on a tick.
# --------------------------------------------------------------------------

def _public_cache_with_fallback(public: list[str], fallback: list[str],
                                interval: float = 1.0) -> GasPriceCache:
    return GasPriceCache(public, chain_id=1, is_legacy_mode=True,
                         refresh_interval_seconds=interval,
                         public_nodes=True, fallback_node_urls=fallback)


@pytest.mark.asyncio
async def test_fallback_serves_when_every_public_node_fails(
    monkeypatch, fast_timeouts, caplog
):
    rpc = FakeRpc({"http://a": ValueError("a"), "http://b": "hang",
                   "http://primary": "0x10"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _public_cache_with_fallback(["http://a", "http://b"],
                                        ["http://primary"])
    caplog.set_level("DEBUG")

    await cache.warm()

    assert (await cache.get_snapshot()).max_fee_per_gas == 0x10
    # public list walked in full first, fallback last
    assert [u for u, _ in rpc.calls] == ["http://a", "http://b", "http://primary"]
    warned = _records(caplog, "WARNING", "all 2 public gas-price nodes failed")
    assert len(warned) == 1
    assert "fallback node 1/1" in warned[0].getMessage()
    # a fallback refresh is a successful refresh
    assert _records(caplog, "WARNING", "background refresh failed") == []


@pytest.mark.asyncio
async def test_fallback_is_not_consulted_while_a_public_node_serves(
    monkeypatch, fast_timeouts, caplog
):
    rpc = FakeRpc({"http://a": ValueError("a"), "http://b": "0x10",
                   "http://primary": "0x99"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _public_cache_with_fallback(["http://a", "http://b"],
                                        ["http://primary"])
    caplog.set_level("DEBUG")

    for _ in range(4):
        await cache._refresh()

    assert (await cache.get_snapshot()).max_fee_per_gas == 0x10
    assert "http://primary" not in [u for u, _ in rpc.calls]
    assert _records(caplog, "WARNING", "public gas-price nodes failed") == []


@pytest.mark.asyncio
async def test_fallback_walks_primary_first_and_fails_over(
    monkeypatch, fast_timeouts
):
    rpc = FakeRpc({"http://a": ValueError("a"),
                   "http://p1": ValueError("p1"), "http://p2": "0x20"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _public_cache_with_fallback(["http://a"], ["http://p1", "http://p2"])

    await cache.warm()
    await cache.warm()

    assert (await cache.get_snapshot()).max_fee_per_gas == 0x20
    # primary-first every time, no rotation on the fallback list
    assert [u for u, _ in rpc.calls] == ["http://a", "http://p1", "http://p2"] * 2


@pytest.mark.asyncio
async def test_fallback_sample_bypasses_the_outlier_clamp(
    monkeypatch, fast_timeouts
):
    """The clamp guards against untrusted public input; the fallback is
    the node the bundler trusts for everything else, so a deviant
    sample from it is the new truth."""
    rpc = FakeRpc({"http://a": "0x10", "http://primary": "0x10"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _public_cache_with_fallback(["http://a"], ["http://primary"])
    await cache.warm()
    rpc.behaviour["http://a"] = ValueError("down")
    rpc.behaviour["http://primary"] = "0x1000"  # 256x the cached value

    await cache._refresh()

    assert (await cache.get_snapshot()).max_fee_per_gas == 0x1000


@pytest.mark.asyncio
async def test_fallback_failing_too_is_a_refresh_failure(
    monkeypatch, fast_timeouts, caplog
):
    rpc = FakeRpc({"http://a": ValueError("a"), "http://primary": ValueError("p")})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _public_cache_with_fallback(["http://a"], ["http://primary"])
    caplog.set_level("DEBUG")

    with pytest.raises(ValueError, match="p"):
        await cache.warm()
    assert _records(caplog, "WARNING", "public gas-price nodes failed") == []


@pytest.mark.asyncio
async def test_fallback_run_is_logged_on_state_change_only(
    monkeypatch, fast_timeouts, caplog
):
    rpc = FakeRpc({"http://a": ValueError("a"), "http://primary": "0x10"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _public_cache_with_fallback(["http://a"], ["http://primary"])
    caplog.set_level("DEBUG")

    for _ in range(5):
        await cache._refresh()
    rpc.behaviour["http://a"] = "0x11"
    await cache._refresh()
    await cache._refresh()

    assert len(_records(caplog, "WARNING", "public gas-price nodes failed")) == 1
    assert _records(caplog, "WARNING", "still on fallback") == []
    back = _records(caplog, "INFO", "back on the public gas-price nodes")
    assert len(back) == 1
    assert "after 5 fallback refreshes" in back[0].getMessage()
    assert (await cache.get_snapshot()).max_fee_per_gas == 0x11
    # the fallback run and the public node's problem run close together
    assert len(_records(caplog, "INFO", "node 1/1 recovered")) == 1


@pytest.mark.asyncio
async def test_fallback_reminder_after_heartbeat_interval(
    monkeypatch, fast_timeouts, caplog
):
    rpc = FakeRpc({"http://a": ValueError("a"), "http://primary": "0x10"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    monkeypatch.setattr(gpc, "_PROBLEM_HEARTBEAT_SECONDS", 0.0)
    cache = _public_cache_with_fallback(["http://a"], ["http://primary"])
    caplog.set_level("DEBUG")

    for _ in range(3):
        await cache._refresh()

    reminders = _records(caplog, "WARNING", "still on fallback")
    assert len(reminders) == 2
    assert "3 consecutive refreshes" in reminders[-1].getMessage()


def test_no_fallback_without_a_list():
    cache = _cache(["http://a"])
    assert cache._fallback_node_urls == []


# ---------------------------------------------------------------- lazy mode
# No background loop: reads serve the cached value while it is younger than
# the interval and fetch on demand otherwise, sharing one in-flight fetch.


def _lazy_cache(urls: list[str], interval: float = 1.0) -> GasPriceCache:
    return GasPriceCache(urls, chain_id=1, is_legacy_mode=True,
                         refresh_interval_seconds=interval, lazy=True)


def _aged_snapshot(max_fee: int, age_s: float) -> GasPriceSnapshot:
    return GasPriceSnapshot(
        max_fee_per_gas=max_fee, max_priority_fee_per_gas=None,
        fetched_at_monotonic=time.monotonic() - age_s,
    )


def test_lazy_mode_rejects_public_nodes():
    with pytest.raises(ValueError):
        GasPriceCache(["http://a"], chain_id=1, is_legacy_mode=True,
                      refresh_interval_seconds=1.0, public_nodes=True,
                      lazy=True)


@pytest.mark.asyncio
async def test_lazy_fresh_snapshot_is_served_without_fetching(
    monkeypatch, fast_timeouts
):
    rpc = FakeRpc({"http://a": "0x10"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _lazy_cache(["http://a"], interval=10.0)
    cache._snapshot = _aged_snapshot(0x30, age_s=1.0)

    snap = await cache.get_snapshot()

    assert snap.max_fee_per_gas == 0x30
    assert rpc.calls == []


@pytest.mark.asyncio
async def test_lazy_stale_snapshot_triggers_fetch(monkeypatch, fast_timeouts):
    rpc = FakeRpc({"http://a": "0x11"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _lazy_cache(["http://a"], interval=1.0)
    cache._snapshot = _aged_snapshot(0x30, age_s=5.0)

    snap = await cache.get_snapshot()

    assert snap.max_fee_per_gas == 0x11
    assert len(rpc.calls) == 1
    # Now fresh: the next read is free.
    assert (await cache.get_snapshot()) is snap
    assert len(rpc.calls) == 1


@pytest.mark.asyncio
async def test_lazy_first_read_fetches_without_warm(monkeypatch, fast_timeouts):
    rpc = FakeRpc({"http://a": "0x12"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _lazy_cache(["http://a"])

    snap = await cache.get_snapshot()

    assert snap.max_fee_per_gas == 0x12
    assert len(rpc.calls) == 1


@pytest.mark.asyncio
async def test_lazy_fetch_failure_raises_even_with_stale_snapshot(
    monkeypatch, fast_timeouts
):
    # Unlike background mode, a stale value is not served on failure: in
    # lazy mode it could be hours old.
    rpc = FakeRpc({"http://a": ValueError("down")})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _lazy_cache(["http://a"], interval=1.0)
    cache._snapshot = _aged_snapshot(0x30, age_s=5.0)

    with pytest.raises(GasPriceUnavailableError):
        await cache.get_snapshot()
    assert len(rpc.calls) == 1


@pytest.mark.asyncio
async def test_lazy_fetch_failure_without_snapshot_raises(
    monkeypatch, fast_timeouts
):
    rpc = FakeRpc({"http://a": "hang"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _lazy_cache(["http://a"])

    with pytest.raises(GasPriceUnavailableError):
        await cache.get_snapshot()


@pytest.mark.asyncio
async def test_lazy_recovers_on_next_read_after_failure(
    monkeypatch, fast_timeouts
):
    rpc = FakeRpc({"http://a": ValueError("down")})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _lazy_cache(["http://a"])
    with pytest.raises(GasPriceUnavailableError):
        await cache.get_snapshot()
    rpc.behaviour["http://a"] = "0x13"

    snap = await cache.get_snapshot()

    assert snap.max_fee_per_gas == 0x13


@pytest.mark.asyncio
async def test_lazy_concurrent_stale_reads_share_one_fetch(
    monkeypatch, fast_timeouts
):
    class SlowRpc(FakeRpc):
        async def __call__(self, node_url, method, params=None):
            await asyncio.sleep(0.01)
            return await super().__call__(node_url, method, params)

    rpc = SlowRpc({"http://a": "0x14"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _lazy_cache(["http://a"], interval=1.0)
    cache._snapshot = _aged_snapshot(0x30, age_s=5.0)

    snaps = await asyncio.gather(*(cache.get_snapshot() for _ in range(10)))

    assert all(s.max_fee_per_gas == 0x14 for s in snaps)
    assert len(rpc.calls) == 1


@pytest.mark.asyncio
async def test_lazy_cancelled_reader_does_not_cancel_shared_fetch(
    monkeypatch, fast_timeouts
):
    class SlowRpc(FakeRpc):
        async def __call__(self, node_url, method, params=None):
            await asyncio.sleep(0.02)
            return await super().__call__(node_url, method, params)

    rpc = SlowRpc({"http://a": "0x15"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _lazy_cache(["http://a"])

    first = asyncio.create_task(cache.get_snapshot())
    second = asyncio.create_task(cache.get_snapshot())
    await asyncio.sleep(0)  # let both park on the shared fetch
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first

    snap = await second
    assert snap.max_fee_per_gas == 0x15
    assert len(rpc.calls) == 1


@pytest.mark.asyncio
async def test_lazy_run_returns_immediately_and_fetches_nothing(
    monkeypatch, fast_timeouts
):
    rpc = FakeRpc({"http://a": "0x10"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _lazy_cache(["http://a"], interval=0.02)

    await asyncio.wait_for(cache.run(), timeout=1)
    await asyncio.sleep(0.1)

    assert rpc.calls == []


@pytest.mark.asyncio
async def test_lazy_warm_then_idle_makes_no_further_calls(
    monkeypatch, fast_timeouts
):
    rpc = FakeRpc({"http://a": "0x10"})
    monkeypatch.setattr(gpc, "send_rpc_request_once", rpc)
    cache = _lazy_cache(["http://a"], interval=0.02)

    await cache.warm()
    await asyncio.sleep(0.1)

    assert len(rpc.calls) == 1
    # A read after the interval elapsed is the first thing to fetch again.
    await cache.get_snapshot()
    assert len(rpc.calls) == 2
