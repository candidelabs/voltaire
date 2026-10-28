"""Behaviour tests for BundlerManager.broadcast_raw_transaction.

The fan-out sends one signed bundle tx to every bundle node in parallel
and folds the answers into a single JSON-RPC-shaped result for
send_bundle. These pin the precedence rules:

- any node returning a hash wins, even if the primary said "already known"
- the first accept returns immediately; slower nodes keep running under
  supervision and are not cancelled
- a stuck error is surfaced only when no node accepted the tx fresh
- a non-stuck RPC error from one node does not mask a stuck signal from
  another (a permanently broken secondary must not starve the fee bump)
- a permanent rejection beats a transient one from another node
- transient errors (rate limits, upstream outages) route to the retrying
  fallback instead of being handed to send_bundle as a hard failure
- with no usable answer from any node, fall back to the retrying call
- a single configured node never fans out
"""
from __future__ import annotations

import asyncio

import pytest

import voltaire_bundler.bundle.bundle_manager as bm
from voltaire_bundler.bundle.bundle_manager import (
    BundlerManager,
    _classify_send_raw_tx_response,
    _is_tx_pool_stuck_error,
)
from voltaire_bundler.utils.eth_client_utils import is_retryable_rpc_error

RAW_TX = "0xdeadbeef"
TX_HASH = "0x" + "11" * 32
ALREADY_KNOWN = {"code": -32000, "message": "already known"}
UNDERPRICED = {"code": -32000, "message": "replacement transaction underpriced"}
FREE_PLAN = {"code": 35, "message": "chain is not available on free plan"}
RATE_LIMITED = {"code": -32005, "message": "rate limited"}
INVALID_SENDER = {"code": -32000, "message": "invalid sender"}


def make_manager(nodes: list[str]) -> BundlerManager:
    # Bypass __init__: the fan-out only reads bundle_node_urls.
    manager = BundlerManager.__new__(BundlerManager)
    manager.bundle_node_urls = nodes
    manager._broadcast_tasks = set()
    return manager


async def drain(manager: BundlerManager) -> None:
    # Cancel any supervised straggler so the test loop closes cleanly.
    tasks = list(manager._broadcast_tasks)
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


class FakeRpc:
    """Per-URL canned responses for send_rpc_request_to_eth_client_no_retry.

    A value that is an Exception instance is raised; "hang" sleeps past
    the broadcast timeout so the caller sees a timeout.
    """

    def __init__(self, by_url: dict[str, object]):
        self.by_url = by_url
        self.calls: list[tuple[str, str, list]] = []

    async def __call__(self, url, method, params=None):
        self.calls.append((url, method, params))
        res = self.by_url[url]
        if res == "hang":
            await asyncio.sleep(60)
        if isinstance(res, Exception):
            raise res
        return res


class FakeRetryRpc:
    def __init__(self, result):
        self.result = result
        self.calls: list[tuple[list[str], str, list]] = []

    async def __call__(self, nodes, method, params=None, *args, **kwargs):
        self.calls.append((list(nodes), method, params))
        return self.result


@pytest.fixture
def no_retry(monkeypatch):
    def install(by_url):
        fake = FakeRpc(by_url)
        monkeypatch.setattr(bm, "send_rpc_request_to_eth_client_no_retry", fake)
        return fake
    return install


@pytest.fixture
def retry(monkeypatch):
    def install(result):
        fake = FakeRetryRpc(result)
        monkeypatch.setattr(bm, "send_rpc_request_to_eth_client", fake)
        return fake
    return install


def test_retryable_predicate_mirrors_retry_loop_rules():
    # Non-retryable codes: the node evaluated the tx and rejected it.
    for code in (3, -32000, -32015, -32010, -32603):
        assert not is_retryable_rpc_error({"code": code, "message": "x"}, 0)
    # Anything else is transient.
    assert is_retryable_rpc_error(RATE_LIMITED, 0)
    assert is_retryable_rpc_error(FREE_PLAN, 1)
    # erpc "upstream" wording only counts on the first node.
    assert is_retryable_rpc_error({"code": -32000, "message": "upstream circuit breaker open"}, 0)
    assert not is_retryable_rpc_error({"code": -32000, "message": "upstream circuit breaker open"}, 1)
    # No code, no upstream wording: nothing to retry on.
    assert not is_retryable_rpc_error({"message": "already known"}, 0)
    assert not is_retryable_rpc_error("boom", 0)
    assert not is_retryable_rpc_error(None, 0)


def test_classifier_buckets():
    assert _classify_send_raw_tx_response({"result": TX_HASH}, 0) == ("accepted", TX_HASH)
    assert _classify_send_raw_tx_response({"error": ALREADY_KNOWN}, 0) == ("stuck", ALREADY_KNOWN)
    assert _classify_send_raw_tx_response({"error": INVALID_SENDER}, 0) == ("permanent", INVALID_SENDER)
    assert _classify_send_raw_tx_response({"error": RATE_LIMITED}, 0) == ("retryable", RATE_LIMITED)
    exc = ConnectionError("refused")
    assert _classify_send_raw_tx_response(exc, 0) == ("unreachable", exc)
    bare = {"jsonrpc": "2.0", "id": 1}
    assert _classify_send_raw_tx_response(bare, 0) == ("unreachable", bare)
    assert _classify_send_raw_tx_response({"result": None}, 0)[0] == "unreachable"


def test_stuck_classifier_matches_known_pool_messages():
    assert _is_tx_pool_stuck_error(ALREADY_KNOWN)
    assert _is_tx_pool_stuck_error(UNDERPRICED)
    assert _is_tx_pool_stuck_error({"message": "AlreadyKnown"})
    assert not _is_tx_pool_stuck_error(FREE_PLAN)
    assert not _is_tx_pool_stuck_error({"code": -32000})
    assert not _is_tx_pool_stuck_error("already known")
    assert not _is_tx_pool_stuck_error(None)


@pytest.mark.asyncio
async def test_single_node_uses_retrying_call_without_fan_out(no_retry, retry):
    fan = no_retry({})
    single = retry({"result": TX_HASH})
    manager = make_manager(["http://a"])

    res = await manager.broadcast_raw_transaction(RAW_TX)

    assert res == {"result": TX_HASH}
    assert fan.calls == []
    assert single.calls == [(["http://a"], "eth_sendRawTransaction", [RAW_TX])]


@pytest.mark.asyncio
async def test_every_node_gets_the_same_tx(no_retry, retry):
    fan = no_retry({
        "http://a": {"result": TX_HASH},
        "http://b": {"result": TX_HASH},
    })
    single = retry({"result": "unused"})
    manager = make_manager(["http://a", "http://b"])

    res = await manager.broadcast_raw_transaction(RAW_TX)

    assert res == {"result": TX_HASH}
    assert sorted(c[0] for c in fan.calls) == ["http://a", "http://b"]
    assert all(c[1:] == ("eth_sendRawTransaction", [RAW_TX]) for c in fan.calls)
    assert single.calls == []


@pytest.mark.asyncio
async def test_fresh_accept_on_secondary_beats_already_known_on_primary(no_retry, retry):
    # The propagation case: primary already holds the tx, secondary takes
    # it fresh. Must look like a successful send so no fee bump fires.
    no_retry({
        "http://a": {"error": ALREADY_KNOWN},
        "http://b": {"result": TX_HASH},
    })
    retry({"result": "unused"})
    manager = make_manager(["http://a", "http://b"])

    res = await manager.broadcast_raw_transaction(RAW_TX)

    assert res == {"result": TX_HASH}


@pytest.mark.asyncio
async def test_all_nodes_stuck_surfaces_stuck_error(no_retry, retry):
    no_retry({
        "http://a": {"error": ALREADY_KNOWN},
        "http://b": {"error": UNDERPRICED},
    })
    retry({"result": "unused"})
    manager = make_manager(["http://a", "http://b"])

    res = await manager.broadcast_raw_transaction(RAW_TX)

    # Both nodes are stuck; whichever answered first is surfaced, and the
    # fan-out completes in arrival order, so accept either.
    assert res["error"] in (ALREADY_KNOWN, UNDERPRICED)
    assert _is_tx_pool_stuck_error(res["error"])


@pytest.mark.asyncio
async def test_broken_secondary_does_not_mask_stuck_primary(no_retry, retry):
    # Node 2 rejects the chain outright (the free-plan case from the
    # production log). Node 1's "already known" must still reach
    # send_bundle's fee-bump branch, or the bump is starved forever.
    no_retry({
        "http://a": {"error": ALREADY_KNOWN},
        "http://b": {"error": FREE_PLAN},
    })
    retry({"result": "unused"})
    manager = make_manager(["http://a", "http://b"])

    res = await manager.broadcast_raw_transaction(RAW_TX)

    assert res == {"error": ALREADY_KNOWN}


@pytest.mark.asyncio
async def test_unreachable_secondary_does_not_mask_stuck_primary(no_retry, retry):
    no_retry({
        "http://a": {"error": ALREADY_KNOWN},
        "http://b": ConnectionError("refused"),
    })
    retry({"result": "unused"})
    manager = make_manager(["http://a", "http://b"])

    res = await manager.broadcast_raw_transaction(RAW_TX)

    assert res == {"error": ALREADY_KNOWN}


@pytest.mark.asyncio
async def test_permanent_error_surfaces_when_nothing_else(no_retry, retry):
    no_retry({
        "http://a": {"error": INVALID_SENDER},
        "http://b": ConnectionError("refused"),
    })
    single = retry({"result": "unused"})
    manager = make_manager(["http://a", "http://b"])

    res = await manager.broadcast_raw_transaction(RAW_TX)

    assert res == {"error": INVALID_SENDER}
    assert single.calls == []


@pytest.mark.asyncio
async def test_permanent_error_beats_transient_error(no_retry, retry):
    # The tx itself is bad; a rate limit elsewhere must not trigger a
    # 60-attempt retry loop over an invalid signature.
    no_retry({
        "http://a": {"error": RATE_LIMITED},
        "http://b": {"error": INVALID_SENDER},
    })
    single = retry({"result": "unused"})
    manager = make_manager(["http://a", "http://b"])

    res = await manager.broadcast_raw_transaction(RAW_TX)

    assert res == {"error": INVALID_SENDER}
    assert single.calls == []


@pytest.mark.asyncio
async def test_only_transient_errors_fall_back_to_retrying_send(no_retry, retry):
    # Same outcome a single-node config gets for a rate-limited node:
    # the retrying path, not a hard "Dropping all user operations".
    no_retry({
        "http://a": {"error": RATE_LIMITED},
        "http://b": ConnectionError("refused"),
    })
    single = retry({"result": TX_HASH})
    manager = make_manager(["http://a", "http://b"])

    res = await manager.broadcast_raw_transaction(RAW_TX)

    assert res == {"result": TX_HASH}
    assert single.calls == [
        (["http://a", "http://b"], "eth_sendRawTransaction", [RAW_TX])
    ]


@pytest.mark.asyncio
async def test_transient_error_does_not_mask_stuck(no_retry, retry):
    no_retry({
        "http://a": {"error": ALREADY_KNOWN},
        "http://b": {"error": RATE_LIMITED},
    })
    single = retry({"result": "unused"})
    manager = make_manager(["http://a", "http://b"])

    res = await manager.broadcast_raw_transaction(RAW_TX)

    assert res == {"error": ALREADY_KNOWN}
    assert single.calls == []


@pytest.mark.asyncio
async def test_all_unreachable_falls_back_to_retrying_send(no_retry, retry, monkeypatch):
    monkeypatch.setattr(bm, "BROADCAST_NODE_TIMEOUT_S", 0.05)
    no_retry({
        "http://a": ConnectionError("refused"),
        "http://b": "hang",
        "http://c": {"jsonrpc": "2.0", "id": 1},  # bare proxy reply, no result/error
    })
    single = retry({"result": TX_HASH})
    manager = make_manager(["http://a", "http://b", "http://c"])

    res = await manager.broadcast_raw_transaction(RAW_TX)

    assert res == {"result": TX_HASH}
    assert single.calls == [
        (["http://a", "http://b", "http://c"], "eth_sendRawTransaction", [RAW_TX])
    ]


@pytest.mark.asyncio
async def test_first_accept_returns_without_waiting_for_hanging_node(no_retry, retry):
    # Default 10 s per-node timeout left in place on purpose: the accept
    # from node b must come back long before node a would time out.
    fan = no_retry({
        "http://a": "hang",
        "http://b": {"result": TX_HASH},
    })
    retry({"result": "unused"})
    manager = make_manager(["http://a", "http://b"])

    res = await asyncio.wait_for(manager.broadcast_raw_transaction(RAW_TX), timeout=1)

    assert res == {"result": TX_HASH}
    # The slow send was not cancelled: it is still in flight, supervised.
    assert len(manager._broadcast_tasks) == 1
    straggler = next(iter(manager._broadcast_tasks))
    assert not straggler.done()
    assert sorted(c[0] for c in fan.calls) == ["http://a", "http://b"]
    await drain(manager)
    assert manager._broadcast_tasks == set()


@pytest.mark.asyncio
async def test_cancelling_broadcast_cancels_in_flight_sends(no_retry, retry):
    # Nothing has answered yet when the caller is cancelled: every
    # per-node send must be cancelled too, not left running unsupervised.
    fan = no_retry({
        "http://a": "hang",
        "http://b": "hang",
    })
    retry({"result": "unused"})
    manager = make_manager(["http://a", "http://b"])

    broadcast = asyncio.create_task(manager.broadcast_raw_transaction(RAW_TX))

    # Let the fan-out start and park on asyncio.wait. Bounded so a
    # missing send fails the test promptly instead of spinning forever.
    async def both_sends_started() -> None:
        while len(fan.calls) < 2:
            await asyncio.sleep(0)

    await asyncio.wait_for(both_sends_started(), timeout=1)
    await asyncio.sleep(0)

    broadcast.cancel()
    with pytest.raises(asyncio.CancelledError):
        await broadcast

    # No orphaned sends: every task spawned by the fan-out is finished.
    leftovers = [
        t for t in asyncio.all_tasks()
        if t is not asyncio.current_task() and not t.done()
    ]
    assert leftovers == []
    assert manager._broadcast_tasks == set()


@pytest.mark.asyncio
async def test_straggler_is_dropped_from_supervision_when_it_finishes(no_retry, retry, monkeypatch):
    monkeypatch.setattr(bm, "BROADCAST_NODE_TIMEOUT_S", 0.05)
    no_retry({
        "http://a": "hang",
        "http://b": {"result": TX_HASH},
    })
    retry({"result": "unused"})
    manager = make_manager(["http://a", "http://b"])

    res = await manager.broadcast_raw_transaction(RAW_TX)
    assert res == {"result": TX_HASH}
    assert len(manager._broadcast_tasks) == 1

    # Let the straggler hit its timeout and run its done-callbacks.
    await asyncio.gather(*manager._broadcast_tasks)
    await asyncio.sleep(0)
    assert manager._broadcast_tasks == set()
