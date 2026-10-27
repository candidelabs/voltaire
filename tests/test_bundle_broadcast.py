"""Behaviour tests for BundlerManager.broadcast_raw_transaction.

The fan-out sends one signed bundle tx to every bundle node in parallel
and folds the answers into a single JSON-RPC-shaped result for
send_bundle. These pin the precedence rules:

- any node returning a hash wins, even if the primary said "already known"
- a stuck error is surfaced only when no node accepted the tx fresh
- a non-stuck RPC error from one node does not mask a stuck signal from
  another (a permanently broken secondary must not starve the fee bump)
- with no usable answer from any node, fall back to the retrying call
- a single configured node never fans out
"""
from __future__ import annotations

import asyncio

import pytest

import voltaire_bundler.bundle.bundle_manager as bm
from voltaire_bundler.bundle.bundle_manager import (
    BundlerManager,
    _is_tx_pool_stuck_error,
)

RAW_TX = "0xdeadbeef"
TX_HASH = "0x" + "11" * 32
ALREADY_KNOWN = {"code": -32000, "message": "already known"}
UNDERPRICED = {"code": -32000, "message": "replacement transaction underpriced"}
FREE_PLAN = {"code": 35, "message": "chain is not available on free plan"}


def make_manager(nodes: list[str]) -> BundlerManager:
    # Bypass __init__: the fan-out only reads bundle_node_urls.
    manager = BundlerManager.__new__(BundlerManager)
    manager.bundle_node_urls = nodes
    return manager


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

    assert res == {"error": ALREADY_KNOWN}
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
async def test_non_stuck_error_surfaces_when_nothing_else(no_retry, retry):
    invalid = {"code": -32000, "message": "invalid sender"}
    no_retry({
        "http://a": {"error": invalid},
        "http://b": ConnectionError("refused"),
    })
    retry({"result": "unused"})
    manager = make_manager(["http://a", "http://b"])

    res = await manager.broadcast_raw_transaction(RAW_TX)

    assert res == {"error": invalid}


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
async def test_hanging_node_does_not_block_accept_from_other(no_retry, retry, monkeypatch):
    monkeypatch.setattr(bm, "BROADCAST_NODE_TIMEOUT_S", 0.05)
    no_retry({
        "http://a": "hang",
        "http://b": {"result": TX_HASH},
    })
    retry({"result": "unused"})
    manager = make_manager(["http://a", "http://b"])

    res = await asyncio.wait_for(manager.broadcast_raw_transaction(RAW_TX), timeout=2)

    assert res == {"result": TX_HASH}
