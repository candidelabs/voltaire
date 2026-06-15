"""
Tests for the centralized receipt fast path inside
``get_user_operation_logs_for_block_range``.

When the bundler submitted the bundle holding the userop, the registry
has the tx hash. The gate pulls the receipt, finds every
``UserOperationEvent`` at the queried entrypoint, caches each in the
userop-logs cache (so peers in the same bundle become instant cache
hits on their next poll), and returns the queried userop's single-log
list. On any miss it returns ``None`` so the eth_getLogs cascade runs.
"""

from unittest.mock import AsyncMock

import pytest

import voltaire_bundler.user_operation.user_operation_handler as handler_mod
from voltaire_bundler.user_operation.user_operation_handler import (
    USER_OPERATION_EVENT_DESCRIPTOR,
    _bundle_tx_hash_registry,
    forget_bundle_tx_hash,
    get_bundle_tx_hash,
    get_user_operation_logs_for_block_range,
    record_bundle_tx_hash,
    set_receipt_fast_path_disabled,
    user_operation_logs_cache,
)


ENTRYPOINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
OP_HASH_A = "0x" + "aa" * 32
OP_HASH_B = "0x" + "bb" * 32
OP_HASH_C = "0x" + "cc" * 32
TX_HASH = "0x" + "ef" * 32

EVENT_DATA = (
    "0x"
    + "00" * 31 + "07"
    + "00" * 31 + "01"
    + "00" * 30 + "1234"
    + "00" * 30 + "5678"
)


def _event_log(
    userop_hash: str,
    *,
    entrypoint: str = ENTRYPOINT,
    tx_hash: str = TX_HASH,
) -> dict:
    return {
        "removed": False,
        "logIndex": "0x1",
        "transactionIndex": "0x0",
        "transactionHash": tx_hash,
        "blockHash": "0x" + "bb" * 32,
        "blockNumber": "0x42",
        "address": entrypoint,
        "data": EVENT_DATA,
        "topics": [
            USER_OPERATION_EVENT_DESCRIPTOR,
            userop_hash,
            "0x" + "00" * 12 + "11" * 20,
            "0x" + "00" * 12 + "22" * 20,
        ],
    }


@pytest.fixture(autouse=True)
def _reset_module_state():
    set_receipt_fast_path_disabled(False)
    _bundle_tx_hash_registry.clear()
    yield
    _bundle_tx_hash_registry.clear()
    set_receipt_fast_path_disabled(False)


@pytest.fixture
def patched_rpc(monkeypatch):
    """Replace external RPC and cache I/O with controllable mocks. Returns
    a holder so each test can inspect calls and override return values."""

    class _Holder:
        def __init__(self):
            self.receipts: dict[str, dict | None] = {}
            self.fetch_receipt_calls: list[str] = []
            self.eth_getlogs_calls: list = []
            self.cache_get: dict[str, list] = {}
            self.cache_set: dict[str, list] = {}
            self.cache_deleted: list[str] = []

    holder = _Holder()

    async def _fetch_receipt(_urls, tx_hash):
        holder.fetch_receipt_calls.append(tx_hash)
        return holder.receipts.get(tx_hash)

    async def _eth_getlogs_once(_urls, op_hash, _ep, _from, _to):
        holder.eth_getlogs_calls.append(op_hash)
        return None

    async def _cache_get(key):
        return holder.cache_get.get(key)

    def _cache_set(key, value):
        holder.cache_set[key] = value

    def _cache_delete(key):
        holder.cache_deleted.append(key)

    monkeypatch.setattr(handler_mod, "fetch_transaction_receipt", _fetch_receipt)
    monkeypatch.setattr(handler_mod, "_eth_getLogs_once", _eth_getlogs_once)
    monkeypatch.setattr(user_operation_logs_cache, "get", _cache_get)
    monkeypatch.setattr(user_operation_logs_cache, "set", _cache_set)
    monkeypatch.setattr(user_operation_logs_cache, "delete", _cache_delete)

    # Bypass the recent-block fallback probe so eth_getLogs path is a
    # single deterministic call.
    monkeypatch.setattr(
        handler_mod, "_fetch_latest_block_number",
        AsyncMock(return_value=None),
    )
    # Don't re-validate cached entries against the chain in tests.
    monkeypatch.setattr(
        handler_mod, "_cached_logs_block_still_canonical",
        AsyncMock(return_value=True),
    )
    return holder


@pytest.mark.asyncio
async def test_returns_matching_log_when_receipt_carries_event(patched_rpc):
    patched_rpc.receipts[TX_HASH] = {"logs": [_event_log(OP_HASH_A)]}
    record_bundle_tx_hash(OP_HASH_A, TX_HASH)

    result = await get_user_operation_logs_for_block_range(
        ["http://node"], OP_HASH_A, ENTRYPOINT, "0x0", "latest",
    )

    assert result == [_event_log(OP_HASH_A)]
    assert patched_rpc.fetch_receipt_calls == [TX_HASH]
    assert patched_rpc.eth_getlogs_calls == []
    # Registry entry dropped after confirmed hit.
    assert get_bundle_tx_hash(OP_HASH_A) is None
    # Cache primed for the queried userop.
    assert f"{ENTRYPOINT.lower()}:{OP_HASH_A}" in patched_rpc.cache_set


@pytest.mark.asyncio
async def test_multi_userop_receipt_primes_cache_for_every_event(patched_rpc):
    """A receipt with events for A, B, C (all bundled together) → one
    receipt fetch caches log lists for all three under their own keys
    and drops all three registry entries, so later calls for B and C
    never need a receipt or eth_getLogs."""
    patched_rpc.receipts[TX_HASH] = {"logs": [
        _event_log(OP_HASH_A),
        _event_log(OP_HASH_B),
        _event_log(OP_HASH_C),
    ]}
    record_bundle_tx_hash(OP_HASH_A, TX_HASH)
    record_bundle_tx_hash(OP_HASH_B, TX_HASH)
    record_bundle_tx_hash(OP_HASH_C, TX_HASH)

    # Query A — should resolve A *and* prime B and C.
    result = await get_user_operation_logs_for_block_range(
        ["http://node"], OP_HASH_A, ENTRYPOINT, "0x0", "latest",
    )

    assert result is not None
    assert patched_rpc.fetch_receipt_calls == [TX_HASH]
    assert patched_rpc.eth_getlogs_calls == []
    ep = ENTRYPOINT.lower()
    # All three userops are now in the userop-logs cache.
    assert f"{ep}:{OP_HASH_A}" in patched_rpc.cache_set
    assert f"{ep}:{OP_HASH_B}" in patched_rpc.cache_set
    assert f"{ep}:{OP_HASH_C}" in patched_rpc.cache_set
    # Each cached entry is the single matching log.
    assert patched_rpc.cache_set[f"{ep}:{OP_HASH_B}"] == [
        _event_log(OP_HASH_B),
    ]
    # Registry drained for all three.
    assert get_bundle_tx_hash(OP_HASH_A) is None
    assert get_bundle_tx_hash(OP_HASH_B) is None
    assert get_bundle_tx_hash(OP_HASH_C) is None


@pytest.mark.asyncio
async def test_falls_back_to_eth_getlogs_when_no_registered_tx(patched_rpc):
    result = await get_user_operation_logs_for_block_range(
        ["http://node"], OP_HASH_A, ENTRYPOINT, "0x0", "latest",
    )
    assert result is None
    assert patched_rpc.fetch_receipt_calls == []
    # Single eth_getLogs call from the non-"earliest" branch.
    assert patched_rpc.eth_getlogs_calls == [OP_HASH_A]


@pytest.mark.asyncio
async def test_falls_back_when_receipt_pending(patched_rpc):
    patched_rpc.receipts[TX_HASH] = None
    record_bundle_tx_hash(OP_HASH_A, TX_HASH)

    result = await get_user_operation_logs_for_block_range(
        ["http://node"], OP_HASH_A, ENTRYPOINT, "0x0", "latest",
    )
    assert result is None
    assert patched_rpc.fetch_receipt_calls == [TX_HASH]
    assert patched_rpc.eth_getlogs_calls == [OP_HASH_A]
    # Registry entry kept since the fast path didn't resolve.
    assert get_bundle_tx_hash(OP_HASH_A) == TX_HASH


@pytest.mark.asyncio
async def test_falls_back_when_receipt_has_no_matching_event(patched_rpc):
    """Receipt is for a tx that bundled some other userop. Fast path
    can't resolve the queried op, so eth_getLogs runs."""
    patched_rpc.receipts[TX_HASH] = {"logs": [_event_log(OP_HASH_B)]}
    record_bundle_tx_hash(OP_HASH_A, TX_HASH)

    result = await get_user_operation_logs_for_block_range(
        ["http://node"], OP_HASH_A, ENTRYPOINT, "0x0", "latest",
    )
    assert result is None
    assert patched_rpc.eth_getlogs_calls == [OP_HASH_A]
    # The unrelated userop B *was* primed in the cache as a side effect
    # — receipt fetches aren't free, so reuse what we have.
    assert f"{ENTRYPOINT.lower()}:{OP_HASH_B}" in patched_rpc.cache_set


@pytest.mark.asyncio
async def test_filters_events_by_entrypoint(patched_rpc):
    """A UserOperationEvent at a different entrypoint must not satisfy
    this entrypoint's query."""
    other_ep = "0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108"
    patched_rpc.receipts[TX_HASH] = {"logs": [
        _event_log(OP_HASH_A, entrypoint=other_ep),
    ]}
    record_bundle_tx_hash(OP_HASH_A, TX_HASH)

    result = await get_user_operation_logs_for_block_range(
        ["http://node"], OP_HASH_A, ENTRYPOINT, "0x0", "latest",
    )
    assert result is None
    assert patched_rpc.eth_getlogs_calls == [OP_HASH_A]


@pytest.mark.asyncio
async def test_disable_flag_skips_fast_path(patched_rpc):
    set_receipt_fast_path_disabled(True)
    patched_rpc.receipts[TX_HASH] = {"logs": [_event_log(OP_HASH_A)]}
    record_bundle_tx_hash(OP_HASH_A, TX_HASH)

    result = await get_user_operation_logs_for_block_range(
        ["http://node"], OP_HASH_A, ENTRYPOINT, "0x0", "latest",
    )
    assert result is None
    assert patched_rpc.fetch_receipt_calls == []
    assert patched_rpc.eth_getlogs_calls == [OP_HASH_A]
    # Registry untouched.
    assert get_bundle_tx_hash(OP_HASH_A) == TX_HASH


@pytest.mark.asyncio
async def test_user_logs_cache_hit_short_circuits_before_fast_path(patched_rpc):
    """If the userop-logs cache already has a fresh entry, return it
    without bothering the receipt path."""
    cached_logs = [_event_log(OP_HASH_A)]
    patched_rpc.cache_get[f"{ENTRYPOINT.lower()}:{OP_HASH_A}"] = cached_logs
    record_bundle_tx_hash(OP_HASH_A, TX_HASH)

    result = await get_user_operation_logs_for_block_range(
        ["http://node"], OP_HASH_A, ENTRYPOINT, "0x0", "latest",
    )

    assert result == cached_logs
    assert patched_rpc.fetch_receipt_calls == []
    assert patched_rpc.eth_getlogs_calls == []


def test_registry_record_and_forget_roundtrip():
    record_bundle_tx_hash(OP_HASH_A, TX_HASH)
    assert get_bundle_tx_hash(OP_HASH_A) == TX_HASH
    forget_bundle_tx_hash(OP_HASH_A)
    assert get_bundle_tx_hash(OP_HASH_A) is None


def test_registry_fifo_cap_evicts_oldest():
    from voltaire_bundler.user_operation.user_operation_handler import (
        _BUNDLE_TX_HASH_REGISTRY_MAX,
    )
    first = "0x" + "00" * 32
    record_bundle_tx_hash(first, "0x" + "01" * 32)
    for i in range(_BUNDLE_TX_HASH_REGISTRY_MAX):
        record_bundle_tx_hash("0x" + format(i + 1, "064x"), TX_HASH)
    assert get_bundle_tx_hash(first) is None
    assert get_bundle_tx_hash(
        "0x" + format(_BUNDLE_TX_HASH_REGISTRY_MAX, "064x"),
    ) == TX_HASH
