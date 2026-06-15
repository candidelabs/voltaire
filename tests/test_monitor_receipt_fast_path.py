"""
Tests for the eth_getTransactionReceipt fast path in
``BundlerManager.remove_included_and_readd_to_mempool_userops_monitoring``.

The monitor used to fire one eth_getLogs per monitored userop per
bundle interval. With the fast path, ops are grouped by their submit-
time tx hash, one receipt resolves every op in the same bundle, and
eth_getLogs only runs for ops the receipt can't confirm (pending
receipt, replaced tx, peer-bundled tx).
"""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from voltaire_bundler.bundle.bundle_manager import BundlerManager
from voltaire_bundler.user_operation.user_operation_handler import (
    USER_OPERATION_EVENT_DESCRIPTOR,
    _bundle_tx_hash_registry,
)


ENTRYPOINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
OP_HASH_A = "0x" + "aa" * 32
OP_HASH_B = "0x" + "bb" * 32
OP_HASH_C = "0x" + "cc" * 32
TX_HASH_1 = "0x" + "11" * 32
TX_HASH_2 = "0x" + "22" * 32


def _event_log(userop_hash: str, *, entrypoint: str = ENTRYPOINT) -> dict:
    return {
        "address": entrypoint,
        "topics": [
            USER_OPERATION_EVENT_DESCRIPTOR,
            userop_hash,
            "0x" + "00" * 32,
            "0x" + "00" * 32,
        ],
    }


def _make_op(
    *, user_operation_hash: str, attempted_tx: str | None,
    validated_block: str = "0x10",
) -> MagicMock:
    op = MagicMock()
    op.user_operation_hash = user_operation_hash
    op.attempted_bundle_transaction_hash = attempted_tx
    op.validated_at_block_hex = validated_block
    op.last_add_to_mempool_date = datetime.now()
    op.number_of_add_to_mempool_attempts = 1
    return op


def _make_manager_and_locals(
    *,
    disable_receipt_fast_path: bool = False,
    receipts: dict[str, dict | None] | None = None,
):
    manager = MagicMock(spec=BundlerManager)
    manager.ethereum_node_urls = ["http://node"]
    # Bind the real method.
    manager.remove_included_and_readd_to_mempool_userops_monitoring = (
        BundlerManager.remove_included_and_readd_to_mempool_userops_monitoring.__get__(
            manager, BundlerManager,
        )
    )

    handler = MagicMock()
    handler.disable_receipt_fast_path = disable_receipt_fast_path
    handler.get_transaction_receipt = AsyncMock(
        side_effect=lambda tx: (receipts or {}).get(tx),
    )

    mempool = MagicMock()
    mempool.user_operation_handler = handler
    mempool.add_user_operation = AsyncMock()
    return manager, mempool, handler


@pytest.fixture(autouse=True)
def _clear_registry():
    _bundle_tx_hash_registry.clear()
    yield
    _bundle_tx_hash_registry.clear()


@pytest.mark.asyncio
async def test_one_receipt_resolves_multiple_ops_in_same_bundle(monkeypatch):
    """Three monitored ops, all bundled into TX_HASH_1 → one receipt
    call, zero eth_getLogs calls, all three evicted from monitoring."""
    receipt = {"logs": [
        _event_log(OP_HASH_A),
        _event_log(OP_HASH_B),
        _event_log(OP_HASH_C),
    ]}
    manager, mempool, handler = _make_manager_and_locals(
        receipts={TX_HASH_1: receipt},
    )

    eth_getlogs_calls: list = []

    async def _spy_logs(*args, **kwargs):
        eth_getlogs_calls.append(args)
        return None

    monkeypatch.setattr(
        "voltaire_bundler.bundle.bundle_manager."
        "get_user_operation_logs_for_block_range",
        _spy_logs,
    )
    monkeypatch.setattr(
        "voltaire_bundler.bundle.bundle_manager._warm_inclusion_caches",
        AsyncMock(),
    )

    ops_to_monitor = {
        OP_HASH_A: _make_op(
            user_operation_hash=OP_HASH_A, attempted_tx=TX_HASH_1),
        OP_HASH_B: _make_op(
            user_operation_hash=OP_HASH_B, attempted_tx=TX_HASH_1),
        OP_HASH_C: _make_op(
            user_operation_hash=OP_HASH_C, attempted_tx=TX_HASH_1),
    }

    await manager.remove_included_and_readd_to_mempool_userops_monitoring(
        ops_to_monitor, ENTRYPOINT, mempool,
    )

    handler.get_transaction_receipt.assert_awaited_once_with(TX_HASH_1)
    assert eth_getlogs_calls == []
    assert ops_to_monitor == {}


@pytest.mark.asyncio
async def test_falls_back_to_eth_getlogs_when_receipt_missing_event(monkeypatch):
    """Receipt exists but has no event for this op (replacement tx /
    peer-bundled) → eth_getLogs runs as the fallback."""
    # Receipt with an event for some unrelated op.
    receipt = {"logs": [_event_log("0x" + "de" * 32)]}
    manager, mempool, handler = _make_manager_and_locals(
        receipts={TX_HASH_1: receipt},
    )

    logs_calls: list = []

    async def _spy_logs(*args, **kwargs):
        logs_calls.append(args[1])  # user_operation_hash
        return None

    monkeypatch.setattr(
        "voltaire_bundler.bundle.bundle_manager."
        "get_user_operation_logs_for_block_range",
        _spy_logs,
    )
    monkeypatch.setattr(
        "voltaire_bundler.bundle.bundle_manager._warm_inclusion_caches",
        AsyncMock(),
    )

    ops_to_monitor = {
        OP_HASH_A: _make_op(
            user_operation_hash=OP_HASH_A, attempted_tx=TX_HASH_1),
    }

    await manager.remove_included_and_readd_to_mempool_userops_monitoring(
        ops_to_monitor, ENTRYPOINT, mempool,
    )

    handler.get_transaction_receipt.assert_awaited_once_with(TX_HASH_1)
    assert logs_calls == [OP_HASH_A]


@pytest.mark.asyncio
async def test_falls_back_when_receipt_pending(monkeypatch):
    """Receipt returns None (pending) → eth_getLogs runs."""
    manager, mempool, handler = _make_manager_and_locals(
        receipts={TX_HASH_1: None},
    )
    logs_calls: list = []

    async def _spy_logs(*args, **kwargs):
        logs_calls.append(args[1])
        return None

    monkeypatch.setattr(
        "voltaire_bundler.bundle.bundle_manager."
        "get_user_operation_logs_for_block_range",
        _spy_logs,
    )
    monkeypatch.setattr(
        "voltaire_bundler.bundle.bundle_manager._warm_inclusion_caches",
        AsyncMock(),
    )

    ops_to_monitor = {
        OP_HASH_A: _make_op(
            user_operation_hash=OP_HASH_A, attempted_tx=TX_HASH_1),
    }

    await manager.remove_included_and_readd_to_mempool_userops_monitoring(
        ops_to_monitor, ENTRYPOINT, mempool,
    )

    assert logs_calls == [OP_HASH_A]


@pytest.mark.asyncio
async def test_ops_without_attempted_tx_hash_use_eth_getlogs(monkeypatch):
    """An op with no attempted_bundle_transaction_hash skips the fast
    path entirely and goes straight to eth_getLogs."""
    manager, mempool, handler = _make_manager_and_locals(receipts={})
    logs_calls: list = []

    async def _spy_logs(*args, **kwargs):
        logs_calls.append(args[1])
        return None

    monkeypatch.setattr(
        "voltaire_bundler.bundle.bundle_manager."
        "get_user_operation_logs_for_block_range",
        _spy_logs,
    )
    monkeypatch.setattr(
        "voltaire_bundler.bundle.bundle_manager._warm_inclusion_caches",
        AsyncMock(),
    )

    ops_to_monitor = {
        OP_HASH_A: _make_op(
            user_operation_hash=OP_HASH_A, attempted_tx=None),
    }

    await manager.remove_included_and_readd_to_mempool_userops_monitoring(
        ops_to_monitor, ENTRYPOINT, mempool,
    )

    handler.get_transaction_receipt.assert_not_called()
    assert logs_calls == [OP_HASH_A]


@pytest.mark.asyncio
async def test_disable_flag_skips_fast_path_entirely(monkeypatch):
    """``--disable_receipt_fast_path`` forces every op back to the
    legacy eth_getLogs path, even when a known tx hash exists."""
    receipt = {"logs": [_event_log(OP_HASH_A)]}
    manager, mempool, handler = _make_manager_and_locals(
        disable_receipt_fast_path=True,
        receipts={TX_HASH_1: receipt},
    )
    logs_calls: list = []

    async def _spy_logs(*args, **kwargs):
        logs_calls.append(args[1])
        return None

    monkeypatch.setattr(
        "voltaire_bundler.bundle.bundle_manager."
        "get_user_operation_logs_for_block_range",
        _spy_logs,
    )
    monkeypatch.setattr(
        "voltaire_bundler.bundle.bundle_manager._warm_inclusion_caches",
        AsyncMock(),
    )

    ops_to_monitor = {
        OP_HASH_A: _make_op(
            user_operation_hash=OP_HASH_A, attempted_tx=TX_HASH_1),
    }

    await manager.remove_included_and_readd_to_mempool_userops_monitoring(
        ops_to_monitor, ENTRYPOINT, mempool,
    )

    handler.get_transaction_receipt.assert_not_called()
    assert logs_calls == [OP_HASH_A]


@pytest.mark.asyncio
async def test_mixed_bundles_fast_path_and_fallback(monkeypatch):
    """Two ops in TX_HASH_1 with a complete receipt; one op in TX_HASH_2
    with a pending receipt. Bundle 1 resolves via fast path with zero
    eth_getLogs; bundle 2's op falls back to eth_getLogs."""
    receipts = {
        TX_HASH_1: {"logs": [
            _event_log(OP_HASH_A), _event_log(OP_HASH_B),
        ]},
        TX_HASH_2: None,
    }
    manager, mempool, handler = _make_manager_and_locals(
        receipts=receipts,
    )
    logs_calls: list = []

    async def _spy_logs(*args, **kwargs):
        logs_calls.append(args[1])
        return None

    monkeypatch.setattr(
        "voltaire_bundler.bundle.bundle_manager."
        "get_user_operation_logs_for_block_range",
        _spy_logs,
    )
    monkeypatch.setattr(
        "voltaire_bundler.bundle.bundle_manager._warm_inclusion_caches",
        AsyncMock(),
    )

    ops_to_monitor = {
        OP_HASH_A: _make_op(
            user_operation_hash=OP_HASH_A, attempted_tx=TX_HASH_1),
        OP_HASH_B: _make_op(
            user_operation_hash=OP_HASH_B, attempted_tx=TX_HASH_1),
        OP_HASH_C: _make_op(
            user_operation_hash=OP_HASH_C, attempted_tx=TX_HASH_2),
    }

    await manager.remove_included_and_readd_to_mempool_userops_monitoring(
        ops_to_monitor, ENTRYPOINT, mempool,
    )

    # Each unique tx hash → one receipt call.
    assert handler.get_transaction_receipt.await_count == 2
    # Only OP_HASH_C (pending bundle) hit eth_getLogs.
    assert logs_calls == [OP_HASH_C]
    # A and B were evicted (fast path hit); C stayed (no inclusion).
    assert OP_HASH_A not in ops_to_monitor
    assert OP_HASH_B not in ops_to_monitor
    assert OP_HASH_C in ops_to_monitor
