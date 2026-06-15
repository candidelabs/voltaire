"""
Tests for the eth_getTransactionReceipt fast path in
``UserOperationHandler.get_user_operation_event_log_info``.

When the bundler submitted the bundle holding the userop, the registry
has the tx hash. The fast path pulls the receipt and decodes the
matching ``UserOperationEvent`` directly — no eth_getLogs round trip.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from voltaire_bundler.user_operation.user_operation_handler import (
    USER_OPERATION_EVENT_DESCRIPTOR,
    UserOperationHandler,
    _bundle_tx_hash_registry,
    forget_bundle_tx_hash,
    record_bundle_tx_hash,
)


ENTRYPOINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
USEROP_HASH = "0x" + "ab" * 32
TX_HASH = "0x" + "ef" * 32

# Test sender / paymaster as 32-byte topic-padded values.
SENDER_ADDR = "0x" + "11" * 20
PAYMASTER_ADDR = "0x" + "22" * 20
SENDER_TOPIC = "0x" + "00" * 12 + "11" * 20
PAYMASTER_TOPIC = "0x" + "00" * 12 + "22" * 20

# UserOperationEvent data: (uint256 nonce, bool success, uint256 actualGasCost,
# uint256 actualGasUsed) ABI-encoded. Encoded by hand for a deterministic
# fixture: nonce=7, success=True, cost=0x1234, used=0x5678.
EVENT_DATA = (
    "0x"
    + "00" * 31 + "07"   # nonce = 7
    + "00" * 31 + "01"   # success = True
    + "00" * 30 + "1234"  # actualGasCost = 0x1234
    + "00" * 30 + "5678"  # actualGasUsed = 0x5678
)


def _bind(handler, name):
    method = getattr(UserOperationHandler, name)
    setattr(handler, name, method.__get__(handler, UserOperationHandler))


def _make_handler(*, disable_fast_path=False):
    handler = MagicMock(spec=UserOperationHandler)
    handler.disable_receipt_fast_path = disable_fast_path
    handler.logs_incremental_range = 0
    handler.logs_number_of_ranges = 0
    handler.get_transaction_receipt = AsyncMock(return_value=None)
    handler.get_user_operation_logs = AsyncMock(return_value=None)
    _bind(handler, "get_user_operation_event_log_info")
    _bind(handler, "_try_event_log_info_via_known_tx")
    return handler


def _matching_log():
    return {
        "removed": False,
        "logIndex": "0x1",
        "transactionIndex": "0x0",
        "transactionHash": TX_HASH,
        "blockHash": "0x" + "bb" * 32,
        "blockNumber": "0x42",
        "address": ENTRYPOINT,
        "data": EVENT_DATA,
        "topics": [
            USER_OPERATION_EVENT_DESCRIPTOR,
            USEROP_HASH,
            SENDER_TOPIC,
            PAYMASTER_TOPIC,
        ],
    }


@pytest.fixture(autouse=True)
def _clear_registry():
    _bundle_tx_hash_registry.clear()
    yield
    _bundle_tx_hash_registry.clear()


@pytest.mark.asyncio
async def test_fast_path_returns_decoded_tuple_when_receipt_has_event():
    from voltaire_bundler.user_operation.user_operation_handler import (
        get_bundle_tx_hash,
    )
    handler = _make_handler()
    handler.get_transaction_receipt.return_value = {
        "logs": [_matching_log()],
    }
    record_bundle_tx_hash(USEROP_HASH, TX_HASH)

    result = await handler.get_user_operation_event_log_info(
        USEROP_HASH, ENTRYPOINT, None,
    )

    handler.get_transaction_receipt.assert_awaited_once_with(TX_HASH)
    handler.get_user_operation_logs.assert_not_called()
    assert result is not None
    (
        log_object, userOpHash, sender, paymaster,
        nonce, success, actualGasCost, actualGasUsed, logs,
    ) = result
    assert userOpHash == USEROP_HASH
    assert sender == SENDER_ADDR
    assert paymaster == PAYMASTER_ADDR
    assert nonce == 7
    assert success is True
    assert actualGasCost == hex(0x1234)
    assert actualGasUsed == hex(0x5678)
    assert log_object.transactionHash == TX_HASH
    # Registry entry was dropped after a confirmed hit, so a second
    # poll falls through to eth_getLogs instead of re-fetching the receipt.
    assert get_bundle_tx_hash(USEROP_HASH) is None


@pytest.mark.asyncio
async def test_fast_path_falls_through_when_no_registered_tx_hash():
    handler = _make_handler()
    # No record_bundle_tx_hash call.
    result = await handler.get_user_operation_event_log_info(
        USEROP_HASH, ENTRYPOINT, None,
    )
    handler.get_transaction_receipt.assert_not_called()
    handler.get_user_operation_logs.assert_awaited_once()
    assert result is None


@pytest.mark.asyncio
async def test_fast_path_falls_through_when_receipt_not_ready():
    handler = _make_handler()
    handler.get_transaction_receipt.return_value = None  # pending
    record_bundle_tx_hash(USEROP_HASH, TX_HASH)

    result = await handler.get_user_operation_event_log_info(
        USEROP_HASH, ENTRYPOINT, None,
    )
    handler.get_transaction_receipt.assert_awaited_once_with(TX_HASH)
    handler.get_user_operation_logs.assert_awaited_once()
    assert result is None


@pytest.mark.asyncio
async def test_fast_path_falls_through_when_receipt_missing_event():
    handler = _make_handler()
    # Receipt is for a different userop — same bundle topic but other hash.
    other_log = _matching_log()
    other_log["topics"] = list(other_log["topics"])
    other_log["topics"][1] = "0x" + "ff" * 32
    handler.get_transaction_receipt.return_value = {"logs": [other_log]}
    record_bundle_tx_hash(USEROP_HASH, TX_HASH)

    result = await handler.get_user_operation_event_log_info(
        USEROP_HASH, ENTRYPOINT, None,
    )
    handler.get_transaction_receipt.assert_awaited_once_with(TX_HASH)
    handler.get_user_operation_logs.assert_awaited_once()
    assert result is None


@pytest.mark.asyncio
async def test_fast_path_filters_by_entrypoint_address():
    handler = _make_handler()
    other_log = _matching_log()
    other_log["address"] = "0x" + "00" * 20  # wrong entrypoint
    handler.get_transaction_receipt.return_value = {"logs": [other_log]}
    record_bundle_tx_hash(USEROP_HASH, TX_HASH)

    result = await handler.get_user_operation_event_log_info(
        USEROP_HASH, ENTRYPOINT, None,
    )
    handler.get_user_operation_logs.assert_awaited_once()
    assert result is None


@pytest.mark.asyncio
async def test_fast_path_disabled_flag_skips_entirely():
    handler = _make_handler(disable_fast_path=True)
    handler.get_transaction_receipt.return_value = {
        "logs": [_matching_log()],
    }
    record_bundle_tx_hash(USEROP_HASH, TX_HASH)

    result = await handler.get_user_operation_event_log_info(
        USEROP_HASH, ENTRYPOINT, None,
    )
    handler.get_transaction_receipt.assert_not_called()
    handler.get_user_operation_logs.assert_awaited_once()
    assert result is None


def test_registry_record_and_forget_roundtrip():
    from voltaire_bundler.user_operation.user_operation_handler import (
        get_bundle_tx_hash,
    )
    record_bundle_tx_hash(USEROP_HASH, TX_HASH)
    assert get_bundle_tx_hash(USEROP_HASH) == TX_HASH
    forget_bundle_tx_hash(USEROP_HASH)
    assert get_bundle_tx_hash(USEROP_HASH) is None


def test_registry_fifo_cap_evicts_oldest():
    from voltaire_bundler.user_operation.user_operation_handler import (
        _BUNDLE_TX_HASH_REGISTRY_MAX,
        get_bundle_tx_hash,
    )
    first = "0x" + "00" * 32
    record_bundle_tx_hash(first, "0x" + "01" * 32)
    for i in range(_BUNDLE_TX_HASH_REGISTRY_MAX):
        record_bundle_tx_hash("0x" + format(i + 1, "064x"), TX_HASH)
    # First entry should have been evicted to make room.
    assert get_bundle_tx_hash(first) is None
    # Latest entry should still be present.
    assert get_bundle_tx_hash(
        "0x" + format(_BUNDLE_TX_HASH_REGISTRY_MAX, "064x"),
    ) == TX_HASH
