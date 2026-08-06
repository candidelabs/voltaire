"""
Tests for _find_handle_ops_calldata and _find_handle_ops_input_in_trace
in user_operation_handler.py.

Verifies that get_user_operation_by_hash correctly handles both direct
handleOps calls (EOA path) and indirect calls via a wrapping contract
(relayer, multicall, aggregator) by falling back to trace_transaction.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from voltaire_bundler.user_operation.user_operation_handler import (
    HANDLE_OPS_SELECTOR_V6,
    HANDLE_OPS_SELECTOR_V7V8V9,
    _find_handle_ops_input_in_trace,
    UserOperationHandler,
)


FAKE_TX_HASH = "0xabc123"
ENTRYPOINT_V6 = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"
ENTRYPOINT_V7 = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
ENTRYPOINT_V8 = "0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108"
ENTRYPOINT_V9 = "0x433709009B8330FDa32311DF1C2AFA402eD8D009"

FAKE_HANDLE_OPS_INPUT_V7 = (
    HANDLE_OPS_SELECTOR_V7V8V9 + "00" * 64
)
FAKE_HANDLE_OPS_INPUT_V6 = (
    HANDLE_OPS_SELECTOR_V6 + "00" * 64
)
WRAPPER_CONTRACT_INPUT = "0xdeadbeef" + "00" * 64


def _make_handler() -> UserOperationHandler:
    """Create a minimal UserOperationHandler for testing."""
    handler = MagicMock(spec=UserOperationHandler)
    handler.ethereum_node_urls = ["http://localhost:8545"]
    handler._find_handle_ops_calldata = (
        UserOperationHandler._find_handle_ops_calldata.__get__(
            handler, UserOperationHandler
        )
    )
    return handler


# ── _find_handle_ops_input_in_trace (pure function) ─────────


def test_trace_finds_matching_entry():
    """Should return input from the entry matching both selector
    and entrypoint."""
    trace = [
        {"action": {
            "to": "0xdeadbeef",
            "input": "0xdeadbeef" + "aa" * 32,
        }},
        {"action": {
            "to": ENTRYPOINT_V7,
            "input": FAKE_HANDLE_OPS_INPUT_V7,
        }},
    ]
    result = _find_handle_ops_input_in_trace(
        trace, HANDLE_OPS_SELECTOR_V7V8V9, ENTRYPOINT_V7
    )
    assert result == FAKE_HANDLE_OPS_INPUT_V7


def test_trace_finds_v6_selector():
    """Should match the v6 selector and entrypoint correctly."""
    trace = [
        {"action": {
            "to": ENTRYPOINT_V6,
            "input": FAKE_HANDLE_OPS_INPUT_V6,
        }},
    ]
    result = _find_handle_ops_input_in_trace(
        trace, HANDLE_OPS_SELECTOR_V6, ENTRYPOINT_V6
    )
    assert result == FAKE_HANDLE_OPS_INPUT_V6


def test_trace_returns_none_when_no_match():
    """Should return None when no entry matches the selector."""
    trace = [
        {"action": {
            "to": ENTRYPOINT_V7,
            "input": "0xdeadbeef" + "aa" * 32,
        }},
    ]
    result = _find_handle_ops_input_in_trace(
        trace, HANDLE_OPS_SELECTOR_V7V8V9, ENTRYPOINT_V7
    )
    assert result is None


def test_trace_returns_none_for_empty_list():
    """Should return None for an empty trace list."""
    assert _find_handle_ops_input_in_trace(
        [], HANDLE_OPS_SELECTOR_V7V8V9, ENTRYPOINT_V7
    ) is None


def test_trace_returns_none_for_non_list():
    """Should return None if trace is not a list."""
    assert _find_handle_ops_input_in_trace(
        {"some": "dict"}, HANDLE_OPS_SELECTOR_V7V8V9, ENTRYPOINT_V7
    ) is None


def test_trace_handles_missing_action_key():
    """Should skip entries without an action key."""
    trace = [
        {"result": {"gasUsed": "0x100"}},
        {"action": {
            "to": ENTRYPOINT_V7,
            "input": FAKE_HANDLE_OPS_INPUT_V7,
        }},
    ]
    result = _find_handle_ops_input_in_trace(
        trace, HANDLE_OPS_SELECTOR_V7V8V9, ENTRYPOINT_V7
    )
    assert result == FAKE_HANDLE_OPS_INPUT_V7


def test_trace_handles_missing_input_key():
    """Should skip entries whose action has no input field."""
    trace = [
        {"action": {"to": ENTRYPOINT_V7}},
        {"action": {
            "to": ENTRYPOINT_V7,
            "input": FAKE_HANDLE_OPS_INPUT_V7,
        }},
    ]
    result = _find_handle_ops_input_in_trace(
        trace, HANDLE_OPS_SELECTOR_V7V8V9, ENTRYPOINT_V7
    )
    assert result == FAKE_HANDLE_OPS_INPUT_V7


def test_trace_filters_by_entrypoint():
    """When multiple entries have the same selector but different
    entrypoints, should only match the requested entrypoint."""
    v8_input = HANDLE_OPS_SELECTOR_V7V8V9 + "aa" * 64
    v9_input = HANDLE_OPS_SELECTOR_V7V8V9 + "bb" * 64
    trace = [
        {"action": {
            "to": ENTRYPOINT_V8,
            "input": v8_input,
        }},
        {"action": {
            "to": ENTRYPOINT_V9,
            "input": v9_input,
        }},
    ]
    # Asking for v9 should skip the v8 entry
    result = _find_handle_ops_input_in_trace(
        trace, HANDLE_OPS_SELECTOR_V7V8V9, ENTRYPOINT_V9
    )
    assert result == v9_input


def test_trace_entrypoint_match_is_case_insensitive():
    """Entrypoint comparison should be case-insensitive."""
    trace = [
        {"action": {
            "to": ENTRYPOINT_V7.lower(),
            "input": FAKE_HANDLE_OPS_INPUT_V7,
        }},
    ]
    result = _find_handle_ops_input_in_trace(
        trace, HANDLE_OPS_SELECTOR_V7V8V9, ENTRYPOINT_V7
    )
    assert result == FAKE_HANDLE_OPS_INPUT_V7


def test_trace_skips_selector_match_with_wrong_entrypoint():
    """Should return None when the selector matches but the
    entrypoint does not."""
    trace = [
        {"action": {
            "to": ENTRYPOINT_V8,
            "input": FAKE_HANDLE_OPS_INPUT_V7,
        }},
    ]
    result = _find_handle_ops_input_in_trace(
        trace, HANDLE_OPS_SELECTOR_V7V8V9, ENTRYPOINT_V9
    )
    assert result is None


# ── _find_handle_ops_calldata (async method) ────────────────


@pytest.mark.asyncio
async def test_fast_path_direct_match():
    """When tx input starts with the selector, should return it
    directly without calling trace_transaction."""
    handler = _make_handler()

    with patch(
        "voltaire_bundler.user_operation.user_operation_handler"
        ".send_rpc_request_to_eth_client",
        new_callable=AsyncMock,
    ) as mock_rpc:
        result = await handler._find_handle_ops_calldata(
            FAKE_TX_HASH,
            FAKE_HANDLE_OPS_INPUT_V7,
            HANDLE_OPS_SELECTOR_V7V8V9,
            ENTRYPOINT_V7,
        )

    assert result == FAKE_HANDLE_OPS_INPUT_V7
    mock_rpc.assert_not_called()


@pytest.mark.asyncio
async def test_fast_path_v6_selector():
    """Fast path should also work with the v6 selector."""
    handler = _make_handler()

    with patch(
        "voltaire_bundler.user_operation.user_operation_handler"
        ".send_rpc_request_to_eth_client",
        new_callable=AsyncMock,
    ) as mock_rpc:
        result = await handler._find_handle_ops_calldata(
            FAKE_TX_HASH,
            FAKE_HANDLE_OPS_INPUT_V6,
            HANDLE_OPS_SELECTOR_V6,
            ENTRYPOINT_V6,
        )

    assert result == FAKE_HANDLE_OPS_INPUT_V6
    mock_rpc.assert_not_called()


@pytest.mark.asyncio
async def test_fallback_traces_and_finds_handle_ops():
    """When tx input doesn't match, should call trace_transaction
    and extract handleOps calldata from the trace."""
    handler = _make_handler()

    trace_result = {
        "result": [
            {"action": {
                "to": "0xwrapper",
                "input": WRAPPER_CONTRACT_INPUT,
            }},
            {"action": {
                "to": ENTRYPOINT_V7,
                "input": FAKE_HANDLE_OPS_INPUT_V7,
            }},
        ]
    }

    with patch(
        "voltaire_bundler.user_operation.user_operation_handler"
        ".send_rpc_request_to_eth_client",
        new_callable=AsyncMock,
        return_value=trace_result,
    ) as mock_rpc:
        result = await handler._find_handle_ops_calldata(
            FAKE_TX_HASH,
            WRAPPER_CONTRACT_INPUT,
            HANDLE_OPS_SELECTOR_V7V8V9,
            ENTRYPOINT_V7,
        )

    assert result == FAKE_HANDLE_OPS_INPUT_V7
    mock_rpc.assert_called_once_with(
        handler.ethereum_node_urls,
        "trace_transaction",
        [FAKE_TX_HASH],
    )


@pytest.mark.asyncio
async def test_fallback_filters_by_entrypoint():
    """When trace has multiple handleOps calls to different
    entrypoints, should return the one matching the requested
    entrypoint."""
    handler = _make_handler()

    v8_input = HANDLE_OPS_SELECTOR_V7V8V9 + "aa" * 64
    v9_input = HANDLE_OPS_SELECTOR_V7V8V9 + "bb" * 64
    trace_result = {
        "result": [
            {"action": {
                "to": ENTRYPOINT_V8,
                "input": v8_input,
            }},
            {"action": {
                "to": ENTRYPOINT_V9,
                "input": v9_input,
            }},
        ]
    }

    with patch(
        "voltaire_bundler.user_operation.user_operation_handler"
        ".send_rpc_request_to_eth_client",
        new_callable=AsyncMock,
        return_value=trace_result,
    ):
        result = await handler._find_handle_ops_calldata(
            FAKE_TX_HASH,
            WRAPPER_CONTRACT_INPUT,
            HANDLE_OPS_SELECTOR_V7V8V9,
            ENTRYPOINT_V9,
        )

    assert result == v9_input


@pytest.mark.asyncio
async def test_fallback_raises_on_rpc_error():
    """Should raise ValueError when trace_transaction returns
    an error response."""
    handler = _make_handler()

    error_response = {
        "error": {"code": -32601, "message": "method not found"}
    }

    with patch(
        "voltaire_bundler.user_operation.user_operation_handler"
        ".send_rpc_request_to_eth_client",
        new_callable=AsyncMock,
        return_value=error_response,
    ):
        with pytest.raises(
            ValueError, match="trace_transaction failed"
        ):
            await handler._find_handle_ops_calldata(
                FAKE_TX_HASH,
                WRAPPER_CONTRACT_INPUT,
                HANDLE_OPS_SELECTOR_V7V8V9,
                ENTRYPOINT_V7,
            )


@pytest.mark.asyncio
async def test_fallback_raises_when_no_match_in_trace():
    """Should raise ValueError when trace has no call matching
    the handleOps selector for the given entrypoint."""
    handler = _make_handler()

    trace_result = {
        "result": [
            {"action": {
                "to": "0xdeadbeef",
                "input": "0xdeadbeef" + "aa" * 32,
            }},
        ]
    }

    with patch(
        "voltaire_bundler.user_operation.user_operation_handler"
        ".send_rpc_request_to_eth_client",
        new_callable=AsyncMock,
        return_value=trace_result,
    ):
        with pytest.raises(
            ValueError, match="No internal call with selector"
        ):
            await handler._find_handle_ops_calldata(
                FAKE_TX_HASH,
                WRAPPER_CONTRACT_INPUT,
                HANDLE_OPS_SELECTOR_V7V8V9,
                ENTRYPOINT_V7,
            )


@pytest.mark.asyncio
async def test_fallback_raises_on_empty_trace():
    """Should raise ValueError when trace result is an empty list."""
    handler = _make_handler()

    with patch(
        "voltaire_bundler.user_operation.user_operation_handler"
        ".send_rpc_request_to_eth_client",
        new_callable=AsyncMock,
        return_value={"result": []},
    ):
        with pytest.raises(
            ValueError, match="No internal call with selector"
        ):
            await handler._find_handle_ops_calldata(
                FAKE_TX_HASH,
                WRAPPER_CONTRACT_INPUT,
                HANDLE_OPS_SELECTOR_V7V8V9,
                ENTRYPOINT_V7,
            )
