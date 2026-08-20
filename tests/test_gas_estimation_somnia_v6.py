"""
Unit tests for the Somnia one-probe-per-eth_call callGasLimit estimation
on the v0.6 EntryPoint (GasManagerV6).

Lives at the tests/ top level (not tests/v6/) on purpose: tests/v6/conftest.py
autouses geth-docker + bundler fixtures for every module in that directory,
and these tests are pure mock-RPC unit tests.

The full behavioral suite lives in tests/v7/test_gas_estimation_iaccount_execute.py;
the shared driver is GasManager._estimate_call_gas_somnia. These tests cover
the GasManagerV6 wiring: its own Somnia gate, its simulateHandleOpMod selector
and v0.6 user-operation ABI, and the fallback to its in-contract search.
"""

import pytest
from unittest.mock import AsyncMock, patch
from eth_abi import decode, encode

from voltaire_bundler.user_operation.user_operation_v6 import UserOperationV6
from voltaire_bundler.gas.gas_manager_v6 import GasManagerV6
from voltaire_bundler.gas.gas_price_cache import GasPriceCache
from voltaire_bundler.bundle.exceptions import ExecutionException


ENTRYPOINT_V6 = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"
BUNDLER_ADDRESS = "0x0000000000000000000000000000000000000001"

USER_OP_ABI_TUPLE = (
    "(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,"
    "bytes,bytes)"
)
PROBE_ARGS_ABI_TUPLE = "(uint256,uint256,uint256,bool,bool)"

SOMNIA_MAX_CALL_DATA_GAS = 10_000_000
PINNED_BLOCK = "0x64"


def _make_user_operation() -> UserOperationV6:
    return UserOperationV6({
        "sender": "0x7e25461EEE6853f89e5bA2bDf87F47a8965EbE04",
        "nonce": "0x4a",
        "initCode": "0x",
        "callData": "0xb61d27f6" + "00" * 96,
        "callGasLimit": "0x0",
        "verificationGasLimit": "0x0",
        "preVerificationGas": "0x0",
        "maxFeePerGas": "0x0",
        "maxPriorityFeePerGas": "0x0",
        "paymasterAndData": "0x",
        "signature": "0x" + "00" * 65,
    })


def _make_gas_manager() -> GasManagerV6:
    return GasManagerV6(
        ethereum_node_urls=["http://localhost:8545"],
        chain_id=50312,  # Somnia testnet
        bundler_address=BUNDLER_ADDRESS,
        is_legacy_mode=False,
        max_verification_gas=10_000_000,
        max_call_data_gas=SOMNIA_MAX_CALL_DATA_GAS,
        gas_price_cache=GasPriceCache(
            ethereum_node_urls=["http://localhost:8545"],
            chain_id=50312,
            is_legacy_mode=False,
            refresh_interval_seconds=10.0,
        ),
    )


def _make_simulation_result_revert(
    verification_gas: int, call_gas_max: int, num_rounds: int
) -> dict:
    # SimulationResult(uint256,uint256,uint256) selector = 0xdeb13018
    encoded = encode(
        ["uint256", "uint256", "uint256"],
        [verification_gas, call_gas_max, num_rounds]
    )
    return {
        "error": {
            "message": "execution reverted",
            "data": "0xdeb13018" + encoded.hex()
        }
    }


def _make_estimate_revert_at_max(revert_data: bytes) -> dict:
    # EstimateCallGasRevertAtMax(bytes) selector = 0x59f233d2
    encoded = encode(["bytes"], [revert_data])
    return {
        "error": {
            "message": "execution reverted",
            "data": "0x59f233d2" + encoded.hex()
        }
    }


def _decode_probe_args(params) -> tuple:
    """(min_gas, max_gas, tolerance, is_continuation, is_check_once) out of
    a v0.6 simulateHandleOpMod eth_call payload."""
    data = params[0]["data"]
    decoded = decode(
        [USER_OP_ABI_TUPLE, PROBE_ARGS_ABI_TUPLE], bytes.fromhex(data[10:])
    )
    return decoded[1]


def _somnia_probe_responder(
    required_gas: int,
    gas_used: int,
    verification_gas: int,
    legacy_response: dict | None = None,
):
    async def responder(nodes_urls, method, params, *args):
        probe_args = _decode_probe_args(params)
        max_gas, is_check_once = probe_args[1], probe_args[4]
        if not is_check_once:
            assert legacy_response is not None, \
                "unexpected legacy (in-contract search) call"
            return legacy_response
        assert params[1] == PINNED_BLOCK
        if max_gas >= required_gas:
            return _make_simulation_result_revert(
                verification_gas, gas_used, 0
            )
        return _make_estimate_revert_at_max(b"")
    return responder


@pytest.mark.asyncio
async def test_somnia_v6_one_probe_estimation_returns_smallest_success():
    gas_manager = _make_gas_manager()
    user_op = _make_user_operation()

    with patch(
        "voltaire_bundler.gas.gas_manager.send_rpc_request_to_eth_client",
        new_callable=AsyncMock,
        return_value={"result": PINNED_BLOCK}
    ) as mock_block_number, patch(
        "voltaire_bundler.gas.gas_manager_v6.send_rpc_request_to_eth_client",
        new_callable=AsyncMock,
        side_effect=_somnia_probe_responder(
            required_gas=2_500_000,
            gas_used=2_000_000,
            verification_gas=120_000,
        )
    ) as mock_rpc:
        call_gas, verification_gas = (
            await gas_manager.estimate_call_gas_and_verificationgas_limit(
                user_op,
                ENTRYPOINT_V6,
                {},
                False,
            )
        )

        assert call_gas == 2_800_000
        assert verification_gas == 120_000
        mock_block_number.assert_called_once()
        assert mock_rpc.call_count == 5  # 1 full-gas + 4 grid probes
        probed_gas_limits = [
            _decode_probe_args(call[0][2])[1]
            for call in mock_rpc.call_args_list
        ]
        assert probed_gas_limits[0] == SOMNIA_MAX_CALL_DATA_GAS
        assert sorted(probed_gas_limits[1:]) == [
            2_105_000, 2_400_000, 2_800_000, 3_250_000
        ]


@pytest.mark.asyncio
async def test_somnia_v6_full_gas_revert_raises_execution_exception():
    gas_manager = _make_gas_manager()
    user_op = _make_user_operation()

    with patch(
        "voltaire_bundler.gas.gas_manager.send_rpc_request_to_eth_client",
        new_callable=AsyncMock,
        return_value={"result": PINNED_BLOCK}
    ), patch(
        "voltaire_bundler.gas.gas_manager_v6.send_rpc_request_to_eth_client",
        new_callable=AsyncMock,
        return_value=_make_estimate_revert_at_max(b"")
    ) as mock_rpc:
        with pytest.raises(ExecutionException):
            await gas_manager.estimate_call_gas_and_verificationgas_limit(
                user_op,
                ENTRYPOINT_V6,
                {},
                False,
            )
        assert mock_rpc.call_count == 1


@pytest.mark.asyncio
async def test_somnia_v6_falls_back_to_legacy_search_when_grid_fails():
    gas_manager = _make_gas_manager()
    user_op = _make_user_operation()

    legacy_response = _make_simulation_result_revert(
        verification_gas=120_000,
        call_gas_max=4_999_999,
        num_rounds=7,
    )

    with patch(
        "voltaire_bundler.gas.gas_manager.send_rpc_request_to_eth_client",
        new_callable=AsyncMock,
        return_value={"result": PINNED_BLOCK}
    ), patch(
        "voltaire_bundler.gas.gas_manager_v6.send_rpc_request_to_eth_client",
        new_callable=AsyncMock,
        side_effect=_somnia_probe_responder(
            required_gas=5_000_000,  # above the grid's top candidate (3.25M)
            gas_used=2_000_000,
            verification_gas=120_000,
            legacy_response=legacy_response,
        )
    ) as mock_rpc:
        call_gas, verification_gas = (
            await gas_manager.estimate_call_gas_and_verificationgas_limit(
                user_op,
                ENTRYPOINT_V6,
                {},
                False,
            )
        )

        assert call_gas == 4_999_999
        assert verification_gas == 120_000
        # 1 full-gas probe + 4 failed grid probes + 1 legacy search call
        assert mock_rpc.call_count == 6
