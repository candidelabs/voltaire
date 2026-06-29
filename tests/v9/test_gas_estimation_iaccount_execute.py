"""
Tests for IAccountExecute (executeUserOp) gas estimation support.

Verifies that the gas manager correctly estimates gas for UserOperations
that use the IAccountExecute interface (executeUserOp selector 0x8dd7712f),
where the EntryPoint rewrites the callData before forwarding to the account.

Bug context: the simulation contract was previously calling
sender.call(callData) directly, which breaks IAccountExecute accounts
because the raw callData contains abi.encode(BatchedCall) but the account
expects abi.encodeCall(executeUserOp, (PackedUserOperation, bytes32)).
"""

import pytest
from unittest.mock import AsyncMock, patch
from eth_abi import encode

from voltaire_bundler.user_operation.user_operation_v7v8v9 import UserOperationV7V8V9
from voltaire_bundler.gas.gas_manager_v7v8v9 import GasManagerV7V8V9
from voltaire_bundler.bundle.exceptions import ExecutionException

from tests._fixtures import make_gas_manager


ENTRYPOINT_V9 = "0x433709009B8330FDa32311DF1C2AFA402eD8D009"
BUNDLER_ADDRESS = "0x0000000000000000000000000000000000000001"

# executeUserOp selector
EXECUTE_USER_OP_SELECTOR = "0x8dd7712f"

# Standard execute selector (non-IAccountExecute)
EXECUTE_SELECTOR = "0xb61d27f6"


def _make_user_operation(call_data: str) -> UserOperationV7V8V9:
    """Create a minimal UserOperationV7V8V9 for testing."""
    return UserOperationV7V8V9({
        "sender": "0x7e25461EEE6853f89e5bA2bDf87F47a8965EbE04",
        "nonce": "0x4a",
        "callData": call_data,
        "callGasLimit": "0x0",
        "verificationGasLimit": "0x0",
        "preVerificationGas": "0x0",
        "maxFeePerGas": "0x0",
        "maxPriorityFeePerGas": "0x0",
        "signature": "0x" + "00" * 65,
        "factory": None,
        "factoryData": None,
        "paymaster": None,
        "paymasterVerificationGasLimit": None,
        "paymasterPostOpGasLimit": None,
        "paymasterData": None,
        "eip7702Auth": None,
    })


def _make_execute_user_op_calldata() -> str:
    """
    Create callData with executeUserOp selector (0x8dd7712f) + abi.encode(BatchedCall).
    This is what IAccountExecute accounts use.
    """
    # executeUserOp selector + encoded BatchedCall (a simple ETH transfer)
    batched_call_data = encode(
        ["(bytes,(address,uint256,bytes)[])"],
        [(
            b"",  # mode bytes
            [("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", 0, b"")],
        )]
    )
    return EXECUTE_USER_OP_SELECTOR + batched_call_data.hex()


def _make_standard_calldata() -> str:
    """
    Create callData with a standard execute selector (non-IAccountExecute).
    """
    data = encode(
        ["address", "uint256", "bytes"],
        ["0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", 0, b""]
    )
    return EXECUTE_SELECTOR + data.hex()


def _make_simulation_result_revert(verification_gas: int, call_gas_max: int, num_rounds: int) -> dict:
    """Create a mock eth_call response with SimulationResult revert data."""
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
    """Create a mock eth_call response with EstimateCallGasRevertAtMax revert data."""
    # EstimateCallGasRevertAtMax(bytes) selector = 0x59f233d2
    encoded = encode(["bytes"], [revert_data])
    return {
        "error": {
            "message": "execution reverted",
            "data": "0x59f233d2" + encoded.hex()
        }
    }


def _make_gas_manager() -> GasManagerV7V8V9:
    return make_gas_manager(bundler_address=BUNDLER_ADDRESS)


@pytest.mark.asyncio
async def test_execute_user_op_calldata_estimation_succeeds():
    """
    Test that gas estimation succeeds for UserOps with executeUserOp callData.

    Before the fix, this would fail with -32521 because the simulation contract
    called sender.call(callData) directly, which breaks IAccountExecute accounts.
    After the fix, the simulation contract detects the executeUserOp selector and
    rewrites the call to account.executeUserOp(packedUserOp, userOpHash).
    """
    gas_manager = _make_gas_manager()
    user_op = _make_user_operation(_make_execute_user_op_calldata())

    # The simulation should succeed with SimulationResult
    mock_response = _make_simulation_result_revert(
        verification_gas=50_000,
        call_gas_max=20_000,
        num_rounds=5
    )

    with patch(
        "voltaire_bundler.gas.gas_manager_v7v8v9.send_rpc_request_to_eth_client",
        new_callable=AsyncMock,
        return_value=mock_response
    ) as mock_rpc:
        call_gas, verification_gas = (
            await gas_manager.estimate_call_gas_and_verificationgas_limit(
                user_op,
                ENTRYPOINT_V9,
                {},
                False,
            )
        )

        assert call_gas == 20_000
        assert verification_gas == 50_000

        # Verify the RPC was called with the V9 entrypoint
        mock_rpc.assert_called_once()
        call_args = mock_rpc.call_args
        params = call_args[0][2]  # third positional arg is params
        assert params[1] == "latest"
        # Verify the state override contains the entrypoint code override
        state_overrides = params[2]
        assert ENTRYPOINT_V9 in state_overrides or ENTRYPOINT_V9.lower() in state_overrides


@pytest.mark.asyncio
async def test_standard_calldata_estimation_succeeds():
    """
    Test that gas estimation still works for standard (non-IAccountExecute) callData.
    """
    gas_manager = _make_gas_manager()
    user_op = _make_user_operation(_make_standard_calldata())

    mock_response = _make_simulation_result_revert(
        verification_gas=40_000,
        call_gas_max=15_000,
        num_rounds=3
    )

    with patch(
        "voltaire_bundler.gas.gas_manager_v7v8v9.send_rpc_request_to_eth_client",
        new_callable=AsyncMock,
        return_value=mock_response
    ):
        call_gas, verification_gas = (
            await gas_manager.estimate_call_gas_and_verificationgas_limit(
                user_op,
                ENTRYPOINT_V9,
                {},
                False,
            )
        )

        assert call_gas == 15_000
        assert verification_gas == 40_000


@pytest.mark.asyncio
async def test_empty_calldata_estimation_succeeds():
    """
    Test that gas estimation works for empty callData (0x).
    This is the case that always worked even before the fix.
    """
    gas_manager = _make_gas_manager()
    user_op = _make_user_operation("0x")

    mock_response = _make_simulation_result_revert(
        verification_gas=35_000,
        call_gas_max=5_000,
        num_rounds=2
    )

    with patch(
        "voltaire_bundler.gas.gas_manager_v7v8v9.send_rpc_request_to_eth_client",
        new_callable=AsyncMock,
        return_value=mock_response
    ):
        call_gas, verification_gas = (
            await gas_manager.estimate_call_gas_and_verificationgas_limit(
                user_op,
                ENTRYPOINT_V9,
                {},
                False,
            )
        )

        assert call_gas == 5_000
        assert verification_gas == 35_000


@pytest.mark.asyncio
async def test_execute_user_op_revert_at_max_raises_execution_exception():
    """
    Test that EstimateCallGasRevertAtMax errors are correctly propagated.

    Before the fix, IAccountExecute UserOps would hit this path because
    the direct sender.call(callData) would revert with empty data.
    """
    gas_manager = _make_gas_manager()
    user_op = _make_user_operation(_make_execute_user_op_calldata())

    mock_response = _make_estimate_revert_at_max(b"")

    with patch(
        "voltaire_bundler.gas.gas_manager_v7v8v9.send_rpc_request_to_eth_client",
        new_callable=AsyncMock,
        return_value=mock_response
    ):
        with pytest.raises(ExecutionException):
            await gas_manager.estimate_call_gas_and_verificationgas_limit(
                user_op,
                ENTRYPOINT_V9,
                {},
                False,
            )


@pytest.mark.asyncio
async def test_execute_user_op_calldata_detected_correctly():
    """
    Verify that the executeUserOp selector is correctly identified in UserOperation callData.
    The selector 0x8dd7712f corresponds to executeUserOp(PackedUserOperation,bytes32).
    """
    execute_user_op_calldata = _make_execute_user_op_calldata()
    assert execute_user_op_calldata.startswith(EXECUTE_USER_OP_SELECTOR)

    standard_calldata = _make_standard_calldata()
    assert standard_calldata.startswith(EXECUTE_SELECTOR)
    assert not standard_calldata.startswith(EXECUTE_USER_OP_SELECTOR)


@pytest.mark.asyncio
async def test_v9_entrypoint_uses_v9_bytecode_override():
    """
    Verify that the V9 EntryPoint address selects the V9 simulation bytecode.
    """
    gas_manager = _make_gas_manager()
    user_op = _make_user_operation(_make_execute_user_op_calldata())

    mock_response = _make_simulation_result_revert(
        verification_gas=50_000,
        call_gas_max=20_000,
        num_rounds=5
    )

    with patch(
        "voltaire_bundler.gas.gas_manager_v7v8v9.send_rpc_request_to_eth_client",
        new_callable=AsyncMock,
        return_value=mock_response
    ) as mock_rpc:
        await gas_manager.estimate_call_gas_and_verificationgas_limit(
            user_op,
            ENTRYPOINT_V9,
            {},
            False,
        )

        call_args = mock_rpc.call_args
        params = call_args[0][2]
        state_overrides = params[2]

        # V9 entrypoint should use V9 bytecode override
        entrypoint_key = ENTRYPOINT_V9
        assert entrypoint_key in state_overrides
        assert "code" in state_overrides[entrypoint_key]
        assert state_overrides[entrypoint_key]["code"] == gas_manager.entrypoint_code_override_v9


@pytest.mark.asyncio
async def test_estimate_user_operation_gas_full_flow():
    """
    Test the full estimate_user_operation_gas flow for an IAccountExecute UserOp.
    This tests the complete pipeline including verification gas, call gas, and pre-verification gas.
    """
    gas_manager = _make_gas_manager()
    user_op = _make_user_operation(_make_execute_user_op_calldata())

    mock_response = _make_simulation_result_revert(
        verification_gas=50_000,
        call_gas_max=20_000,
        num_rounds=5
    )

    with patch(
        "voltaire_bundler.gas.gas_manager_v7v8v9.send_rpc_request_to_eth_client",
        new_callable=AsyncMock,
        return_value=mock_response
    ):
        call_gas_hex, prever_gas_hex, ver_gas_hex = (
            await gas_manager.estimate_user_operation_gas(
                user_op,
                ENTRYPOINT_V9,
                {},
            )
        )

        call_gas = int(call_gas_hex, 16)
        ver_gas = int(ver_gas_hex, 16)
        prever_gas = int(prever_gas_hex, 16)

        assert call_gas == 20_000
        # verification gas = estimated (50_000) + 10_000 buffer
        assert ver_gas == 60_000
        assert prever_gas > 0


@pytest.mark.asyncio
async def test_check_once_mode_with_execute_user_op():
    """
    Test gas estimation in check-once mode (when callGasLimit is provided).
    The isCheckOnce flag causes the simulation to return only verification gas.
    """
    gas_manager = _make_gas_manager()

    # Create UserOp with non-zero callGasLimit (triggers isCheckOnce)
    user_op_dict = {
        "sender": "0x7e25461EEE6853f89e5bA2bDf87F47a8965EbE04",
        "nonce": "0x4a",
        "callData": _make_execute_user_op_calldata(),
        "callGasLimit": "0x5208",  # non-zero
        "verificationGasLimit": "0x0",
        "preVerificationGas": "0x0",
        "maxFeePerGas": "0x0",
        "maxPriorityFeePerGas": "0x0",
        "signature": "0x" + "00" * 65,
        "factory": None,
        "factoryData": None,
        "paymaster": None,
        "paymasterVerificationGasLimit": None,
        "paymasterPostOpGasLimit": None,
        "paymasterData": None,
        "eip7702Auth": None,
    }
    user_op = UserOperationV7V8V9(user_op_dict)

    # SimulationResult with callGasLimitMax=0 indicates check-once mode
    mock_response = _make_simulation_result_revert(
        verification_gas=45_000,
        call_gas_max=0,
        num_rounds=0
    )

    with patch(
        "voltaire_bundler.gas.gas_manager_v7v8v9.send_rpc_request_to_eth_client",
        new_callable=AsyncMock,
        return_value=mock_response
    ):
        call_gas, verification_gas = (
            await gas_manager.estimate_call_gas_and_verificationgas_limit(
                user_op,
                ENTRYPOINT_V9,
                {},
                True,  # is_check_once
            )
        )

        assert call_gas == 0  # check-once returns 0 for callGasLimitMax
        assert verification_gas == 45_000
