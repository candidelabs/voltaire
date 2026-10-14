"""
Unit tests for the verify-under-cap pass that follows every
verificationGasLimit estimate (GasManager.verify_verification_gas_limit).

The in-contract estimate is a gasleft() measurement taken while validation
runs under max_verification_gas. On EIP-8037 chains (Glamsterdam) a
create-then-reset of state refills gas into the frame that undid it, so
such measurements can undercount what the account needed under its cap.
The pass re-runs validation with the quoted limit as the actual cap and
raises it when validation does not fit.

Lives at the tests/ top level on purpose: tests/v6/conftest.py autouses
geth-docker + bundler fixtures for every module in that directory, and
these are pure mock-RPC unit tests.
"""

import pytest
from unittest.mock import AsyncMock, patch
from eth_abi import decode, encode

from voltaire_bundler.bundle.exceptions import ValidationException
from voltaire_bundler.gas.gas_manager_v6 import GasManagerV6
from voltaire_bundler.gas.gas_manager_v7v8v9 import GasManagerV7V8V9
from voltaire_bundler.gas.gas_price_cache import GasPriceCache
from voltaire_bundler.user_operation.models import FailedOp
from voltaire_bundler.user_operation.user_operation_v6 import UserOperationV6
from voltaire_bundler.user_operation.user_operation_v7v8v9 import UserOperationV7V8V9


ENTRYPOINT_V6 = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"
ENTRYPOINT_V7 = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
BUNDLER_ADDRESS = "0x0000000000000000000000000000000000000001"
SENDER = "0x7e25461EEE6853f89e5bA2bDf87F47a8965EbE04"
CHAIN_ID = 11155111  # Sepolia: EIP-8037 chain, no VGL multiplier, no L1 fee lookups

MAX_VERIFICATION_GAS = 1_000_000
MAX_CALL_DATA_GAS = 5_000_000

ARGS_ABI_TUPLE = "(uint256,uint256,uint256,bool,bool)"
OP_ABI_TUPLE = {
    "v6": "(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)",
    "v7": "(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)",
}
ENTRYPOINT = {"v6": ENTRYPOINT_V6, "v7": ENTRYPOINT_V7}
RPC_PATH = {
    "v6": "voltaire_bundler.gas.gas_manager_v6.send_rpc_request_to_eth_client",
    "v7": "voltaire_bundler.gas.gas_manager_v7v8v9.send_rpc_request_to_eth_client",
}


def _make_user_operation(version: str, verification_gas_limit: str = "0x0",
                         call_gas_limit: str = "0x0"):
    if version == "v6":
        return UserOperationV6({
            "sender": SENDER,
            "nonce": "0x4a",
            "initCode": "0x",
            "callData": "0xb61d27f6" + "00" * 96,
            "callGasLimit": call_gas_limit,
            "verificationGasLimit": verification_gas_limit,
            "preVerificationGas": "0x0",
            "maxFeePerGas": "0x0",
            "maxPriorityFeePerGas": "0x0",
            "paymasterAndData": "0x",
            "signature": "0x" + "00" * 65,
        })
    return UserOperationV7V8V9({
        "sender": SENDER,
        "nonce": "0x4a",
        "callData": "0xb61d27f6" + "00" * 96,
        "callGasLimit": call_gas_limit,
        "verificationGasLimit": verification_gas_limit,
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


def _make_gas_manager(version: str):
    cls = GasManagerV6 if version == "v6" else GasManagerV7V8V9
    return cls(
        ethereum_node_urls=["http://localhost:8545"],
        chain_id=CHAIN_ID,
        bundler_address=BUNDLER_ADDRESS,
        is_legacy_mode=False,
        max_verification_gas=MAX_VERIFICATION_GAS,
        max_call_data_gas=MAX_CALL_DATA_GAS,
        gas_price_cache=GasPriceCache(
            ethereum_node_urls=["http://localhost:8545"],
            chain_id=CHAIN_ID,
            is_legacy_mode=False,
            refresh_interval_seconds=10.0,
        ),
    )


def _simulation_result(verification_gas: int, call_gas: int, rounds: int) -> dict:
    encoded = encode(["uint256", "uint256", "uint256"],
                     [verification_gas, call_gas, rounds])
    return {"error": {"message": "execution reverted",
                      "data": "0xdeb13018" + encoded.hex()}}


def _failed_op(reason: str) -> dict:
    encoded = encode(["uint256", "string"], [0, reason])
    return {"error": {"message": "execution reverted",
                      "data": FailedOp.SELECTOR + encoded.hex()}}


def _decode_call(version: str, params) -> tuple[int, int, tuple]:
    """(verificationGasLimit, callGasLimit, EstimateCallGasArgs) of a
    simulateHandleOpMod eth_call payload."""
    op, args = decode([OP_ABI_TUPLE[version], ARGS_ABI_TUPLE],
                      bytes.fromhex(params[0]["data"][10:]))
    if version == "v6":
        return op[5], op[4], args
    account_gas_limits = op[4]  # bytes32: verificationGasLimit ++ callGasLimit
    return (int.from_bytes(account_gas_limits[:16], "big"),
            int.from_bytes(account_gas_limits[16:], "big"), args)


def _responder(version: str, estimated_vgl: int, required_vgl: int,
               verify_error: str = "AA23 reverted (or OOG)"):
    """Mock eth_call: the estimation run (not check-once) reports
    estimated_vgl; a check-once verification run passes iff the op's
    verificationGasLimit covers required_vgl, else reverts verify_error."""
    calls: list[tuple[int, int, tuple]] = []

    async def responder(nodes_urls, method, params, *args):
        vgl, cgl, probe_args = _decode_call(version, params)
        calls.append((vgl, cgl, probe_args))
        is_check_once = probe_args[4]
        if not is_check_once:
            return _simulation_result(estimated_vgl, 20_000, 3)
        if vgl >= required_vgl:
            return _simulation_result(estimated_vgl, 20_000, 0)
        return _failed_op(verify_error)

    return responder, calls


@pytest.mark.parametrize("version", ["v6", "v7"])
@pytest.mark.asyncio
async def test_estimate_is_verified_once_under_its_own_cap(version):
    """Common case: one extra check-once eth_call, run with the quoted
    verificationGasLimit as the op's actual limit and the full call-data
    gas (the callGasLimit estimate is not re-probed), and the quote is
    unchanged."""
    gas_manager = _make_gas_manager(version)
    responder, calls = _responder(version, estimated_vgl=50_000, required_vgl=0)

    with patch(RPC_PATH[version], new_callable=AsyncMock, side_effect=responder):
        call_gas_hex, _, ver_gas_hex = await gas_manager.estimate_user_operation_gas(
            _make_user_operation(version), ENTRYPOINT[version], {}
        )

    # estimate + 10_000 buffer (+ 10% of the estimate from v0.7)
    expected_vgl = 60_000 if version == "v6" else 65_000
    assert int(ver_gas_hex, 16) == expected_vgl
    assert int(call_gas_hex, 16) == 23_000  # estimate + 3_000 buffer
    assert len(calls) == 2
    estimate_vgl, _, estimate_args = calls[0]
    assert estimate_vgl == MAX_VERIFICATION_GAS
    assert estimate_args[4] is False
    verify_vgl, verify_cgl, verify_args = calls[1]
    assert verify_vgl == expected_vgl
    assert verify_cgl == 23_000
    assert verify_args == (0, MAX_CALL_DATA_GAS, 10, False, True)


@pytest.mark.parametrize("version", ["v6", "v7"])
@pytest.mark.asyncio
async def test_shortfall_is_doubled_then_bisected(version):
    """The measurement says 60k (+buffer) but validation needs 200k
    under its cap: v0.6 quotes 70k, so 70k and 140k fail, 280k fits, then
    bisection of (140k, 280k] tightens the quote to 210k within 3 rounds.
    From v0.7 the quote is 76k (10_000 + 10%) and the same steps follow."""
    gas_manager = _make_gas_manager(version)
    responder, calls = _responder(version, estimated_vgl=60_000, required_vgl=200_000)

    with patch(RPC_PATH[version], new_callable=AsyncMock, side_effect=responder):
        _, _, ver_gas_hex = await gas_manager.estimate_user_operation_gas(
            _make_user_operation(version), ENTRYPOINT[version], {}
        )

    probed = [vgl for vgl, _, args in calls if args[4]]
    if version == "v6":
        assert int(ver_gas_hex, 16) == 210_000
        assert probed == [70_000, 140_000, 280_000, 210_000, 175_000, 192_500]
    else:
        assert int(ver_gas_hex, 16) == 209_000
        assert probed == [76_000, 152_000, 304_000, 228_000, 190_000, 209_000]
    assert len(calls) == 1 + len(probed)


@pytest.mark.parametrize("version", ["v6", "v7"])
@pytest.mark.parametrize("reason", [
    "AA13 initCode failed or OOG",
    "AA21 didn't pay prefund",
    "AA26 over verificationGasLimit",
    "AA40 over verificationGasLimit",
])
@pytest.mark.asyncio
async def test_every_shortfall_code_triggers_a_raise(version, reason):
    gas_manager = _make_gas_manager(version)
    responder, calls = _responder(
        version, estimated_vgl=60_000, required_vgl=100_000, verify_error=reason
    )

    with patch(RPC_PATH[version], new_callable=AsyncMock, side_effect=responder):
        _, _, ver_gas_hex = await gas_manager.estimate_user_operation_gas(
            _make_user_operation(version), ENTRYPOINT[version], {}
        )

    assert int(ver_gas_hex, 16) >= 100_000


@pytest.mark.parametrize("version", ["v6", "v7"])
@pytest.mark.asyncio
async def test_non_shortfall_failure_propagates(version):
    """A verification failure that is not a gas shortfall is a real
    rejection, not something to paper over with more gas."""
    gas_manager = _make_gas_manager(version)
    responder, calls = _responder(
        version, estimated_vgl=60_000, required_vgl=100_000,
        verify_error="AA24 signature error",
    )

    with patch(RPC_PATH[version], new_callable=AsyncMock, side_effect=responder):
        with pytest.raises(ValidationException) as excinfo:
            await gas_manager.estimate_user_operation_gas(
                _make_user_operation(version), ENTRYPOINT[version], {}
            )

    assert "AA24" in excinfo.value.message
    assert len(calls) == 2


@pytest.mark.parametrize("version", ["v6", "v7"])
@pytest.mark.asyncio
async def test_shortfall_at_max_verification_gas_propagates(version):
    """Validation passed under max_verification_gas during the estimate,
    so still failing there is state drift: give up after the doublings
    reach the cap instead of looping."""
    gas_manager = _make_gas_manager(version)
    responder, calls = _responder(
        version, estimated_vgl=60_000, required_vgl=MAX_VERIFICATION_GAS + 1
    )

    with patch(RPC_PATH[version], new_callable=AsyncMock, side_effect=responder):
        with pytest.raises(ValidationException) as excinfo:
            await gas_manager.estimate_user_operation_gas(
                _make_user_operation(version), ENTRYPOINT[version], {}
            )

    assert "AA23" in excinfo.value.message
    probed = [vgl for vgl, _, args in calls if args[4]]
    first = 70_000 if version == "v6" else 76_000
    assert probed == [first, 2 * first, 4 * first, 8 * first, MAX_VERIFICATION_GAS]


@pytest.mark.parametrize("version", ["v6", "v7"])
@pytest.mark.asyncio
async def test_user_supplied_verification_gas_limit_is_not_verified(version):
    """A caller-provided verificationGasLimit is not our estimate; it is
    passed through untouched with no extra eth_call."""
    gas_manager = _make_gas_manager(version)
    responder, calls = _responder(version, estimated_vgl=60_000, required_vgl=10**9)

    with patch(RPC_PATH[version], new_callable=AsyncMock, side_effect=responder):
        _, _, ver_gas_hex = await gas_manager.estimate_user_operation_gas(
            _make_user_operation(version, verification_gas_limit="0x30000"),
            ENTRYPOINT[version], {},
        )

    assert int(ver_gas_hex, 16) == 0x30000
    assert len(calls) == 1


@pytest.mark.parametrize("version", ["v6", "v7"])
@pytest.mark.asyncio
async def test_verify_pass_only_runs_on_eip8037_chains(version):
    """Off the listed chains a gasleft() measurement is a faithful upper
    bound, so the estimate is quoted as-is with no extra eth_call."""
    gas_manager = _make_gas_manager(version)
    gas_manager.chain_id = 1337
    responder, calls = _responder(version, estimated_vgl=60_000, required_vgl=10**9)

    with patch(RPC_PATH[version], new_callable=AsyncMock, side_effect=responder):
        _, _, ver_gas_hex = await gas_manager.estimate_user_operation_gas(
            _make_user_operation(version), ENTRYPOINT[version], {}
        )

    # (60_000 + 10_000 [+ 6_000 from v0.7]) * 1.1 for chain 1337
    assert int(ver_gas_hex, 16) == (77_000 if version == "v6" else 83_600)
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_buffered_estimate_is_capped_at_max_verification_gas():
    """Near the cap, 10_000 + 10% would exceed max_verification_gas, which
    eth_sendUserOperation rejects; validation fit under the cap during the
    estimate, so the quote is the cap."""
    gas_manager = _make_gas_manager("v7")
    gas_manager.chain_id = 1337
    estimated = MAX_VERIFICATION_GAS - 50_000
    responder, calls = _responder("v7", estimated_vgl=estimated, required_vgl=0)

    with patch(RPC_PATH["v7"], new_callable=AsyncMock, side_effect=responder):
        _, _, ver_gas_hex = await gas_manager.estimate_user_operation_gas(
            _make_user_operation("v7"), ENTRYPOINT["v7"], {}
        )

    assert int(ver_gas_hex, 16) == MAX_VERIFICATION_GAS
