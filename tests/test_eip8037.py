"""--eip8037: simulations run at 2**24 gas and bundles are kept within 2**24
(voltaire_bundler/gas/eip8037.py). Pure mock-RPC unit tests."""
from __future__ import annotations

import math
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from eth_abi import decode, encode

from voltaire_bundler.gas import eip8037
from voltaire_bundler.gas.gas_manager_v7v8v9 import GasManagerV7V8V9
from voltaire_bundler.gas.gas_price_cache import GasPriceCache
from voltaire_bundler.bundle.bundle_manager import BundlerManager
from voltaire_bundler.user_operation.user_operation_v6 import UserOperationV6
from voltaire_bundler.user_operation.user_operation_v7v8v9 import \
    UserOperationV7V8V9
from voltaire_bundler.validation.validation_manager_v7v8v9 import \
    ValidationManagerV7V8V9

ENTRYPOINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
BUNDLER = "0x3cfdc212769c890907bce93d3d8c2c53de6a7a89"
SENDER = "0x7e25461EEE6853f89e5bA2bDf87F47a8965EbE04"
CHAIN_ID = 11155111
NODE = ["http://localhost:8545"]


@pytest.fixture
def eip8037_flag(monkeypatch):
    """Set the module-level flag for one test only."""
    def set_flag(value: bool) -> None:
        monkeypatch.setattr(eip8037, "enabled", value)
    set_flag(False)
    return set_flag


def _op(vgl=0, cgl=0, pvg=0, sender=SENDER, call_data="0x"):
    return UserOperationV7V8V9({
        "sender": sender, "nonce": "0x0", "callData": call_data,
        "callGasLimit": hex(cgl), "verificationGasLimit": hex(vgl),
        "preVerificationGas": hex(pvg), "maxFeePerGas": "0x1e",
        "maxPriorityFeePerGas": "0x3", "signature": "0x" + "11" * 65,
        "factory": None, "factoryData": None, "paymaster": None,
        "paymasterVerificationGasLimit": None, "paymasterPostOpGasLimit": None,
        "paymasterData": None, "eip7702Auth": None,
    })


def _op_v6(vgl=0, cgl=0, pvg=0, sender=SENDER, call_data="0x",
           init_code="0x", paymaster_and_data="0x"):
    return UserOperationV6({
        "sender": sender, "nonce": "0x0", "initCode": init_code,
        "callData": call_data, "callGasLimit": hex(cgl),
        "verificationGasLimit": hex(vgl), "preVerificationGas": hex(pvg),
        "maxFeePerGas": "0x1e", "maxPriorityFeePerGas": "0x3",
        "paymasterAndData": paymaster_and_data,
        "signature": "0x" + "11" * 65,
    })


def _bundle_formula(ops) -> int:
    """What BundlerManager.create_bundle_calldata_and_estimate_gas sets as
    the bundle gas limit (mirrors that code, for the bundler above)."""
    from voltaire_bundler.bundle.bundle_manager import \
        calculate_bundle_calldata_init_gas
    from voltaire_bundler.utils.eth_client_utils import (
        encode_handleops_calldata_v6, encode_handleops_calldata_v7v8v9)
    if isinstance(ops[0], UserOperationV6):
        call_data = encode_handleops_calldata_v6(
            [op.to_list() for op in ops], BUNDLER)
    else:
        call_data = encode_handleops_calldata_v7v8v9(
            [op.to_list() for op in ops], BUNDLER)
    return (sum(op.get_max_gas_with_pre_verification_gas() for op in ops)
            + 50_000 + calculate_bundle_calldata_init_gas(call_data))


# ------------------------------------------------------------------ packing

def test_packing_estimate_bounds_the_bundle_gas_limit():
    """Packing sums operation_bundle_gas + BUNDLE_OVERHEAD_GAS and only
    selects within 2**24, so that sum must never undershoot the gas limit
    the bundle manager sets."""
    paymaster = "0x" + "99" * 20
    v7 = [
        _op(1_469_122, 154_352, 50_468, call_data="0x" + "ab" * 3000),
        _op(300_000, 100_000, 50_000, sender="0x" + "12" * 20,
            call_data="0x" + "00" * 500),
        _op(70_000, 21_000, 45_000, sender="0x" + "34" * 20),
    ]
    # the packed paymasterAndData / initCode prefixes (paymaster address
    # and gas limits, factory address) aren't dynamic fields, so they're
    # covered by the per-operation encoding allowance
    with_paymaster = _op(200_000, 90_000, 48_000, sender="0x" + "56" * 20)
    with_paymaster.paymaster = paymaster
    with_paymaster.paymaster_verification_gas_limit = 60_000
    with_paymaster.paymaster_post_op_gas_limit = 20_000
    with_paymaster.paymaster_data = b"\xcd" * 100
    with_paymaster.factory = "0x" + "77" * 20
    with_paymaster.factory_data = b"\xef" * 64
    with_paymaster._set_factory_and_paymaster_address()
    v7.append(with_paymaster)
    # v0.6 has the widest ABI head (11 words per operation)
    v6 = [
        _op_v6(1_469_122, 154_352, 50_468, call_data="0x" + "ab" * 3000),
        _op_v6(300_000, 100_000, 50_000, sender="0x" + "12" * 20,
               init_code="0x" + "77" * 20 + "ef" * 64,
               paymaster_and_data=paymaster + "cd" * 100),
        _op_v6(70_000, 21_000, 45_000, sender="0x" + "34" * 20),
    ]
    for ops in (v7, v7[:1], [with_paymaster], v6, v6[1:2]):
        estimate = eip8037.BUNDLE_OVERHEAD_GAS + sum(
            eip8037.operation_bundle_gas(op) for op in ops)
        assert estimate >= _bundle_formula(ops)


def test_packing_skips_an_operation_that_would_exceed_the_cap():
    """Three large operations fit the 15M limits-only budget, but only two
    fit 2**24 once preVerificationGas and calldata count."""
    big = [_op(3_000_000, 1_000_000, 2_000_000, sender=f"0x{i:040x}")
           for i in range(1, 4)]
    per_op = eip8037.operation_bundle_gas(big[0])
    assert eip8037.BUNDLE_OVERHEAD_GAS + 2 * per_op <= eip8037.TX_GAS_LIMIT_CAP
    assert eip8037.BUNDLE_OVERHEAD_GAS + 3 * per_op > eip8037.TX_GAS_LIMIT_CAP


def test_multiplier_is_headroom_and_never_shrinks_what_is_accepted(
    eip8037_flag,
):
    """The estimation multiplier adds gas on top of the bundle gas limit;
    with --eip8037 that headroom is cut short at 2**24, but the limit the
    bundler accepts and packs is the cap itself, whatever the multiplier."""
    eip8037_flag(True)
    at_cap = eip8037.TX_GAS_LIMIT_CAP - eip8037.BUNDLE_OVERHEAD_GAS
    for multiplier in (1.0, 1.1, 1.5):
        manager = _bundle_manager()
        manager.bundle_gas_estimation_multiplier = multiplier
        assert eip8037.operation_bundle_gas_limit() == at_cap
        # full headroom while it fits under the cap ...
        assert manager.bundle_transaction_gas(1_000_000) == math.ceil(
            1_000_000 * multiplier)
        # ... cut short, not refused, for a bundle packed to the cap
        assert manager.bundle_transaction_gas(
            eip8037.TX_GAS_LIMIT_CAP) == eip8037.TX_GAS_LIMIT_CAP


# ---------------------------------------------------------- bundle tx gas

def _bundle_manager() -> BundlerManager:
    manager = object.__new__(BundlerManager)
    manager.chain_id = CHAIN_ID
    manager.bundle_gas_estimation_multiplier = 1.1
    manager.conditional_rpc = None
    manager.ethereum_node_urls = NODE
    manager.user_operations_to_ban = {}
    manager.local_mempool_manager_v9 = SimpleNamespace(entrypoint="0x" + "09" * 20)
    manager.local_mempool_manager_v8 = SimpleNamespace(entrypoint="0x" + "08" * 20)
    manager.local_mempool_manager_v7 = SimpleNamespace(entrypoint=ENTRYPOINT)
    return manager


def test_transaction_gas_is_clamped_to_the_cap_only_with_the_flag(eip8037_flag):
    manager = _bundle_manager()
    eip8037_flag(False)
    assert manager.bundle_transaction_gas(16_000_000) == 17_600_000
    eip8037_flag(True)
    assert manager.bundle_transaction_gas(16_000_000) == eip8037.TX_GAS_LIMIT_CAP
    assert manager.bundle_transaction_gas(1_000_000) == 1_100_000


BUNDLE_RPC = "voltaire_bundler.bundle.bundle_manager.send_rpc_request_to_eth_client"


@pytest.mark.asyncio
async def test_bundle_pre_check_simulates_with_the_transaction_gas(eip8037_flag):
    """Without a gas value the pre-check runs under the node's default call
    gas, which hides state creation; with the flag it runs at the gas the
    transaction will carry."""
    op = _op(1_469_122, 154_352, 50_468)
    for flag in (True, False):
        eip8037_flag(flag)
        manager = _bundle_manager()
        seen: list[dict] = []

        async def responder(nodes_urls, method, params, *args):
            seen.append(params[0])
            return {"result": "0x"}

        with patch(BUNDLE_RPC, new_callable=AsyncMock, side_effect=responder):
            _, bundle_gas_limit, _, _ = \
                await manager.create_bundle_calldata_and_estimate_gas(
                    [op], BUNDLER, ENTRYPOINT, 0)
        if flag:
            assert seen[0]["gas"] == hex(
                manager.bundle_transaction_gas(bundle_gas_limit))
        else:
            assert "gas" not in seen[0]


@pytest.mark.asyncio
async def test_bundle_over_cap_sheds_the_last_operation_without_banning(
    eip8037_flag,
):
    """If the packing estimate ever undershoots, the pre-send check drops
    the last operation and retries instead of dead-ending (which would
    re-select the same bundle every tick), and doesn't treat it as a
    third-validation failure."""
    eip8037_flag(True)
    manager = _bundle_manager()
    ops = [_op(300_000, 100_000, 50_000, sender=f"0x{i:040x}")
           for i in range(1, 4)]
    for i, op in enumerate(ops):
        op.user_operation_hash = f"0x{i:064x}"
    seen: list[dict] = []

    async def responder(nodes_urls, method, params, *args):
        seen.append(params[0])
        return {"result": "0x"}

    # a cap that fits two of the three operations
    two = _bundle_formula(ops[:2])
    three = _bundle_formula(ops)
    with patch.object(eip8037, "TX_GAS_LIMIT_CAP", (two + three) // 2), \
            patch(BUNDLE_RPC, new_callable=AsyncMock, side_effect=responder):
        call_data, bundle_gas_limit, _, _ = \
            await manager.create_bundle_calldata_and_estimate_gas(
                ops, BUNDLER, ENTRYPOINT, 0)
    assert bundle_gas_limit == two
    assert [op.user_operation_hash for op in ops] == ["0x" + "0" * 64,
                                                      "0x" + "0" * 63 + "1"]
    assert len(seen) == 1  # the over-cap set never hit the node
    assert manager.user_operations_to_ban == {}

    # nothing left: no bundle, no error
    with patch.object(eip8037, "TX_GAS_LIMIT_CAP", 1), \
            patch(BUNDLE_RPC, new_callable=AsyncMock, side_effect=responder):
        assert await manager.create_bundle_calldata_and_estimate_gas(
            [ops[0]], BUNDLER, ENTRYPOINT, 0) == (None, None, None, [])


# -------------------------------------------------------------- simulations

@pytest.mark.asyncio
async def test_validation_simulation_runs_at_the_cap_only_with_the_flag(
    eip8037_flag,
):
    """With the flag the validation eth_call carries 2**24 gas, so the
    EIP-8037 reservoir is empty as in a real bundle."""
    for flag, expected in [(True, eip8037.TX_GAS_LIMIT_CAP_HEX), (False, None)]:
        eip8037_flag(flag)
        manager = ValidationManagerV7V8V9(
            MagicMock(), NODE, BUNDLER, CHAIN_ID, True, False, 0, 0, NODE)
        gases: list = []

        async def responder(nodes_urls, method, params, *args):
            gases.append(params[0].get("gas"))
            return {"result": "0x00"}

        with patch("voltaire_bundler.validation.validation_manager_v7v8v9."
                   "send_rpc_request_to_eth_client",
                   new_callable=AsyncMock, side_effect=responder):
            await manager.simulate_validation_without_tracing(
                _op(300_000, 90_000, 50_000), ENTRYPOINT, None)
        assert gases == [expected]


@pytest.mark.asyncio
async def test_estimation_simulation_runs_at_the_cap_only_with_the_flag(
    eip8037_flag,
):
    revert = {"error": {"message": "execution reverted", "data": "0xdeb13018"
                        + encode(["uint256"] * 3, [60_000, 20_000, 3]).hex()}}
    for flag, expected in [(True, eip8037.TX_GAS_LIMIT_CAP_HEX), (False, None)]:
        eip8037_flag(flag)
        gas_manager = GasManagerV7V8V9(
            NODE, CHAIN_ID, BUNDLER, False, 10_000_000, 30_000_000,
            GasPriceCache(NODE, CHAIN_ID, False, 10.0))
        gases: list = []

        async def responder(nodes_urls, method, params, *args):
            gases.append(params[0].get("gas"))
            return revert

        # pvg is estimated too: the zero-deposit read must not be counted
        async def deposit(nodes_urls, method, params, *args):
            return {"result": hex(10**18)}

        with patch("voltaire_bundler.gas.gas_manager_v7v8v9."
                   "send_rpc_request_to_eth_client",
                   new_callable=AsyncMock, side_effect=responder), \
                patch("voltaire_bundler.gas.gas_manager."
                      "send_rpc_request_to_eth_client",
                      new_callable=AsyncMock, side_effect=deposit):
            await gas_manager.estimate_user_operation_gas(
                _op(), ENTRYPOINT, {})
        assert gases and all(gas == expected for gas in gases)


# ------------------------------------------------------------ per-op fit

def _endpoint(gas_manager) -> "ExecutionEndpoint":
    from voltaire_bundler.execution_endpoint import ExecutionEndpoint
    endpoint = object.__new__(ExecutionEndpoint)
    endpoint.chain_id = CHAIN_ID
    endpoint.is_eip7702 = False
    endpoint.user_operation_handler_v7v8v9 = SimpleNamespace(
        gas_manager=gas_manager)
    endpoint.user_operation_handler_v6 = None
    endpoint.local_mempool_manager_v7 = SimpleNamespace(
        add_user_operation=AsyncMock(return_value="0x" + "ab" * 32))
    endpoint.local_mempool_manager_v6 = None
    return endpoint


def _op_json(vgl, cgl, pvg, call_data="0x"):
    return {
        "sender": SENDER, "nonce": "0x0", "callData": call_data,
        "callGasLimit": hex(cgl), "verificationGasLimit": hex(vgl),
        "preVerificationGas": hex(pvg), "maxFeePerGas": "0x1e",
        "maxPriorityFeePerGas": "0x3", "signature": "0x" + "11" * 65,
        "factory": None, "factoryData": None, "paymaster": None,
        "paymasterVerificationGasLimit": None, "paymasterPostOpGasLimit": None,
        "paymasterData": None,
    }


def test_check_operation_fits_is_a_no_op_unless_enabled(eip8037_flag):
    from voltaire_bundler.bundle.exceptions import ValidationException
    too_big = _op(10_000_000, 5_000_000, 2_000_000)
    assert eip8037.operation_bundle_gas(too_big) > eip8037.TX_GAS_LIMIT_CAP
    eip8037.check_operation_fits(too_big)  # disabled: nothing happens
    eip8037_flag(True)
    with pytest.raises(ValidationException) as excinfo:
        eip8037.check_operation_fits(too_big)
    assert "EIP-7825" in excinfo.value.message
    # the largest operation that fits a bundle on its own
    limit = eip8037.operation_bundle_gas_limit()
    fits = _op(0, 0, limit - eip8037.PER_OPERATION_ENCODING_GAS
               - eip8037.CALLDATA_GAS_PER_BYTE * 65)
    assert eip8037.operation_bundle_gas(fits) == limit
    eip8037.check_operation_fits(fits)


@pytest.mark.asyncio
async def test_send_user_operation_rejects_an_operation_that_cannot_be_bundled(
    eip8037_flag,
):
    """Under 15M of gas limits (the submit-time check), but over 2**24 once
    preVerificationGas and calldata count: reject instead of leaving it in
    the mempool forever."""
    from voltaire_bundler.bundle.exceptions import ValidationException
    endpoint = _endpoint(None)
    big = _op_json(9_000_000, 5_000_000, 3_000_000)
    eip8037_flag(True)
    with pytest.raises(ValidationException) as excinfo:
        await endpoint._event_rpc_sendUserOperation([big, ENTRYPOINT])
    assert "bundle gas" in excinfo.value.message
    endpoint.local_mempool_manager_v7.add_user_operation.assert_not_called()
    # without the flag the same operation goes through to the mempool
    eip8037_flag(False)
    assert await endpoint._event_rpc_sendUserOperation(
        [big, ENTRYPOINT]) == "0x" + "ab" * 32
    endpoint.local_mempool_manager_v7.add_user_operation.assert_awaited_once()


@pytest.mark.asyncio
async def test_estimation_rejects_a_quote_that_cannot_be_bundled(eip8037_flag):
    from voltaire_bundler.bundle.exceptions import ValidationException
    quote = (hex(5_000_000), hex(3_000_000), hex(9_000_000))
    gas_manager = SimpleNamespace(
        estimate_user_operation_gas=AsyncMock(return_value=quote))
    endpoint = _endpoint(gas_manager)
    request = [_op_json(0, 0, 0), ENTRYPOINT, None]
    eip8037_flag(False)
    assert await endpoint._event_rpc_estimateUserOperationGas(request) == {
        "callGasLimit": quote[0], "preVerificationGas": quote[1],
        "verificationGasLimit": quote[2]}
    eip8037_flag(True)
    with pytest.raises(ValidationException) as excinfo:
        await endpoint._event_rpc_estimateUserOperationGas(request)
    assert "bundle gas" in excinfo.value.message
    # a quote that fits is returned unchanged
    small = (hex(100_000), hex(50_000), hex(200_000))
    gas_manager.estimate_user_operation_gas = AsyncMock(return_value=small)
    assert await endpoint._event_rpc_estimateUserOperationGas(request) == {
        "callGasLimit": small[0], "preVerificationGas": small[1],
        "verificationGasLimit": small[2]}


# -------------------------------------------------------------------- cli

@pytest.mark.asyncio
async def test_cli_refuses_the_flag_on_somnia(monkeypatch):
    from voltaire_bundler.cli_manager import parse_args
    from voltaire_bundler.gas.somnia_gas_estimation import SOMNIA_CHAIN_IDS
    monkeypatch.delenv("VOLTAIRE_EIP8037", raising=False)
    base = ["--bundler_secret", "0x" + "11" * 32, "--unsafe"]
    for chain_id in SOMNIA_CHAIN_IDS:
        with pytest.raises(SystemExit):
            await parse_args(base + ["--chain_id", str(chain_id), "--eip8037"])


# ------------------------------------------------- zero-deposit refund

GAS_MANAGER_RPC = "voltaire_bundler.gas.gas_manager.send_rpc_request_to_eth_client"


def _gas_manager() -> GasManagerV7V8V9:
    return GasManagerV7V8V9(
        NODE, CHAIN_ID, BUNDLER, False, 10_000_000, 30_000_000,
        GasPriceCache(NODE, CHAIN_ID, False, 10.0))


def _deposit_responder(deposit_hex: str):
    calls: list = []

    async def responder(nodes_urls, method, params, *args):
        calls.append((method, params))
        return {"result": deposit_hex}
    return responder, calls


@pytest.mark.asyncio
async def test_zero_deposit_refund_is_charged_only_when_it_creates_a_slot(
    eip8037_flag,
):
    gas_manager = _gas_manager()
    op = _op(300_000, 90_000, 50_000)

    # flag off: no read, nothing charged
    responder, calls = _deposit_responder("0x0")
    with patch(GAS_MANAGER_RPC, new_callable=AsyncMock, side_effect=responder):
        assert await gas_manager._zero_deposit_refund_gas(op, ENTRYPOINT) == 0
    assert calls == []

    eip8037_flag(True)
    # zero deposit: the refund creates the slot
    responder, calls = _deposit_responder("0x0")
    with patch(GAS_MANAGER_RPC, new_callable=AsyncMock, side_effect=responder):
        assert await gas_manager._zero_deposit_refund_gas(op, ENTRYPOINT) == \
            eip8037.ZERO_DEPOSIT_REFUND_GAS
    (method, params), = calls
    assert method == "eth_call"
    assert params[0]["to"] == ENTRYPOINT
    assert params[0]["data"] == "0x70a08231" + encode(["address"], [SENDER]).hex()
    assert params[1] == "latest"

    # an empty return value is a zero deposit too
    responder, _ = _deposit_responder("0x")
    with patch(GAS_MANAGER_RPC, new_callable=AsyncMock, side_effect=responder):
        assert await gas_manager._zero_deposit_refund_gas(op, ENTRYPOINT) == \
            eip8037.ZERO_DEPOSIT_REFUND_GAS

    # funded deposit: the refund writes an existing slot
    responder, _ = _deposit_responder(hex(10**15))
    with patch(GAS_MANAGER_RPC, new_callable=AsyncMock, side_effect=responder):
        assert await gas_manager._zero_deposit_refund_gas(op, ENTRYPOINT) == 0

    # paymaster: the refund goes to its deposit, which covered the prefund
    with_paymaster = _op(300_000, 90_000, 50_000)
    with_paymaster.paymaster = "0x" + "99" * 20
    with_paymaster._set_factory_and_paymaster_address()
    responder, calls = _deposit_responder("0x0")
    with patch(GAS_MANAGER_RPC, new_callable=AsyncMock, side_effect=responder):
        assert await gas_manager._zero_deposit_refund_gas(
            with_paymaster, ENTRYPOINT) == 0
    assert calls == []


@pytest.mark.asyncio
async def test_unreadable_deposit_is_priced_as_zero(eip8037_flag, caplog):
    eip8037_flag(True)
    gas_manager = _gas_manager()
    op = _op(300_000, 90_000, 50_000)
    for response in ({"error": {"message": "boom"}}, RuntimeError("down")):
        with patch(GAS_MANAGER_RPC, new_callable=AsyncMock,
                   side_effect=[response]):
            assert await gas_manager._zero_deposit_refund_gas(
                op, ENTRYPOINT) == eip8037.ZERO_DEPOSIT_REFUND_GAS
    assert "pricing the zero-deposit refund" in caplog.text


@pytest.mark.asyncio
async def test_zero_deposit_refund_is_in_the_quote_and_the_submit_check(
    eip8037_flag,
):
    """Both go through get_preverification_gas: the estimate carries the
    slot's state gas, and an operation submitted with a preVerificationGas
    that omits it is rejected rather than costing the bundler the slot."""
    from voltaire_bundler.bundle.exceptions import ValidationException
    gas_manager = _gas_manager()
    op = _op(300_000, 90_000, 50_000)
    responder, _ = _deposit_responder("0x0")

    with patch(GAS_MANAGER_RPC, new_callable=AsyncMock, side_effect=responder):
        eip8037_flag(False)
        without = await gas_manager.get_preverification_gas(op, ENTRYPOINT)
        eip8037_flag(True)
        with_term = await gas_manager.get_preverification_gas(op, ENTRYPOINT)
    assert with_term == without + eip8037.ZERO_DEPOSIT_REFUND_GAS

    op.pre_verification_gas = without
    with patch(GAS_MANAGER_RPC, new_callable=AsyncMock, side_effect=responder):
        with pytest.raises(ValidationException) as excinfo:
            await gas_manager.verify_preverification_gas_and_verification_gas_limit(
                op, ENTRYPOINT)
        assert "preVerificationGas is too low" in excinfo.value.message
        op.pre_verification_gas = with_term
        await gas_manager.verify_preverification_gas_and_verification_gas_limit(
            op, ENTRYPOINT)


# --------------------------------------------------- call gas search stall

@pytest.mark.asyncio
async def test_call_gas_search_stops_when_a_continuation_makes_no_progress(
    eip8037_flag,
):
    """EstimateCallGasContinuation's numRounds is per call, so a
    continuation whose first guess doesn't fit the capped call's gas
    comes back with the bounds it was given; re-issuing it would loop
    forever. With the flag the search also starts from a max the capped
    simulation can run."""
    eip8037_flag(True)
    gas_manager = _gas_manager()
    args_seen: list[tuple] = []
    stuck = {"error": {"message": "execution reverted", "data": "0x22cf94e6"
                       + encode(["uint256"] * 3, [14_000_000, 30_000_000, 1]).hex()}}

    async def responder(nodes_urls, method, params, *args):
        _, probe_args = decode(
            ["(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)",
             "(uint256,uint256,uint256,bool,bool)"],
            bytes.fromhex(params[0]["data"][10:]))
        args_seen.append(probe_args)
        return stuck

    with patch("voltaire_bundler.gas.gas_manager_v7v8v9."
               "send_rpc_request_to_eth_client",
               new_callable=AsyncMock, side_effect=responder):
        with pytest.raises(ValueError):
            await gas_manager.estimate_call_gas_and_verificationgas_limit(
                _op(), ENTRYPOINT, {}, False)
    # first probe at the capped max, then one continuation at the returned
    # bounds; it coming back with the same bounds stops the search
    assert [(a[0], a[1], a[3]) for a in args_seen] == [
        (0, eip8037.TX_GAS_LIMIT_CAP, False),
        (14_000_000, 30_000_000, True),
    ]
