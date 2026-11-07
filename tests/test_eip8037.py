"""--eip8037: simulations run at 2**24 gas and bundles are kept within 2**24
(voltaire_bundler/gas/eip8037.py). Pure mock-RPC unit tests."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from eth_abi import encode

from voltaire_bundler.gas import eip8037
from voltaire_bundler.gas.gas_manager_v7v8v9 import GasManagerV7V8V9
from voltaire_bundler.gas.gas_price_cache import GasPriceCache
from voltaire_bundler.bundle.bundle_manager import BundlerManager
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


def _bundle_formula(ops) -> int:
    """What BundlerManager.create_bundle_calldata_and_estimate_gas sets as
    the bundle gas limit (mirrors that code, for the bundler above)."""
    from voltaire_bundler.bundle.bundle_manager import \
        calculate_bundle_calldata_init_gas
    from voltaire_bundler.utils.eth_client_utils import \
        encode_handleops_calldata_v7v8v9
    call_data = encode_handleops_calldata_v7v8v9(
        [op.to_list() for op in ops], BUNDLER)
    return (sum(op.get_max_gas_with_pre_verification_gas() for op in ops)
            + 50_000 + calculate_bundle_calldata_init_gas(call_data))


# ------------------------------------------------------------------ packing

def test_packing_estimate_bounds_the_bundle_gas_limit():
    """Packing sums operation_bundle_gas + BUNDLE_OVERHEAD_GAS and only
    selects within 2**24, so that sum must never undershoot the gas limit
    the bundle manager sets."""
    ops = [
        _op(1_469_122, 154_352, 50_468, call_data="0x" + "ab" * 3000),
        _op(300_000, 100_000, 50_000, sender="0x" + "12" * 20,
            call_data="0x" + "00" * 500),
        _op(70_000, 21_000, 45_000, sender="0x" + "34" * 20),
    ]
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

        with patch("voltaire_bundler.gas.gas_manager_v7v8v9."
                   "send_rpc_request_to_eth_client",
                   new_callable=AsyncMock, side_effect=responder):
            await gas_manager.estimate_user_operation_gas(
                _op(), ENTRYPOINT, {})
        assert gases and all(gas == expected for gas in gases)
