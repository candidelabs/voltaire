"""--eip7623 (on by default) / --eip8037: the EIP-7623 and EIP-7976 calldata floors in
preVerificationGas and the bundle gas limit (gas/calldata_floor.py).
Pure mock-RPC unit tests."""
from unittest.mock import AsyncMock, patch

import pytest

from voltaire_bundler.bundle.bundle_manager import BundlerManager
from voltaire_bundler.bundle.exceptions import ValidationException
from voltaire_bundler.gas import calldata_floor, eip8037
from voltaire_bundler.gas.gas_manager_v6 import GasManagerV6
from voltaire_bundler.gas.gas_manager_v7v8v9 import GasManagerV7V8V9
from voltaire_bundler.gas.gas_price_cache import GasPriceCache
from voltaire_bundler.user_operation.user_operation_v6 import UserOperationV6
from voltaire_bundler.user_operation.user_operation_v7v8v9 import \
    UserOperationV7V8V9

ENTRYPOINT_V6 = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"
ENTRYPOINT_V7 = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
BUNDLER = "0x3cfdc212769c890907bce93d3d8c2c53de6a7a89"
SENDER = "0x7e25461EEE6853f89e5bA2bDf87F47a8965EbE04"
CHAIN_ID = 11155111  # no VGL multiplier, no L1 fee lookups
NODE = ["http://localhost:8545"]


@pytest.fixture
def floors(monkeypatch):
    """Select no floor, the EIP-7623 floor, or (via --eip8037) EIP-7976."""
    monkeypatch.setattr(calldata_floor, "enabled", False)
    monkeypatch.setattr(eip8037, "enabled", False)

    def select(eip7623: bool = False, eip8037_flag: bool = False) -> None:
        monkeypatch.setattr(calldata_floor, "enabled", eip7623)
        monkeypatch.setattr(eip8037, "enabled", eip8037_flag)
    return select


def _op_v7(cgl=0, vgl=0, pvg=0, call_data="0x", post_op=None):
    """A v0.7 operation; ``post_op`` adds a paymaster postOp limit."""
    return UserOperationV7V8V9({
        "sender": SENDER, "nonce": "0x0", "callData": call_data,
        "callGasLimit": hex(cgl), "verificationGasLimit": hex(vgl),
        "preVerificationGas": hex(pvg), "maxFeePerGas": "0x1e",
        "maxPriorityFeePerGas": "0x3", "signature": "0x" + "11" * 65,
        "factory": None, "factoryData": None,
        "paymaster": None if post_op is None else "0x" + "99" * 20,
        "paymasterVerificationGasLimit": None if post_op is None else "0x186a0",
        "paymasterPostOpGasLimit": None if post_op is None else hex(post_op),
        "paymasterData": None if post_op is None else "0x",
        "eip7702Auth": None,
    })


def _op_v6(cgl=0, vgl=0, pvg=0, call_data="0x"):
    """A v0.6 operation."""
    return UserOperationV6({
        "sender": SENDER, "nonce": "0x0", "initCode": "0x",
        "callData": call_data, "callGasLimit": hex(cgl),
        "verificationGasLimit": hex(vgl), "preVerificationGas": hex(pvg),
        "maxFeePerGas": "0x1e", "maxPriorityFeePerGas": "0x3",
        "paymasterAndData": "0x", "signature": "0x" + "11" * 65,
    })


def _gas_manager(version: str):
    """A v0.6 or v0.7 gas manager against the mock node."""
    cls = GasManagerV6 if version == "v6" else GasManagerV7V8V9
    return cls(NODE, CHAIN_ID, BUNDLER, False, 10_000_000, 30_000_000,
               GasPriceCache(NODE, CHAIN_ID, False, 10.0))


# --------------------------------------------------------------- floor

def test_floor_gas_rates(floors):
    """No floor without a flag; 10 per token (zero byte 1, non-zero 4)
    under EIP-7623; 64 per byte, zero or not, under EIP-7976."""
    data = b"\x00" * 10 + b"\xff" * 5
    assert calldata_floor.floor_gas(data) == 0
    assert not calldata_floor.active()
    floors(eip7623=True)
    assert calldata_floor.active()
    assert calldata_floor.floor_gas(data) == 10 * (10 + 4 * 5)
    floors(eip8037_flag=True)
    assert calldata_floor.active()
    assert calldata_floor.floor_gas(data) == 64 * 15
    floors(eip7623=True, eip8037_flag=True)
    assert calldata_floor.floor_gas(data) == 64 * 15


def test_bundle_gas_limit_is_raised_to_the_floor(floors):
    """A transaction below 21000 + floor is invalid, so the bundle gas
    limit is raised to it, and left alone above it or without a floor."""
    data = b"\xff" * 1000
    assert calldata_floor.bundle_gas_limit(30_000, data) == 30_000
    floors(eip7623=True)
    assert calldata_floor.bundle_gas_limit(30_000, data) == 21_000 + 40_000
    assert calldata_floor.bundle_gas_limit(100_000, data) == 100_000
    floors(eip8037_flag=True)
    assert calldata_floor.bundle_gas_limit(30_000, data) == 21_000 + 64_000


def test_top_up_is_the_floor_less_the_gas_the_operation_surely_uses(floors):
    """An operation's floor less its overhead (without the base
    transaction share) and a tenth of its execution limits; never
    negative; 0 without a floor."""
    packed = b"\xff" * 1000  # floor 40,000 under 7623, 64,000 under 7976
    assert calldata_floor.pre_verification_gas_top_up(packed, 40_000, 100_000) == 0
    floors(eip7623=True)
    # overhead 40,000 - 21,000 = 19,000, plus 10,000 of execution: 29,000 used
    assert calldata_floor.pre_verification_gas_top_up(packed, 40_000, 100_000) == 11_000
    # enough execution covers the floor
    assert calldata_floor.pre_verification_gas_top_up(packed, 40_000, 300_000) == 0
    floors(eip8037_flag=True)
    assert calldata_floor.pre_verification_gas_top_up(packed, 40_000, 100_000) == 35_000


# -------------------------------------------- preVerificationGas

@pytest.mark.parametrize("version", ["v6", "v7"])
@pytest.mark.asyncio
async def test_pvg_covers_the_floor_of_a_calldata_heavy_operation(version, floors):
    """A large callData with a small callGasLimit: the quoted
    preVerificationGas rises by exactly the top-up, under either floor."""
    gas_manager = _gas_manager(version)
    make = _op_v6 if version == "v6" else _op_v7
    entrypoint = ENTRYPOINT_V6 if version == "v6" else ENTRYPOINT_V7
    op = make(cgl=50_000, vgl=100_000, call_data="0x" + "ab" * 4000)
    packed = gas_manager.packed_for_preverification_gas(op)

    base = await gas_manager.get_preverification_gas(op, entrypoint)
    for select in ({"eip7623": True}, {"eip8037_flag": True}):
        floors(**select)
        expected = base + calldata_floor.pre_verification_gas_top_up(
            packed, base, 50_000)
        assert expected > base
        with patch("voltaire_bundler.gas.gas_manager.send_rpc_request_to_eth_client",
                   new_callable=AsyncMock, return_value={"result": hex(10**18)}):
            assert await gas_manager.get_preverification_gas(op, entrypoint) == expected


@pytest.mark.asyncio
async def test_pvg_is_unchanged_when_execution_covers_the_floor(floors):
    """An ordinary operation (small callData, real callGasLimit) pays no
    top-up: its execution already lifts the bundle above the floor."""
    gas_manager = _gas_manager("v7")
    op = _op_v7(cgl=300_000, vgl=100_000, call_data="0x" + "ab" * 100)
    base = await gas_manager.get_preverification_gas(op, ENTRYPOINT_V7)
    floors(eip7623=True)
    assert await gas_manager.get_preverification_gas(op, ENTRYPOINT_V7) == base


@pytest.mark.asyncio
async def test_post_op_counts_as_execution(floors):
    """The paymaster's postOp limit is execution the operation is sure to
    use a tenth of, so it lowers the top-up."""
    gas_manager = _gas_manager("v7")
    floors(eip7623=True)
    without = _op_v7(cgl=50_000, vgl=100_000, call_data="0x" + "ab" * 4000)
    with_post_op = _op_v7(cgl=50_000, vgl=100_000, call_data="0x" + "ab" * 4000,
                          post_op=200_000)
    assert gas_manager.execution_gas_limit(without) == 50_000
    assert gas_manager.execution_gas_limit(with_post_op) == 250_000
    packed = gas_manager.packed_for_preverification_gas(without)
    assert (calldata_floor.pre_verification_gas_top_up(packed, 60_000, 250_000)
            < calldata_floor.pre_verification_gas_top_up(packed, 60_000, 50_000))


@pytest.mark.asyncio
async def test_submission_rejects_a_pvg_that_omits_the_floor(floors):
    """The submit-time check goes through the same quote, so an operation
    submitted with the floor-less preVerificationGas is rejected."""
    gas_manager = _gas_manager("v7")
    op = _op_v7(cgl=50_000, vgl=100_000, call_data="0x" + "ab" * 4000)
    base = await gas_manager.get_preverification_gas(op, ENTRYPOINT_V7)
    op.pre_verification_gas = base
    await gas_manager.verify_preverification_gas_and_verification_gas_limit(
        op, ENTRYPOINT_V7)
    floors(eip7623=True)
    with pytest.raises(ValidationException) as excinfo:
        await gas_manager.verify_preverification_gas_and_verification_gas_limit(
            op, ENTRYPOINT_V7)
    assert "preVerificationGas is too low" in excinfo.value.message


# ------------------------------------------------------- bundle gas

@pytest.mark.asyncio
async def test_bundle_gas_limit_covers_the_handleops_floor(floors):
    """A bundle of calldata-heavy operations with small limits is sent
    with at least 21000 + the floor of its handleOps calldata."""
    from types import SimpleNamespace
    manager = object.__new__(BundlerManager)
    manager.chain_id = CHAIN_ID
    manager.bundle_gas_estimation_multiplier = 1.1
    manager.conditional_rpc = None
    manager.ethereum_node_urls = NODE
    manager.user_operations_to_ban = {}
    manager.local_mempool_manager_v9 = SimpleNamespace(entrypoint="0x" + "09" * 20)
    manager.local_mempool_manager_v8 = SimpleNamespace(entrypoint="0x" + "08" * 20)
    manager.local_mempool_manager_v7 = SimpleNamespace(entrypoint=ENTRYPOINT_V7)
    ops = [_op_v7(cgl=5_000, vgl=5_000, pvg=5_000, call_data="0x" + "ab" * 8000)]

    async def ok(nodes_urls, method, params, *args):
        """The pre-check succeeds."""
        return {"result": "0x"}

    limits = {}
    for name, select in (("none", {}), ("7623", {"eip7623": True}),
                         ("7976", {"eip8037_flag": True})):
        floors(**select)
        with patch("voltaire_bundler.bundle.bundle_manager.send_rpc_request_to_eth_client",
                   new_callable=AsyncMock, side_effect=ok):
            call_data, limits[name], _, _ = \
                await manager.create_bundle_calldata_and_estimate_gas(
                    list(ops), BUNDLER, ENTRYPOINT_V7, 0)
    calldata = bytes.fromhex(call_data[2:])
    floors(eip7623=True)
    assert limits["7623"] == 21_000 + calldata_floor.floor_gas(calldata)
    floors(eip8037_flag=True)
    assert limits["7976"] == 21_000 + calldata_floor.floor_gas(calldata)
    assert limits["none"] < limits["7623"] < limits["7976"]


@pytest.mark.asyncio
async def test_packing_bound_still_covers_a_floor_raised_bundle(floors):
    """Under --eip8037 the bundle gas limit can be the EIP-7976 floor; the
    mempool's packing bound (eip8037.operation_bundle_gas) must stay above
    it. It does because an operation's quoted preVerificationGas already
    carries its own floor less a tenth of its execution."""
    from voltaire_bundler.bundle.bundle_manager import \
        calculate_bundle_calldata_init_gas
    from voltaire_bundler.utils.eth_client_utils import \
        encode_handleops_calldata_v7v8v9
    floors(eip8037_flag=True)
    gas_manager = _gas_manager("v7")
    ops = []
    for i, size in enumerate((8000, 3000, 500)):
        op = _op_v7(cgl=5_000, vgl=5_000, call_data="0x" + "ab" * size)
        op.sender_address = f"0x{i + 1:040x}"
        with patch("voltaire_bundler.gas.gas_manager.send_rpc_request_to_eth_client",
                   new_callable=AsyncMock, return_value={"result": hex(10**18)}):
            op.pre_verification_gas = await gas_manager.get_preverification_gas(
                op, ENTRYPOINT_V7)
        ops.append(op)
    call_data = encode_handleops_calldata_v7v8v9([op.to_list() for op in ops], BUNDLER)
    calldata = bytes.fromhex(call_data[2:])
    limit = (sum(op.get_max_gas_with_pre_verification_gas() for op in ops)
             + 50_000 + calculate_bundle_calldata_init_gas(call_data))
    limit = calldata_floor.bundle_gas_limit(limit, calldata)
    bound = eip8037.BUNDLE_OVERHEAD_GAS + sum(
        eip8037.operation_bundle_gas(op) for op in ops)
    assert bound >= limit


# -------------------------------------------------------------------- cli

def test_cli_floor_is_on_by_default_and_can_be_turned_off(monkeypatch):
    """No flag and no env means the EIP-7623 floor; --eip7623 false or
    VOLTAIRE_EIP7623=false turns it off."""
    from voltaire_bundler.cli_manager import initialize_argument_parser
    monkeypatch.delenv("VOLTAIRE_EIP7623", raising=False)
    base = ["--bundler_secret", "0x" + "11" * 32, "--chain_id", "1"]
    assert initialize_argument_parser().parse_args(base).eip7623 is True
    assert initialize_argument_parser().parse_args(
        base + ["--eip7623", "false"]).eip7623 is False
    assert initialize_argument_parser().parse_args(
        base + ["--eip7623"]).eip7623 is True
    monkeypatch.setenv("VOLTAIRE_EIP7623", "false")
    assert initialize_argument_parser().parse_args(base).eip7623 is False


def test_module_default_is_on():
    """The module default matches the CLI default."""
    import importlib
    assert importlib.reload(calldata_floor).enabled is True
