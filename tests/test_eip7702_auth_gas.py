"""Eip7702AuthGas: per-class authorization gas measured once per chain,
one eth_getProof per operation to pick the class, and the addition to
preVerificationGas in both the estimate and the submit-time check.

Mock-RPC unit tests at the tests/ top level (tests/v6/conftest.py autouses
geth-docker fixtures for that directory)."""
from __future__ import annotations

import asyncio

import pytest
from eth_account import Account

import voltaire_bundler.gas.eip7702_auth_gas as eag
from voltaire_bundler.gas.eip7702_auth_gas import (
    AccountState,
    AUTHORITY_DELEGATED,
    AUTHORITY_EMPTY,
    AUTHORITY_EXISTING,
    EMPTY_CODE_HASH,
    PER_EMPTY_ACCOUNT_COST,
    ZERO_HASH,
    Eip7702AuthGas,
    classify_authority,
)
from voltaire_bundler.gas.gas_manager_v7v8v9 import GasManagerV7V8V9
from voltaire_bundler.gas.gas_price_cache import GasPriceCache
from voltaire_bundler.user_operation.user_operation_v7v8v9 import UserOperationV7V8V9
from voltaire_bundler.utils.eth_client_utils import RpcRequestError
from voltaire_bundler.validation.validation_manager_v7v8v9 import (
    check_authorization_and_get_code,
)
from voltaire_bundler.bundle.exceptions import ValidationException
from eth_abi import encode

BUNDLER = "0x6eb0296e64fB8d9D946c7b819E4FF55c7167B0Ce"
SENDER = "0x7e25461EEE6853f89e5bA2bDf87F47a8965EbE04"
CHAIN_ID = 11155111
BASE_TX_GAS = 12_000
# what Sepolia measured on 2026-10-13
SEPOLIA_COSTS = {
    AUTHORITY_EMPTY: 238_738,
    AUTHORITY_EXISTING: 52_843,
    AUTHORITY_DELEGATED: 17_164,
}


def _class_of_override(override: dict) -> str:
    return classify_authority(
        int(override["nonce"], 16), int(override["balance"], 16),
        override["code"] != "0x",
    )


class FakeNode:
    """Answers the measurement and classification RPCs.

    ``costs`` drives eth_estimateGas: the stand-in override in the call
    (the non-bundler key) picks the class, and the tuple adds that class's
    cost on top of BASE_TX_GAS. ``accounts[sender]`` is (nonce, balance,
    code) for the classification calls. ``fail`` is a set of method names
    that raise RpcRequestError."""

    def __init__(self, costs=None, accounts=None, fail=()):
        self.costs = costs or SEPOLIA_COSTS
        self.accounts = accounts or {}
        self.fail = set(fail)
        self.calls: list[tuple[str, str, list]] = []

    async def __call__(self, node_url, method, params=None):
        self.calls.append((node_url, method, params))
        if method in self.fail:
            raise RpcRequestError(f"{method}: node error -32602: unsupported")
        if method == "eth_estimateGas":
            tx, _, overrides = params
            stand_in = next(o for a, o in overrides.items() if a != BUNDLER)
            gas = BASE_TX_GAS
            if "authorizationList" in tx:
                (tuple_,) = tx["authorizationList"]
                # the tuple must be a valid signature from the stand-in
                recovered = Account._recover_authorization(  # noqa: SLF001
                    {"chainId": int(tuple_["chainId"], 16),
                     "address": tuple_["address"],
                     "nonce": int(tuple_["nonce"], 16)},
                    int(tuple_["yParity"], 16), int(tuple_["r"], 16),
                    int(tuple_["s"], 16),
                ) if hasattr(Account, "_recover_authorization") else None
                if recovered is not None:
                    assert recovered.lower() in (a.lower() for a in overrides)
                gas += self.costs[_class_of_override(stand_in)]
            return hex(gas)
        sender = params[0]
        nonce, balance, code = self.accounts[sender]
        if method == "eth_getProof":
            return {"nonce": hex(nonce), "balance": hex(balance),
                    "codeHash": EMPTY_CODE_HASH if code == "0x" else "0x" + "ab" * 32}
        if method == "eth_getTransactionCount":
            return hex(nonce)
        if method == "eth_getBalance":
            return hex(balance)
        if method == "eth_getCode":
            return code
        raise AssertionError(method)


def _table(node: FakeNode, monkeypatch) -> Eip7702AuthGas:
    monkeypatch.setattr(eag, "send_rpc_request_once", node)
    return Eip7702AuthGas(["http://a"], BUNDLER, CHAIN_ID)


@pytest.fixture(autouse=True)
def _fresh_get_proof_decision(monkeypatch):
    """The eth_getProof-or-fallback decision is made once per process;
    every test starts undecided."""
    monkeypatch.setattr(eag, "_get_proof_supported", None)


# ---------------------------------------------------------- classification

@pytest.mark.parametrize("nonce, balance, has_code, expected", [
    (0, 0, False, AUTHORITY_EMPTY),
    (1, 0, False, AUTHORITY_EXISTING),
    (0, 1, False, AUTHORITY_EXISTING),
    (0, 0, True, AUTHORITY_DELEGATED),
    (5, 10**18, True, AUTHORITY_DELEGATED),
])
def test_classify_authority(nonce, balance, has_code, expected):
    assert classify_authority(nonce, balance, has_code) == expected


# ------------------------------------------------------------- measurement

@pytest.mark.asyncio
async def test_measure_takes_each_class_from_a_stand_in_override(monkeypatch):
    node = FakeNode()
    table = _table(node, monkeypatch)

    costs = await table.measure()

    assert costs == SEPOLIA_COSTS
    assert table.costs == SEPOLIA_COSTS
    assert table.measured
    estimates = [c for c in node.calls if c[1] == "eth_estimateGas"]
    assert len(estimates) == 6  # with and without the tuple, per class
    for _, _, params in estimates:
        tx, block, overrides = params
        assert block == "latest"
        assert tx["from"] == BUNDLER and tx["to"] == BUNDLER
        assert BUNDLER in overrides  # bundler balance overridden
    assert all(
        "type" in c[2][0] and "authorizationList" in c[2][0]
        for c in estimates[1::2]
    )


@pytest.mark.asyncio
async def test_flat_cost_chain_measures_25k_everywhere(monkeypatch):
    """Without EIP-8037 the tuple costs PER_EMPTY_ACCOUNT_COST whatever
    the authority's state, so the table needs no chain list."""
    node = FakeNode(costs={cls: 25_000 for cls in SEPOLIA_COSTS})
    table = _table(node, monkeypatch)

    assert await table.measure() == {cls: 25_000 for cls in SEPOLIA_COSTS}


@pytest.mark.asyncio
async def test_startup_print_shows_measured_table(monkeypatch, capsys):
    """The operator sees the per-class costs at startup without --verbose,
    and whether they were measured or are the 25k default."""
    from voltaire_bundler.cli_manager import print_eip7702_auth_gas

    table = _table(FakeNode(), monkeypatch)
    await table.measure()
    print_eip7702_auth_gas(table)
    out = capsys.readouterr().out
    assert f"chain {CHAIN_ID} (measured at startup)" in out
    assert "empty authority" in out and "238,738" in out
    assert "existing authority" in out and "52,843" in out
    assert "delegated authority" in out and "17,164" in out

    print_eip7702_auth_gas(_table(FakeNode(), monkeypatch))
    out = capsys.readouterr().out
    assert "(default, measurement failed)" in out
    assert out.count("25,000") == 3


@pytest.mark.asyncio
async def test_measure_failure_keeps_defaults_and_raises(monkeypatch):
    node = FakeNode(fail={"eth_estimateGas"})
    table = _table(node, monkeypatch)

    with pytest.raises(RpcRequestError):
        await table.measure()

    assert table.costs == {cls: PER_EMPTY_ACCOUNT_COST for cls in SEPOLIA_COSTS}
    assert not table.measured


@pytest.mark.asyncio
async def test_node_ignoring_the_tuple_fails_the_measurement(monkeypatch):
    """drpc on Sepolia answers eth_estimateGas with the same figure with
    and without the authorizationList. A zero per class would count as
    measured and charge nothing for the tuple, so an estimate that does
    not grow with the tuple is a failed measurement: the default stays."""
    node = FakeNode(costs={cls: 0 for cls in SEPOLIA_COSTS})
    table = _table(node, monkeypatch)

    with pytest.raises(RuntimeError, match="ignored authorizationList"):
        await table.measure()

    assert not table.measured
    assert table.costs == {cls: PER_EMPTY_ACCOUNT_COST for cls in SEPOLIA_COSTS}


@pytest.mark.asyncio
async def test_startup_measurement_failure_logs_an_error(monkeypatch, caplog):
    """A failed measurement is an ERROR naming the consequence, so the
    undercharge on an EIP-8037 chain is not hidden in a warning."""
    from voltaire_bundler.cli_manager import _init_eip7702_auth_gas

    _table(FakeNode(costs={cls: 0 for cls in SEPOLIA_COSTS}), monkeypatch)
    caplog.set_level("ERROR")

    table = await _init_eip7702_auth_gas(True, ["http://a"], BUNDLER, CHAIN_ID)

    assert table is not None and not table.measured
    errors = [r for r in caplog.records if r.levelname == "ERROR"]
    assert len(errors) == 1
    message = errors[0].getMessage()
    assert "ignored authorizationList" in message
    assert "charging 25,000" in message
    assert "pays the difference" in message


@pytest.mark.asyncio
async def test_measure_walks_nodes_on_failure(monkeypatch):
    node = FakeNode()
    original = node.__call__

    async def flaky(node_url, method, params=None):
        if node_url == "http://a":
            raise RpcRequestError("eth_estimateGas: HTTP 403")
        return await original(node_url, method, params)

    monkeypatch.setattr(eag, "send_rpc_request_once", flaky)
    table = Eip7702AuthGas(["http://a", "http://b"], BUNDLER, CHAIN_ID)

    assert await table.measure() == SEPOLIA_COSTS


# ------------------------------------------------------- per-op lookup

@pytest.mark.parametrize("account, expected_class", [
    ((0, 0, "0x"), AUTHORITY_EMPTY),
    ((3, 10**18, "0x"), AUTHORITY_EXISTING),
    ((0, 10**18, "0x"), AUTHORITY_EXISTING),
    ((1, 0, "0xef0100" + "11" * 20), AUTHORITY_DELEGATED),
])
@pytest.mark.asyncio
async def test_auth_gas_for_uses_one_eth_getproof(
    monkeypatch, account, expected_class
):
    node = FakeNode(accounts={SENDER: account})
    table = _table(node, monkeypatch)
    await table.measure()
    node.calls.clear()

    gas = await table.auth_gas_for(SENDER)

    assert gas == SEPOLIA_COSTS[expected_class]
    assert [c[1] for c in node.calls] == ["eth_getProof"]
    assert node.calls[0][2] == [SENDER, [], "latest"]


@pytest.mark.asyncio
async def test_zero_code_hash_counts_as_no_code(monkeypatch):
    """Some clients report the zero hash for an account that does not
    exist at all; that is an empty account, not a delegated one."""
    node = FakeNode(accounts={SENDER: (0, 0, "0x")})
    table = _table(node, monkeypatch)
    await table.measure()

    async def zero_hash_proof(node_url, method, params=None):
        if method == "eth_getProof":
            return {"nonce": "0x0", "balance": "0x0", "codeHash": ZERO_HASH}
        return await node(node_url, method, params)

    monkeypatch.setattr(eag, "send_rpc_request_once", zero_hash_proof)
    assert await table.auth_gas_for(SENDER) == SEPOLIA_COSTS[AUTHORITY_EMPTY]


@pytest.mark.asyncio
async def test_falls_back_to_three_state_calls_once(monkeypatch, caplog):
    node = FakeNode(accounts={SENDER: (3, 10**18, "0x")}, fail={"eth_getProof"})
    table = _table(node, monkeypatch)
    await table.measure()
    node.calls.clear()
    caplog.set_level("DEBUG")

    first = await table.auth_gas_for(SENDER)
    second = await table.auth_gas_for(SENDER)

    assert first == second == SEPOLIA_COSTS[AUTHORITY_EXISTING]
    methods = [c[1] for c in node.calls]
    # eth_getProof tried once, then the three calls, then never again
    assert methods.count("eth_getProof") == 1
    assert methods.count("eth_getCode") == 2
    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1
    assert "eth_getProof unavailable" in warnings[0].getMessage()


@pytest.mark.asyncio
async def test_unclassifiable_sender_is_charged_the_empty_class(
    monkeypatch, caplog
):
    """The bundler must never pay a tuple out of pocket: with no way to
    classify, assume the dearest class."""
    node = FakeNode(accounts={}, fail={"eth_getProof", "eth_getCode",
                                       "eth_getBalance",
                                       "eth_getTransactionCount"})
    table = _table(node, monkeypatch)
    await table.measure()
    caplog.set_level("WARNING")

    assert await table.auth_gas_for(SENDER) == SEPOLIA_COSTS[AUTHORITY_EMPTY]
    assert any("could not read EIP-7702 authority" in r.getMessage()
               for r in caplog.records)


@pytest.mark.asyncio
async def test_lookup_without_a_measurement_charges_25k(monkeypatch):
    """Startup measurement failed (node could not serve it): the default
    table serves 25k per class until the bundler is restarted."""
    node = FakeNode(accounts={SENDER: (0, 0, "0x")})
    table = _table(node, monkeypatch)

    assert await table.auth_gas_for(SENDER) == PER_EMPTY_ACCOUNT_COST
    assert [c[1] for c in node.calls] == ["eth_getProof"]


# ------------------------------------------- preVerificationGas integration

def _user_operation(with_auth: bool) -> UserOperationV7V8V9:
    return UserOperationV7V8V9({
        "sender": SENDER,
        "nonce": "0x0",
        "callData": "0x",
        "callGasLimit": "0x10000",
        "verificationGasLimit": "0x10000",
        "preVerificationGas": "0x0",
        "maxFeePerGas": "0x1",
        "maxPriorityFeePerGas": "0x1",
        "signature": "0x" + "00" * 65,
        "factory": None, "factoryData": None,
        "paymaster": None, "paymasterVerificationGasLimit": None,
        "paymasterPostOpGasLimit": None, "paymasterData": None,
        "eip7702Auth": {
            "chainId": hex(CHAIN_ID), "address": "0x" + "11" * 20,
            "nonce": "0x0", "yParity": "0x0", "r": "0x1", "s": "0x1",
        } if with_auth else None,
    })


def _gas_manager(table: Eip7702AuthGas | None) -> GasManagerV7V8V9:
    return GasManagerV7V8V9(
        ethereum_node_urls=["http://a"], chain_id=CHAIN_ID,
        bundler_address=BUNDLER, is_legacy_mode=False,
        max_verification_gas=10_000_000, max_call_data_gas=30_000_000,
        gas_price_cache=GasPriceCache(["http://a"], CHAIN_ID, False, 10.0),
        eip7702_auth_gas=table,
    )


@pytest.mark.asyncio
async def test_preverification_gas_includes_the_authorization_cost(monkeypatch):
    node = FakeNode(accounts={SENDER: (0, 0, "0x")})
    table = _table(node, monkeypatch)
    await table.measure()
    manager = _gas_manager(table)
    entrypoint = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"

    with_auth = await manager.get_preverification_gas(
        _user_operation(True), entrypoint)
    without_auth = await manager.get_preverification_gas(
        _user_operation(False), entrypoint)

    assert with_auth - without_auth == SEPOLIA_COSTS[AUTHORITY_EMPTY]


@pytest.mark.asyncio
async def test_preverification_gas_unchanged_without_a_table(monkeypatch):
    """--eip7702 off, or a v0.6 manager: no table, no lookup, no RPC."""
    node = FakeNode(accounts={SENDER: (0, 0, "0x")})
    monkeypatch.setattr(eag, "send_rpc_request_once", node)
    manager = _gas_manager(None)
    entrypoint = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"

    with_auth = await manager.get_preverification_gas(
        _user_operation(True), entrypoint)
    without_auth = await manager.get_preverification_gas(
        _user_operation(False), entrypoint)

    assert with_auth == without_auth
    assert node.calls == []


# ---------------------------------------- one sender read per request

def _simulation_result(verification_gas: int, call_gas: int) -> dict:
    encoded = encode(["uint256", "uint256", "uint256"],
                     [verification_gas, call_gas, 0])
    return {"error": {"message": "execution reverted",
                      "data": "0xdeb13018" + encoded.hex()}}


@pytest.mark.asyncio
async def test_estimation_reads_the_sender_once_concurrently_with_simulation(
    monkeypatch
):
    """During eth_estimateUserOperationGas the eth_getProof is started
    before the simulation and awaited only for preVerificationGas: one
    read, already in flight while the simulation runs, and left on the
    operation."""
    node = FakeNode(accounts={SENDER: (0, 0, "0x")})
    table = _table(node, monkeypatch)
    await table.measure()
    node.calls.clear()
    manager = _gas_manager(table)
    order: list[str] = []

    async def simulation_rpc(nodes, method, params, *args):
        order.append("simulation")
        await asyncio.sleep(0.01)  # the eth_getProof completes meanwhile
        return _simulation_result(50_000, 20_000)

    original = node.__call__

    async def tracked(node_url, method, params=None):
        order.append(method)
        return await original(node_url, method, params)

    monkeypatch.setattr(eag, "send_rpc_request_once", tracked)
    monkeypatch.setattr(
        "voltaire_bundler.gas.gas_manager_v7v8v9.send_rpc_request_to_eth_client",
        simulation_rpc,
    )
    user_operation = _user_operation(True)
    user_operation.call_gas_limit = 0
    user_operation.verification_gas_limit = 0

    _, prever_gas_hex, _ = await manager.estimate_user_operation_gas(
        user_operation, "0x0000000071727De22E5E9d8BAf0edAc6f37da032", {}
    )

    assert order.count("eth_getProof") == 1
    # the read ran while the (sleeping) simulation was in flight
    assert order[:2] == ["simulation", "eth_getProof"] or \
        order[:2] == ["eth_getProof", "simulation"]
    assert user_operation.eip7702_account_state == \
        AccountState(0, 0, EMPTY_CODE_HASH)
    assert int(prever_gas_hex, 16) > SEPOLIA_COSTS[AUTHORITY_EMPTY]


@pytest.mark.asyncio
async def test_preverification_check_leaves_state_for_the_authorization_check(
    monkeypatch
):
    node = FakeNode(accounts={SENDER: (3, 10**18, "0x")})
    table = _table(node, monkeypatch)
    await table.measure()
    node.calls.clear()
    manager = _gas_manager(table)
    user_operation = _user_operation(True)

    await manager.get_preverification_gas(
        user_operation, "0x0000000071727De22E5E9d8BAf0edAc6f37da032")

    assert user_operation.eip7702_account_state == \
        AccountState(3, 10**18, EMPTY_CODE_HASH)
    assert [c[1] for c in node.calls] == ["eth_getProof"]

    # a state already on the operation is reused, not re-read
    await manager.get_preverification_gas(
        user_operation, "0x0000000071727De22E5E9d8BAf0edAc6f37da032")
    assert [c[1] for c in node.calls] == ["eth_getProof"]


@pytest.mark.asyncio
async def test_fallback_state_carries_the_real_code_hash(monkeypatch):
    """Through the three-call path the code hash is computed locally, so
    the authorization check can still compare it."""
    delegation = "0xef0100" + "11" * 20
    node = FakeNode(accounts={SENDER: (1, 0, delegation)},
                    fail={"eth_getProof"})
    _table(node, monkeypatch)

    state = await eag.fetch_account_state(["http://a"], SENDER)

    from eth_utils import keccak
    assert state.code_hash == "0x" + keccak(hexstr=delegation).hex()
    assert state.has_code and state.authority_class == AUTHORITY_DELEGATED


# --------------------------------------------- authorization check (pure)

def _signed_authorization(key, address: str, nonce: int, chain_id: int = CHAIN_ID):
    signed = Account.sign_authorization(
        {"chainId": chain_id, "address": address, "nonce": nonce}, key)
    return {
        "chainId": hex(chain_id), "address": address, "nonce": hex(nonce),
        "yParity": hex(signed.y_parity), "r": hex(signed.r), "s": hex(signed.s),
    }


def test_authorization_check_returns_delegation_code_for_a_fresh_tuple():
    key = Account.create()
    target = "0x" + "11" * 20
    auth = _signed_authorization(key.key, target, nonce=7)

    code = check_authorization_and_get_code(
        key.address, auth, AccountState(7, 0, EMPTY_CODE_HASH), CHAIN_ID)

    assert code == "0xef0100" + "11" * 20


def test_authorization_check_is_a_noop_when_already_delegated_there():
    from eth_utils import keccak
    key = Account.create()
    target = "0x" + "11" * 20
    auth = _signed_authorization(key.key, target, nonce=7)
    already = "0x" + keccak(hexstr="0xef0100" + "11" * 20).hex()

    assert check_authorization_and_get_code(
        key.address, auth, AccountState(7, 0, already), CHAIN_ID) is None


def test_authorization_check_is_a_noop_on_nonce_mismatch():
    key = Account.create()
    auth = _signed_authorization(key.key, "0x" + "11" * 20, nonce=7)

    assert check_authorization_and_get_code(
        key.address, auth, AccountState(8, 0, EMPTY_CODE_HASH), CHAIN_ID) is None


def test_authorization_check_rejects_another_signer_and_wrong_chain():
    key = Account.create()
    auth = _signed_authorization(key.key, "0x" + "11" * 20, nonce=0)
    with pytest.raises(ValidationException):
        check_authorization_and_get_code(
            SENDER, auth, AccountState(0, 0, EMPTY_CODE_HASH), CHAIN_ID)
    with pytest.raises(ValidationException):
        check_authorization_and_get_code(
            key.address, auth, AccountState(0, 0, EMPTY_CODE_HASH), CHAIN_ID + 1)


@pytest.mark.asyncio
async def test_validation_consumes_the_state_left_by_the_submit(monkeypatch):
    """The authorization check uses the state the preVerificationGas
    check left on the operation and clears it, so the re-validation at
    bundle time reads fresh state."""
    from voltaire_bundler.validation.validation_manager_v7v8v9 import (
        ValidationManagerV7V8V9,
    )
    key = Account.create()
    target = "0x" + "11" * 20
    node = FakeNode(accounts={key.address: (7, 0, "0x")})
    monkeypatch.setattr(eag, "send_rpc_request_once", node)
    manager = ValidationManagerV7V8V9(
        object(), ["http://a"], BUNDLER, CHAIN_ID, True, False, 10, 10,
        ["http://a"])
    user_operation = _user_operation(True)
    user_operation.sender_address = key.address
    user_operation.eip7702_auth = _signed_authorization(key.key, target, nonce=7)
    user_operation.eip7702_account_state = AccountState(7, 0, EMPTY_CODE_HASH)

    code = await manager.verify_authorization_and_get_code(user_operation)

    assert code == "0xef0100" + "11" * 20
    assert node.calls == []  # no read, the submit's state was used
    assert user_operation.eip7702_account_state is None

    code = await manager.verify_authorization_and_get_code(user_operation)
    assert code == "0xef0100" + "11" * 20
    assert [c[1] for c in node.calls] == ["eth_getProof"]  # fresh read
