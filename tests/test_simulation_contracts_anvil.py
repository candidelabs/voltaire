"""
End-to-end check of the shipped EntryPointSimulations*WithBinarySearch
bytecode on a real EVM (anvil), driven through the real gas managers.

The simulation bytecode is injected at the EntryPoint address via eth_call
state overrides, so nothing has to be deployed: the EntryPoint's storage is
empty (sender deposit 0 - the exact state behind the EIP-8037 deposit-slot
undercount), and the sender is a minimal hand-assembled account that pays
whatever prefund it is asked for and accepts any call. A non-zero
maxFeePerGas makes the prefund real, so validation creates the deposit slot
and resets it, exercising the measurement path the contracts were changed
for. anvil has no EIP-8037, so the account-call bound can only be shown to
be harmless here (it never exceeds the net figure); the point is that every
version's recompiled bytecode executes validation + the callGasLimit search
without reverting.

Skipped when anvil is not installed. Lives at the tests/ top level because
tests/v6/conftest.py autouses geth-docker fixtures for that directory.
"""

import json
import shutil
import socket
import subprocess
import time
import urllib.request
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio

from voltaire_bundler.gas.gas_manager_v6 import GasManagerV6
from voltaire_bundler.gas.gas_manager_v7v8v9 import GasManagerV7V8V9
from voltaire_bundler.gas.gas_price_cache import GasPriceCache
from voltaire_bundler.user_operation.user_operation_v6 import UserOperationV6
from voltaire_bundler.user_operation.user_operation_v7v8v9 import UserOperationV7V8V9
from voltaire_bundler.utils import eth_client_utils

pytestmark = pytest.mark.skipif(shutil.which("anvil") is None, reason="anvil not installed")

ENTRYPOINTS = {
    "v6": "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789",
    "v7": "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
    "v8": "0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108",
    "v9": "0x433709009B8330FDa32311DF1C2AFA402eD8D009",
}
BUNDLER_ADDRESS = "0x0000000000000000000000000000000000000001"
SENDER = "0x7e25461EEE6853f89e5bA2bDf87F47a8965EbE04"
CHAIN_ID = 1337
MAX_VERIFICATION_GAS = 10_000_000
MAX_CALL_DATA_GAS = 30_000_000
ONE_GWEI = 10**9

# validateUserOp(op, hash, missingAccountFunds): forward missingAccountFunds
# (3rd arg, calldata offset 0x44) to the caller (the EntryPoint, whose
# receive() deposits it) and return 0 (validation ok). Empty calldata (the
# execution call) takes the same path with value 0 and succeeds.
ACCOUNT_CODE = "0x" + "".join([
    "6000", "6000", "6000", "6000",  # retSize, retOffset, argsSize, argsOffset
    "604435",                        # CALLDATALOAD(0x44) -> value
    "33",                            # CALLER -> to
    "5a",                            # GAS
    "f1", "50",                      # CALL, POP
    "6000", "6000", "52",            # MSTORE(0, 0)
    "6020", "6000", "f3",            # RETURN(0, 32)
])


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def anvil_url():
    """One anvil and one event loop for the whole module: the bundler's RPC
    helper keeps a process-wide aiohttp session bound to the loop it was
    first used on, so the tests share a loop and the session is closed at
    teardown for whatever runs next."""
    port = _free_port()
    proc = subprocess.Popen(
        ["anvil", "--port", str(port), "--chain-id", str(CHAIN_ID), "--silent"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                req = urllib.request.Request(
                    url, data=json.dumps({"jsonrpc": "2.0", "id": 1,
                                          "method": "eth_chainId", "params": []}).encode(),
                    headers={"content-type": "application/json"})
                urllib.request.urlopen(req, timeout=1).read()
                break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("anvil did not start")
        yield url
    finally:
        if eth_client_utils._session is not None:
            await eth_client_utils._session.close()
            eth_client_utils._session = None
        proc.kill()
        proc.wait()


def _make_gas_manager(version: str, url: str):
    cls = GasManagerV6 if version == "v6" else GasManagerV7V8V9
    return cls(
        ethereum_node_urls=[url],
        chain_id=CHAIN_ID,
        bundler_address=BUNDLER_ADDRESS,
        is_legacy_mode=False,
        max_verification_gas=MAX_VERIFICATION_GAS,
        max_call_data_gas=MAX_CALL_DATA_GAS,
        gas_price_cache=GasPriceCache(
            ethereum_node_urls=[url], chain_id=CHAIN_ID,
            is_legacy_mode=False, refresh_interval_seconds=10.0,
        ),
    )


def _make_user_operation(version: str):
    common = {
        "sender": SENDER,
        "nonce": "0x0",
        "callData": "0x",
        "callGasLimit": "0x0",
        "verificationGasLimit": "0x0",
        "preVerificationGas": "0x0",
        "maxFeePerGas": hex(ONE_GWEI),
        "maxPriorityFeePerGas": hex(ONE_GWEI),
        "signature": "0x" + "00" * 65,
    }
    if version == "v6":
        return UserOperationV6({**common, "initCode": "0x", "paymasterAndData": "0x"})
    return UserOperationV7V8V9({
        **common,
        "factory": None, "factoryData": None,
        "paymaster": None, "paymasterVerificationGasLimit": None,
        "paymasterPostOpGasLimit": None, "paymasterData": None,
        "eip7702Auth": None,
    })


@pytest.mark.parametrize("version", ["v6", "v7", "v8", "v9"])
@pytest.mark.asyncio(loop_scope="module")
async def test_estimation_runs_on_anvil_and_verify_pass_accepts_the_quote(anvil_url, version):
    gas_manager = _make_gas_manager(version, anvil_url)
    user_operation = _make_user_operation(version)
    sender_override = {SENDER: {"code": ACCOUNT_CODE, "balance": hex(10**18)}}
    module = ("voltaire_bundler.gas.gas_manager_v6" if version == "v6"
              else "voltaire_bundler.gas.gas_manager_v7v8v9")

    with patch(f"{module}.send_rpc_request_to_eth_client",
               new_callable=AsyncMock,
               side_effect=eth_client_utils.send_rpc_request_to_eth_client) as rpc:
        call_gas_hex, prever_gas_hex, ver_gas_hex = (
            await gas_manager.estimate_user_operation_gas(
                user_operation, ENTRYPOINTS[version], sender_override
            )
        )

    verification_gas = int(ver_gas_hex, 16)
    call_gas = int(call_gas_hex, 16)
    # validation of this account: deposit the prefund (slot creation) and
    # the EntryPoint's own bookkeeping - tens of thousands of gas, well
    # under the 10M cap it was measured under
    assert 20_000 < verification_gas < 300_000
    assert 3_000 <= call_gas < 50_000
    assert int(prever_gas_hex, 16) > 0

    simulations = [c for c in rpc.call_args_list if c[0][1] == "eth_call"]
    # the in-contract search finishes in one eth_call for a trivial callData
    # (chain 1337 is not an EIP-8037 chain, so no verify probe follows)
    assert len(simulations) == 1


@pytest.mark.asyncio(loop_scope="module")
async def test_eip7702_authorization_gas_is_flat_25k_on_a_standard_chain(anvil_url):
    """Without EIP-8037 every authority class costs PER_EMPTY_ACCOUNT_COST
    up front; the measurement must find that on its own (no chain list),
    and anvil must accept the type-4 estimate with state overrides."""
    from voltaire_bundler.gas.eip7702_auth_gas import (
        AUTHORITY_CLASSES, PER_EMPTY_ACCOUNT_COST, Eip7702AuthGas,
    )
    # a real EOA, not BUNDLER_ADDRESS: 0x..01 is the ecrecover precompile
    # and anvil prices a type-4 self-call to it differently (28k)
    table = Eip7702AuthGas(
        [anvil_url], "0x6eb0296e64fB8d9D946c7b819E4FF55c7167B0Ce", CHAIN_ID
    )

    costs = await table.measure()

    for cls in AUTHORITY_CLASSES:
        # anvil reports one extra gas unit over the nominal figure
        assert PER_EMPTY_ACCOUNT_COST <= costs[cls] <= PER_EMPTY_ACCOUNT_COST + 100, cls
    assert len(set(costs.values())) == 1
