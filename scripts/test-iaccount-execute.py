#!/usr/bin/env python3
"""
End-to-end test: IAccountExecute gas estimation on v0.7, v0.8, v0.9 EntryPoints.

Verifies that the simulation contracts correctly handle executeUserOp
callData rewriting. Runs against a local anvil instance — no bundler needed.

Usage:
    # Start anvil first (in another terminal):
    anvil --chain-id 1337 --gas-limit 30000000 --port 8545 --block-time 1

    # Then deploy EntryPoints:
    ./scripts/local-dev-setup.sh   # or just the deploy steps

    # Then run this test:
    poetry run python3 scripts/test-iaccount-execute.py

    # Or run everything with:
    poetry run python3 scripts/test-iaccount-execute.py --start-anvil
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

from eth_abi import encode, decode

# ── Constants ────────────────────────────────────────────────────────

ANVIL_URL = "http://127.0.0.1:8545"
ENTRYPOINT_V07 = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
ENTRYPOINT_V08 = "0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108"
ENTRYPOINT_V09 = "0x433709009B8330FDa32311DF1C2AFA402eD8D009"
DETERMINISTIC_FACTORY = "0x4e59b44847b379578588920ca78fbf26c0b4956c"
FACTORY_DEPLOYER = "0x3fab184622dc19b6109349b94811493bf2a45362"
ANVIL_FUNDER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

# v0.9 gets deployed to a different address by the factory, then anvil_setCode
# copies it to the vanity address.
V09_FACTORY_ADDR = "0x40be45b895e2553602327bdf3adf2553d2a24a70"

# Test account address (arbitrary)
ACCOUNT_ADDRESS = "0x7e25461EEE6853f89e5bA2bDf87F47a8965EbE04"

# Bundler / from address for eth_call
BUNDLER_ADDRESS = "0x0000000000000000000000000000000000000001"

# MinimalIAccountExecute runtime bytecode (validates + implements executeUserOp)
MINIMAL_ACCOUNT_BYTECODE = (
    "0x60806040526004361061002c575f3560e01c806319822f7c146100375780638dd7712f"
    "1461007357610033565b3661003357005b5f5ffd5b348015610042575f5ffd5b5061005d"
    "600480360381019061005891906101ad565b61009b565b60405161006a9190610228565b"
    "60405180910390f35b34801561007e575f5ffd5b5061009960048036038101906100949190"
    "610241565b610118565b005b5f5f82111561010e575f3373ffffffffffffffffffffffff"
    "ffffffffffffffff16836040516100c9906102c8565b5f6040518083038185875af19250"
    "50503d805f8114610103576040519150601f19603f3d011682016040523d82523d5f6020"
    "84013e610108565b606091505b50509050505b5f90509392505050565b5050565b5f5ffd"
    "5b5f5ffd5b5f5ffd5b5f610120828403121561013e5761013d610124565b5b8190509291"
    "5050565b5f819050919050565b61015981610147565b8114610163575f5ffd5b50565b5f"
    "8135905061017481610150565b92915050565b5f819050919050565b61018c8161017a565b"
    "8114610196575f5ffd5b50565b5f813590506101a781610183565b92915050565b5f5f5f"
    "606084860312156101c4576101c361011c565b5b5f84013567ffffffffffffffff811115"
    "6101e1576101e0610120565b5b6101ed86828701610128565b93505060206101fe868287"
    "01610166565b925050604061020f86828701610199565b9150509250925092565b610222"
    "8161017a565b82525050565b5f60208201905061023b5f830184610219565b9291505056"
    "5b5f5f604083850312156102575761025661011c565b5b5f83013567ffffffffffffffff"
    "81111561027457610273610120565b5b61028085828601610128565b92505060206102918582"
    "8601610166565b9150509250929050565b5f81905092915050565b50565b5f6102b35f83"
    "61029b565b91506102be826102a5565b5f82019050919050565b5f6102d2826102a8565b"
    "915081905091905056fea2646970667358221220c5d0337181bc5cde10d2500ae62c433f"
    "5e55bbd8d943be74c8986d8a5a0a97fc64736f6c634300081d0033"
)

# Selectors
EXECUTE_USER_OP_SELECTOR = "8dd7712f"  # executeUserOp(PackedUserOperation,bytes32)
SIMULATE_HANDLE_OP_MOD_SELECTOR = "bbfd906b"  # simulateHandleOpMod(PackedUserOperation,EstimateCallGasArgs)
SIMULATION_RESULT_SELECTOR = "deb13018"  # SimulationResult(uint256,uint256,uint256)
ESTIMATE_REVERT_AT_MAX_SELECTOR = "59f233d2"  # EstimateCallGasRevertAtMax(bytes)


def rpc(method: str, params: list) -> dict:
    """Send a JSON-RPC request to anvil."""
    payload = json.dumps({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    }).encode()
    req = urllib.request.Request(
        ANVIL_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def wait_for_anvil(timeout: int = 10):
    """Wait for anvil to be ready."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            result = rpc("eth_chainId", [])
            if "result" in result:
                return
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError("anvil did not become ready in time")


def extract_deploy_data(version_label: str, var_name: str) -> str:
    """Extract deploy data from deploy.js for a given EntryPoint version."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    deploy_js = os.path.join(script_dir, "deploy.js")
    with open(deploy_js) as f:
        content = f.read()
    idx = content.find(f"Deploy Entrypoint {version_label}")
    if idx == -1:
        raise RuntimeError(f"Could not find 'Deploy Entrypoint {version_label}' in deploy.js")
    section = content[idx:idx + 200000]
    match = re.search(rf'var {var_name}\s*=\s*"(0x[0-9a-fA-F]+)"', section)
    if not match:
        raise RuntimeError(f"Could not find {var_name} in deploy.js")
    return match.group(1)


def deploy_factory():
    """Deploy the deterministic deployer factory."""
    # Fund factory deployer
    rpc("eth_sendTransaction", [{
        "from": ANVIL_FUNDER,
        "to": FACTORY_DEPLOYER,
        "value": "0x2386F26FC10000",
        "gas": "0x5208",
    }])

    # Deploy deterministic factory
    rpc("eth_sendRawTransaction", [
        "0xf8a58085174876e800830186a08080b853604580600e600039806000f350fe"
        "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0"
        "3601600081602082378035828234f58015156039578182fd5b8082525050506014"
        "600cf31ba022222222222222222222222222222222222222222222222222222222"
        "22222222a02222222222222222222222222222222222222222222222222222222222"
        "22222222"
    ])
    rpc("anvil_mine", ["0x2"])


def deploy_entrypoints():
    """Deploy EntryPoint v0.7, v0.8, and v0.9."""
    deploy_factory()

    # ── v0.7 ──
    deploy_data = extract_deploy_data("v0.07", "entrypointDeployDataV7")
    rpc("eth_sendTransaction", [{
        "from": ANVIL_FUNDER,
        "to": DETERMINISTIC_FACTORY,
        "data": deploy_data,
        "gas": "0x1C9C380",
    }])

    # ── v0.8 ──
    deploy_data = extract_deploy_data("v0.08", "entrypointDeployDataV8")
    rpc("eth_sendTransaction", [{
        "from": ANVIL_FUNDER,
        "to": DETERMINISTIC_FACTORY,
        "data": deploy_data,
        "gas": "0x1C9C380",
    }])

    # ── v0.9 ──
    deploy_data = extract_deploy_data("v0.09", "entrypointDeployDataV9")
    rpc("eth_sendTransaction", [{
        "from": ANVIL_FUNDER,
        "to": DETERMINISTIC_FACTORY,
        "data": deploy_data,
        "gas": "0x1C9C380",
    }])

    # Mine all deployment txs
    rpc("anvil_mine", ["0x4"])
    time.sleep(1)

    # v0.9: copy runtime bytecode from factory-deployed address to vanity address
    result = rpc("eth_getCode", [V09_FACTORY_ADDR, "latest"])
    runtime_code = result.get("result", "0x")
    if len(runtime_code) < 10:
        raise RuntimeError(f"Failed to fetch v0.9 runtime bytecode from {V09_FACTORY_ADDR}")
    rpc("anvil_setCode", [ENTRYPOINT_V09, runtime_code])

    # Verify all deployments
    for label, addr in [("v0.7", ENTRYPOINT_V07), ("v0.8", ENTRYPOINT_V08), ("v0.9", ENTRYPOINT_V09)]:
        result = rpc("eth_getCode", [addr, "latest"])
        code = result.get("result", "0x")
        if len(code) < 10:
            raise RuntimeError(f"EntryPoint {label} not deployed at {addr}")
        print(f"  EntryPoint {label} deployed at {addr} ({len(code)} chars)")


def setup_account():
    """Deploy minimal IAccountExecute account and deposit into all EntryPoints."""
    # Set account code
    rpc("anvil_setCode", [ACCOUNT_ADDRESS, MINIMAL_ACCOUNT_BYTECODE])
    result = rpc("eth_getCode", [ACCOUNT_ADDRESS, "latest"])
    if len(result.get("result", "0x")) < 10:
        raise RuntimeError("Failed to set account code")

    # Fund account with 100 ETH
    rpc("eth_sendTransaction", [{
        "from": ANVIL_FUNDER,
        "to": ACCOUNT_ADDRESS,
        "value": "0x56BC75E2D63100000",
        "gas": "0x5208",
    }])

    # Deposit into each EntryPoint for account
    padded = "000000000000000000000000" + ACCOUNT_ADDRESS[2:]
    for ep in [ENTRYPOINT_V07, ENTRYPOINT_V08, ENTRYPOINT_V09]:
        rpc("eth_sendTransaction", [{
            "from": ANVIL_FUNDER,
            "to": ep,
            "data": "0xb760faf9" + padded,
            "value": "0x8AC7230489E80000",
            "gas": "0x30000",
        }])

    rpc("anvil_mine", ["0x4"])
    print(f"  Account deployed at {ACCOUNT_ADDRESS}")
    print(f"  Deposited 10 ETH into each EntryPoint for account")


def load_simulation_bytecode(filename: str) -> str:
    """Load simulation bytecode from a JSON file in voltaire_bundler/contracts/."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(
        script_dir, "..", "voltaire_bundler", "contracts", filename
    )
    with open(json_path) as f:
        data = json.load(f)
    return data["bytecode"]


def build_user_op(call_data_hex: str) -> list:
    """Build a PackedUserOperation as a tuple for ABI encoding."""
    # accountGasLimits = verificationGasLimit (16 bytes) || callGasLimit (16 bytes)
    verification_gas = 1_000_000
    call_gas = 0  # will be estimated
    account_gas_limits = verification_gas.to_bytes(16) + call_gas.to_bytes(16)

    # gasFees = maxPriorityFeePerGas (16 bytes) || maxFeePerGas (16 bytes)
    gas_fees = (1).to_bytes(16) + (1).to_bytes(16)

    return [
        ACCOUNT_ADDRESS,            # sender
        0,                          # nonce
        b"",                        # initCode (empty = account exists)
        bytes.fromhex(call_data_hex),  # callData
        account_gas_limits,         # accountGasLimits
        0,                          # preVerificationGas
        gas_fees,                   # gasFees
        b"",                        # paymasterAndData
        b"\x00" * 65,              # signature (dummy)
    ]


def make_simulate_call_data(user_op_tuple: list, max_gas: int = 10_000_000) -> str:
    """Build the simulateHandleOpMod calldata."""
    call_data_params = encode(
        [
            "(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)",
            "(uint256,uint256,uint256,bool,bool)",
        ],
        [
            user_op_tuple,
            [0, max_gas, 10_000, False, False],  # EstimateCallGasArgs
        ],
    )
    return "0x" + SIMULATE_HANDLE_OP_MOD_SELECTOR + call_data_params.hex()


def test_eth_call(
    description: str,
    call_data_hex: str,
    expect_success: bool,
    entrypoint: str,
    simulation_bytecode: str,
) -> bool:
    """
    Send eth_call with the simulation bytecode override.
    Returns True if the test passed.
    """
    user_op = build_user_op(call_data_hex)
    data = make_simulate_call_data(user_op)

    state_overrides = {
        BUNDLER_ADDRESS: {
            "balance": "0x314dc6448d9338c15b0a00000000",
        },
        entrypoint: {
            "code": simulation_bytecode,
        },
    }

    result = rpc("eth_call", [
        {
            "from": BUNDLER_ADDRESS,
            "to": entrypoint,
            "data": data,
        },
        "latest",
        state_overrides,
    ])

    error_data = result.get("error", {}).get("data", "")
    if not error_data:
        # No error at all — unexpected
        print(f"  FAIL {description}: eth_call did not revert (got result: {result.get('result', '???')[:40]})")
        return False

    selector = error_data[2:10] if error_data.startswith("0x") else error_data[:8]

    if selector == SIMULATION_RESULT_SELECTOR:
        # Decode SimulationResult(uint256 verificationGasLimit, uint256 callGasLimitMax, uint256 numRounds)
        decoded = decode(
            ["uint256", "uint256", "uint256"],
            bytes.fromhex(error_data[10:] if error_data.startswith("0x") else error_data[8:]),
        )
        ver_gas, call_gas_max, num_rounds = decoded
        if expect_success:
            print(f"  PASS {description}")
            print(f"       SimulationResult: verificationGas={ver_gas}, callGasMax={call_gas_max}, rounds={num_rounds}")
            return True
        else:
            print(f"  FAIL {description}: expected revert but got SimulationResult")
            return False

    elif selector == ESTIMATE_REVERT_AT_MAX_SELECTOR:
        # Decode EstimateCallGasRevertAtMax(bytes)
        decoded = decode(
            ["bytes"],
            bytes.fromhex(error_data[10:] if error_data.startswith("0x") else error_data[8:]),
        )
        revert_data = decoded[0]
        if not expect_success:
            print(f"  PASS {description}")
            print(f"       EstimateCallGasRevertAtMax (expected failure)")
            return True
        else:
            print(f"  FAIL {description}")
            print(f"       EstimateCallGasRevertAtMax: {revert_data.hex()[:80]}")
            return False

    else:
        error_msg = result.get("error", {}).get("message", "unknown")
        print(f"  FAIL {description}")
        print(f"       Unexpected error selector: 0x{selector}")
        print(f"       Message: {error_msg}")
        print(f"       Data: {error_data[:120]}...")
        return False


def run_tests_for_version(
    version_label: str,
    entrypoint: str,
    simulation_bytecode: str,
) -> list[bool]:
    """Run the 3 IAccountExecute test cases against a specific EntryPoint version."""
    print(f"── {version_label} ({entrypoint}) ──")
    results = []

    # Test 1: executeUserOp callData (the fix)
    inner_data = encode(
        ["address", "uint256"],
        [ANVIL_FUNDER, 0],
    )
    execute_user_op_calldata = EXECUTE_USER_OP_SELECTOR + inner_data.hex()

    results.append(test_eth_call(
        f"[{version_label}] IAccountExecute (executeUserOp callData) — should SUCCEED",
        execute_user_op_calldata,
        expect_success=True,
        entrypoint=entrypoint,
        simulation_bytecode=simulation_bytecode,
    ))

    # Test 2: standard callData (non-IAccountExecute)
    standard_data = encode(
        ["address", "uint256", "bytes"],
        [ANVIL_FUNDER, 0, b""],
    )
    standard_calldata = "b61d27f6" + standard_data.hex()

    results.append(test_eth_call(
        f"[{version_label}] Standard callData (account doesn't support it) — should REVERT",
        standard_calldata,
        expect_success=False,
        entrypoint=entrypoint,
        simulation_bytecode=simulation_bytecode,
    ))

    # Test 3: empty callData
    results.append(test_eth_call(
        f"[{version_label}] Empty callData (0x) — should SUCCEED",
        "",
        expect_success=True,
        entrypoint=entrypoint,
        simulation_bytecode=simulation_bytecode,
    ))

    print()
    return results


def main():
    parser = argparse.ArgumentParser(
        description="E2E test: IAccountExecute gas estimation on v0.7, v0.8, v0.9"
    )
    parser.add_argument("--start-anvil", action="store_true", help="Start anvil automatically")
    args = parser.parse_args()

    anvil_proc = None
    if args.start_anvil:
        print("Starting anvil...")
        anvil_proc = subprocess.Popen(
            ["anvil", "--chain-id", "1337", "--gas-limit", "30000000",
             "--port", "8545", "--block-time", "1"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        wait_for_anvil()
        print("  anvil running")

    try:
        # Verify anvil is reachable
        try:
            rpc("eth_chainId", [])
        except Exception:
            print("ERROR: anvil not running. Start it with: anvil --chain-id 1337 --gas-limit 30000000 --port 8545")
            print("Or use --start-anvil flag.")
            sys.exit(1)

        # Deploy EntryPoints if not already present
        result = rpc("eth_getCode", [ENTRYPOINT_V07, "latest"])
        if len(result.get("result", "0x")) < 10:
            print("Deploying EntryPoints v0.7, v0.8, v0.9...")
            deploy_entrypoints()
        else:
            print("EntryPoints already deployed")

        print("Setting up test account...")
        setup_account()

        # Load simulation bytecodes
        print("Loading simulation bytecodes...")
        bytecode_v7 = load_simulation_bytecode("EntryPointSimulationsV7WithBinarySearch.json")
        bytecode_v8 = load_simulation_bytecode("EntryPointSimulationsV8WithBinarySearch.json")
        bytecode_v9 = load_simulation_bytecode("EntryPointSimulationsV9WithBinarySearch.json")
        print("  Loaded v0.7, v0.8, v0.9 simulation bytecodes")

        print()
        print("=" * 60)
        print("Running IAccountExecute gas estimation tests")
        print("=" * 60)
        print()

        all_results = []

        all_results.extend(run_tests_for_version("v0.7", ENTRYPOINT_V07, bytecode_v7))
        all_results.extend(run_tests_for_version("v0.8", ENTRYPOINT_V08, bytecode_v8))
        all_results.extend(run_tests_for_version("v0.9", ENTRYPOINT_V09, bytecode_v9))

        print("=" * 60)
        passed = sum(all_results)
        total = len(all_results)
        if passed == total:
            print(f"ALL {total} TESTS PASSED")
        else:
            print(f"{passed}/{total} tests passed, {total - passed} FAILED")
        print("=" * 60)

        sys.exit(0 if passed == total else 1)

    finally:
        if anvil_proc:
            anvil_proc.terminate()
            anvil_proc.wait()
            print("\nanvil stopped")


if __name__ == "__main__":
    main()
