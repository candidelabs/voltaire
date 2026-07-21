import logging

from voltaire_bundler.utils.eth_client_utils import \
    send_rpc_request_to_eth_client
from voltaire_bundler.utils.load_bytecode import load_bytecode

# Canonical CREATE2 addresses of the pre-deployed EntryPoint simulation
# contracts (see the voltaire-sim-deployer project). They are deployed through
# the deterministic-deployment proxy 0x4e59b44847b379578588920cA78FbF26c0B4956C
# (the same factory the EntryPoint uses) with the salt
# keccak256("voltaire.entrypoint.simulations.v1"), so the addresses are
# identical on every chain. The deployed code is byte-identical to the runtime
# bytecode bundled in voltaire_bundler/contracts/*.json.
DEPLOYED_SIMULATIONS_ADDRESSES: dict[str, str] = {
    "EntryPointSimulationsV6": "0x22f87463FB44061C5D5949535177a6ccd8cEc4bA",
    "EntryPointSimulationsV6Arb": "0xE06533B364DA907F8E75909A2FB90d2C80FA48Fc",
    "EntryPointSimulationsV7": "0xbdA6700BC1A485Dc6E965bf6771E03c5820daa6D",
    "EntryPointSimulationsV7Arb": "0x54Ac13CE92b748a75C4fD563b0A2A070d4C0e2E1",
    "EntryPointSimulationsV8": "0xc350d92dd8E9e4f9aaC6B9E590820BC21999D050",
    "EntryPointSimulationsV8Arb": "0xB75F762E25d9DF772C44E34aD5c9dF71948Ae4f6",
    "EntryPointSimulationsV9": "0x70d62534631aF6548521c22Ed71d09d1E744518a",
    "EntryPointSimulationsModV9Arb": "0xC3f016A494F4F1e70b0526e8eB9996be775e23b8",
}

ENTRYPOINT_V6_LOWERCASE = "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789"
ENTRYPOINT_V7_LOWERCASE = "0x0000000071727de22e5e9d8baf0edac6f37da032"
ENTRYPOINT_V8_LOWERCASE = "0x4337084d9e255ff0702461cf8895ce9e3b5ff108"
ENTRYPOINT_V9_LOWERCASE = "0x433709009b8330fda32311df1c2afa402ed8d009"


def delegatecall_proxy_runtime(target: str) -> str:
    """EIP-1167-style runtime bytecode that DELEGATECALLs `target`,
    forwarding calldata and bubbling up return data/reverts.

    Used as a ~45 byte eth_call code override at the EntryPoint address
    instead of the full ~40KB simulation runtime once the simulation
    contract is found pre-deployed on-chain. Delegatecall keeps
    address(this) = EntryPoint and the EntryPoint's storage, so execution
    is semantically identical to overriding with the full bytecode (and,
    for v0.9, does not trip the EntryPoint's contract-caller guard the way
    a separate-address CALL proxy would).
    """
    return (
        "0x363d3d373d3d3d363d73"
        + target.lower().removeprefix("0x")
        + "5af43d82803e903d91602b57fd5bf3"
    )


async def check_deployed_simulations(
    ethereum_node_urls: list[str],
    chain_id: int,
    disable_v6: bool,
) -> dict[str, str]:
    """Check at boot whether the simulation contracts used for validation on
    this chain are pre-deployed at their canonical addresses, logging the
    result for each. Returns a mapping of entrypoint address (lowercase) to a
    delegatecall-proxy code override for every simulation contract that is
    deployed with the expected bytecode; entrypoints whose simulation contract
    is missing (or mismatched) are absent, and validation falls back to the
    full bytecode state override for them.
    """
    # arbitrum One or arbitrum sepolia use the Arb simulation variants
    # for validation, mirror that here
    is_arb = chain_id == 42161 or chain_id == 421614
    checks: list[tuple[str, str]] = []
    if not disable_v6:
        checks.append((
            ENTRYPOINT_V6_LOWERCASE,
            "EntryPointSimulationsV6Arb" if is_arb
            else "EntryPointSimulationsV6",
        ))
    checks += [
        (
            ENTRYPOINT_V7_LOWERCASE,
            "EntryPointSimulationsV7Arb" if is_arb
            else "EntryPointSimulationsV7",
        ),
        (
            ENTRYPOINT_V8_LOWERCASE,
            "EntryPointSimulationsV8Arb" if is_arb
            else "EntryPointSimulationsV8",
        ),
        (
            ENTRYPOINT_V9_LOWERCASE,
            "EntryPointSimulationsModV9Arb" if is_arb
            else "EntryPointSimulationsV9",
        ),
    ]

    overrides: dict[str, str] = {}
    for entrypoint_lowercase, contract_name in checks:
        address = DEPLOYED_SIMULATIONS_ADDRESSES[contract_name]
        try:
            result = await send_rpc_request_to_eth_client(
                ethereum_node_urls, "eth_getCode", [address, "latest"]
            )
            onchain_code = result.get("result")
        except Exception:
            logging.warning(
                f"eth_getCode failed while checking if {contract_name} is "
                f"deployed at {address} - falling back to the full bytecode "
                "state override for validation."
            )
            continue

        if onchain_code is None or len(onchain_code) <= 2:
            logging.info(
                f"{contract_name} is not deployed at {address} - using the "
                "full bytecode state override for validation."
            )
            continue

        expected_runtime = load_bytecode(f"{contract_name}.json")
        if onchain_code.lower() != expected_runtime.lower():
            logging.warning(
                f"{contract_name} at {address} does not match the bundled "
                "runtime bytecode - using the full bytecode state override "
                "for validation."
            )
            continue

        logging.info(
            f"{contract_name} is deployed at {address} - using the deployed "
            "simulation contract for validation (delegatecall override)."
        )
        overrides[entrypoint_lowercase] = delegatecall_proxy_runtime(address)

    return overrides
