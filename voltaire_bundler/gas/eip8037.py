"""--eip8037: state-gas handling for chains that price state creation per
EIP-8037 (Glamsterdam).

Transaction gas above the EIP-7825 cap (2**24) funds a state-gas reservoir
that pays for state creation before the frame's own gas. Two consequences:

* A simulation eth_call without a "gas" field runs under the node's default
  cap (~50M), so the reservoir hides state creation from the limits being
  estimated or validated. Those simulations run at 2**24 instead, which
  leaves the reservoir empty, as in a real bundle.
* A bundle above 2**24 funds a reservoir that pays its operations' state
  creation, which the bundler pays for. Bundles are packed to stay within
  2**24 and the transaction gas is clamped to it.

Don't enable it on chains whose operations legitimately exceed 2**24
(e.g. Somnia).
"""
from typing import Any

# Set once at startup from --eip8037 (see cli_manager.get_init_data).
enabled: bool = False

# EIP-7825 per-transaction gas cap; gas above it is the state-gas reservoir.
TX_GAS_LIMIT_CAP = 2**24
TX_GAS_LIMIT_CAP_HEX = hex(TX_GAS_LIMIT_CAP)

# Gas the bundle manager adds to a bundle beyond its operations: 50k overhead
# plus the 21k base transaction, with some slack for the handleOps head.
BUNDLE_OVERHEAD_GAS = 75_000

# Upper bounds used when packing, without ABI-encoding each operation:
# calldata at the non-zero byte price for every dynamic byte, and a fixed
# allowance for the ABI head words and padding of each operation.
CALLDATA_GAS_PER_BYTE = 16
PER_OPERATION_ENCODING_GAS = 12_000

_DYNAMIC_FIELDS = (
    "init_code", "factory_data", "call_data",
    "paymaster_and_data", "paymaster_data", "signature",
)


def operation_bundle_gas(user_operation: Any) -> int:
    """Upper bound on what adding ``user_operation`` adds to a bundle's gas
    limit: its limits including preVerificationGas, its dynamic bytes at
    the calldata price, and the encoding allowance."""
    dynamic_bytes = sum(
        len(getattr(user_operation, field, None) or b"")
        for field in _DYNAMIC_FIELDS
    )
    return (
        user_operation.get_max_gas_with_pre_verification_gas()
        + CALLDATA_GAS_PER_BYTE * dynamic_bytes
        + PER_OPERATION_ENCODING_GAS
    )
