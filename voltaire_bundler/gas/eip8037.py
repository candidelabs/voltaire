"""--eip8037: state-gas handling for chains that price state creation per
EIP-8037 (Glamsterdam).

EIP-8037 relaxes the EIP-7825 per-transaction gas cap (2**24): a
transaction may carry more, but the gas above the cap is a state-gas
reservoir that pays for state creation before the frame's own gas. Two
consequences for a bundler:

* A simulation eth_call without a "gas" field runs under the node's default
  cap (~50M), so the reservoir hides state creation from the limits being
  estimated or validated. Those simulations run at 2**24 instead, which
  leaves the reservoir empty, as in a real bundle.
* A bundle above 2**24 funds a reservoir that pays its operations' state
  creation; the operations' frames then report less gas, the users are
  charged less and the bundler pays the difference. So the bundle gas
  limit (the operations' limits incl. preVerificationGas, plus calldata
  and overhead) is kept within 2**24: operations that could never fit are
  rejected at estimation and submission, bundles are packed within it, and
  the transaction gas, normally the bundle gas limit times
  --bundle_gas_estimation_multiplier, is clamped to it. The multiplier is
  headroom on top of the limit, so it never reduces what is accepted; near
  the cap it is simply cut short.

Don't enable it on chains whose operations legitimately exceed 2**24
(e.g. Somnia).
"""
from typing import Any

from voltaire_bundler.bundle.exceptions import (
    ValidationException, ValidationExceptionCode)

# Set once at startup from --eip8037 (see cli_manager.get_init_data).
enabled: bool = False

# EIP-7825 per-transaction gas cap; gas above it is the state-gas reservoir.
TX_GAS_LIMIT_CAP = 2**24
TX_GAS_LIMIT_CAP_HEX = hex(TX_GAS_LIMIT_CAP)

# State gas of one new storage slot: 64 state bytes at 1530 gas each. A
# self-paying sender whose EntryPoint deposit is zero has the slot created
# by its prefund and cleared again during validation (refilled), then
# re-created by the refund in _postExecution after the EntryPoint stopped
# metering, so only preVerificationGas can charge for it (see
# GasManager._zero_deposit_refund_gas).
ZERO_DEPOSIT_REFUND_GAS = 97_920

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


def operation_bundle_gas_limit() -> int:
    """Largest operation_bundle_gas() a single operation may have and still
    fit a bundle on its own."""
    return TX_GAS_LIMIT_CAP - BUNDLE_OVERHEAD_GAS


def check_operation_fits(user_operation: Any) -> None:
    """Raise ValidationException (InvalidFields) if the operation can never
    be bundled within the cap, so it is rejected at estimation and
    submission instead of sitting in the mempool unbundled. No-op unless
    enabled."""
    if not enabled:
        return
    gas = operation_bundle_gas(user_operation)
    limit = operation_bundle_gas_limit()
    if gas > limit:
        raise ValidationException(
            ValidationExceptionCode.InvalidFields,
            f"UserOperation bundle gas {gas} (gas limits, preVerificationGas "
            f"and calldata) is larger than {limit}, the most a bundle can "
            f"carry within the EIP-7825 transaction gas cap",
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
