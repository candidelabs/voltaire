"""The calldata floor of EIP-7623 (Ethereum since Pectra), on by default,
and with --eip8037 the higher one of EIP-7976 (Glamsterdam).

The EIP-7623 floor is assumed on every chain unless --eip7623 false: on
a chain without it (Arbitrum) assuming it only overcharges calldata-heavy
operations, while missing it on a chain that has it loses the bundler the
difference on every such bundle and can send bundles below the floor,
which are invalid.

A transaction's gas used is ``21000 + max(standard, floor)``: ``standard``
is its calldata at 4/16 gas per byte plus everything it executes, and
``floor`` prices the same calldata at a higher rate - 10 per token under
EIP-7623 (a zero byte is one token, a non-zero byte four), 64 per byte,
zero or not, under EIP-7976. A transaction whose gas limit is below
``21000 + floor`` is invalid, whatever it would execute.

For a bundle that means:

* the bundle transaction's gas limit must be at least ``21000 + floor``
  of the handleOps calldata (``bundle_gas_limit``);
* an operation that carries more calldata than it executes gas for pushes
  the bundle's gas used up to the floor, and the EntryPoint only charges
  the operation for what it executes. preVerificationGas has to cover the
  difference (``pre_verification_gas_top_up``): the operation's floor,
  less the gas it is sure to use - its preVerificationGas overhead, its
  intrinsic and state gas (EIP-7702 tuple, zero-deposit refund) and a
  tenth of its execution limits. The tenth is a floor on how little of
  callGasLimit (and postOp) a sensible operation uses; assuming less
  would overcharge every operation to cover the odd one.

The top-up is per operation and so is the floor, on the operation's own
ABI-encoded bytes (the handleOps head is the bundle's), and both are
checked at submission like the rest of preVerificationGas.
"""

from voltaire_bundler.gas import eip8037

# Set once at startup from --eip7623 (see cli_manager.get_init_data);
# on unless the operator turns it off for a chain without the floor.
enabled: bool = True

# EIP-7623: TOTAL_COST_FLOOR_PER_TOKEN, tokens_in_calldata = zero + 4 * nonzero
EIP7623_FLOOR_PER_TOKEN = 10
EIP7623_TOKENS_PER_NON_ZERO_BYTE = 4
# EIP-7976: TOTAL_COST_FLOOR_PER_TOKEN 16, every byte four tokens
EIP7976_FLOOR_PER_BYTE = 64

BASE_TRANSACTION_GAS = 21_000

# Share of an operation's execution limits it is assumed to use at least.
EXECUTION_USE_FLOOR_PERCENT = 10


def active() -> bool:
    """Whether a calldata floor applies: EIP-7623 (on unless --eip7623
    false), or --eip8037 (Glamsterdam includes EIP-7976)."""
    return enabled or eip8037.enabled


def floor_gas(calldata: bytes) -> int:
    """The floor cost of ``calldata`` at the active rate, without the base
    transaction gas. 0 when no floor applies."""
    if eip8037.enabled:
        return EIP7976_FLOOR_PER_BYTE * len(calldata)
    if enabled:
        zero_bytes = calldata.count(b"\x00")
        non_zero_bytes = len(calldata) - zero_bytes
        tokens = zero_bytes + EIP7623_TOKENS_PER_NON_ZERO_BYTE * non_zero_bytes
        return EIP7623_FLOOR_PER_TOKEN * tokens
    return 0


def bundle_gas_limit(gas_limit: int, handleops_calldata: bytes) -> int:
    """``gas_limit`` raised to the least a transaction carrying
    ``handleops_calldata`` is valid with."""
    if not active():
        return gas_limit
    return max(gas_limit, BASE_TRANSACTION_GAS + floor_gas(handleops_calldata))


def pre_verification_gas_top_up(
    packed_user_operation: bytes,
    pre_verification_gas: int,
    execution_gas_limit: int,
) -> int:
    """What to add to ``pre_verification_gas`` (the operation's overhead
    incl. base transaction share, intrinsic and state gas) so the
    operation pays for its calldata floor: the floor of its encoded bytes
    less the gas it is sure to use. 0 when the floor is covered or no
    floor applies."""
    if not active():
        return 0
    lowest_gas_used = (
        pre_verification_gas - BASE_TRANSACTION_GAS
        + execution_gas_limit * EXECUTION_USE_FLOOR_PERCENT // 100
    )
    return max(0, floor_gas(packed_user_operation) - lowest_gas_used)
