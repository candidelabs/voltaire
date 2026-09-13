"""callGasLimit estimation for the Somnia chain — one probe per eth_call.

Somnia prices state access against persistent, chain-global LRU sets of
recently accessed keys instead of EIP-2929 per-transaction access lists.
For storage slot keys (SLOAD/SSTORE, 128M-entry set):

- key in the set (warm):      no extra cost beyond the 100 static gas
- cold existing key:          +1,000,000 gas, charged
- non-existent key:           requires >=1,000,000 gas remaining in the
                              current frame, but charges nothing (an
                              SSTORE of a non-zero value charges 200k)

and analogously for account keys (BALANCE/EXTCODE*/CALL/CREATE,
32M-entry set):

- recently accessed account:  no extra cost
- cold existing account:      +1,000,000 gas, charged
- non-existent account read:  requires >=1M received gas, charges nothing
- account creation (e.g. a value transfer to a fresh address):
                              requires >=1M received gas, charges 400,000

This breaks the in-contract binary search of the
EntryPointSimulations*WithBinarySearch contracts, which assumes EIP-2929
semantics: its always-reverting probes roll back per-transaction access
lists so every search round measures against the same cold state. On
Somnia, probe 1 warms the op's keys for probes 2..N *within* one
eth_call and the search converges on warm costs — undercounting by ~1M
gas per cold key. Running each probe as its own eth_call instead makes
every measurement start from canonical chain state.

Every probe MUST run against the "latest" block tag, never a pinned
block number. Somnia nodes evaluate the required-but-uncharged >=1M
rules against their live LRU state, which only exists for the chain
head: an eth_call at any explicit block number — even the current
head's — silently skips those checks while still applying the
deterministic charges (verified empirically against dream-rpc; e.g. a
value transfer to a fresh account charges ~407k and needs >=1M
forwarded at "latest", but succeeds inside ~433k at a pinned number).
Pinned probes therefore let every candidate succeed and quote a
callGasLimit that runs out of gas on-chain. The cost of "latest" is
that concurrent probes may observe different sub-second blocks; a grid
only ever returns a candidate whose probe actually succeeded, so drift
costs an extra round trip or a fallback, never an undersized estimate.

The driver stays fast (2 network round trips in the common case) by
exploiting the gas model: the first full-gas probe's gasUsed is a
faithful measurement of everything charged, and the only gas that is
required on top is the >=1M-received rule for non-existent keys and
accounts. That headroom is amplified by EIP-150 — an access D
call-levels below the account frame needs ~1M * (64/63)^D available in
the account frame (each parent holds back 1/64 when forwarding) — so
the answer lies in [gasUsed, gasUsed + ~1M * (64/63)^D]. The probe
rounds escalate by scenario likelihood:

- phase 1, main grid: spans [gasUsed, gasUsed + 1.07M] — zero or any
  number of non-existent-key or fresh-account accesses up to ~4 frames
  deep, the overwhelmingly common cases. The per-access constraints max
  rather than sum, so access count never widens the window, only depth
  does.
- phase 2, retry grid: pathological depth up to gasUsed + ~3.2M, plus
  the max_call_data_gas anchor (the limit the full-gas probe proved
  succeeds, so under stable state this round cannot come back empty).
- phase 3, bisection: a coarse retry result is localized with parallel
  bisection of the proven bracket so the driver never quotes the raw
  anchor (a max-sized callGasLimit is an unusable prefund quote).

Overshoot in a limit only pads the prefund (unused gas is refunded), so
~360k resolution is enough — and it doubles as margin for slots evicted
from the LRU set between estimation and inclusion. A grid only ever
returns a candidate whose probe actually succeeded, so a violated window
costs an extra round trip, never an undersized estimate.
"""

import asyncio
import logging
import math
from typing import Any

# Somnia mainnet / testnet
SOMNIA_CHAIN_IDS = (5031, 50312)


async def estimate_call_gas_somnia(
    gas_manager: Any,
    user_operation: Any,
    entrypoint: str,
    state_override_set_dict: dict[str, Any],
) -> tuple[int, int] | None:
    """Run the one-probe-per-eth_call estimation (see module docstring).

    ``gas_manager`` is a GasManagerV6 / GasManagerV7V8V9 instance — used
    for its ``simulate_handle_op_mod`` and ``max_call_data_gas``.

    Returns (call_gas_limit, verification_gas_limit), or None if no probe
    of any round succeeded (state drift between probes) so the caller can
    fall back to the in-contract search.
    """
    # module-level import would cycle:
    # user_operation_handler -> gas_manager_v* -> this module
    from voltaire_bundler.user_operation.user_operation_handler import \
        decode_revert_bytes
    from voltaire_bundler.bundle.exceptions import \
        ExecutionException, ExecutionExceptionCode

    max_call_data_gas = gas_manager.max_call_data_gas

    # Every probe targets the "latest" block tag on purpose: at any
    # explicit block number Somnia nodes skip the required-but-uncharged
    # >=1M rules for non-existent keys/accounts (see module docstring),
    # which would make every candidate succeed and the estimate come out
    # too low to execute on-chain.

    # Round trip 1: one probe at full gas — proves success is possible
    # (or surfaces the real revert) and measures cold-faithful gasUsed.
    (solidity_error, error_params) = await gas_manager.simulate_handle_op_mod(
        user_operation,
        entrypoint,
        0,
        max_call_data_gas,
        False,
        True,  # check once: single probe at max_gas, reverts with gasUsed
        state_override_set_dict,
    )
    if solidity_error[:10] == "0x59f233d2":  # EstimateCallGasRevertAtMax
        raise ExecutionException(
            ExecutionExceptionCode.UserOperationReverted,
            decode_revert_bytes(bytes(error_params[0])),
        )
    if solidity_error[:10] != "0xdeb13018":  # SimulationResult
        return None
    verification_gas_limit = int(error_params[0])
    gas_used = int(error_params[1])

    probes_sent = 1  # the full-gas probe above

    async def probe_round(candidates: list[int]) -> int | None:
        """Probe all candidates concurrently; smallest success or None."""
        nonlocal probes_sent
        probes_sent += len(candidates)
        probe_results = await asyncio.gather(
            *[
                gas_manager.simulate_handle_op_mod(
                    user_operation,
                    entrypoint,
                    0,
                    candidate,
                    False,
                    True,
                    state_override_set_dict,
                )
                for candidate in candidates
            ],
            return_exceptions=True,
        )
        for candidate, probe_result in zip(candidates, probe_results):
            if isinstance(probe_result, BaseException):
                # out-of-gas at this candidate raises through the error
                # decoding paths (e.g. FailedOp) or failed transport —
                # either way treat as an unsuccessful guess so a higher
                # candidate wins
                logging.debug(
                    "somnia call gas probe at %s failed: %s",
                    candidate, probe_result,
                )
                continue
            if probe_result[0][:10] == "0xdeb13018":  # SimulationResult
                return candidate
        return None

    # Round trip 2 / phase 1: parallel grid over [gasUsed, gasUsed+1.07M]
    # — the window for the common cases (see module docstring).
    main_grid = sorted({
        min(math.ceil(gas_used * 1.05) + 5_000, max_call_data_gas),
        min(gas_used + 360_000, max_call_data_gas),
        min(gas_used + 715_000, max_call_data_gas),
        min(gas_used + 1_070_000, max_call_data_gas),
    })
    chosen = await probe_round(main_grid)
    if chosen is not None:
        logging.info(
            "somnia gas estimation for sender %s resolved at phase=1 "
            "(main grid): gasUsed=%s callGasLimit=%s probes=%s",
            user_operation.sender_address, gas_used, chosen, probes_sent,
        )
        return chosen, verification_gas_limit

    # Phase 2: retry round for pathological EIP-150 depth amplification
    # of the uncharged headroom, or for measurement drift.
    retry_grid = sorted({
        min(math.ceil(gas_used * 1.05) + 1_600_000, max_call_data_gas),
        min(gas_used + 3_200_000, max_call_data_gas),
        max_call_data_gas,
    })
    chosen = await probe_round(retry_grid)
    if chosen is None:
        logging.info(
            "somnia gas estimation for sender %s exhausted phase=1 "
            "(main grid) and phase=2 (retry) (gasUsed=%s probes=%s) — "
            "falling back to the in-contract binary search",
            user_operation.sender_address, gas_used, probes_sent,
        )
        return None

    # Phase 3: localize a coarse retry result with parallel bisection
    # rather than quoting it as-is. Every candidate below `chosen` is a
    # proven failure, so bisect the bracket (largest_fail, chosen) until
    # it is within ~10% (mirroring the contract's tolerancePct) or a
    # bounded number of rounds.
    chosen, bisection_rounds = await _localize_bracket(
        probe_round,
        chosen,
        max((c for c in main_grid + retry_grid if c < chosen), default=0),
    )
    logging.info(
        "somnia gas estimation for sender %s resolved at phase=%s "
        "(retry, %s bisection round(s)): gasUsed=%s callGasLimit=%s "
        "probes=%s",
        user_operation.sender_address,
        3 if bisection_rounds else 2,
        bisection_rounds, gas_used, chosen, probes_sent,
    )
    return chosen, verification_gas_limit


async def _localize_bracket(
    probe_round: Any,
    chosen: int,
    largest_fail: int,
) -> tuple[int, int]:
    """Shrink a proven (largest_fail, chosen) probe bracket with up to
    3 rounds of 4 parallel interior probes (each round ~5x tighter),
    stopping within max(400k, 10%) of the answer. Returns the localized
    limit and the number of bisection rounds used."""
    rounds = 0
    for _ in range(3):
        width = chosen - largest_fail
        if width <= max(400_000, chosen // 10):
            break
        rounds += 1
        step = width // 5
        interior = sorted({
            largest_fail + step * i for i in (1, 2, 3, 4)
        })
        interior_chosen = await probe_round(interior)
        if interior_chosen is not None:
            chosen = interior_chosen
            largest_fail = max(
                (c for c in interior if c < chosen),
                default=largest_fail,
            )
        else:
            largest_fail = max(interior)
    return chosen, rounds
