"""Unit tests for the failure-driven adaptive limiter.

The limiter reacts only to hard failures (errors / timeouts / non-2xx),
never to latency. Most tests drive the algorithm through its private
acquire/release primitives so outcomes are deterministic (no real sleeps).
A few integration-flavored tests use the public per-call slot to check
acquire/release and outcome classification.
"""
from __future__ import annotations

import asyncio

import pytest

from voltaire_bundler.utils import adaptive_limiter as al


@pytest.fixture(autouse=True)
def _reset():
    al.reset_for_tests()
    al.configure(disabled=False)
    yield
    al.reset_for_tests()
    al.configure(disabled=False)


async def _drive_successes(lim: al.AdaptiveLimiter, n: int) -> None:
    """Record ``n`` successful completions, saturating each batch to the
    current cap so releases exercise the real notify path. Replays batches
    until ``n`` total are recorded, so callers can ask for arbitrarily many
    without deadlocking when ``n`` > cap."""
    remaining = n
    while remaining > 0:
        batch = min(remaining, lim.cap)
        for _ in range(batch):
            await lim._acquire()
        for _ in range(batch):
            await lim._release_success()
        remaining -= batch


async def _drive_errors(
    lim: al.AdaptiveLimiter, n: int, reason: str = "test"
) -> None:
    for _ in range(n):
        await lim._acquire()
        await lim._release_error(reason=reason)


# --- API --------------------------------------------------------------

@pytest.mark.asyncio
async def test_snapshot_after_creation_matches_initial_config():
    lim = al.get_method_limiter("eth_call")
    snap = lim.snapshot()
    assert snap["cap"] == al._METHOD_INITIAL_CAPS["eth_call"]
    assert snap["ceiling"] == al._METHOD_INITIAL_CAPS["eth_call"]
    assert snap["in_flight"] == 0
    assert snap["adaptive"] is True


@pytest.mark.asyncio
async def test_cap_starts_at_ceiling():
    lim = al.AdaptiveLimiter("eth_call", initial_cap=32, min_cap=4)
    assert lim.cap == lim.ceiling == 32


# --- Backoff on failure ----------------------------------------------

@pytest.mark.asyncio
async def test_errors_halve_cap_down_to_floor():
    """Errors halve the cap, never below the method's floor."""
    lim = al.AdaptiveLimiter(
        "eth_sendRawTransaction", initial_cap=32, min_cap=4
    )
    await _drive_errors(lim, 50)
    assert lim.cap == lim.min_cap == 4


@pytest.mark.asyncio
async def test_single_error_halves_once():
    lim = al.AdaptiveLimiter("eth_call", initial_cap=32, min_cap=4)
    await _drive_errors(lim, 1)
    assert lim.cap == 16


@pytest.mark.asyncio
async def test_non_2xx_status_treated_as_failure_via_context():
    """A non-2xx status set on the slot must halve the cap."""
    lim = al.AdaptiveLimiter("eth_call", initial_cap=16, min_cap=2)
    start_cap = lim.cap
    async with lim.slot() as slot:
        slot.set_status(502)
    assert lim.cap == max(lim.min_cap, start_cap // 2)


@pytest.mark.asyncio
async def test_timeout_treated_as_failure():
    """A timeout raised through the slot halves the cap."""
    lim = al.AdaptiveLimiter("eth_call", initial_cap=16, min_cap=2)
    start_cap = lim.cap
    slot = lim.slot()
    await slot.__aenter__()
    await slot.__aexit__(
        asyncio.TimeoutError, asyncio.TimeoutError(), None
    )
    assert lim.cap == max(lim.min_cap, start_cap // 2)
    assert lim.in_flight == 0


# --- Cancellation is neutral -----------------------------------------

@pytest.mark.asyncio
async def test_cancellation_does_not_move_cap():
    """A caller-side cancellation is not a node-health signal and must
    leave the cap untouched (and leak no permit)."""
    lim = al.AdaptiveLimiter("eth_call", initial_cap=16, min_cap=2)
    start_cap = lim.cap
    slot = lim.slot()
    await slot.__aenter__()
    await slot.__aexit__(
        asyncio.CancelledError, asyncio.CancelledError(), None
    )
    assert lim.cap == start_cap
    assert lim.in_flight == 0


# --- Recovery ---------------------------------------------------------

@pytest.mark.asyncio
async def test_success_does_not_grow_above_ceiling():
    lim = al.AdaptiveLimiter("eth_call", initial_cap=8, min_cap=2)
    await _drive_successes(lim, al.RECOVER_STEP_SUCCESSES * 5)
    assert lim.cap == lim.ceiling == 8


@pytest.mark.asyncio
async def test_recovers_one_step_per_success_window():
    lim = al.AdaptiveLimiter("eth_call", initial_cap=32, min_cap=4)
    await _drive_errors(lim, 10)              # collapse to the floor
    backed_off = lim.cap
    assert backed_off == 4

    # Just under a full recovery window: no step yet.
    await _drive_successes(lim, al.RECOVER_STEP_SUCCESSES - 1)
    assert lim.cap == backed_off

    # One more success completes the window → exactly one step.
    await _drive_successes(lim, 1)
    assert lim.cap == backed_off + 1


@pytest.mark.asyncio
async def test_sustained_success_recovers_all_the_way_to_ceiling():
    lim = al.AdaptiveLimiter("eth_call", initial_cap=32, min_cap=4)
    await _drive_errors(lim, 10)
    assert lim.cap == 4
    await _drive_successes(lim, al.RECOVER_STEP_SUCCESSES * 40)
    assert lim.cap == lim.ceiling == 32


@pytest.mark.asyncio
async def test_failure_resets_recovery_progress():
    """Hysteresis: a failure zeroes the success streak, so partial
    progress toward the next recovery step is lost."""
    lim = al.AdaptiveLimiter("eth_call", initial_cap=32, min_cap=4)
    await _drive_errors(lim, 10)
    assert lim.cap == 4

    # Almost a full window of successes, then one failure.
    await _drive_successes(lim, al.RECOVER_STEP_SUCCESSES - 1)
    assert lim.cap == 4
    await _drive_errors(lim, 1)               # already at floor: cap stays 4
    assert lim.cap == 4

    # Streak was reset, so a fresh near-full window still doesn't step up.
    await _drive_successes(lim, al.RECOVER_STEP_SUCCESSES - 1)
    assert lim.cap == 4
    # Completing the window now does.
    await _drive_successes(lim, 1)
    assert lim.cap == 5


# --- Bounds -----------------------------------------------------------

@pytest.mark.asyncio
async def test_cap_never_exceeds_ceiling_under_load():
    lim = al.AdaptiveLimiter("eth_call", initial_cap=64, min_cap=2)
    await _drive_successes(lim, 5000)
    assert lim.cap <= 64


@pytest.mark.asyncio
async def test_per_method_min_beats_global_min_after_errors():
    lim = al.get_method_limiter("eth_sendRawTransaction")
    await _drive_errors(lim, 100)
    assert lim.cap == 4
    assert al.GLOBAL_MIN_CAP == 2


# --- Kill switch ------------------------------------------------------

@pytest.mark.asyncio
async def test_kill_switch_keeps_cap_fixed():
    lim = al.AdaptiveLimiter(
        "eth_call", initial_cap=8, min_cap=4, disabled=True
    )
    start_cap = lim.cap
    await _drive_successes(lim, 200)
    await _drive_errors(lim, 50)
    assert lim.cap == start_cap


# --- Concurrency semantics -------------------------------------------

@pytest.mark.asyncio
async def test_saturation_blocks_further_acquires():
    lim = al.AdaptiveLimiter("eth_call", initial_cap=2, min_cap=2)

    release = asyncio.Event()

    async def hold_slot() -> None:
        async with lim.slot():
            await release.wait()

    holders = [asyncio.create_task(hold_slot()) for _ in range(2)]
    for _ in range(50):
        if lim.in_flight == 2:
            break
        await asyncio.sleep(0.01)
    assert lim.in_flight == 2

    async def third_caller() -> None:
        async with lim.slot():
            pass

    third = asyncio.create_task(third_caller())
    await asyncio.sleep(0.02)
    assert not third.done(), "third caller should be blocked at the gate"

    release.set()
    await asyncio.gather(*holders, third)


@pytest.mark.asyncio
async def test_cancellation_does_not_leak_permits():
    lim = al.AdaptiveLimiter("eth_call", initial_cap=1, min_cap=1)

    holder_release = asyncio.Event()

    async def hold_slot() -> None:
        async with lim.slot():
            await holder_release.wait()

    holder = asyncio.create_task(hold_slot())
    for _ in range(50):
        if lim.in_flight == 1:
            break
        await asyncio.sleep(0.01)
    assert lim.in_flight == 1

    async def waiter() -> None:
        async with lim.slot():
            pass

    waiter_task = asyncio.create_task(waiter())
    await asyncio.sleep(0.02)
    waiter_task.cancel()
    try:
        await waiter_task
    except asyncio.CancelledError:
        pass
    assert waiter_task.done()

    holder_release.set()
    await holder
    assert lim.in_flight == 0

    # New callers should proceed normally.
    async with lim.slot():
        pass
    assert lim.in_flight == 0
