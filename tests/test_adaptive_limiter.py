"""Unit tests for the AIMD adaptive limiter.

Most tests drive the algorithm through its private acquire/release
primitives so latency and saturation are deterministic (no real sleeps,
no gather-and-hope). Two integration-flavored tests at the bottom use
the public async context manager to check acquire/release semantics.
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


async def _drive_burst(
    lim: al.AdaptiveLimiter, n: int, elapsed_ms: float
) -> None:
    """Record ``n`` completions at ``elapsed_ms``. Each batch fills the
    limiter to cap before releasing, so the first release per batch sees
    ``in_flight >= cap`` (saturated → eligible for grow). Batches are
    replayed until ``n`` total completions are recorded, so callers can
    ask for arbitrarily many samples without deadlocking when ``n`` >
    cap."""
    remaining = n
    while remaining > 0:
        batch = min(remaining, lim.cap)
        for _ in range(batch):
            await lim._acquire()
        for _ in range(batch):
            await lim._release_success(elapsed_ms)
        remaining -= batch


async def _drive_errors(lim: al.AdaptiveLimiter, n: int) -> None:
    for _ in range(n):
        await lim._acquire()
        await lim._release_error(reason="test")


# --- API --------------------------------------------------------------

@pytest.mark.asyncio
async def test_snapshot_after_creation_matches_initial_config():
    lim = al.get_method_limiter("eth_call")
    snap = lim.snapshot()
    assert snap["cap"] == al._METHOD_INITIAL_CAPS["eth_call"]
    assert snap["in_flight"] == 0
    assert snap["baseline_p50_ms"] is None
    assert snap["adaptive"] is True


# --- Grow -------------------------------------------------------------

@pytest.mark.asyncio
async def test_grow_when_saturated_and_stable():
    """Cap must additively increase when the queue is saturated AND
    recent p50 stays within GROWTH_TOL of baseline."""
    lim = al.AdaptiveLimiter("eth_call", initial_cap=8, min_cap=4)
    start_cap = lim.cap

    # Six bursts sized to whatever the current cap is: each saturates the
    # limiter and provides stable latency, so AIMD should grow the cap.
    for _ in range(6):
        await _drive_burst(lim, lim.cap, elapsed_ms=50.0)

    assert lim.cap > start_cap, (
        f"cap did not grow: start={start_cap} end={lim.cap}"
    )


@pytest.mark.asyncio
async def test_no_grow_when_not_saturated():
    """Cap must NOT grow when in_flight stays below cap - even if latency
    is fine. Grow only where there is demand."""
    lim = al.AdaptiveLimiter("eth_call", initial_cap=32, min_cap=4)
    start_cap = lim.cap

    # 100 sequential completions — never saturates (in_flight == 1).
    for _ in range(100):
        await _drive_burst(lim, 1, elapsed_ms=50.0)

    assert lim.cap == start_cap


# --- Shrink -----------------------------------------------------------

@pytest.mark.asyncio
async def test_shrink_on_latency_climb():
    """Once baseline is established, a run of calls at SHRINK_TRIGGER *
    baseline must halve the cap."""
    lim = al.AdaptiveLimiter("eth_call", initial_cap=32, min_cap=4)

    # Establish a baseline of ~50ms with enough completions to fill the
    # window.
    await _drive_burst(lim, al.WINDOW_SIZE + 4, elapsed_ms=50.0)
    baseline_before = lim.baseline_p50_ms
    assert baseline_before is not None
    start_cap = lim.cap

    slow_latency = baseline_before * al.SHRINK_TRIGGER * 1.1
    await _drive_burst(lim, al.WINDOW_SIZE + 4, elapsed_ms=slow_latency)

    assert lim.cap < start_cap
    # At least one halving happened.
    assert lim.cap <= max(lim.min_cap, start_cap // 2)


@pytest.mark.asyncio
async def test_error_forces_shrink_bounded_by_floor():
    """Errors halve the cap regardless of the ratio check, but never
    below the method's floor."""
    lim = al.AdaptiveLimiter(
        "eth_sendRawTransaction", initial_cap=32, min_cap=4
    )
    await _drive_errors(lim, 50)
    assert lim.cap == lim.min_cap == 4


@pytest.mark.asyncio
async def test_non_2xx_status_treated_as_error_via_context():
    """Non-2xx status set via the context manager should halve the cap."""
    lim = al.AdaptiveLimiter("eth_call", initial_cap=16, min_cap=2)
    start_cap = lim.cap
    async with lim as slot:
        slot.set_status(502)
    assert lim.cap == max(lim.min_cap, start_cap // 2)


# --- Bounds -----------------------------------------------------------

@pytest.mark.asyncio
async def test_cap_never_exceeds_max_cap():
    lim = al.AdaptiveLimiter(
        "eth_call", initial_cap=al.MAX_CAP - 2, min_cap=2
    )
    for _ in range(200):
        await _drive_burst(lim, lim.cap, elapsed_ms=10.0)
    assert lim.cap <= al.MAX_CAP


@pytest.mark.asyncio
async def test_per_method_min_beats_global_min_after_errors():
    """After 100 errors on eth_sendRawTransaction, cap sits at 4 (its
    floor), not 2 (GLOBAL_MIN_CAP)."""
    lim = al.get_method_limiter("eth_sendRawTransaction")
    await _drive_errors(lim, 100)
    assert lim.cap == 4
    assert al.GLOBAL_MIN_CAP == 2


# --- Baseline drift --------------------------------------------------

@pytest.mark.asyncio
async def test_baseline_drifts_up_on_sustained_slowdown():
    lim = al.AdaptiveLimiter("eth_call", initial_cap=32, min_cap=4)

    # Fast baseline first.
    await _drive_burst(lim, al.WINDOW_SIZE + 4, elapsed_ms=50.0)
    baseline0 = lim.baseline_p50_ms
    assert baseline0 is not None

    # Sustained moderate slowdown: recent > baseline * upward_trigger
    # but < shrink trigger. The baseline should drift up after a few
    # windows.
    slow = baseline0 * (al.BASELINE_UPWARD_TRIGGER + 0.1)
    await _drive_burst(
        lim, al.WINDOW_SIZE * (al.BASELINE_UPWARD_WINDOWS + 1),
        elapsed_ms=slow,
    )

    assert lim.baseline_p50_ms is not None
    assert lim.baseline_p50_ms > baseline0


# --- Kill switch ------------------------------------------------------

@pytest.mark.asyncio
async def test_kill_switch_keeps_cap_fixed():
    al.configure(disabled=True)
    lim = al.AdaptiveLimiter(
        "eth_call", initial_cap=8, min_cap=4, disabled=True
    )
    start_cap = lim.cap
    # Everything that would normally move the cap.
    await _drive_burst(lim, lim.cap, elapsed_ms=5000.0)
    await _drive_errors(lim, 50)
    assert lim.cap == start_cap


# --- Concurrency semantics -------------------------------------------

@pytest.mark.asyncio
async def test_saturation_blocks_further_acquires():
    lim = al.AdaptiveLimiter("eth_call", initial_cap=2, min_cap=2)

    release = asyncio.Event()

    async def hold_slot() -> None:
        async with lim:
            await release.wait()

    holders = [asyncio.create_task(hold_slot()) for _ in range(2)]
    for _ in range(50):
        if lim.in_flight == 2:
            break
        await asyncio.sleep(0.01)
    assert lim.in_flight == 2

    async def third_caller() -> None:
        async with lim:
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
        async with lim:
            await holder_release.wait()

    holder = asyncio.create_task(hold_slot())
    for _ in range(50):
        if lim.in_flight == 1:
            break
        await asyncio.sleep(0.01)
    assert lim.in_flight == 1

    async def waiter() -> None:
        async with lim:
            pass

    waiter_task = asyncio.create_task(waiter())
    await asyncio.sleep(0.02)
    waiter_task.cancel()
    # asyncio.Condition.wait() has subtle notify-vs-cancel semantics on
    # 3.11+ — don't over-assert on how the exception surfaces. What we
    # care about is that the task ends and no permit leaks.
    try:
        await waiter_task
    except asyncio.CancelledError:
        pass
    assert waiter_task.done()

    # Release the holder; waiter never held a slot (or if it did briefly
    # from a notify-before-cancel race, __aexit__ released it), so
    # in_flight drops to 0 cleanly with no permit leak.
    holder_release.set()
    await holder
    assert lim.in_flight == 0

    # New callers should proceed normally.
    async with lim:
        pass
    assert lim.in_flight == 0
