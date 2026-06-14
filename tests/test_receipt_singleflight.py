"""
Tests for single-flight coalescing in
``UserOperationHandler.get_user_operation_receipt_rpc``.

When N concurrent ``eth_getUserOperationReceipt`` polls arrive for the
same (entrypoint, userOpHash), only one underlying receipt-building
lookup should run; the rest should observe its result.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock

from voltaire_bundler.bundle.exceptions import UserOpReceiptFoundException
from voltaire_bundler.user_operation.user_operation_handler import (
    UserOperationHandler,
    _inflight_receipt_lookups,
)


ENTRYPOINT_V7 = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
ENTRYPOINT_V8 = "0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108"
USEROP_HASH = "0x" + "ab" * 32
OTHER_USEROP_HASH = "0x" + "cd" * 32


def _bind(handler, name):
    """Bind an unbound UserOperationHandler method to a mock instance."""
    method = getattr(UserOperationHandler, name)
    setattr(handler, name, method.__get__(handler, UserOperationHandler))


def _make_handler(build_side_effect):
    """Build a mock handler with a stubbed _build_user_operation_receipt_rpc.

    The real ``get_user_operation_receipt_rpc`` is bound so single-flight
    runs end-to-end; only the inner builder is mocked.
    """
    handler = MagicMock(spec=UserOperationHandler)
    handler._build_user_operation_receipt_rpc = AsyncMock(
        side_effect=build_side_effect,
    )
    _bind(handler, "get_user_operation_receipt_rpc")
    return handler


@pytest.fixture(autouse=True)
def _clear_inflight_registry():
    """Each test starts and ends with an empty in-flight registry so
    cross-test bleed cannot mask a regression."""
    _inflight_receipt_lookups.clear()
    yield
    _inflight_receipt_lookups.clear()


@pytest.mark.asyncio
async def test_concurrent_polls_for_same_key_coalesce_into_one_lookup():
    """10 simultaneous polls for the same (entrypoint, hash) → 1 build."""
    call_count = 0
    started = asyncio.Event()
    release = asyncio.Event()

    async def slow_build(*_args):
        nonlocal call_count
        call_count += 1
        started.set()
        # Hold the in-flight task open until every poll has had a chance
        # to find the existing entry and attach as a waiter.
        await release.wait()
        return {"userOpHash": USEROP_HASH, "receipt": "ok"}

    handler = _make_handler(slow_build)

    async def poll():
        with pytest.raises(UserOpReceiptFoundException) as exc:
            await handler.get_user_operation_receipt_rpc(
                USEROP_HASH, ENTRYPOINT_V7, None,
            )
        return exc.value.user_op_receipt_result

    # Kick off all polls before letting the build complete so they
    # genuinely race the in-flight slot.
    tasks = [asyncio.create_task(poll()) for _ in range(10)]
    await started.wait()
    release.set()
    results = await asyncio.gather(*tasks)

    assert call_count == 1, "single-flight must collapse N polls to 1 build"
    # Every waiter sees the same payload — same dict instance, in fact.
    assert all(r is results[0] for r in results)


@pytest.mark.asyncio
async def test_not_found_result_is_shared_across_waiters():
    """A None lookup result must propagate as None to every waiter,
    not as UserOpReceiptFoundException."""
    call_count = 0
    started = asyncio.Event()
    release = asyncio.Event()

    async def slow_miss(*_args):
        nonlocal call_count
        call_count += 1
        started.set()
        await release.wait()
        return None

    handler = _make_handler(slow_miss)

    tasks = [
        asyncio.create_task(handler.get_user_operation_receipt_rpc(
            USEROP_HASH, ENTRYPOINT_V7, None,
        ))
        for _ in range(5)
    ]
    await started.wait()
    release.set()
    results = await asyncio.gather(*tasks)

    assert call_count == 1
    assert all(r is None for r in results)


@pytest.mark.asyncio
async def test_different_keys_do_not_coalesce():
    """Polls for different entrypoint OR different userop hash run
    independently — coalescing must be per-key, not global."""
    call_count = 0

    async def build(hash_arg, ep_arg, _hint):
        nonlocal call_count
        call_count += 1
        # Yield once so concurrent calls overlap.
        await asyncio.sleep(0)
        return {"userOpHash": hash_arg, "entryPoint": ep_arg}

    handler = _make_handler(build)

    async def poll(hash_arg, ep_arg):
        with pytest.raises(UserOpReceiptFoundException):
            await handler.get_user_operation_receipt_rpc(
                hash_arg, ep_arg, None,
            )

    await asyncio.gather(
        poll(USEROP_HASH, ENTRYPOINT_V7),
        poll(USEROP_HASH, ENTRYPOINT_V8),         # same hash, different EP
        poll(OTHER_USEROP_HASH, ENTRYPOINT_V7),   # different hash, same EP
    )

    assert call_count == 3


@pytest.mark.asyncio
async def test_inflight_slot_cleared_after_completion():
    """A new poll arriving after the previous lookup finishes must
    trigger a fresh build (the slot is not retained as a cache)."""
    call_count = 0

    async def build(*_args):
        nonlocal call_count
        call_count += 1
        return None

    handler = _make_handler(build)

    await handler.get_user_operation_receipt_rpc(
        USEROP_HASH, ENTRYPOINT_V7, None,
    )
    # Done-callback runs synchronously when the task completes, so the
    # registry should already be empty here.
    assert not _inflight_receipt_lookups

    await handler.get_user_operation_receipt_rpc(
        USEROP_HASH, ENTRYPOINT_V7, None,
    )
    assert call_count == 2


@pytest.mark.asyncio
async def test_cancelled_waiter_does_not_kill_lookup_for_others():
    """If one polling client disconnects mid-flight, the underlying
    lookup (shielded) must still complete and serve other waiters."""
    call_count = 0
    started = asyncio.Event()
    release = asyncio.Event()

    async def slow_build(*_args):
        nonlocal call_count
        call_count += 1
        started.set()
        await release.wait()
        return {"userOpHash": USEROP_HASH, "receipt": "ok"}

    handler = _make_handler(slow_build)

    async def poll():
        with pytest.raises(UserOpReceiptFoundException) as exc:
            await handler.get_user_operation_receipt_rpc(
                USEROP_HASH, ENTRYPOINT_V7, None,
            )
        return exc.value.user_op_receipt_result

    survivor = asyncio.create_task(poll())
    quitter = asyncio.create_task(poll())
    await started.wait()

    quitter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await quitter

    release.set()
    result = await survivor
    assert call_count == 1
    assert result == {"userOpHash": USEROP_HASH, "receipt": "ok"}


@pytest.mark.asyncio
async def test_exception_propagates_to_all_waiters():
    """An unexpected error from the lookup must surface in every waiter
    (not be silently swallowed because they're sharing the future)."""
    call_count = 0
    started = asyncio.Event()
    release = asyncio.Event()

    class BoomError(RuntimeError):
        pass

    async def boom(*_args):
        nonlocal call_count
        call_count += 1
        started.set()
        await release.wait()
        raise BoomError("rpc backend exploded")

    handler = _make_handler(boom)

    tasks = [
        asyncio.create_task(handler.get_user_operation_receipt_rpc(
            USEROP_HASH, ENTRYPOINT_V7, None,
        ))
        for _ in range(3)
    ]
    await started.wait()
    release.set()

    results = await asyncio.gather(*tasks, return_exceptions=True)
    assert call_count == 1
    assert all(isinstance(r, BoomError) for r in results)


@pytest.mark.asyncio
async def test_abandoned_failing_task_does_not_log_unretrieved_warning(caplog):
    """When all waiters cancel a single-flight lookup that ends up
    raising, the underlying task continues to completion (asyncio.shield
    semantics). If nothing consumes ``task.exception()`` asyncio logs
    "Task exception was never retrieved" at GC time — under a transient
    upstream outage that would spam logs. The _evict callback must
    consume the exception so the warning never fires."""
    import gc
    import logging

    started = asyncio.Event()
    release = asyncio.Event()

    async def boom(*_args):
        started.set()
        await release.wait()
        raise RuntimeError("upstream rpc down")

    handler = _make_handler(boom)

    waiter = asyncio.create_task(handler.get_user_operation_receipt_rpc(
        USEROP_HASH, ENTRYPOINT_V7, None,
    ))
    await started.wait()

    # Sole waiter abandons before the task finishes. The shielded task
    # keeps running and will raise; nothing else awaits its result.
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter

    with caplog.at_level(logging.WARNING, logger="asyncio"):
        release.set()
        # Let the underlying task run to completion + done callback fire.
        # Two yields are enough: one to schedule the task's exception,
        # one to run the done callback.
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        # Force GC of the task object so any deferred "exception never
        # retrieved" warning would surface now if it were going to.
        gc.collect()

    unretrieved = [
        r for r in caplog.records
        if "exception was never retrieved" in r.getMessage()
    ]
    assert not unretrieved, (
        "single-flight should consume task.exception() in _evict — "
        f"saw: {[r.getMessage() for r in unretrieved]}"
    )


@pytest.mark.asyncio
async def test_key_is_case_insensitive_for_entrypoint_and_hash():
    """Coalescing must hold even when callers pass mixed-case hex
    (different EIP-55 checksums for the same address, or 0xABC vs 0xabc
    for the same hash)."""
    call_count = 0
    started = asyncio.Event()
    release = asyncio.Event()

    async def slow_build(*_args):
        nonlocal call_count
        call_count += 1
        started.set()
        await release.wait()
        return {"userOpHash": USEROP_HASH}

    handler = _make_handler(slow_build)

    async def poll(hash_arg, ep_arg):
        with pytest.raises(UserOpReceiptFoundException):
            await handler.get_user_operation_receipt_rpc(
                hash_arg, ep_arg, None,
            )

    t1 = asyncio.create_task(poll(USEROP_HASH.lower(), ENTRYPOINT_V7.lower()))
    t2 = asyncio.create_task(poll(USEROP_HASH.upper(), ENTRYPOINT_V7.upper()))
    await started.wait()
    release.set()
    await asyncio.gather(t1, t2)

    assert call_count == 1
