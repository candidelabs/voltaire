"""LogsCoalescer unit tests.

Patches ``send_rpc_request_to_eth_client`` to a controllable async fake
and asserts both the contract (each waiter sees its own logs / None) and
the upstream-call shape (one batched call instead of N per-waiter calls,
correct topic-array filter, range bounds).
"""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from voltaire_bundler.user_operation.logs_coalescer import (
    LogsCoalescer,
    USER_OPERATION_EVENT_DESCRIPTOR,
)


ENTRYPOINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
URLS = ["http://node-a"]


def _log(user_op_hash: str, block: int = 100) -> dict[str, Any]:
    """A minimal eth_getLogs entry shape with the userOpHash in topics[1]."""
    return {
        "blockNumber": hex(block),
        "blockHash": "0xblock" + hex(block)[2:],
        "transactionHash": "0xtx" + user_op_hash[2:8],
        "topics": [
            USER_OPERATION_EVENT_DESCRIPTOR,
            user_op_hash.lower(),
        ],
    }


def _rpc_result(logs: list[dict[str, Any]]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 1, "result": logs}


@pytest.mark.asyncio
async def test_single_request_issues_one_call():
    """Baseline: one waiter → one upstream eth_getLogs."""
    coalescer = LogsCoalescer(debounce_ms=10)
    fake = AsyncMock(return_value=_rpc_result([_log("0xaaa")]))
    with patch(
        "voltaire_bundler.user_operation.logs_coalescer."
        "send_rpc_request_to_eth_client",
        fake,
    ):
        result = await coalescer.request(
            URLS, "0xAAA", ENTRYPOINT, 100, 200,
        )
    assert result is not None and len(result) == 1
    assert fake.call_count == 1


@pytest.mark.asyncio
async def test_concurrent_distinct_hashes_coalesce_to_one_call():
    """Five concurrent requests for five distinct hashes get folded into
    one upstream call; each waiter sees only its own log."""
    coalescer = LogsCoalescer(debounce_ms=30)

    hashes = [f"0x{i:064x}" for i in range(1, 6)]
    fake_logs = [_log(h) for h in hashes]
    fake = AsyncMock(return_value=_rpc_result(fake_logs))
    with patch(
        "voltaire_bundler.user_operation.logs_coalescer."
        "send_rpc_request_to_eth_client",
        fake,
    ):
        results = await asyncio.gather(*[
            coalescer.request(URLS, h, ENTRYPOINT, 100, 200) for h in hashes
        ])

    assert fake.call_count == 1, "five concurrent waiters → one upstream call"
    # The single upstream call must have OR-filtered on all five hashes.
    params = fake.call_args.args[2]
    assert isinstance(params, list) and len(params) == 1
    filt = params[0]
    assert filt["topics"][0] == USER_OPERATION_EVENT_DESCRIPTOR
    assert sorted(filt["topics"][1]) == sorted(h.lower() for h in hashes)
    assert filt["fromBlock"] == hex(100) and filt["toBlock"] == hex(200)

    # Each waiter sees ONLY its own hash's logs.
    for h, r in zip(hashes, results):
        assert r is not None and len(r) == 1
        assert r[0]["topics"][1] == h.lower()


@pytest.mark.asyncio
async def test_same_hash_from_multiple_waiters_dedupes():
    """If two waiters request the same hash, the upstream call sends one
    element in the OR-array and both waiters resolve to the same logs."""
    coalescer = LogsCoalescer(debounce_ms=30)
    fake = AsyncMock(return_value=_rpc_result([_log("0xaaa")]))
    with patch(
        "voltaire_bundler.user_operation.logs_coalescer."
        "send_rpc_request_to_eth_client",
        fake,
    ):
        a, b = await asyncio.gather(
            coalescer.request(URLS, "0xaaa", ENTRYPOINT, 100, 200),
            coalescer.request(URLS, "0xaaa", ENTRYPOINT, 100, 200),
        )
    assert fake.call_count == 1
    filt = fake.call_args.args[2][0]
    assert filt["topics"][1] == ["0xaaa"]
    assert a == b


@pytest.mark.asyncio
async def test_more_than_max_hashes_splits_into_parallel_calls():
    """A batch of >max_hashes_per_call splits into parallel chunks; each
    waiter still sees its own log."""
    coalescer = LogsCoalescer(debounce_ms=30, max_hashes_per_call=3)

    hashes = [f"0x{i:064x}" for i in range(1, 8)]  # 7 hashes → 3 chunks (3+3+1)
    # Fake returns ALL the logs regardless of filter — coalescer's
    # client-side bucketing handles distribution.
    fake = AsyncMock(return_value=_rpc_result([_log(h) for h in hashes]))
    with patch(
        "voltaire_bundler.user_operation.logs_coalescer."
        "send_rpc_request_to_eth_client",
        fake,
    ):
        results = await asyncio.gather(*[
            coalescer.request(URLS, h, ENTRYPOINT, 100, 200) for h in hashes
        ])

    assert fake.call_count == 3, "7 hashes / 3 per chunk → 3 upstream calls"
    # Each waiter resolves with its own log only (not the whole 7-log
    # batch — bucketing on topics[1] is correct).
    for h, r in zip(hashes, results):
        assert r is not None and len(r) == 1
        assert r[0]["topics"][1] == h.lower()


@pytest.mark.asyncio
async def test_range_too_wide_falls_back_to_per_waiter():
    """If the union range exceeds max_range_blocks, every waiter gets its
    own call rather than dragging the whole batch's scan range."""
    coalescer = LogsCoalescer(
        debounce_ms=30, max_range_blocks=1000,
    )

    # Two waiters with ranges that union to > 1000 blocks.
    fake = AsyncMock(return_value=_rpc_result([]))
    with patch(
        "voltaire_bundler.user_operation.logs_coalescer."
        "send_rpc_request_to_eth_client",
        fake,
    ):
        results = await asyncio.gather(
            coalescer.request(URLS, "0xaaa", ENTRYPOINT, 100, 200),
            coalescer.request(URLS, "0xbbb", ENTRYPOINT, 5_000, 10_000),
        )

    # Fallback path = one call per waiter.
    assert fake.call_count == 2
    assert results == [None, None]


@pytest.mark.asyncio
async def test_upstream_failure_resolves_waiters_with_none():
    """Upstream raises (transport error, etc.) → every waiter sees None."""
    coalescer = LogsCoalescer(debounce_ms=10)
    fake = AsyncMock(side_effect=RuntimeError("boom"))
    with patch(
        "voltaire_bundler.user_operation.logs_coalescer."
        "send_rpc_request_to_eth_client",
        fake,
    ):
        a, b = await asyncio.gather(
            coalescer.request(URLS, "0xaaa", ENTRYPOINT, 100, 200),
            coalescer.request(URLS, "0xbbb", ENTRYPOINT, 100, 200),
        )
    assert a is None and b is None


@pytest.mark.asyncio
async def test_debounce_zero_bypasses_batching():
    """debounce_ms=0 → every request immediately makes its own single-hash
    call. Used for local dev and "disable coalescing" mode."""
    coalescer = LogsCoalescer(debounce_ms=0)
    fake = AsyncMock(return_value=_rpc_result([_log("0xaaa")]))
    with patch(
        "voltaire_bundler.user_operation.logs_coalescer."
        "send_rpc_request_to_eth_client",
        fake,
    ):
        # Two concurrent requests → two separate calls (no batching).
        await asyncio.gather(
            coalescer.request(URLS, "0xaaa", ENTRYPOINT, 100, 200),
            coalescer.request(URLS, "0xbbb", ENTRYPOINT, 100, 200),
        )
    assert fake.call_count == 2
    # The bypass path filters on a single hash, not an OR-array.
    for call in fake.call_args_list:
        filt = call.args[2][0]
        assert isinstance(filt["topics"][1], str)


@pytest.mark.asyncio
async def test_late_arrival_after_dispatch_starts_new_batch():
    """A waiter arriving after the debounce flush has dispatched starts a
    fresh batch — should still resolve correctly, not hang."""
    coalescer = LogsCoalescer(debounce_ms=20)
    fake = AsyncMock(return_value=_rpc_result([_log("0xaaa")]))
    with patch(
        "voltaire_bundler.user_operation.logs_coalescer."
        "send_rpc_request_to_eth_client",
        fake,
    ):
        first = await coalescer.request(URLS, "0xaaa", ENTRYPOINT, 100, 200)
        # First batch dispatched and cleared; a second request should
        # spin up a fresh batch and complete on its own.
        second = await coalescer.request(URLS, "0xaaa", ENTRYPOINT, 100, 200)
    assert first is not None and second is not None
    assert fake.call_count == 2


@pytest.mark.asyncio
async def test_cancelled_waiter_does_not_break_siblings():
    """If one waiter is cancelled before the flush, the remaining waiters
    in the batch still get their results."""
    coalescer = LogsCoalescer(debounce_ms=40)
    fake = AsyncMock(return_value=_rpc_result([_log("0xbbb")]))

    async def _cancelled_after_join():
        # Join the batch then cancel ourselves shortly after.
        task = asyncio.create_task(
            coalescer.request(URLS, "0xaaa", ENTRYPOINT, 100, 200)
        )
        await asyncio.sleep(0.005)  # ensure we're queued in the batch
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    with patch(
        "voltaire_bundler.user_operation.logs_coalescer."
        "send_rpc_request_to_eth_client",
        fake,
    ):
        cancelled, sibling = await asyncio.gather(
            _cancelled_after_join(),
            coalescer.request(URLS, "0xbbb", ENTRYPOINT, 100, 200),
        )
    assert sibling is not None and len(sibling) == 1
    assert sibling[0]["topics"][1] == "0xbbb"
