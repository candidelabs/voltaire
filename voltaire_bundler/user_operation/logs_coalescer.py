"""Coalesce concurrent eth_getLogs cache misses into a single upstream call.

When N client polls for distinct userOpHashes hit the userop-logs cache miss
path within a short window (typical pattern: a fleet of clients polling
``getUserOperationByHash`` / ``getUserOperationReceipt`` at the same cadence),
the per-poll path issues N independent ``eth_getLogs`` requests — each
filtered to a single hash via ``topics[1]``. The coalescer batches those
into a single request that uses ``topics[1]`` as an OR-array of hashes:
the upstream node still does the per-hash filtering, but we pay ONE round
trip and ONE response-parse instead of N.

Trade-offs:

* Adds up to ``debounce_ms`` (50 ms default) latency to the cache-miss path.
  Negligible against the typical 1–2 s client poll cadence.
* If the batch's union block range exceeds ``max_range_blocks`` (1000) — e.g.
  one stale requester with a very early ``validated_at_block`` joins the
  batch — coalescing is skipped for that flush and every waiter falls back
  to its own per-request call. Prevents a sticky requester from dragging
  everyone's scan range.
* Hash batches larger than ``max_hashes_per_call`` (10, Alchemy's cap) split
  into parallel upstream calls under the chunk semaphore.

Contract preservation: each waiter sees the same shape its per-call path
returned — a non-empty list of log dicts on hit, ``None`` on miss or any
failure. Callers don't need to know coalescing happened.
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from prometheus_client import Counter

from voltaire_bundler.utils.eth_client_utils import \
    send_rpc_request_to_eth_client


USER_OPERATION_EVENT_DESCRIPTOR = (
    "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f"
)

# Prometheus counters. Operators can compute the savings ratio as
# 1 - upstream_calls_total / waiters_total: 0.8 means 80% of polls
# would have been their own RPC and were saved by batching.
_WAITERS_TOTAL = Counter(
    "voltaire_logs_coalescer_waiters_total",
    "Concurrent eth_getLogs cache-miss polls handed to the coalescer.",
)
_UPSTREAM_CALLS_TOTAL = Counter(
    "voltaire_logs_coalescer_upstream_calls_total",
    "Upstream eth_getLogs calls the coalescer actually issued, "
    "including chunk splits and per-waiter fallbacks.",
)
_BATCHES_TOTAL = Counter(
    "voltaire_logs_coalescer_batches_total",
    "Coalesced batches dispatched (one per debounce window per "
    "(entrypoint, urls) bucket).",
)
_FALLBACKS_TOTAL = Counter(
    "voltaire_logs_coalescer_fallbacks_total",
    "Times the coalescer fell back to per-waiter calls because the "
    "batch's union block range exceeded max_range_blocks.",
)


@dataclass
class _Waiter:
    user_operation_hash: str  # lowercased
    from_block_int: int
    to_block_int: int
    future: asyncio.Future


@dataclass
class _Batch:
    """One in-flight batch of waiters keyed by (entrypoint, urls).

    A batch lives from the first waiter arrival to the flush moment;
    once ``dispatched`` is set the flush task has committed to issuing
    the upstream call(s) and any new arrivals must start a new batch."""
    entrypoint: str
    urls: tuple[str, ...]
    waiters: list[_Waiter] = field(default_factory=list)
    dispatched: bool = False


class LogsCoalescer:
    """Per-process coalescer for ``get_user_operation_logs`` cache-miss
    paths. Constructor-injected onto the user_operation_handler so it's
    explicit (and testable) rather than a module global.

    Set ``debounce_ms=0`` to disable batching — every request immediately
    triggers its own upstream call. Useful for local dev, debugging, and
    bypassing the coalescer when latency-on-miss matters more than RPC
    count."""

    def __init__(
        self,
        debounce_ms: int = 50,
        max_hashes_per_call: int = 10,
        max_range_blocks: int = 1_000,
        max_concurrent_calls: int = 8,
        request_timeout_s: float = 2.0,
    ) -> None:
        self._debounce_ms = debounce_ms
        self._max_hashes_per_call = max_hashes_per_call
        self._max_range_blocks = max_range_blocks
        self._max_concurrent_calls = max_concurrent_calls
        self._request_timeout_s = request_timeout_s
        # Bucket key: (entrypoint_lower, urls_tuple) → pending batch.
        # Distinct URL pools (e.g. logs vs validation node lists) don't
        # cross-pollinate even when querying the same entrypoint.
        self._pending: dict[tuple[str, tuple[str, ...]], _Batch] = {}
        self._lock = asyncio.Lock()

    async def request(
        self,
        ethereum_node_urls: list[str],
        user_operation_hash: str,
        entrypoint: str,
        from_block_int: int,
        to_block_int: int,
    ) -> list[Any] | None:
        """Return the eth_getLogs result for ``user_operation_hash`` over
        [from_block_int, to_block_int]. Joins (or starts) a batch for the
        same (entrypoint, urls); the upstream call happens after the
        debounce window or when the batch's hash union saturates the
        max-per-call cap."""
        _WAITERS_TOTAL.inc()
        loop = asyncio.get_event_loop()
        future: asyncio.Future = loop.create_future()
        waiter = _Waiter(
            user_operation_hash=user_operation_hash.lower(),
            from_block_int=from_block_int,
            to_block_int=to_block_int,
            future=future,
        )

        if self._debounce_ms == 0:
            # Bypass coalescing entirely — immediate single-hash call.
            _UPSTREAM_CALLS_TOTAL.inc()
            return await self._single_call(
                tuple(ethereum_node_urls),
                entrypoint.lower(),
                waiter,
            )

        key = (entrypoint.lower(), tuple(ethereum_node_urls))
        flush_immediately = False
        async with self._lock:
            batch = self._pending.get(key)
            if batch is None or batch.dispatched:
                batch = _Batch(entrypoint=entrypoint.lower(), urls=key[1])
                self._pending[key] = batch
                # The first waiter spawns the debounce flush.
                asyncio.create_task(self._flush_after_debounce(key, batch))
            batch.waiters.append(waiter)
            # Saturation flush: if the batch is already big enough to fill
            # a single upstream call to the cap, dispatch immediately so
            # we don't pay debounce latency for a batch we can't grow.
            distinct_hashes = {w.user_operation_hash for w in batch.waiters}
            if len(distinct_hashes) >= self._max_hashes_per_call:
                if not batch.dispatched:
                    batch.dispatched = True
                    self._pending.pop(key, None)
                    flush_immediately = True
        if flush_immediately:
            asyncio.create_task(self._dispatch(batch))
        try:
            return await future
        except asyncio.CancelledError:
            # Drop this waiter from the batch if the consumer is gone.
            # The batch still runs for the remaining waiters; no need to
            # mutate batch.waiters here since the flush only resolves
            # un-cancelled futures.
            raise

    async def _flush_after_debounce(
        self,
        key: tuple[str, tuple[str, ...]],
        batch: _Batch,
    ) -> None:
        try:
            await asyncio.sleep(self._debounce_ms / 1000)
        except asyncio.CancelledError:
            # Inherited cancellation while sleeping: still try to flush
            # so waiters don't hang forever.
            pass
        async with self._lock:
            # Another path (saturation flush) may have already dispatched
            # this batch. Re-check under lock.
            if batch.dispatched:
                return
            batch.dispatched = True
            # Only clear the slot if it's still our batch. A late saturation
            # flush could have replaced us with a new one in the same key.
            if self._pending.get(key) is batch:
                self._pending.pop(key, None)
        await self._dispatch(batch)

    async def _dispatch(self, batch: _Batch) -> None:
        """Issue upstream call(s) for ``batch`` and resolve every waiter's
        future. Never raises — any error path resolves waiters with
        ``None`` to match the per-call miss contract."""
        live = [w for w in batch.waiters if not w.future.done()]
        if not live:
            return
        _BATCHES_TOTAL.inc()

        # Compute the union range across waiters. If it's too wide for one
        # eth_getLogs call (a sticky waiter with a very early validated_at
        # block joined), bail to per-waiter calls.
        from_min = min(w.from_block_int for w in live)
        to_max = max(w.to_block_int for w in live)
        if to_max - from_min > self._max_range_blocks:
            _FALLBACKS_TOTAL.inc()
            logging.debug(
                "logs coalescer: %d waiters → fallback (range %d > %d)",
                len(live), to_max - from_min, self._max_range_blocks,
            )
            await self._fallback_per_waiter(batch.urls, batch.entrypoint, live)
            return

        # Hash union; sorted for deterministic batch boundaries.
        all_hashes = sorted({w.user_operation_hash for w in live})
        # Split into provider-portable batches.
        hash_batches = [
            all_hashes[i:i + self._max_hashes_per_call]
            for i in range(0, len(all_hashes), self._max_hashes_per_call)
        ]
        _UPSTREAM_CALLS_TOTAL.inc(len(hash_batches))
        logging.debug(
            "logs coalescer: %d waiters / %d unique hashes → %d upstream call(s)",
            len(live), len(all_hashes), len(hash_batches),
        )
        semaphore = asyncio.Semaphore(self._max_concurrent_calls)
        sub_results = await asyncio.gather(
            *(self._fetch_chunk(
                batch.urls, batch.entrypoint, from_min, to_max, hb, semaphore,
            ) for hb in hash_batches),
            return_exceptions=False,  # _fetch_chunk swallows internally
        )

        # Bucket logs by topics[1] (userOpHash, already lowercased on
        # arrival to match our key).
        by_hash: dict[str, list[Any]] = defaultdict(list)
        for chunk_logs in sub_results:
            for log_entry in chunk_logs:
                topics = log_entry.get("topics") or []
                if len(topics) < 2 or not isinstance(topics[1], str):
                    continue
                by_hash[topics[1].lower()].append(log_entry)

        # Resolve each waiter with its own hash's logs.
        for waiter in live:
            if waiter.future.done():
                continue
            hits = by_hash.get(waiter.user_operation_hash)
            # Match per-call contract: non-empty list on hit, None on miss.
            waiter.future.set_result(hits if hits else None)

    async def _fetch_chunk(
        self,
        urls: tuple[str, ...],
        entrypoint: str,
        from_block_int: int,
        to_block_int: int,
        hashes: list[str],
        semaphore: asyncio.Semaphore,
    ) -> list[Any]:
        async with semaphore:
            params = [
                {
                    "address": entrypoint,
                    "topics": [USER_OPERATION_EVENT_DESCRIPTOR, hashes],
                    "fromBlock": hex(from_block_int),
                    "toBlock": hex(to_block_int),
                }
            ]
            try:
                res = await asyncio.wait_for(
                    send_rpc_request_to_eth_client(
                        list(urls), "eth_getLogs", params,
                    ),
                    timeout=self._request_timeout_s,
                )
            except asyncio.TimeoutError:
                logging.error(
                    "coalesced poll eth_getLogs (%s -> %s, %d hashes) "
                    "timed out after %ss; treating chunk as miss",
                    hex(from_block_int), hex(to_block_int),
                    len(hashes), self._request_timeout_s,
                )
                return []
            except Exception:
                logging.error(
                    "coalesced poll eth_getLogs (%s -> %s, %d hashes) "
                    "failed; treating chunk as miss",
                    hex(from_block_int), hex(to_block_int),
                    len(hashes), exc_info=True,
                )
                return []
            if not (isinstance(res, dict) and isinstance(res.get("result"), list)):
                return []
            return res["result"]

    async def _fallback_per_waiter(
        self,
        urls: tuple[str, ...],
        entrypoint: str,
        waiters: list[_Waiter],
    ) -> None:
        """Range too wide for a single coalesced call. Issue independent
        single-hash queries for each waiter, in parallel under the
        concurrency cap. Same as the un-batched per-call path."""
        _UPSTREAM_CALLS_TOTAL.inc(len(waiters))
        semaphore = asyncio.Semaphore(self._max_concurrent_calls)

        async def _one(waiter: _Waiter) -> None:
            result = await self._single_call(
                urls, entrypoint, waiter, semaphore=semaphore,
            )
            if not waiter.future.done():
                waiter.future.set_result(result)

        await asyncio.gather(*(_one(w) for w in waiters))

    async def _single_call(
        self,
        urls: tuple[str, ...],
        entrypoint: str,
        waiter: _Waiter,
        *,
        semaphore: asyncio.Semaphore | None = None,
    ) -> list[Any] | None:
        """One eth_getLogs filtered to a single waiter's hash. Used by the
        debounce-0 (bypass) path and the wide-range fallback. Mirrors
        ``_eth_getLogs_once`` in user_operation_handler."""
        params = [
            {
                "address": entrypoint,
                "topics": [
                    USER_OPERATION_EVENT_DESCRIPTOR,
                    waiter.user_operation_hash,
                ],
                "fromBlock": hex(waiter.from_block_int),
                "toBlock": hex(waiter.to_block_int),
            }
        ]

        async def _do() -> list[Any] | None:
            try:
                res = await asyncio.wait_for(
                    send_rpc_request_to_eth_client(
                        list(urls), "eth_getLogs", params,
                    ),
                    timeout=self._request_timeout_s,
                )
            except asyncio.TimeoutError:
                logging.error(
                    "poll eth_getLogs (%s, %s -> %s) timed out after %ss; miss",
                    waiter.user_operation_hash,
                    hex(waiter.from_block_int), hex(waiter.to_block_int),
                    self._request_timeout_s,
                )
                return None
            except Exception:
                logging.error(
                    "poll eth_getLogs (%s, %s -> %s) failed; miss",
                    waiter.user_operation_hash,
                    hex(waiter.from_block_int), hex(waiter.to_block_int),
                    exc_info=True,
                )
                return None
            if (
                isinstance(res, dict)
                and isinstance(res.get("result"), list)
                and len(res["result"]) > 0
            ):
                return res["result"]
            return None

        if semaphore is None:
            return await _do()
        async with semaphore:
            return await _do()
