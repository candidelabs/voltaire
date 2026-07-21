"""Process-wide TTL cache for the chain head block number.

Both validation (every `eth_sendUserOperation`) and the userop-logs fast
path need a recent "latest" block number. Validation already learns the
chain head as a side-effect of running ``debug_traceCall`` / ``eth_call``
at ``block=latest``, so under load the bundler discovers a fresh head
many times per second without any extra RPC. Publishing that value here
lets the logs path skip its own ``eth_getBlockByNumber("latest")`` call
whenever the most recent validation was within ``max_age_s`` seconds.

When the cache is stale (or never populated, e.g. quiet period right
after startup), ``get_or_fetch`` falls back to a real
``eth_getBlockByNumber("latest")`` and writes the result back into the
cache so the next caller in the same window hits. A module-level
asyncio.Lock serialises the fallback fetch so a burst of stale reads
collapses into a single upstream RPC instead of N parallel ones.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from voltaire_bundler.utils.eth_client_utils import (
    send_rpc_request_to_eth_client,
)


_FETCH_TIMEOUT_S = 2.0  # matches ETH_RPC_LOOKUP_TIMEOUT_S in user_operation_handler

_cached_block_number: int | None = None
_cached_at_monotonic: float = 0.0
# Created lazily so importing this module doesn't require a running event
# loop (e.g. during unit-test collection). The first awaiter creates the
# lock; subsequent awaiters share it.
_fetch_lock: asyncio.Lock | None = None


def publish(block_number: int) -> None:
    """Record a freshly observed chain head. Cheap, sync, no I/O.

    Called from validation paths so the cache stays warm under load
    without ever issuing eth_getBlockByNumber on its own.

    The most recent publish always wins, even if it carries a LOWER
    block number than the previous cached value: a reorg can legitimately
    drop the canonical head, and rejecting the lower value would leave
    the cache stuck on a phantom block that no longer exists on chain.
    A late-arriving validation with a stale observation is the trade-off
    — it self-corrects on the next ``get_or_fetch`` past max_age_s."""
    global _cached_block_number, _cached_at_monotonic
    _cached_block_number = block_number
    _cached_at_monotonic = time.monotonic()


def peek() -> int | None:
    """Return the cached chain head without any I/O or freshness check.

    None if nothing has been published yet. Unlike ``get_or_fetch`` this
    never issues an RPC, so it can be used for cheap heuristics (e.g.
    "is this per-block cache probably still fresh?") where a slightly
    stale answer only costs a redundant fetch, never correctness."""
    return _cached_block_number


def _get_fetch_lock() -> asyncio.Lock:
    global _fetch_lock
    if _fetch_lock is None:
        _fetch_lock = asyncio.Lock()
    return _fetch_lock


async def get_or_fetch(
    ethereum_node_urls: list[str],
    max_age_s: float = 2.0,
) -> int | None:
    """Return a recent chain head, refreshing via eth_getBlockByNumber if
    the cached value is older than ``max_age_s`` (or never populated).

    On RPC failure with a populated cache: return the stale cached value
    rather than ``None``, so a transient upstream blip doesn't propagate
    as "no head known" to downstream chunking decisions (which then send
    unbounded ``toBlock=latest`` requests and trigger provider block-
    range caps). Only the genuinely-broken case — node was unreachable
    AND cache was never populated — returns ``None``. Call ``warm()`` at
    startup to make that case impossible in steady state."""
    now = time.monotonic()
    if (
        _cached_block_number is not None
        and now - _cached_at_monotonic <= max_age_s
    ):
        return _cached_block_number

    # Serialise fallback fetches: a burst of concurrent stale reads
    # (e.g. first batch of getUserOperationReceipt polls after startup,
    # before validation has called publish()) would otherwise each fire
    # its own eth_getBlockByNumber, defeating the cache. Re-check inside
    # the lock so only the first awaiter performs the RPC.
    async with _get_fetch_lock():
        now = time.monotonic()
        if (
            _cached_block_number is not None
            and now - _cached_at_monotonic <= max_age_s
        ):
            return _cached_block_number

        try:
            res: Any = await asyncio.wait_for(
                send_rpc_request_to_eth_client(
                    ethereum_node_urls,
                    "eth_getBlockByNumber",
                    ["latest", False],
                ),
                timeout=_FETCH_TIMEOUT_S,
            )
        except asyncio.TimeoutError:
            logging.error(
                "eth_getBlockByNumber(latest) timed out after %ss; "
                "serving stale cached head (%s)",
                _FETCH_TIMEOUT_S, _cached_block_number,
            )
            return _cached_block_number
        except Exception:
            logging.error(
                "eth_getBlockByNumber(latest) failed; "
                "serving stale cached head (%s)",
                _cached_block_number, exc_info=True,
            )
            return _cached_block_number

        if not isinstance(res, dict):
            return _cached_block_number
        result = res.get("result")
        if not isinstance(result, dict):
            return _cached_block_number
        raw = result.get("number")
        if not isinstance(raw, str):
            return _cached_block_number
        try:
            block_number = int(raw, 16)
        except ValueError:
            return _cached_block_number
        publish(block_number)
        return block_number


async def warm(ethereum_node_urls: list[str]) -> None:
    """Populate the cache with one synchronous eth_getBlockByNumber.
    Raises on failure so a bad ``--ethereum_node_url`` surfaces at
    startup rather than at the first eth_getLogs sweep. Mirrors
    ``GasPriceCache.warm``."""
    res: Any = await asyncio.wait_for(
        send_rpc_request_to_eth_client(
            ethereum_node_urls,
            "eth_getBlockByNumber",
            ["latest", False],
        ),
        timeout=_FETCH_TIMEOUT_S,
    )
    if not isinstance(res, dict):
        raise ValueError(f"eth_getBlockByNumber returned non-dict: {res!r}")
    result = res.get("result")
    if not isinstance(result, dict):
        raise ValueError(f"eth_getBlockByNumber result not a dict: {result!r}")
    raw = result.get("number")
    if not isinstance(raw, str):
        raise ValueError(f"eth_getBlockByNumber result.number not a str: {raw!r}")
    publish(int(raw, 16))
