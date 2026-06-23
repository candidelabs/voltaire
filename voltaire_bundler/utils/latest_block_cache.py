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
cache so the next caller in the same window hits.

Single-value cache (the chain head is chain-global), no locking — all
mutation happens synchronously between awaits in the asyncio loop.
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


def publish(block_number: int) -> None:
    """Record a freshly observed chain head. Cheap, sync, no I/O.

    Called from validation paths so the cache stays warm under load
    without ever issuing eth_getBlockByNumber on its own."""
    global _cached_block_number, _cached_at_monotonic
    # Only move forward — a stale-by-a-block validation result published
    # after a newer one shouldn't rewind the cache.
    if _cached_block_number is None or block_number >= _cached_block_number:
        _cached_block_number = block_number
        _cached_at_monotonic = time.monotonic()


async def get_or_fetch(
    ethereum_node_urls: list[str],
    max_age_s: float = 2.0,
) -> int | None:
    """Return a recent chain head, refreshing via eth_getBlockByNumber if
    the cached value is older than ``max_age_s`` (or never populated).

    On RPC failure, returns ``None`` — same contract as the previous
    inline implementation in user_operation_handler so callers that use
    this to size a fast-path window degrade to "skip the window" rather
    than crashing."""
    global _cached_block_number, _cached_at_monotonic
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
            "latest-block cache miss returns None",
            _FETCH_TIMEOUT_S,
        )
        return None
    except Exception:
        logging.error(
            "eth_getBlockByNumber(latest) failed; "
            "latest-block cache miss returns None",
            exc_info=True,
        )
        return None

    if not isinstance(res, dict):
        return None
    result = res.get("result")
    if not isinstance(result, dict):
        return None
    raw = result.get("number")
    if not isinstance(raw, str):
        return None
    try:
        block_number = int(raw, 16)
    except ValueError:
        return None
    publish(block_number)
    return block_number
