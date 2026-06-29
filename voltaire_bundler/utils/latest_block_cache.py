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
``eth_getBlockByNumber("latest")``. An ``asyncio.Lock`` serialises that
fallback so a burst of stale reads collapses into a single upstream RPC
instead of N parallel ones. On RPC failure with a populated cache the
stale cached value is returned rather than ``None``; the only ``None``
return path is "node was unreachable AND cache was never populated",
which ``warm()`` at startup eliminates.

Shape: a ``LatestBlockCache`` class mirrors ``GasPriceCache`` so both
caches have the same lifecycle (``warm`` / ``get_or_fetch`` / ``publish``)
and are amenable to further consolidation behind a shared TtlCache base
later. A module-level singleton + thin facade functions
(``publish``, ``get_or_fetch``, ``warm``) preserve every existing
call site — converting all of them to constructor injection would
be a much larger touch with no behaviour change.
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


class LatestBlockCache:
    """Concurrency-safe TTL cache of the chain head block number.

    Lazy lifecycle (no background loop): the cache stays populated by
    ``publish`` calls from validation paths (where eth_call against
    block=latest naturally returns the head), and by inline fallback
    fetches inside ``get_or_fetch`` when nothing has published recently.
    """

    def __init__(self, max_age_s: float = 2.0) -> None:
        self._max_age_s = max_age_s
        self._cached_block_number: int | None = None
        self._cached_at_monotonic: float = 0.0
        # Lazy so importing this module doesn't require a running event
        # loop (e.g. during test collection).
        self._fetch_lock: asyncio.Lock | None = None

    # ------------------------------------------------------------------ read
    async def get_or_fetch(
        self,
        ethereum_node_urls: list[str],
        max_age_s: float | None = None,
    ) -> int | None:
        """Return a recent chain head, refreshing via eth_getBlockByNumber
        if the cached value is older than ``max_age_s`` (or never
        populated). ``max_age_s=None`` uses the instance default.

        On RPC failure with a populated cache returns the stale cached
        value, not ``None`` — so a transient upstream blip doesn't
        propagate as "no head known" to downstream chunking decisions.
        Only the genuinely-broken case (node unreachable AND cache never
        populated) returns ``None``; ``warm()`` at startup eliminates
        that path in steady state."""
        ttl = self._max_age_s if max_age_s is None else max_age_s
        now = time.monotonic()
        if (
            self._cached_block_number is not None
            and now - self._cached_at_monotonic <= ttl
        ):
            return self._cached_block_number

        # Single-flight: a burst of concurrent stale reads collapses to
        # one upstream call. Re-check inside the lock so only the first
        # awaiter performs the RPC.
        async with self._get_fetch_lock():
            now = time.monotonic()
            if (
                self._cached_block_number is not None
                and now - self._cached_at_monotonic <= ttl
            ):
                return self._cached_block_number

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
                    _FETCH_TIMEOUT_S, self._cached_block_number,
                )
                return self._cached_block_number
            except Exception:
                logging.error(
                    "eth_getBlockByNumber(latest) failed; "
                    "serving stale cached head (%s)",
                    self._cached_block_number, exc_info=True,
                )
                return self._cached_block_number

            parsed = self._parse_block_number(res)
            if parsed is None:
                return self._cached_block_number
            self.publish(parsed)
            return parsed

    # --------------------------------------------------------------- update
    def publish(self, block_number: int) -> None:
        """Record a freshly observed chain head. Cheap, sync, no I/O.

        Called from validation paths so the cache stays warm under load
        without ever issuing eth_getBlockByNumber on its own.

        The most recent publish always wins, even if it carries a LOWER
        block number than the previous cached value: a reorg can
        legitimately drop the canonical head, and rejecting the lower
        value would leave the cache stuck on a phantom block that no
        longer exists on chain. A late-arriving validation with a stale
        observation is the trade-off — it self-corrects on the next
        get_or_fetch past max_age_s."""
        self._cached_block_number = block_number
        self._cached_at_monotonic = time.monotonic()

    # ------------------------------------------------------------ lifecycle
    async def warm(self, ethereum_node_urls: list[str]) -> None:
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
        parsed = self._parse_block_number(res)
        if parsed is None:
            raise ValueError(
                f"eth_getBlockByNumber returned unexpected shape: {res!r}"
            )
        self.publish(parsed)

    # ----------------------------------------------------------- internals
    def _get_fetch_lock(self) -> asyncio.Lock:
        if self._fetch_lock is None:
            self._fetch_lock = asyncio.Lock()
        return self._fetch_lock

    @staticmethod
    def _parse_block_number(res: Any) -> int | None:
        if not isinstance(res, dict):
            return None
        result = res.get("result")
        if not isinstance(result, dict):
            return None
        raw = result.get("number")
        if not isinstance(raw, str):
            return None
        try:
            return int(raw, 16)
        except ValueError:
            return None


# ---------------------------------------------------------- module facade
# A single process-wide instance with the historical module-level API.
# Keeps every existing call site (``latest_block_cache.publish(...)``,
# ``latest_block_cache.get_or_fetch(...)``, ``latest_block_cache.warm(...)``)
# working without per-site changes. The class is exported separately so
# new code can use it via constructor injection.
_default = LatestBlockCache()


def publish(block_number: int) -> None:
    _default.publish(block_number)


async def get_or_fetch(
    ethereum_node_urls: list[str],
    max_age_s: float = 2.0,
) -> int | None:
    return await _default.get_or_fetch(ethereum_node_urls, max_age_s)


async def warm(ethereum_node_urls: list[str]) -> None:
    await _default.warm(ethereum_node_urls)
