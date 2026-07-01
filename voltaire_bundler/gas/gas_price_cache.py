"""Background-refreshed cache of network gas prices.

A single asyncio task polls ``eth_gasPrice`` (and ``eth_maxPriorityFeePerGas``
where applicable) on a per-chain interval and stores the latest values in
memory. All consumers in the bundler read from this cache instead of issuing
the RPC themselves on the userop hot path.

Why a cache: at >10 ops/sec, the per-submit and per-bundle fee fetches were
the second-biggest contributor to upstream RPC pressure (after
``debug_traceCall``, eliminated by ``--unsafe``). The fee values themselves
change at block cadence at most, so polling once per chain's typical block
time is sufficient and lets every userop submit skip two RPCs.

Staleness behaviour: if the background loop is dead or the last successful
refresh is older than ``3 * interval`` seconds, ``get_snapshot`` performs a
synchronous one-shot fetch so callers never operate on arbitrarily stale
data. A failure on that fallback path is propagated to the caller so the
userop request fails fast rather than silently using a hours-old fee.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

from voltaire_bundler.utils.eth_client_utils import \
    send_rpc_request_to_eth_client


# Per-chain refresh cadence (seconds). Picked to track each chain's typical
# block time: gas price doesn't change between blocks, so refreshing faster
# than the block rate is wasted work; refreshing slower means the cache lags
# real conditions during fee spikes and risks rejecting legitimate userops
# (or accepting underpriced ones that then fail bundle inclusion).
_REFRESH_INTERVAL_BY_CHAIN: dict[int, float] = {
    1: 10.0,            # Ethereum mainnet (12s blocks)
    11155111: 10.0,     # Sepolia
    137: 2.0,           # Polygon
    80002: 2.0,         # Polygon Amoy
    10: 2.0,            # Optimism
    11155420: 2.0,      # OP Sepolia
    8453: 2.0,          # Base
    84532: 2.0,         # Base Sepolia
    480: 2.0,           # World Chain
    4801: 2.0,          # World Chain Sepolia
    42161: 1.0,         # Arbitrum One (250ms blocks)
    421614: 1.0,        # Arbitrum Sepolia
    999: 1.0,           # HyperEVM
    998: 1.0,           # HyperEVM testnet
    5031: 1.0,          # Somnia
    50312: 1.0,         # Somnia testnet
    1337: 1.0,          # local anvil / dev
}
_DEFAULT_REFRESH_INTERVAL_SECONDS = 5.0

# Chains where ``eth_maxPriorityFeePerGas`` is not available. ``--legacy_mode``
# also disables the call (handled at construction time).
_CHAINS_WITHOUT_PRIORITY_FEE: frozenset[int] = frozenset({999, 998})


def default_refresh_interval(chain_id: int) -> float:
    return _REFRESH_INTERVAL_BY_CHAIN.get(
        chain_id, _DEFAULT_REFRESH_INTERVAL_SECONDS
    )


@dataclass(frozen=True)
class GasPriceSnapshot:
    """One sample of network fee values, plus the monotonic-clock timestamp at
    which it was successfully fetched."""
    max_fee_per_gas: int
    # ``None`` when the chain doesn't expose ``eth_maxPriorityFeePerGas``
    # (HyperEVM) or when the bundler is in legacy mode. Arbitrum DOES populate
    # this — the value is fetched, but most validation paths ignore it
    # because Arbitrum doesn't follow EIP-1559 priority semantics. Callers
    # keep their own conditional logic for when to USE the priority fee.
    max_priority_fee_per_gas: int | None
    fetched_at_monotonic: float


class GasPriceCache:
    """Background-refreshed cache of ``eth_gasPrice`` +
    ``eth_maxPriorityFeePerGas``.

    Lifecycle::

        cache = GasPriceCache(urls, chain_id, is_legacy_mode, interval)
        await cache.warm()                # one-shot fetch; raises on failure
        # ... start ``cache.run()`` as a TaskGroup child ...
        snap = await cache.get_snapshot() # never hits the network on hot path
    """

    def __init__(
        self,
        ethereum_node_urls: list[str],
        chain_id: int,
        is_legacy_mode: bool,
        refresh_interval_seconds: float,
    ):
        # Reject non-positive intervals at construction: a zero or
        # negative interval would make the staleness check trivially
        # true on every read and turn run()'s sleep into a hot loop.
        if refresh_interval_seconds <= 0:
            raise ValueError(
                "refresh_interval_seconds must be > 0, got "
                f"{refresh_interval_seconds!r}"
            )
        self._ethereum_node_urls = ethereum_node_urls
        self._chain_id = chain_id
        self._is_legacy_mode = is_legacy_mode
        self._interval = refresh_interval_seconds
        self._fetch_priority_fee = not (
            is_legacy_mode or chain_id in _CHAINS_WITHOUT_PRIORITY_FEE
        )
        self._snapshot: GasPriceSnapshot | None = None
        # Serialises fallback fetches so a burst of stale reads doesn't
        # produce N concurrent RPC calls.
        self._lock = asyncio.Lock()
        self._stop = asyncio.Event()

    # ------------------------------------------------------------------ read
    async def get_snapshot(self) -> GasPriceSnapshot:
        """Return the most recent fee snapshot. If no successful refresh has
        happened in the last ``3 * interval`` seconds, perform a synchronous
        one-shot fetch first so consumers never see arbitrarily stale data.
        """
        snap = self._snapshot
        if snap is not None and not self._is_stale(snap):
            return snap

        async with self._lock:
            # Re-check inside the lock: another caller may have refreshed
            # while we were waiting.
            snap = self._snapshot
            if snap is None or self._is_stale(snap):
                logging.warning(
                    "GasPriceCache stale (background loop dead or starved); "
                    "performing synchronous fallback fetch."
                )
                await self._refresh()
                snap = self._snapshot
        assert snap is not None
        return snap

    async def get_max_fee_per_gas(self) -> int:
        return (await self.get_snapshot()).max_fee_per_gas

    async def get_max_priority_fee_per_gas(self) -> int | None:
        return (await self.get_snapshot()).max_priority_fee_per_gas

    # ------------------------------------------------------------ lifecycle
    async def warm(self) -> None:
        """One synchronous fetch. Raises on failure so a bad
        ``--ethereum_node_url`` surfaces at startup instead of on the first
        userop."""
        await self._refresh()

    async def run(self) -> None:
        """Background refresh loop. Designed to be a child of the main
        TaskGroup — cancellation propagates naturally."""
        while not self._stop.is_set():
            try:
                # Sleep ``interval`` seconds, or wake early on stop.
                await asyncio.wait_for(
                    self._stop.wait(), timeout=self._interval
                )
                return  # stop was set
            except asyncio.TimeoutError:
                pass
            try:
                # Hold the same lock as the synchronous-fallback path so
                # the two refreshes can't race: without it, a slow
                # background gather can complete AFTER a fast fallback
                # refresh and overwrite the fresher snapshot with stale
                # data stamped at the (newer) write-time monotonic clock,
                # defeating the staleness guard.
                async with self._lock:
                    await self._refresh()
            except Exception as exc:
                # Background failures must not kill the loop. The staleness
                # guard in ``get_snapshot`` will trigger a synchronous retry
                # the next time a consumer reads, and that path will surface
                # the error to its caller.
                logging.warning(
                    "GasPriceCache background refresh failed: %s", exc
                )

    def stop(self) -> None:
        self._stop.set()

    # ----------------------------------------------------------- internals
    def _is_stale(self, snap: GasPriceSnapshot) -> bool:
        return (
            time.monotonic() - snap.fetched_at_monotonic > 3 * self._interval
        )

    async def _refresh(self) -> None:
        tasks: list = [send_rpc_request_to_eth_client(
            self._ethereum_node_urls, "eth_gasPrice", None, None, "result"
        )]
        if self._fetch_priority_fee:
            tasks.append(send_rpc_request_to_eth_client(
                self._ethereum_node_urls,
                "eth_maxPriorityFeePerGas",
                None, None, "result",
            ))
        results = await asyncio.gather(*tasks)

        max_fee = int(results[0]["result"], 16)
        priority: int | None = (
            int(results[1]["result"], 16) if self._fetch_priority_fee else None
        )

        self._snapshot = GasPriceSnapshot(
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority,
            fetched_at_monotonic=time.monotonic(),
        )
