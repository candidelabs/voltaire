"""Background-refreshed cache of network gas prices.

A single asyncio task polls ``eth_gasPrice`` (and ``eth_maxPriorityFeePerGas``
where applicable) on a fixed interval and stores the latest values in
memory. All consumers in the bundler read from this cache instead of issuing
the RPC themselves on the userop hot path.

Why a cache: at >10 ops/sec, the per-submit and per-bundle fee fetches were
the second-biggest contributor to upstream RPC pressure (after
``debug_traceCall``, eliminated by ``--unsafe``). The fee values themselves
change at block cadence at most, so polling on a fixed interval is
sufficient and lets every userop submit skip two RPCs.

Reads never touch the network. ``get_snapshot`` returns whatever the
background loop last stored, so a slow or unreachable eth node adds zero
latency to userop submission or bundle building: the loop logs the failure,
keeps the previous value, and retries on the next tick. The only time a
read can fail is before the cache has ever been populated (startup ``warm``
failed and no background tick has succeeded yet), which raises
``GasPriceUnavailableError``.

Node failover: every refresh tries the configured node URLs one at a time,
each under its own short deadline, so a primary that hangs (rather than
erroring) falls through to the next node instead of stalling the loop.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any

from voltaire_bundler.utils.eth_client_utils import \
    send_rpc_request_to_eth_client


# Uniform 1-second refresh cadence across every chain. Gives the tightest
# bound on how old a served value can be (one interval plus the fetch
# time) and matches the block time of the fast L2s (Arbitrum, HyperEVM,
# Somnia) that ran at this cadence before.
#
# Tradeoff on slow-block chains: the loop refreshes every interval
# regardless of block time. On mainnet that's ~12 eth_gasPrice /
# eth_maxPriorityFeePerGas calls per block, 11 of which return the same
# value. Operators on metered eth-node providers should raise this via
# --gas_price_refresh_interval or VOLTAIRE_GAS_PRICE_REFRESH_INTERVAL;
# both accept a positive float and take precedence over this default.
DEFAULT_REFRESH_INTERVAL_SECONDS = 1.0

# Chains where ``eth_maxPriorityFeePerGas`` is not available. ``--legacy_mode``
# also disables the call (handled at construction time).
_CHAINS_WITHOUT_PRIORITY_FEE: frozenset[int] = frozenset({999, 998})

# Per-node deadline for one refresh's RPC fetch. send_rpc_request_to_eth_client
# bounds each HTTP attempt at 60 s but internally retries up to 60 times, so
# against a dead upstream a single call can block for ~an hour and starve
# the refresh loop. eth_gasPrice normally answers in milliseconds; 5 s is
# generous headroom. The node list is walked one URL at a time, so a
# refresh takes at most ``_PER_NODE_TIMEOUT_SECONDS * len(nodes)``.
#
# Why walk nodes here instead of relying on send_rpc_request_to_eth_client's
# own rotation: that helper only moves to the next URL after an attempt
# *fails*, and a hanging node doesn't fail until aiohttp's 60 s total
# timeout. Giving each node its own short deadline is the only way a slow
# primary lets a healthy secondary answer.
_PER_NODE_TIMEOUT_SECONDS = 5.0

# Once the cached value is this old the loop's failure log is escalated
# from warning to error, so a long-running outage is visible in operator
# logs as more than a stream of per-tick warnings.
_STALE_ERROR_AFTER_SECONDS = 60.0


class GasPriceUnavailableError(Exception):
    """Raised by ``get_snapshot`` when the cache has never been populated:
    startup ``warm`` failed and no background refresh has succeeded since.
    The RPC layer maps this to a JSON-RPC error carrying the message."""


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
        snap = await cache.get_snapshot() # never hits the network
    """

    def __init__(
        self,
        ethereum_node_urls: list[str],
        chain_id: int,
        is_legacy_mode: bool,
        refresh_interval_seconds: float,
    ):
        # Reject non-positive intervals at construction: a zero or
        # negative interval would turn run()'s sleep into a hot loop.
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
        self._stop = asyncio.Event()

    # ------------------------------------------------------------------ read
    async def get_snapshot(self) -> GasPriceSnapshot:
        """Return the most recent fee snapshot without touching the network.

        Kept ``async`` so callers can ``gather`` it alongside real RPCs;
        it never awaits anything. Raises ``GasPriceUnavailableError`` only
        if no fetch has ever succeeded (see module docstring)."""
        snap = self._snapshot
        if snap is None:
            raise GasPriceUnavailableError(
                "gas price unavailable: the gas-price cache has not been "
                "populated yet (eth node unreachable at startup); retry "
                "shortly"
            )
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
        TaskGroup — cancellation propagates naturally.

        Refreshes every ``interval`` seconds unconditionally. A failed
        refresh keeps the previous snapshot in place and is retried on the
        next tick; readers are never blocked or failed by it."""
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
                await self._refresh()
            except Exception as exc:
                # Background failures must not kill the loop. Escalate to
                # error once the value being served is old enough that
                # fee validation is likely working from a wrong price.
                # %r, not %s: str(TimeoutError()) is an empty string.
                snap = self._snapshot
                age = (
                    time.monotonic() - snap.fetched_at_monotonic
                    if snap is not None else None
                )
                log = (
                    logging.error
                    if age is None or age > _STALE_ERROR_AFTER_SECONDS
                    else logging.warning
                )
                log(
                    "GasPriceCache background refresh failed: %r; "
                    "serving cached value aged %s",
                    exc, f"{age:.1f}s" if age is not None else "<none>",
                )

    def stop(self) -> None:
        self._stop.set()

    # ----------------------------------------------------------- internals
    async def _fetch_from_node(self, node_url: str) -> list[Any]:
        """Fetch the fee values from one node under a hard deadline."""
        tasks: list[asyncio.Task[Any]] = [asyncio.create_task(
            send_rpc_request_to_eth_client(
                [node_url], "eth_gasPrice", None, None, "result"
            )
        )]
        if self._fetch_priority_fee:
            tasks.append(asyncio.create_task(send_rpc_request_to_eth_client(
                [node_url], "eth_maxPriorityFeePerGas", None, None, "result",
            )))
        try:
            return await asyncio.wait_for(
                asyncio.gather(*tasks), timeout=_PER_NODE_TIMEOUT_SECONDS
            )
        finally:
            # gather() propagates the first failure without cancelling its
            # siblings, so without this a failed eth_gasPrice would leave
            # the eth_maxPriorityFeePerGas task (and its retry loop)
            # running against the node while we move on to the next one.
            # The timeout path already cancels both via wait_for; this
            # makes the exception path behave the same. Awaiting the
            # cancelled tasks lets them settle and retrieves their
            # exceptions so asyncio doesn't log "never retrieved".
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _refresh(self) -> None:
        """Try each configured node in order until one answers within its
        deadline. Raises the last node's error if all of them fail."""
        results: list[Any] | None = None
        last_exc: Exception | None = None
        node_count = len(self._ethereum_node_urls)
        for index, node_url in enumerate(self._ethereum_node_urls):
            try:
                results = await self._fetch_from_node(node_url)
                break
            except Exception as exc:
                last_exc = exc
                logging.warning(
                    "GasPriceCache: node %d/%d failed to serve gas price "
                    "(%r)%s",
                    index + 1, node_count, exc,
                    "; trying next node" if index + 1 < node_count else "",
                )
        if results is None:
            assert last_exc is not None
            raise last_exc

        try:
            max_fee = int(results[0]["result"], 16)
            priority: int | None = (
                int(results[1]["result"], 16)
                if self._fetch_priority_fee else None
            )
        except (ValueError, TypeError) as exc:
            # TypeError covers JSON null / bare numbers in "result";
            # ValueError covers non-hex garbage. Either way the bare
            # int() message doesn't say what produced it.
            raise ValueError(
                "GasPriceCache: eth node returned a malformed gas-price "
                "response (eth_gasPrice / eth_maxPriorityFeePerGas): "
                f"{results!r}"
            ) from exc

        self._snapshot = GasPriceSnapshot(
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority,
            fetched_at_monotonic=time.monotonic(),
        )
