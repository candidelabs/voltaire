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

Public-node mode (``--gas_price_node_url``): operators can point the
refresh loop at a list of free public RPC endpoints instead of their paid
provider, since the two fee calls are cheap and carry no state. In that
mode each refresh starts from the next node in the list (round-robin) so
the per-node request rate is ``1 / (interval * len(nodes))``, well under
public rate limits, and samples that deviate wildly from the current
snapshot are rejected unless several consecutive samples agree (see
``_OUTLIER_RATIO``). Public nodes are an unauthenticated input to a cost
decision — ``eth_maxPriorityFeePerGas`` drives the tip the bundler pays —
so one buggy or hostile endpoint must not be able to set the price alone.

Logging: the loop ticks every few seconds forever, so it logs on *state
changes*, not on every tick. A node's first failure (or outlier sample) is
a warning, its recovery an info line, and while it stays broken a single
reminder is logged every ``_PROBLEM_HEARTBEAT_SECONDS``; the ticks in
between log nothing, even at debug level, since the reminder carries the
running count and the latest error. The same applies to the refresh as a
whole, with one escalation to error at the moment the served value turns
stale. Fetches
go through ``send_rpc_request_once`` (one attempt, no logging) because the
cache already has its own per-node deadline and failover; the retrying
helper would add an error line plus a traceback for every attempt.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Any

from voltaire_bundler.utils.eth_client_utils import send_rpc_request_once


# Uniform 5-second refresh cadence across every chain. Bounds how old a
# served value can be at one interval plus the fetch time, while keeping
# upstream RPC volume modest: ~17k eth_gasPrice calls per day (plus the
# same again for eth_maxPriorityFeePerGas where fetched), versus ~86k at
# the previous 1 s default.
#
# Tradeoff on fast-block L2s (Arbitrum, HyperEVM, Somnia run ~1 s blocks):
# the served price can lag a few blocks. Fee validation tolerates that
# because gas prices move slowly relative to block time; operators who
# want tighter tracking can lower this via --gas_price_refresh_interval
# or VOLTAIRE_GAS_PRICE_REFRESH_INTERVAL. On slow-block chains (mainnet,
# ~12 s) this still refreshes 2-3 times per block. Both overrides accept
# a positive float and take precedence over this default.
DEFAULT_REFRESH_INTERVAL_SECONDS = 5.0

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

# Once the cached value is this old a continuing refresh failure is
# escalated from warning to error (once, when the threshold is crossed,
# and in the periodic reminders after that), so a long outage is visible
# in operator logs as more than the initial warning.
_STALE_ERROR_AFTER_SECONDS = 60.0

# While a node, or the refresh as a whole, keeps failing tick after tick,
# one reminder line is logged this often; the ticks in between are silent.
_PROBLEM_HEARTBEAT_SECONDS = 60.0

# Outlier rejection, active only in public-node mode. A fetched value that
# is more than this factor above or below the currently cached value is
# treated as that node's failure and the walk moves on to the next node.
# 5x is far outside what one refresh interval can legitimately move
# (EIP-1559 base fee changes at most 12.5% per block) while still
# catching the realistic bad cases: a node returning a wrong-chain
# price, a stuck/zero value, or a deliberately inflated tip.
_OUTLIER_RATIO = 5.0

# Escape hatch for the clamp. A genuine market jump beyond _OUTLIER_RATIO
# (a mint frenzy spiking the priority fee) would otherwise be rejected on
# every tick forever, pinning the cache at a stale low price. Once this
# many *consecutive* samples all deviate, the next deviant sample is
# accepted. Under round-robin, consecutive samples come from different
# nodes, so this is effectively "N nodes agree the price moved". A single
# bad node can't reach the threshold alone because the healthy node that
# follows it in the rotation resets the count.
_OUTLIER_CONFIRMATIONS = 3


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
        public_nodes: bool = False,
    ):
        """``public_nodes`` switches the node-selection policy from
        primary-first (walk the list from index 0 every refresh, so a
        trusted primary always answers when healthy) to round-robin with
        outlier rejection, for lists of untrusted public endpoints. See
        the module docstring."""
        # Reject non-positive intervals at construction: a zero or
        # negative interval would turn run()'s sleep into a hot loop.
        if refresh_interval_seconds <= 0:
            raise ValueError(
                "refresh_interval_seconds must be > 0, got "
                f"{refresh_interval_seconds!r}"
            )
        if not ethereum_node_urls:
            raise ValueError("GasPriceCache needs at least one node URL")
        self._ethereum_node_urls = ethereum_node_urls
        self._public_nodes = public_nodes
        # Index of the node the next refresh starts from (round-robin).
        self._next_start = 0
        # Consecutive samples rejected by the outlier clamp.
        self._outlier_streak = 0
        self._chain_id = chain_id
        self._is_legacy_mode = is_legacy_mode
        self._interval = refresh_interval_seconds
        self._fetch_priority_fee = not (
            is_legacy_mode or chain_id in _CHAINS_WITHOUT_PRIORITY_FEE
        )
        self._snapshot: GasPriceSnapshot | None = None
        self._stop = asyncio.Event()
        # Per-node log state (see _note_node_problem): consecutive problems,
        # when the current run of problems started, and when it was last
        # logged. A problem is a failed fetch or a rejected outlier sample.
        node_count = len(ethereum_node_urls)
        self._node_problems = [0] * node_count
        self._node_problem_since = [0.0] * node_count
        self._node_problem_logged_at = [0.0] * node_count
        # Same for the refresh as a whole (see _on_refresh_failure).
        self._refresh_failures = 0
        self._refresh_failed_since = 0.0
        self._refresh_failure_logged_at = 0.0
        self._stale_escalated = False

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
                # Background failures must not kill the loop; readers keep
                # getting the previous snapshot.
                self._on_refresh_failure(exc)
            else:
                self._on_refresh_success()

    def stop(self) -> None:
        self._stop.set()

    # ----------------------------------------------------------- internals
    async def _fetch_from_node(self, node_url: str) -> tuple[int, int | None]:
        """Fetch and parse the fee values from one node under a hard
        deadline. Returns ``(max_fee, priority_fee_or_None)``. A malformed
        response raises ValueError so the caller treats it as this node's
        failure and falls through to the next one."""
        tasks: list[asyncio.Task[Any]] = [asyncio.create_task(
            send_rpc_request_once(node_url, "eth_gasPrice")
        )]
        if self._fetch_priority_fee:
            tasks.append(asyncio.create_task(
                send_rpc_request_once(node_url, "eth_maxPriorityFeePerGas")
            ))
        try:
            results = await asyncio.wait_for(
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

        try:
            max_fee = int(results[0], 16)
            priority: int | None = (
                int(results[1], 16)
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
        return max_fee, priority

    def _node_walk_order(self) -> list[tuple[int, str]]:
        """``(configured_index, url)`` pairs in the order this refresh
        should try them. Primary-first by default; in public-node mode the
        start rotates one position per refresh and the rest of the list
        follows as failover. Indices are logged instead of URLs, which may
        embed provider API keys."""
        indexed = list(enumerate(self._ethereum_node_urls))
        if not self._public_nodes:
            return indexed
        start = self._next_start % len(indexed)
        # Advance even if this refresh ends up failing, so a dead node
        # doesn't get retried first on every tick.
        self._next_start = start + 1
        return indexed[start:] + indexed[:start]

    def _is_outlier(self, max_fee: int, priority: int | None) -> bool:
        """Public-node mode only: does this sample deviate from the cached
        snapshot by more than ``_OUTLIER_RATIO`` in either direction? A
        field whose cached value is zero can't be compared by ratio and is
        skipped. With no snapshot yet there is nothing to compare against,
        so the first sample is always accepted."""
        if not self._public_nodes or self._snapshot is None:
            return False
        pairs = [(max_fee, self._snapshot.max_fee_per_gas)]
        if priority is not None and \
                self._snapshot.max_priority_fee_per_gas is not None:
            pairs.append((priority, self._snapshot.max_priority_fee_per_gas))
        for new, old in pairs:
            if old == 0:
                continue
            if new > old * _OUTLIER_RATIO or new * _OUTLIER_RATIO < old:
                return True
        return False

    async def _refresh(self) -> None:
        """Try the configured nodes one at a time (see ``_node_walk_order``)
        until one answers within its deadline with well-formed, plausible
        values. Raises the last node's error if all of them fail."""
        parsed: tuple[int, int | None] | None = None
        last_exc: Exception | None = None
        node_count = len(self._ethereum_node_urls)
        for position, (index, node_url) in enumerate(self._node_walk_order()):
            is_last = position + 1 == node_count
            try:
                candidate = await self._fetch_from_node(node_url)
            except Exception as exc:
                last_exc = exc
                # %r, not %s: str(TimeoutError()) is an empty string.
                self._note_node_problem(
                    index, f"failed to serve gas price ({exc!r})", is_last
                )
                continue

            if self._is_outlier(*candidate):
                self._outlier_streak += 1
                if self._outlier_streak < _OUTLIER_CONFIRMATIONS:
                    assert self._snapshot is not None
                    description = (
                        "returned an outlier gas price (max_fee %d, "
                        "priority %s vs cached %d, %s); %d/%d consecutive "
                        "deviant samples" % (
                            candidate[0], candidate[1],
                            self._snapshot.max_fee_per_gas,
                            self._snapshot.max_priority_fee_per_gas,
                            self._outlier_streak, _OUTLIER_CONFIRMATIONS,
                        )
                    )
                    last_exc = ValueError(
                        "GasPriceCache: node %d/%d %s"
                        % (index + 1, node_count, description)
                    )
                    self._note_node_problem(index, description, is_last)
                    continue
                logging.warning(
                    "GasPriceCache: accepting deviant gas price from node "
                    "%d/%d after %d consecutive agreeing samples",
                    index + 1, node_count, self._outlier_streak,
                )
            parsed = candidate
            self._note_node_ok(index)
            break

        if parsed is None:
            assert last_exc is not None
            raise last_exc

        self._outlier_streak = 0
        max_fee, priority = parsed
        self._snapshot = GasPriceSnapshot(
            max_fee_per_gas=max_fee,
            max_priority_fee_per_gas=priority,
            fetched_at_monotonic=time.monotonic(),
        )

    # ------------------------------------------------------------- logging
    def _note_node_problem(
        self, index: int, description: str, is_last: bool
    ) -> None:
        """A node failed to produce a usable sample this tick. Logged at
        warning the first time, then as a reminder every
        ``_PROBLEM_HEARTBEAT_SECONDS`` while it keeps happening; silent
        in between."""
        now = time.monotonic()
        node_count = len(self._ethereum_node_urls)
        count = self._node_problems[index] + 1
        self._node_problems[index] = count
        suffix = "" if is_last else "; trying next node"
        if count == 1:
            self._node_problem_since[index] = now
            self._node_problem_logged_at[index] = now
            logging.warning(
                "GasPriceCache: node %d/%d %s%s",
                index + 1, node_count, description, suffix,
            )
            return
        if now - self._node_problem_logged_at[index] >= _PROBLEM_HEARTBEAT_SECONDS:
            self._node_problem_logged_at[index] = now
            logging.warning(
                "GasPriceCache: node %d/%d still failing: %d consecutive "
                "problems over %.0fs, latest: %s%s",
                index + 1, node_count, count,
                now - self._node_problem_since[index], description, suffix,
            )

    def _note_node_ok(self, index: int) -> None:
        """A node produced an accepted sample; closes its problem run, if
        any, with one info line."""
        count = self._node_problems[index]
        if count == 0:
            return
        logging.info(
            "GasPriceCache: node %d/%d recovered after %d consecutive "
            "problems over %.0fs",
            index + 1, len(self._ethereum_node_urls), count,
            time.monotonic() - self._node_problem_since[index],
        )
        self._node_problems[index] = 0

    def _on_refresh_failure(self, exc: Exception) -> None:
        """Every node failed this tick. First failure is a warning (error if
        nothing has ever been cached), the moment the served value turns
        stale is one error, then a reminder every
        ``_PROBLEM_HEARTBEAT_SECONDS`` at the matching level; silent in
        between."""
        now = time.monotonic()
        snap = self._snapshot
        age = now - snap.fetched_at_monotonic if snap is not None else None
        age_text = f"{age:.1f}s" if age is not None else "<none>"
        stale = age is None or age > _STALE_ERROR_AFTER_SECONDS
        self._refresh_failures += 1
        count = self._refresh_failures
        if count == 1:
            self._refresh_failed_since = now
            self._refresh_failure_logged_at = now
            self._stale_escalated = stale
            log = logging.error if stale else logging.warning
            log(
                "GasPriceCache background refresh failed: %r; "
                "serving cached value aged %s",
                exc, age_text,
            )
            return
        since = now - self._refresh_failed_since
        if stale and not self._stale_escalated:
            self._stale_escalated = True
            self._refresh_failure_logged_at = now
            logging.error(
                "GasPriceCache: refresh has failed %d times in a row over "
                "%.0fs; the served gas price is now %s old and fee "
                "validation is likely working from a wrong price "
                "(latest: %r)",
                count, since, age_text, exc,
            )
            return
        if now - self._refresh_failure_logged_at >= _PROBLEM_HEARTBEAT_SECONDS:
            self._refresh_failure_logged_at = now
            log = logging.error if stale else logging.warning
            log(
                "GasPriceCache: refresh still failing: %d consecutive "
                "failures over %.0fs; serving cached value aged %s "
                "(latest: %r)",
                count, since, age_text, exc,
            )

    def _on_refresh_success(self) -> None:
        count = self._refresh_failures
        if count == 0:
            return
        logging.info(
            "GasPriceCache: refresh recovered after %d consecutive failures "
            "over %.0fs",
            count, time.monotonic() - self._refresh_failed_since,
        )
        self._refresh_failures = 0
        self._stale_escalated = False
