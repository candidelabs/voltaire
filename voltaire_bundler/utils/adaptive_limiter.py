"""Per-method adaptive concurrency limiter for outbound RPC calls.

Replaces the previous fixed asyncio.Semaphore. Behaves like a resizable
semaphore whose limit is driven by AIMD (additive-increase, multiplicative-
decrease) on observed call latency, so the bundler stays roughly at the
sweet spot for whatever upstream node it happens to be pointed at.

Algorithm summary (per method, rolling last WINDOW_SIZE completions):
  - baseline_p50_ms: rolling minimum of observed window p50s (the "fast"
    latency the node can serve at low load).
  - recent_p50_ms:   median of the current window.
  - saturation:      whether in_flight was at (cap - 1) or higher when
                     the call completed.

  Additive Increase — grow the cap by 1 when the queue is under pressure
  (saturation) AND recent p50 is still within GROWTH_TOL of baseline.
  Multiplicative Decrease — halve the cap (down to the method's floor)
  when recent p50 climbs to SHRINK_TRIGGER * baseline, OR when the call
  itself errored / was cancelled.

Per-method floors (``_METHOD_MIN_CAPS``) exist because a few methods must
not be starved even under upstream distress — the write path
(eth_sendRawTransaction) and bundle-inclusion polling in particular. The
floor is a SHRINK limit, not a starting point; grow is unaffected.

Kill switch: ``configure(disabled=True)`` swaps every limiter for a
fixed-cap variant that never mutates. Same acquire/release surface; no
downstream code changes required to fall back.
"""
from __future__ import annotations

import asyncio
import collections
import time
from types import TracebackType
from typing import Any, Callable

# --- algorithm constants ---------------------------------------------------
GROWTH_TOL: float = 1.5
SHRINK_TRIGGER: float = 3.0
BASELINE_UPWARD_TRIGGER: float = 2.0
BASELINE_UPWARD_WINDOWS: int = 4
GLOBAL_MIN_CAP: int = 2
MAX_CAP: int = 256
WINDOW_SIZE: int = 32
MIN_SAMPLES: int = 8

# Seed caps used when a new limiter is created. These are STARTING values;
# AIMD moves them from there. Kept generous on the way up because we want
# the algorithm to explore, not to sit right at the seed.
_METHOD_INITIAL_CAPS: dict[str, int] = {
    "eth_call": 32,
    "eth_getLogs": 16,
    "eth_getBlockByNumber": 8,
    "eth_getTransactionReceipt": 32,
    "eth_getTransactionByHash": 32,
    "eth_getTransactionCount": 16,
    "eth_sendRawTransaction": 8,
    "debug_traceCall": 16,
    "eth_gasPrice": 4,
    "eth_maxPriorityFeePerGas": 4,
    "eth_getProof": 16,
    "eth_getCode": 8,
    "eth_getBalance": 4,
    "trace_transaction": 8,
}
_DEFAULT_INITIAL_CAP: int = 16

# Per-method shrink floors. See module docstring for rationale on why some
# methods have explicit floors above the global minimum.
_METHOD_MIN_CAPS: dict[str, int] = {
    "eth_sendRawTransaction": 4,
    "eth_getTransactionReceipt": 8,
    "eth_getTransactionByHash": 8,
    "eth_getTransactionCount": 4,
    "eth_gasPrice": 2,
    "eth_maxPriorityFeePerGas": 2,
    "eth_call": 4,
}
_DEFAULT_MIN_CAP: int = GLOBAL_MIN_CAP


# --- module state ----------------------------------------------------------
_disabled: bool = False
_limiters: dict[str, "AdaptiveLimiter"] = {}


def configure(disabled: bool = False) -> None:
    """Configure the limiter module. Currently only the kill switch.

    Call once at startup. Idempotent — repeated calls just flip the flag."""
    global _disabled
    _disabled = disabled


def is_disabled() -> bool:
    return _disabled


def get_method_limiter(method: str) -> "AdaptiveLimiter":
    """Return the process-wide limiter for one RPC method, creating it
    on first use. Lazy so the internal asyncio.Condition binds to the
    running event loop."""
    lim = _limiters.get(method)
    if lim is None:
        initial = _METHOD_INITIAL_CAPS.get(method, _DEFAULT_INITIAL_CAP)
        floor = _METHOD_MIN_CAPS.get(method, _DEFAULT_MIN_CAP)
        lim = AdaptiveLimiter(
            method=method,
            initial_cap=initial,
            min_cap=floor,
            disabled=_disabled,
        )
        _limiters[method] = lim
    return lim


def snapshot_all() -> dict[str, dict[str, Any]]:
    """Return a per-method snapshot of every live limiter. Used by the
    rpc_profiler summary flush to embed the current cap/in_flight into
    each ``by_method`` entry."""
    return {m: lim.snapshot() for m, lim in _limiters.items()}


def reset_for_tests() -> None:
    """Wipe all limiters. Test-only helper."""
    _limiters.clear()


# --- optional profiler hook ------------------------------------------------
# The limiter emits a "cap_change" JSONL row whenever it grows or shrinks.
# We can't import rpc_profiler at module import time (would create a cycle
# with eth_client_utils via the profiler's future ``configure`` step), so
# resolve lazily on first use.
_cap_change_sink: Callable[..., None] | None = None


def _emit_cap_change(
    method: str,
    old: int,
    new: int,
    reason: str,
    baseline_ms: float | None,
    recent_ms: float | None,
) -> None:
    global _cap_change_sink
    if _cap_change_sink is None:
        try:
            from voltaire_bundler.utils import rpc_profiler
            _cap_change_sink = rpc_profiler.record_cap_change
        except Exception:
            # No profiler available; silently drop cap-change signals.
            _cap_change_sink = lambda *a, **kw: None  # noqa: E731
    try:
        _cap_change_sink(
            method=method,
            from_cap=old,
            to_cap=new,
            reason=reason,
            baseline_ms=baseline_ms,
            recent_ms=recent_ms,
        )
    except Exception:
        # Never let telemetry break the RPC hot path.
        pass


# --- limiter implementations ----------------------------------------------
class _FixedLimiter:
    """Static-cap fallback used when the kill switch is on. Presents the
    same async context-manager surface as AdaptiveLimiter so the RPC
    wrapper doesn't branch."""

    __slots__ = ("method", "cap", "min_cap", "_sem", "_t_start")

    def __init__(self, method: str, cap: int, min_cap: int) -> None:
        self.method = method
        self.cap = cap
        self.min_cap = min_cap
        self._sem = asyncio.Semaphore(cap)
        self._t_start = 0.0

    async def __aenter__(self) -> "_FixedLimiter":
        await self._sem.acquire()
        self._t_start = time.monotonic()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._sem.release()

    # Same surface as AdaptiveLimiter — no-ops on the fixed variant.
    def set_status(self, status: int) -> None:
        pass

    def snapshot(self) -> dict[str, Any]:
        return {
            "cap": self.cap,
            "in_flight": self.cap - getattr(self._sem, "_value", 0),
            "baseline_p50_ms": None,
            "adaptive": False,
        }


def _median(values: collections.deque[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


class AdaptiveLimiter:
    """AIMD-driven concurrency gate for one RPC method.

    Use as an async context manager::

        async with get_method_limiter("eth_call") as slot:
            resp = await session.post(...)
            slot.set_status(resp.status)   # 0/2xx → success, else error
            body = await resp.read()

    The context manager decides on __aexit__ whether the call was
    successful, failed by status, or raised — and releases accordingly.
    Growing/shrinking the cap never affects in-flight callers; only the
    next entry gate is affected."""

    __slots__ = (
        "method", "cap", "min_cap", "in_flight",
        "_cond", "_window", "baseline_p50_ms", "_baseline_stale_windows",
        "_t_start", "_status", "_disabled",
    )

    def __init__(
        self,
        method: str,
        initial_cap: int,
        min_cap: int,
        disabled: bool = False,
    ) -> None:
        self.method = method
        self.min_cap = max(GLOBAL_MIN_CAP, min_cap)
        self.cap = max(self.min_cap, min(MAX_CAP, initial_cap))
        self.in_flight = 0
        self._cond = asyncio.Condition()
        self._window: collections.deque[float] = collections.deque(
            maxlen=WINDOW_SIZE
        )
        self.baseline_p50_ms: float | None = None
        self._baseline_stale_windows = 0
        self._t_start = 0.0
        self._status = 0
        self._disabled = disabled

    # --- API used by the RPC wrapper --------------------------------------
    def set_status(self, status: int) -> None:
        """Called by the RPC wrapper after reading the HTTP status. Any
        non-2xx marks the call as failed for AIMD purposes."""
        self._status = status

    def snapshot(self) -> dict[str, Any]:
        return {
            "cap": self.cap,
            "in_flight": self.in_flight,
            "baseline_p50_ms": self.baseline_p50_ms,
            "adaptive": not self._disabled,
        }

    # --- async context manager --------------------------------------------
    async def __aenter__(self) -> "AdaptiveLimiter":
        await self._acquire()
        self._t_start = time.monotonic()
        self._status = 0
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        elapsed_ms = (time.monotonic() - self._t_start) * 1000.0
        if exc_type is not None:
            await self._release_error(reason="exception")
            return
        if self._status and (self._status < 200 or self._status >= 300):
            await self._release_error(reason="non_2xx")
            return
        await self._release_success(elapsed_ms)

    # --- core primitives --------------------------------------------------
    async def _acquire(self) -> None:
        async with self._cond:
            while self.in_flight >= self.cap:
                await self._cond.wait()
            self.in_flight += 1

    async def _release_success(self, elapsed_ms: float) -> None:
        async with self._cond:
            saturated = self.in_flight >= self.cap
            self.in_flight -= 1
            if not self._disabled:
                self._record(elapsed_ms)
                self._maybe_adjust(saturated)
            self._cond.notify()

    async def _release_error(self, reason: str) -> None:
        async with self._cond:
            self.in_flight -= 1
            if self._disabled:
                self._cond.notify()
                return
            old = self.cap
            self.cap = max(self.min_cap, self.cap // 2)
            if old != self.cap:
                _emit_cap_change(
                    self.method, old, self.cap,
                    reason=f"error:{reason}",
                    baseline_ms=self.baseline_p50_ms,
                    recent_ms=_median(self._window) if self._window else None,
                )
                # Cap shrank — wake at most enough waiters to fit under
                # the new cap. notify_all is fine; extra wakes just
                # re-enter the wait loop.
                self._cond.notify_all()
            else:
                self._cond.notify()

    # --- state maintenance -------------------------------------------------
    def _record(self, elapsed_ms: float) -> None:
        self._window.append(elapsed_ms)

    def _maybe_adjust(self, saturated: bool) -> None:
        if len(self._window) < MIN_SAMPLES:
            return
        recent = _median(self._window)
        # First good sample, or new low — re-baseline and return without
        # touching the cap. Prevents growing on the same tick we just
        # discovered a faster baseline.
        if self.baseline_p50_ms is None or recent < self.baseline_p50_ms:
            self.baseline_p50_ms = recent
            self._baseline_stale_windows = 0
            return

        assert self.baseline_p50_ms is not None
        if recent > self.baseline_p50_ms * BASELINE_UPWARD_TRIGGER:
            self._baseline_stale_windows += 1
            if self._baseline_stale_windows >= BASELINE_UPWARD_WINDOWS:
                # Sustained slowdown — accommodate the new normal so the
                # cap doesn't shrink forever if the node's actual serving
                # speed dropped for reasons unrelated to our load.
                self.baseline_p50_ms *= 1.1
                self._baseline_stale_windows = 0
        else:
            self._baseline_stale_windows = 0

        old = self.cap
        if saturated and recent <= self.baseline_p50_ms * GROWTH_TOL:
            self.cap = min(MAX_CAP, self.cap + 1)
        elif recent >= self.baseline_p50_ms * SHRINK_TRIGGER:
            self.cap = max(self.min_cap, self.cap // 2)

        if old != self.cap:
            _emit_cap_change(
                self.method, old, self.cap,
                reason=("grow" if self.cap > old else "shrink"),
                baseline_ms=self.baseline_p50_ms,
                recent_ms=recent,
            )
            if self.cap > old:
                # New slot available — one waiter may proceed.
                self._cond.notify()


__all__ = [
    "AdaptiveLimiter",
    "configure",
    "get_method_limiter",
    "is_disabled",
    "reset_for_tests",
    "snapshot_all",
    "GROWTH_TOL",
    "SHRINK_TRIGGER",
    "GLOBAL_MIN_CAP",
    "MAX_CAP",
    "WINDOW_SIZE",
    "MIN_SAMPLES",
]
