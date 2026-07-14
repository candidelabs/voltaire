"""Per-method adaptive concurrency limiter for outbound RPC calls.

Behaves like a resizable semaphore whose limit reacts ONLY to hard failure
signals from the upstream node — errors, timeouts, and non-2xx responses —
never to latency. Latency-based control proved fragile (it misread ordinary
jitter on a fast node as congestion and throttled the bundler into
multi-second self-inflicted queues); failures are unambiguous, so the
limiter now moves on those alone.

Algorithm (per method):
  - Each method starts at, and never exceeds, a fixed CEILING (its seed cap
    in ``_METHOD_INITIAL_CAPS``). In the healthy case the cap simply sits at
    the ceiling and behaves like a plain fixed semaphore.
  - Multiplicative Decrease — on an error / timeout / non-2xx the cap is
    halved (down to the method's floor). A burst of failures backs off fast.
  - Additive Increase — after RECOVER_STEP_SUCCESSES consecutive clean
    completions the cap grows by 1, back toward the ceiling. Any failure
    resets the success streak, so a flapping provider keeps the cap low
    (hysteresis) instead of oscillating.
  - Cancellations are NEUTRAL: a caller-side cancellation (e.g. a bundle
    round moving on) is not a node-health signal and never moves the cap.

Per-method floors (``_METHOD_MIN_CAPS``) keep a few methods above the global
minimum even under sustained upstream distress — the write path
(eth_sendRawTransaction) and bundle-inclusion polling in particular.

Kill switch: ``configure(disabled=True)`` freezes every cap at its ceiling
(pure fixed semaphore). Same acquire/release surface; no downstream code
changes required to fall back.
"""
from __future__ import annotations

import asyncio
from types import TracebackType
from typing import Any, Callable

# --- algorithm constants ---------------------------------------------------
GLOBAL_MIN_CAP: int = 2
MAX_CAP: int = 256

# Consecutive successful completions required to recover the cap by one step
# after a backoff. Provides hysteresis: recovery is deliberately slower than
# backoff so a provider that is intermittently failing settles at a low cap
# rather than sawtoothing. Any failure resets the streak to zero.
RECOVER_STEP_SUCCESSES: int = 16

# Seed caps. These are the normal operating point AND the recovery ceiling —
# the cap never grows above its method's value here. Sized to what a typical
# provider sustains comfortably; the limiter only ever moves BELOW these
# under failure, then climbs back. Tune per deployment if a node wants more
# or less headroom.
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

# Per-method backoff floors. See module docstring for rationale on why some
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


def _emit_cap_change(method: str, old: int, new: int, reason: str) -> None:
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
        )
    except Exception:
        # Never let telemetry break the RPC hot path.
        pass


# --- limiter implementations ----------------------------------------------
class _FixedSlot:
    """Per-acquire handle for the fixed limiter. No-op status hook; releases
    the underlying semaphore on exit. Fresh per call, so nothing is shared
    across concurrent callers."""

    __slots__ = ("_sem",)

    def __init__(self, sem: asyncio.Semaphore) -> None:
        self._sem = sem

    def set_status(self, status: int) -> None:
        pass

    async def __aenter__(self) -> "_FixedSlot":
        await self._sem.acquire()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._sem.release()


class _FixedLimiter:
    """Static-cap fallback used when the kill switch is on. Presents the
    same ``slot()`` surface as AdaptiveLimiter so the RPC wrapper doesn't
    branch."""

    __slots__ = ("method", "cap", "min_cap", "_sem")

    def __init__(self, method: str, cap: int, min_cap: int) -> None:
        self.method = method
        self.cap = cap
        self.min_cap = min_cap
        self._sem = asyncio.Semaphore(cap)

    def slot(self) -> "_FixedSlot":
        return _FixedSlot(self._sem)

    def snapshot(self) -> dict[str, Any]:
        return {
            "cap": self.cap,
            "in_flight": self.cap - getattr(self._sem, "_value", 0),
            "adaptive": False,
        }


class _Slot:
    """Per-acquire handle for one AdaptiveLimiter call.

    The limiter is a process-wide singleton per method, shared by every
    concurrent call, so per-call state (this call's HTTP status) MUST live
    here rather than on the limiter. On exit it classifies the outcome —
    success, failure (error / timeout / non-2xx), or neutral cancellation —
    and releases accordingly. Changing the cap never affects in-flight
    callers; only the next entry gate is affected."""

    __slots__ = ("_limiter", "_status")

    def __init__(self, limiter: "AdaptiveLimiter") -> None:
        self._limiter = limiter
        self._status = 0

    def set_status(self, status: int) -> None:
        """Called by the RPC wrapper after reading the HTTP status. Any
        non-2xx marks the call as a failure for backoff purposes."""
        self._status = status

    async def __aenter__(self) -> "_Slot":
        await self._limiter._acquire()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if exc_type is not None:
            if issubclass(exc_type, asyncio.CancelledError):
                # Caller-side cancellation, not a node-health signal.
                await self._limiter._release_neutral()
            elif issubclass(exc_type, (asyncio.TimeoutError, TimeoutError)):
                await self._limiter._release_error(reason="timeout")
            else:
                await self._limiter._release_error(reason="exception")
            return
        if self._status and (self._status < 200 or self._status >= 300):
            await self._limiter._release_error(reason="non_2xx")
            return
        await self._limiter._release_success()


class AdaptiveLimiter:
    """Failure-driven concurrency gate for one RPC method.

    Acquire one slot per call via ``slot()``::

        async with get_method_limiter("eth_call").slot() as slot:
            resp = await session.post(...)
            slot.set_status(resp.status)   # 0/2xx → success, else failure
            body = await resp.read()

    The returned slot is a fresh per-call object; on exit it classifies the
    outcome and releases. The cap halves on failure and recovers slowly
    toward its ceiling on sustained success — it never grows past the seed
    ceiling and never reacts to latency. See the module docstring."""

    __slots__ = (
        "method", "cap", "ceiling", "min_cap", "in_flight",
        "_cond", "_success_streak", "_disabled",
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
        self.ceiling = max(self.min_cap, min(MAX_CAP, initial_cap))
        self.cap = self.ceiling
        self.in_flight = 0
        self._cond = asyncio.Condition()
        self._success_streak = 0
        self._disabled = disabled

    # --- API used by the RPC wrapper --------------------------------------
    def slot(self) -> "_Slot":
        """Return a fresh per-call acquire handle. Use as an async context
        manager; see the class docstring."""
        return _Slot(self)

    def snapshot(self) -> dict[str, Any]:
        return {
            "cap": self.cap,
            "ceiling": self.ceiling,
            "in_flight": self.in_flight,
            "adaptive": not self._disabled,
        }

    # --- core primitives --------------------------------------------------
    async def _acquire(self) -> None:
        async with self._cond:
            while self.in_flight >= self.cap:
                await self._cond.wait()
            self.in_flight += 1

    async def _release_success(self) -> None:
        async with self._cond:
            self.in_flight -= 1
            if self._disabled:
                self._cond.notify()
                return
            self._success_streak += 1
            old = self.cap
            if (
                self._success_streak >= RECOVER_STEP_SUCCESSES
                and self.cap < self.ceiling
            ):
                # Additive increase toward the ceiling.
                self.cap += 1
                self._success_streak = 0
            if old != self.cap:
                _emit_cap_change(self.method, old, self.cap, reason="recover")
                # Two slots are now free: the one this call vacated plus the
                # one recovery just added.
                self._cond.notify(2)
            else:
                self._cond.notify()

    async def _release_error(self, reason: str) -> None:
        async with self._cond:
            self.in_flight -= 1
            if self._disabled:
                self._cond.notify()
                return
            self._success_streak = 0
            old = self.cap
            self.cap = max(self.min_cap, self.cap // 2)
            if old != self.cap:
                _emit_cap_change(
                    self.method, old, self.cap, reason=f"error:{reason}"
                )
                # Cap shrank — notify_all is fine; waiters that no longer fit
                # under the new cap just re-enter the wait loop.
                self._cond.notify_all()
            else:
                self._cond.notify()

    async def _release_neutral(self) -> None:
        """Release without moving the cap or the success streak. Used for
        cancellations, which carry no information about node health."""
        async with self._cond:
            self.in_flight -= 1
            self._cond.notify()


__all__ = [
    "AdaptiveLimiter",
    "configure",
    "is_disabled",
    "get_method_limiter",
    "reset_for_tests",
    "snapshot_all",
    "RECOVER_STEP_SUCCESSES",
    "GLOBAL_MIN_CAP",
    "MAX_CAP",
]
