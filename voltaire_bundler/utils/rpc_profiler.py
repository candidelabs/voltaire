"""JSONL profiler for outbound Ethereum-node RPC calls.

Off by default. `configure(path=...)` at startup enables it. Once on, each
call through the two send-RPC helpers in ``eth_client_utils`` writes a
``slow_call`` row when its latency exceeds ``slow_ms``, and a background
sampler writes a ``summary`` row per node every ``sampler_interval_s``
seconds. Both row types share the same rotating JSONL file so operators
can grep/jq the file after a spike without needing to be online while it
happened.

Overhead when disabled: one boolean check per RPC (``_enabled`` is False,
``RpcCallContext.__aenter__`` returns immediately). No counters touched.
"""
import asyncio
import contextvars
import json
import logging
import time
from collections import defaultdict
from logging.handlers import RotatingFileHandler
from types import TracebackType
from typing import Any, Callable

# --- module state ----------------------------------------------------------
_enabled: bool = False
_slow_sec: float = 0.5
_sampler_interval_s: float = 5.0
_writer: logging.Logger | None = None

# Live counters — cheap to read for the slow-call embed. Only touched when
# ``_enabled`` is True.
_inflight_by_method: dict[str, int] = defaultdict(int)
_inflight_by_node: dict[str, int] = defaultdict(int)
_inflight_bytes_by_node: dict[str, int] = defaultdict(int)

# Rolling window aggregates. The sampler resets these each tick.
_window_started_at: float = 0.0
_window_calls: dict[tuple[str, str], int] = defaultdict(int)
_window_latency: dict[tuple[str, str], list[float]] = defaultdict(list)
_window_bytes: dict[str, int] = defaultdict(int)
_window_errors: dict[tuple[str, str], int] = defaultdict(int)
_window_retries: dict[tuple[str, str], int] = defaultdict(int)
_window_latency_all_by_node: dict[str, list[float]] = defaultdict(list)

# Carries the just-measured semaphore-wait time from
# ``record_semaphore_wait`` into the RpcCallContext that follows. Using a
# ContextVar (rather than a stack variable) keeps the wrapper API clean —
# call sites don't have to pass the value into RpcCallContext explicitly.
_sem_wait_var: contextvars.ContextVar[float] = contextvars.ContextVar(
    "rpc_profiler_sem_wait", default=0.0
)


def is_enabled() -> bool:
    return _enabled


def configure(
    path: str,
    slow_ms: int = 500,
    sampler_interval_s: float = 5.0,
    max_bytes: int = 128 * 1024 * 1024,
    backup_count: int = 4,
) -> None:
    """Turn the profiler on. Idempotent: repeated calls just re-point the
    output file. Safe to call before an event loop exists."""
    global _enabled, _slow_sec, _sampler_interval_s, _writer, _window_started_at
    _slow_sec = slow_ms / 1000.0
    _sampler_interval_s = sampler_interval_s

    logger = logging.getLogger("voltaire.rpc_profiler")
    logger.setLevel(logging.INFO)
    # Never bubble up to root — the JSONL file is a data channel, not a
    # log stream. Bubbling would duplicate every row into the operator's
    # main log.
    logger.propagate = False
    for h in list(logger.handlers):
        logger.removeHandler(h)
    handler = RotatingFileHandler(
        path, maxBytes=max_bytes, backupCount=backup_count
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    _writer = logger

    _window_started_at = time.monotonic()
    _enabled = True
    logging.info(
        "rpc_profiler enabled: path=%s slow_ms=%d interval_s=%.1f "
        "max_bytes=%d backup_count=%d",
        path, slow_ms, sampler_interval_s, max_bytes, backup_count,
    )


def _write_row(row: dict[str, Any]) -> None:
    if _writer is None:
        return
    row["ts"] = time.time()
    try:
        _writer.info(json.dumps(row, separators=(",", ":")))
    except Exception:
        # Never let profiling failures break RPC.
        pass


def record_retry(method: str, node: str) -> None:
    if not _enabled:
        return
    _window_retries[(node, method)] += 1


def record_semaphore_wait(method: str, wait_seconds: float) -> None:
    if not _enabled:
        return
    _sem_wait_var.set(wait_seconds)


def _percentiles(samples: list[float], ps: tuple[float, ...]) -> dict[str, float]:
    if not samples:
        return {f"p{int(p * 100)}": 0.0 for p in ps}
    ordered = sorted(samples)
    n = len(ordered)
    out: dict[str, float] = {}
    for p in ps:
        idx = int(p * (n - 1))
        out[f"p{int(p * 100)}"] = ordered[idx]
    return out


class RpcCallContext:
    """Async context manager wrapping one outbound RPC call.

    ``__aenter__`` bumps live counters and records the start time.
    ``__aexit__`` decrements the counters, records the sample into the
    rolling window, and emits a ``slow_call`` row if the elapsed time
    exceeds the configured threshold.

    Callers set ``.content_length``, ``.bytes`` and ``.status`` inline
    during the call so the emitted row carries the response size and HTTP
    status without extra bookkeeping.
    """

    __slots__ = (
        "method", "node", "_t_start", "_content_length",
        "bytes", "status", "outcome", "attempt", "_active",
    )

    def __init__(self, method: str, node: str, attempt: int = 1) -> None:
        self.method = method
        self.node = node
        self.attempt = attempt
        self._t_start = 0.0
        self._content_length = 0
        self.bytes: int = 0
        self.status: int = 0
        self.outcome: str = "ok"
        self._active = False

    def set_content_length(self, header_value: str | None) -> None:
        if not self._active:
            return
        try:
            n = int(header_value) if header_value is not None else 0
        except ValueError:
            n = 0
        # For chunked responses (no Content-Length), fall back to a small
        # constant so the in-flight-bytes gauge isn't perpetually zero.
        # 8 KiB is a rough average; the true value is recorded in
        # ``self.bytes`` once the body has been read.
        if n <= 0:
            n = 8 * 1024
        delta = n - self._content_length
        self._content_length = n
        _inflight_bytes_by_node[self.node] += delta

    def set_bytes(self, n: int) -> None:
        self.bytes = n

    def set_status(self, status: int) -> None:
        self.status = status

    async def __aenter__(self) -> "RpcCallContext":
        if not _enabled:
            return self
        self._active = True
        self._t_start = time.monotonic()
        _inflight_by_method[self.method] += 1
        _inflight_by_node[self.node] += 1
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if not self._active:
            return
        elapsed = time.monotonic() - self._t_start
        _inflight_by_method[self.method] -= 1
        _inflight_by_node[self.node] -= 1
        if self._content_length:
            _inflight_bytes_by_node[self.node] -= self._content_length

        key = (self.node, self.method)
        _window_calls[key] += 1
        _window_latency[key].append(elapsed)
        _window_latency_all_by_node[self.node].append(elapsed)
        _window_bytes[self.node] += self.bytes

        if exc_type is not None:
            self.outcome = "cancelled" if exc_type is asyncio.CancelledError \
                else "error"
            _window_errors[key] += 1
        elif self.status and self.status != 200:
            self.outcome = "non_200"
            _window_errors[key] += 1
        elif self.status == 0:
            # Body read never assigned a status — treat as error path.
            self.outcome = "error"
            _window_errors[key] += 1

        if elapsed >= _slow_sec:
            _write_row({
                "type": "slow_call",
                "method": self.method,
                "node": self.node,
                "elapsed_ms": round(elapsed * 1000, 2),
                "sem_wait_ms": round(_sem_wait_var.get() * 1000, 2),
                "resp_bytes": self.bytes,
                "content_length": self._content_length,
                "status": self.status,
                "outcome": self.outcome,
                "attempt": self.attempt,
                "inflight_method": _inflight_by_method[self.method],
                "inflight_total_node": _inflight_by_node[self.node],
                "inflight_bytes_node": _inflight_bytes_by_node[self.node],
            })


def _flush_summary(pool_state_by_node: dict[str, tuple[int, int]]) -> None:
    global _window_started_at
    now = time.monotonic()
    window_sec = max(now - _window_started_at, 1e-9)
    # Collect every node we saw activity for OR every node with a live
    # pool entry — either can be non-empty on its own.
    nodes = set(_window_latency_all_by_node.keys()) | set(pool_state_by_node.keys())
    for node in nodes:
        lats = _window_latency_all_by_node.get(node, [])
        by_method: dict[str, dict[str, Any]] = {}
        for (n, method), count in _window_calls.items():
            if n != node:
                continue
            m_lats = _window_latency[(n, method)]
            m_pcts = _percentiles(m_lats, (0.5, 0.99))
            by_method[method] = {
                "calls": count,
                "p50_ms": round(m_pcts["p50"] * 1000, 2),
                "p99_ms": round(m_pcts["p99"] * 1000, 2),
                "errors": _window_errors.get((n, method), 0),
                "retries": _window_retries.get((n, method), 0),
            }
        pool_idle, pool_acquired = pool_state_by_node.get(node, (0, 0))
        pcts = _percentiles(lats, (0.5, 0.9, 0.95, 0.99))
        row = {
            "type": "summary",
            "node": node,
            "window_sec": round(window_sec, 3),
            "calls": sum(v["calls"] for v in by_method.values()),
            "errors": sum(v["errors"] for v in by_method.values()),
            "retries": sum(v["retries"] for v in by_method.values()),
            "resp_bytes_total": _window_bytes.get(node, 0),
            "bytes_per_sec": int(_window_bytes.get(node, 0) / window_sec),
            "inflight_total": _inflight_by_node.get(node, 0),
            "inflight_bytes": _inflight_bytes_by_node.get(node, 0),
            "pool_idle": pool_idle,
            "pool_acquired": pool_acquired,
            "latency_ms": {
                "p50": round(pcts["p50"] * 1000, 2),
                "p90": round(pcts["p90"] * 1000, 2),
                "p95": round(pcts["p95"] * 1000, 2),
                "p99": round(pcts["p99"] * 1000, 2),
                "max": round((max(lats) if lats else 0.0) * 1000, 2),
            },
            "by_method": by_method,
        }
        _write_row(row)

    _window_calls.clear()
    _window_latency.clear()
    _window_latency_all_by_node.clear()
    _window_bytes.clear()
    _window_errors.clear()
    _window_retries.clear()
    _window_started_at = now


def _read_pool_state(session_getter: Callable[[], Any]) -> dict[str, tuple[int, int]]:
    """Best-effort probe of aiohttp's connection pool. Returns
    {host: (idle_count, acquired_count)}. Any exception yields an empty
    dict so a future aiohttp upgrade cannot crash the sampler."""
    out: dict[str, tuple[int, int]] = {}
    try:
        session = session_getter()
        conn = getattr(session, "connector", None)
        if conn is None:
            return out
        idle: dict[str, int] = defaultdict(int)
        acquired: dict[str, int] = defaultdict(int)
        for key, sockets in getattr(conn, "_conns", {}).items():
            host = getattr(key, "host", str(key))
            idle[host] += len(sockets)
        for key, acq in getattr(conn, "_acquired_per_host", {}).items():
            host = getattr(key, "host", str(key))
            acquired[host] += len(acq)
        for host in set(idle) | set(acquired):
            out[host] = (idle.get(host, 0), acquired.get(host, 0))
    except Exception:
        return {}
    return out


async def start_pool_sampler(
    session_getter: Callable[[], Any],
    node_urls: list[str],
) -> None:
    """Background task: every ``_sampler_interval_s`` write one summary
    row per known node with rolling-window aggregates and live pool state.

    ``node_urls`` is used only to project host→url so summary rows carry
    the full URL the operator recognises (aiohttp only knows the host)."""
    if not _enabled or _sampler_interval_s <= 0:
        return

    host_to_url: dict[str, str] = {}
    for url in node_urls:
        # Best-effort host extraction; if the URL doesn't parse just use
        # the whole string.
        try:
            from urllib.parse import urlparse
            host = urlparse(url).hostname or url
        except Exception:
            host = url
        host_to_url.setdefault(host, url)

    try:
        while True:
            await asyncio.sleep(_sampler_interval_s)
            raw_pool = _read_pool_state(session_getter)
            # Re-key by the caller-friendly URL when we can match.
            pool_by_node: dict[str, tuple[int, int]] = {}
            for host, counts in raw_pool.items():
                pool_by_node[host_to_url.get(host, host)] = counts
            _flush_summary(pool_by_node)
    except asyncio.CancelledError:
        # One last flush so we don't drop the trailing window on shutdown.
        try:
            _flush_summary({})
        except Exception:
            pass
        raise


def snapshot() -> dict[str, Any]:
    """Return live counters as a plain dict. Handy for ad-hoc probing."""
    return {
        "enabled": _enabled,
        "inflight_by_method": dict(_inflight_by_method),
        "inflight_by_node": dict(_inflight_by_node),
        "inflight_bytes_by_node": dict(_inflight_bytes_by_node),
    }


__all__ = [
    "configure",
    "is_enabled",
    "record_retry",
    "record_semaphore_wait",
    "RpcCallContext",
    "start_pool_sampler",
    "snapshot",
]
