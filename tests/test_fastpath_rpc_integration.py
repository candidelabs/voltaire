"""
Integration tests for the receipt + byHash fresh-submission fast paths
wired through ``ExecutionEndpoint``.

The unit tests in ``test_recent_submission_fast_path.py`` and
``test_byhash_local_mempool_dispatch.py`` cover the helpers in
isolation. These tests verify the integration: that
``_event_rpc_getUserOperationReceipt`` and
``_event_rpc_getUserOperationByHash`` actually consult the
recent-submissions registry **before** launching any handler task, and
that they fall through to the normal cascade once the window expires
or when the hash was never submitted to this bundler. Without these
end-to-end checks a refactor of the RPC handlers could silently bypass
the fast path while every helper-level unit test still passed.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from voltaire_bundler import execution_endpoint as ep_module
from voltaire_bundler.bundle.exceptions import (
    UserOpFoundException, UserOpReceiptFoundException,
)
from voltaire_bundler.execution_endpoint import (
    RECENT_SUBMISSION_FAST_PATH_S,
    ExecutionEndpoint,
    _record_recent_submission,
    _recent_userop_submissions,
    user_operation_by_hash_cache,
    user_operation_receipt_cache,
)
from voltaire_bundler.mempool.mempool_manager_v6 import LocalMempoolManagerV6
from voltaire_bundler.mempool.mempool_manager_v7 import LocalMempoolManagerV7
from voltaire_bundler.mempool.mempool_manager_v9 import LocalMempoolManagerV9


HASH = "0x" + "ab" * 32
NEVER_SUBMITTED_HASH = "0x" + "cd" * 32
ENTRYPOINT_V9_LC = LocalMempoolManagerV9.entrypoint_lowercase
ENTRYPOINT_V7_LC = LocalMempoolManagerV7.entrypoint_lowercase
ENTRYPOINT_V6_LC = LocalMempoolManagerV6.entrypoint_lowercase


def _bind(endpoint, name):
    """Bind a real ExecutionEndpoint method onto the mock so the
    method's actual logic runs end-to-end while every other attribute
    on the endpoint is still mocked. Without binding, ``MagicMock``
    auto-attributes would short-circuit the method we're trying to
    exercise."""
    method = getattr(ExecutionEndpoint, name)
    setattr(endpoint, name, method.__get__(endpoint, ExecutionEndpoint))


def _make_endpoint(*, v6_enabled: bool = True) -> ExecutionEndpoint:
    """Build an ExecutionEndpoint mock with the minimum surface area the
    receipt + byHash RPC handlers touch. Handlers / mempools are mocks
    so we can both detect calls and stub responses."""
    endpoint = MagicMock(spec=ExecutionEndpoint)

    endpoint.user_operation_handler_v6 = MagicMock() if v6_enabled else None
    endpoint.user_operation_handler_v7v8v9 = MagicMock()

    # Receipt handler returns None (= "not on chain") so the test can
    # observe whether the cascade ran at all without entangling that
    # with the cascade's result. The fast path should pre-empt the call.
    endpoint.user_operation_handler_v7v8v9.get_user_operation_receipt_rpc = (
        AsyncMock(return_value=None)
    )
    endpoint.user_operation_handler_v7v8v9.get_user_operation_by_hash_rpc = (
        AsyncMock(return_value=None)
    )
    endpoint.user_operation_handler_v7v8v9.get_user_operation_by_hash_from_local_mempool = (
        MagicMock(return_value={
            "userOperation": {"sender": "0x" + "11" * 20},
            "entryPoint": LocalMempoolManagerV9.entrypoint,
            "blockNumber": None,
            "blockHash": None,
            "transactionHash": None,
        })
    )
    if v6_enabled:
        endpoint.user_operation_handler_v6.get_user_operation_receipt_rpc = (
            AsyncMock(return_value=None)
        )
        endpoint.user_operation_handler_v6.get_user_operation_by_hash_rpc = (
            AsyncMock(return_value=None)
        )

    def _mempool() -> MagicMock:
        m = MagicMock()
        m.senders_to_senders_mempools.values.return_value = []
        return m

    endpoint.local_mempool_manager_v6 = _mempool() if v6_enabled else None
    endpoint.local_mempool_manager_v7 = _mempool()
    endpoint.local_mempool_manager_v8 = _mempool()
    endpoint.local_mempool_manager_v9 = _mempool()

    # Bundle manager surface used by the byHash post-cascade fallback;
    # an empty monitor dict means "not bundled, not on chain".
    endpoint.bundle_manager = MagicMock()
    endpoint.bundle_manager.user_operations_to_monitor_v6 = {}
    endpoint.bundle_manager.user_operations_to_monitor_v7 = {}
    endpoint.bundle_manager.user_operations_to_monitor_v8 = {}
    endpoint.bundle_manager.user_operations_to_monitor_v9 = {}

    _bind(endpoint, "_event_rpc_getUserOperationReceipt")
    _bind(endpoint, "_event_rpc_getUserOperationByHash")
    _bind(endpoint, "_lookup_userop_in_local_mempool_by_entrypoint")
    return endpoint


@pytest.fixture(autouse=True)
def _clean_module_state():
    """Wipe every module-level cache the RPC paths touch so tests are
    order-independent: receipt/byHash positive caches, the
    recent-submissions registry, and the seen-cache (it would otherwise
    fall through to the normal cascade and our handler mocks)."""
    _recent_userop_submissions.clear()
    user_operation_by_hash_cache.clear()
    user_operation_receipt_cache.clear()
    yield
    _recent_userop_submissions.clear()
    user_operation_by_hash_cache.clear()
    user_operation_receipt_cache.clear()


@pytest.fixture
def monotonic_clock():
    fake = {"now": 1_000.0}

    def _now():
        return fake["now"]

    def _advance(seconds: float):
        fake["now"] += seconds

    with patch.object(ep_module.time, "monotonic", _now):
        yield _advance


@pytest.fixture
def empty_seen_cache():
    """Stub the seen cache to "no result". For tests that exit via the
    fast path this is unreachable, but for cascade tests it prevents the
    cascade from picking up a v6 hint and going through the v6 task
    branch (which our mock endpoint may not have wired up)."""
    async def _none(_hash):
        return None
    with patch.object(ep_module, "search_user_operation_seen_cache", _none):
        yield


@pytest.mark.asyncio
async def test_receipt_fastpath_skips_handler_cascade_within_window(
    monotonic_clock, empty_seen_cache,
):
    """Fresh submission → receipt poll → returns ``None`` without
    invoking any handler. This is the whole point of the optimization:
    no chain RPC fan-out during the guaranteed-miss window."""
    endpoint = _make_endpoint()
    _record_recent_submission(HASH, ENTRYPOINT_V9_LC)

    result = await endpoint._event_rpc_getUserOperationReceipt([HASH])

    assert result is None
    endpoint.user_operation_handler_v7v8v9 \
        .get_user_operation_receipt_rpc.assert_not_called()


@pytest.mark.asyncio
async def test_receipt_normal_cascade_runs_after_window_expires(
    monotonic_clock, empty_seen_cache,
):
    """After the freshness window elapses the fast path must NOT kick
    in, so the handler cascade runs (and in this stub returns None)."""
    endpoint = _make_endpoint()
    _record_recent_submission(HASH, ENTRYPOINT_V9_LC)
    monotonic_clock(RECENT_SUBMISSION_FAST_PATH_S + 0.1)

    result = await endpoint._event_rpc_getUserOperationReceipt([HASH])

    assert result is None
    assert endpoint.user_operation_handler_v7v8v9 \
        .get_user_operation_receipt_rpc.await_count >= 1


@pytest.mark.asyncio
async def test_receipt_normal_cascade_runs_for_never_submitted_hash(
    monotonic_clock, empty_seen_cache,
):
    """A hash this bundler never accepted must not be short-circuited —
    it might have been submitted to a peer and is now on chain, which
    is exactly what the cascade is for."""
    endpoint = _make_endpoint()

    result = await endpoint._event_rpc_getUserOperationReceipt(
        [NEVER_SUBMITTED_HASH]
    )

    assert result is None
    assert endpoint.user_operation_handler_v7v8v9 \
        .get_user_operation_receipt_rpc.await_count >= 1


@pytest.mark.asyncio
async def test_byhash_fastpath_returns_mempool_form_within_window(
    monotonic_clock, empty_seen_cache,
):
    """Fresh submission → byHash poll → returns the mempool form
    (blockNumber/blockHash/transactionHash = null) from
    ``get_user_operation_by_hash_from_local_mempool`` without ever
    hitting ``get_user_operation_by_hash_rpc``."""
    endpoint = _make_endpoint()
    _record_recent_submission(HASH, ENTRYPOINT_V9_LC)

    result = await endpoint._event_rpc_getUserOperationByHash([HASH])

    assert result is not None
    assert result["blockNumber"] is None
    assert result["transactionHash"] is None
    endpoint.user_operation_handler_v7v8v9 \
        .get_user_operation_by_hash_rpc.assert_not_called()
    endpoint.user_operation_handler_v7v8v9 \
        .get_user_operation_by_hash_from_local_mempool \
        .assert_called_once()


@pytest.mark.asyncio
async def test_byhash_falls_through_when_mempool_misses(
    monotonic_clock, empty_seen_cache,
):
    """Recent-submission tagged but mempool returns None (bundled and
    evicted within the window on a fast chain). The fast path must NOT
    return; it has to fall through to the normal cascade so the on-chain
    form can still be served."""
    endpoint = _make_endpoint()
    endpoint.user_operation_handler_v7v8v9 \
        .get_user_operation_by_hash_from_local_mempool.return_value = None
    _record_recent_submission(HASH, ENTRYPOINT_V9_LC)

    result = await endpoint._event_rpc_getUserOperationByHash([HASH])

    assert result is None
    # Mempool was probed (fast path entered)...
    endpoint.user_operation_handler_v7v8v9 \
        .get_user_operation_by_hash_from_local_mempool \
        .assert_called_once()
    # ...and the cascade ran when the mempool missed.
    assert endpoint.user_operation_handler_v7v8v9 \
        .get_user_operation_by_hash_rpc.await_count >= 1


@pytest.mark.asyncio
async def test_byhash_routes_at_correct_entrypoint_handler(
    monotonic_clock, empty_seen_cache,
):
    """A submission tagged with v7 must NOT route at the v9 mempool
    (and would miss if it did). This guards against regressions where
    the dispatcher dropped the entrypoint hint."""
    endpoint = _make_endpoint()
    # Only the v7 handler returns something; the others return None.
    # If we route at the wrong entrypoint we'd get None back.
    expected = {
        "userOperation": {"sender": "0x" + "22" * 20},
        "entryPoint": LocalMempoolManagerV7.entrypoint,
        "blockNumber": None,
        "blockHash": None,
        "transactionHash": None,
    }
    endpoint.user_operation_handler_v7v8v9 \
        .get_user_operation_by_hash_from_local_mempool.side_effect = (
            lambda h, ep, mempools: expected if str(ep) == LocalMempoolManagerV7.entrypoint else None
        )
    _record_recent_submission(HASH, ENTRYPOINT_V7_LC)

    result = await endpoint._event_rpc_getUserOperationByHash([HASH])

    assert result == expected


@pytest.mark.asyncio
async def test_byhash_fastpath_does_not_pollute_cache(
    monotonic_clock, empty_seen_cache,
):
    """``user_operation_by_hash_cache`` is only meant to memoize results
    with ``blockNumber != None`` (existing convention — once on chain,
    stable). Caching the fast-path mempool form would freeze the
    "queued" answer for the rest of the process lifetime."""
    endpoint = _make_endpoint()
    _record_recent_submission(HASH, ENTRYPOINT_V9_LC)

    await endpoint._event_rpc_getUserOperationByHash([HASH])

    assert HASH not in user_operation_by_hash_cache


@pytest.mark.asyncio
async def test_receipt_cache_hit_pre_empts_fastpath(
    monotonic_clock, empty_seen_cache,
):
    """A positive entry already in ``user_operation_receipt_cache``
    (set on a previous on-chain hit) must take precedence over the
    fast path so the client doesn't suddenly see ``None`` after having
    been told the receipt is final."""
    endpoint = _make_endpoint()
    cached_receipt = {"userOpHash": HASH, "receipt": {"blockNumber": "0x1"}}
    user_operation_receipt_cache[HASH] = cached_receipt
    _record_recent_submission(HASH, ENTRYPOINT_V9_LC)

    result = await endpoint._event_rpc_getUserOperationReceipt([HASH])

    assert result is cached_receipt
    endpoint.user_operation_handler_v7v8v9 \
        .get_user_operation_receipt_rpc.assert_not_called()
