"""
Tests for ``--disable_bundle_monitoring``.

When the flag is on, ``BundlerManager.update_send_queue_and_monitor_queue``
must:

- skip the per-entrypoint ``remove_included_and_readd_to_mempool_userops_monitoring``
  calls (the eth_getLogs-heavy work whose cost we're opting out of);
- skip writes to ``user_operations_to_monitor_*`` so the dicts stay empty
  and ``update_monitor_status_transation_hash`` /
  ``_event_rpc_getUserOperationByHash``'s in-flight fallback both
  self-disable gracefully;
- still build the next bundle (the prep half of the method is the whole
  reason the bundler runs).
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from voltaire_bundler.bundle.bundle_manager import BundlerManager


def _make_manager(*, disable_bundle_monitoring: bool) -> BundlerManager:
    """Build a BundlerManager skeleton with just the fields
    ``update_send_queue_and_monitor_queue`` reads. ``spec=BundlerManager``
    catches typos in attribute names so a refactor that renames a
    monitor dict can't silently make the test irrelevant."""
    manager = MagicMock(spec=BundlerManager)

    manager.disable_bundle_monitoring = disable_bundle_monitoring
    manager.conditional_rpc = None

    def _mempool() -> MagicMock:
        m = MagicMock()
        m.entrypoint = "0xEP"
        m.get_user_operations_to_bundle = AsyncMock(return_value={})
        return m

    manager.local_mempool_manager_v6 = _mempool()
    manager.local_mempool_manager_v7 = _mempool()
    manager.local_mempool_manager_v8 = _mempool()
    manager.local_mempool_manager_v9 = _mempool()

    manager.remove_included_and_readd_to_mempool_userops_monitoring = (
        AsyncMock(return_value=None)
    )

    manager.bundles_to_send_v6 = []
    manager.bundles_to_send_v7 = []
    manager.bundles_to_send_v8 = []
    manager.bundles_to_send_v9 = []

    manager.user_operations_to_monitor_v6 = {}
    manager.user_operations_to_monitor_v7 = {}
    manager.user_operations_to_monitor_v8 = {}
    manager.user_operations_to_monitor_v9 = {}

    # Bind the real method so the production gating logic runs.
    manager.update_send_queue_and_monitor_queue = (
        BundlerManager.update_send_queue_and_monitor_queue.__get__(
            manager, BundlerManager,
        )
    )
    return manager


@pytest.mark.asyncio
async def test_monitor_calls_skipped_when_disabled():
    manager = _make_manager(disable_bundle_monitoring=True)

    await manager.update_send_queue_and_monitor_queue()

    manager.remove_included_and_readd_to_mempool_userops_monitoring \
        .assert_not_called()


@pytest.mark.asyncio
async def test_monitor_calls_fire_when_enabled():
    """Sanity check: 4 entrypoints (v6 enabled) → 4 monitor sweeps per
    cycle. Guards against the gating accidentally suppressing the
    default-on path."""
    manager = _make_manager(disable_bundle_monitoring=False)

    await manager.update_send_queue_and_monitor_queue()

    assert manager.remove_included_and_readd_to_mempool_userops_monitoring \
        .await_count == 4


@pytest.mark.asyncio
async def test_monitor_dicts_stay_empty_when_disabled():
    """Even when bundle prep yields non-empty results, the dicts must
    not grow. This is what lets
    ``_event_rpc_getUserOperationByHash``'s monitor fallback
    self-disable."""
    manager = _make_manager(disable_bundle_monitoring=True)
    op = MagicMock(name="userop")
    op.user_operation_hash = "0xabc"
    manager.local_mempool_manager_v9.get_user_operations_to_bundle \
        .return_value = {"0xabc": op}

    await manager.update_send_queue_and_monitor_queue()

    assert manager.user_operations_to_monitor_v9 == {}


@pytest.mark.asyncio
async def test_monitor_dicts_populated_when_enabled():
    manager = _make_manager(disable_bundle_monitoring=False)
    op = MagicMock(name="userop")
    op.user_operation_hash = "0xabc"
    manager.local_mempool_manager_v9.get_user_operations_to_bundle \
        .return_value = {"0xabc": op}

    await manager.update_send_queue_and_monitor_queue()

    assert "0xabc" in manager.user_operations_to_monitor_v9


@pytest.mark.asyncio
async def test_bundle_prep_still_runs_when_monitoring_disabled():
    """The whole point of the bundler is to build bundles; disabling
    monitoring must not also disable that."""
    manager = _make_manager(disable_bundle_monitoring=True)
    op = MagicMock(name="userop")
    op.user_operation_hash = "0xabc"
    manager.local_mempool_manager_v9.get_user_operations_to_bundle \
        .return_value = {"0xabc": op}

    await manager.update_send_queue_and_monitor_queue()

    # Every mempool's get_user_operations_to_bundle was invoked once.
    for mem in (
        manager.local_mempool_manager_v9,
        manager.local_mempool_manager_v8,
        manager.local_mempool_manager_v7,
        manager.local_mempool_manager_v6,
    ):
        mem.get_user_operations_to_bundle.assert_awaited_once()
    # And the v9 bundle landed in the send queue.
    assert manager.bundles_to_send_v9 == [{"0xabc": op}]


@pytest.mark.asyncio
async def test_works_with_v6_disabled_and_monitoring_disabled():
    """v6 being disabled (``local_mempool_manager_v6 is None``) is a
    separate axis from monitoring being disabled. The gather indexing
    must not blow up when both are off."""
    manager = _make_manager(disable_bundle_monitoring=True)
    manager.local_mempool_manager_v6 = None
    manager.bundles_to_send_v6 = None

    await manager.update_send_queue_and_monitor_queue()

    manager.remove_included_and_readd_to_mempool_userops_monitoring \
        .assert_not_called()
    assert manager.bundles_to_send_v6 is None
