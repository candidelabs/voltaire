"""
Tests for ``ExecutionEndpoint._lookup_userop_in_local_mempool_by_entrypoint``.

The byHash fresh-submission fast path routes a recent userop's hash
straight at the local mempool for the entrypoint it was submitted
under, skipping the eth_getLogs / eth_getTransactionByHash cascade.
This dispatcher must:

- map each of the four entrypoint addresses to the matching mempool +
  handler instance (different handlers for v6 vs v7v8v9);
- pass the **checksummed** entrypoint string into the response so the
  ``entryPoint`` field on the JSON-RPC reply matches the rest of the
  bundler's responses;
- return ``None`` (not raise) for an unknown or disabled entrypoint so
  the caller can fall through to the normal lookup cascade.
"""

from unittest.mock import MagicMock

import pytest

from voltaire_bundler.execution_endpoint import ExecutionEndpoint
from voltaire_bundler.mempool.mempool_manager_v6 import LocalMempoolManagerV6
from voltaire_bundler.mempool.mempool_manager_v7 import LocalMempoolManagerV7
from voltaire_bundler.mempool.mempool_manager_v8 import LocalMempoolManagerV8
from voltaire_bundler.mempool.mempool_manager_v9 import LocalMempoolManagerV9


HASH = "0x" + "ab" * 32
UNKNOWN_ENTRYPOINT = "0x" + "ff" * 20


def _make_endpoint(*, v6_enabled: bool = True) -> ExecutionEndpoint:
    """Build an ExecutionEndpoint skeleton with just the fields the
    dispatcher touches. spec=ExecutionEndpoint anchors the mock so a
    typo in an attribute name fails fast rather than silently always
    returning a Mock."""
    ep = MagicMock(spec=ExecutionEndpoint)

    ep.user_operation_handler_v6 = MagicMock() if v6_enabled else None
    ep.user_operation_handler_v7v8v9 = MagicMock()

    def _mempool() -> MagicMock:
        m = MagicMock()
        m.senders_to_senders_mempools.values.return_value = []
        return m

    ep.local_mempool_manager_v6 = _mempool() if v6_enabled else None
    ep.local_mempool_manager_v7 = _mempool()
    ep.local_mempool_manager_v8 = _mempool()
    ep.local_mempool_manager_v9 = _mempool()

    # Bind the real method onto the mock so we exercise the production
    # dispatch logic, not a Mock auto-attribute.
    ep._lookup_userop_in_local_mempool_by_entrypoint = (
        ExecutionEndpoint._lookup_userop_in_local_mempool_by_entrypoint
        .__get__(ep, ExecutionEndpoint)
    )
    return ep


@pytest.mark.parametrize(
    "entrypoint_lc, expected_handler_attr, expected_mempool_attr, "
    "expected_checksummed",
    [
        (
            LocalMempoolManagerV6.entrypoint_lowercase,
            "user_operation_handler_v6",
            "local_mempool_manager_v6",
            LocalMempoolManagerV6.entrypoint,
        ),
        (
            LocalMempoolManagerV7.entrypoint_lowercase,
            "user_operation_handler_v7v8v9",
            "local_mempool_manager_v7",
            LocalMempoolManagerV7.entrypoint,
        ),
        (
            LocalMempoolManagerV8.entrypoint_lowercase,
            "user_operation_handler_v7v8v9",
            "local_mempool_manager_v8",
            LocalMempoolManagerV8.entrypoint,
        ),
        (
            LocalMempoolManagerV9.entrypoint_lowercase,
            "user_operation_handler_v7v8v9",
            "local_mempool_manager_v9",
            LocalMempoolManagerV9.entrypoint,
        ),
    ],
)
def test_dispatches_to_right_handler_and_mempool(
    entrypoint_lc,
    expected_handler_attr,
    expected_mempool_attr,
    expected_checksummed,
):
    """Each entrypoint must route at its own (handler, mempool) pair —
    and the response carries the checksummed entrypoint string."""
    ep = _make_endpoint()
    expected_handler = getattr(ep, expected_handler_attr)
    expected_handler.get_user_operation_by_hash_from_local_mempool.return_value = {
        "ok": True,
    }
    expected_mempool = getattr(ep, expected_mempool_attr)

    result = ep._lookup_userop_in_local_mempool_by_entrypoint(
        HASH, entrypoint_lc,
    )

    assert result == {"ok": True}
    expected_handler.get_user_operation_by_hash_from_local_mempool \
        .assert_called_once_with(
            HASH,
            expected_checksummed,
            expected_mempool.senders_to_senders_mempools.values.return_value,
        )


def test_returns_none_for_unknown_entrypoint():
    ep = _make_endpoint()
    assert ep._lookup_userop_in_local_mempool_by_entrypoint(
        HASH, UNKNOWN_ENTRYPOINT,
    ) is None


def test_returns_none_when_v6_disabled():
    """--disable_v6 leaves handler_v6 / mempool_v6 as ``None``. The
    dispatcher must treat a v6-tagged recent submission as "fall back
    to the normal lookup" rather than raising or trying to call methods
    on None."""
    ep = _make_endpoint(v6_enabled=False)
    assert ep._lookup_userop_in_local_mempool_by_entrypoint(
        HASH, LocalMempoolManagerV6.entrypoint_lowercase,
    ) is None


def test_returns_none_when_mempool_miss():
    """If the local mempool reports None (the op already left the
    mempool — bundled and dropped within the freshness window on a fast
    chain), the dispatcher must propagate the miss so the caller can
    fall through to the normal chain cascade."""
    ep = _make_endpoint()
    ep.user_operation_handler_v7v8v9.get_user_operation_by_hash_from_local_mempool \
        .return_value = None
    assert ep._lookup_userop_in_local_mempool_by_entrypoint(
        HASH, LocalMempoolManagerV9.entrypoint_lowercase,
    ) is None
