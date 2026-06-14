"""
Tests for the guaranteed-miss receipt fast-path in execution_endpoint.

When a userop was submitted to this bundler less than
``RECENT_SUBMISSION_FAST_PATH_S`` seconds ago, ``_is_recent_submission``
must return True so the receipt RPC can short-circuit before doing any
chain lookups. Stale entries must be pruned lazily so the in-memory
dict stays bounded by the most recent burst of submissions.
"""

import pytest
from unittest.mock import patch

from voltaire_bundler import execution_endpoint as ep_module
from voltaire_bundler.execution_endpoint import (
    RECENT_SUBMISSION_FAST_PATH_S,
    _get_recent_submission_entrypoint,
    _is_recent_submission,
    _record_recent_submission,
    _recent_userop_submissions,
)


ENTRYPOINT_V7_LC = "0x0000000071727de22e5e9d8baf0edac6f37da032"
ENTRYPOINT_V8_LC = "0x4337084d9e255ff0702461cf8895ce9e3b5ff108"


HASH_A = "0x" + "aa" * 32
HASH_B = "0x" + "bb" * 32
HASH_C = "0x" + "cc" * 32


@pytest.fixture(autouse=True)
def _clear_recent_submissions():
    """Reset the module-level dict around every test so we don't leak
    state between cases (or from other test modules)."""
    _recent_userop_submissions.clear()
    yield
    _recent_userop_submissions.clear()


@pytest.fixture
def monotonic_clock():
    """Patchable monotonic clock so age comparisons are deterministic
    instead of depending on real wall time + test scheduler jitter."""
    fake = {"now": 1_000.0}

    def _now():
        return fake["now"]

    def _advance(seconds):
        fake["now"] += seconds

    with patch.object(ep_module.time, "monotonic", _now):
        yield _advance


def test_fresh_submission_is_recent(monotonic_clock):
    _record_recent_submission(HASH_A, ENTRYPOINT_V7_LC)
    assert _is_recent_submission(HASH_A) is True


def test_submission_expires_after_threshold(monotonic_clock):
    _record_recent_submission(HASH_A, ENTRYPOINT_V7_LC)
    # Step just past the threshold — strict ``<`` boundary should miss.
    monotonic_clock(RECENT_SUBMISSION_FAST_PATH_S + 0.001)
    assert _is_recent_submission(HASH_A) is False


def test_submission_still_recent_just_before_threshold(monotonic_clock):
    _record_recent_submission(HASH_A, ENTRYPOINT_V7_LC)
    monotonic_clock(RECENT_SUBMISSION_FAST_PATH_S - 0.001)
    assert _is_recent_submission(HASH_A) is True


def test_unknown_hash_is_not_recent(monotonic_clock):
    _record_recent_submission(HASH_A, ENTRYPOINT_V7_LC)
    assert _is_recent_submission(HASH_B) is False


def test_hash_match_is_case_insensitive(monotonic_clock):
    _record_recent_submission(HASH_A.upper(), ENTRYPOINT_V7_LC)
    assert _is_recent_submission(HASH_A.lower()) is True


def test_stale_entry_is_dropped_on_lookup(monotonic_clock):
    """A poll that finds a stale entry should evict it as a side effect
    so an endlessly-retried expired hash doesn't camp in memory."""
    _record_recent_submission(HASH_A, ENTRYPOINT_V7_LC)
    monotonic_clock(RECENT_SUBMISSION_FAST_PATH_S + 1.0)
    assert HASH_A.lower() in _recent_userop_submissions
    assert _is_recent_submission(HASH_A) is False
    assert HASH_A.lower() not in _recent_userop_submissions


def test_record_prunes_stale_head_entries(monotonic_clock):
    """Recording a new submission should evict everything that has
    already aged past the threshold. This is what keeps the dict's size
    bounded to roughly the submission rate × threshold window."""
    _record_recent_submission(HASH_A, ENTRYPOINT_V7_LC)
    _record_recent_submission(HASH_B, ENTRYPOINT_V7_LC)
    monotonic_clock(RECENT_SUBMISSION_FAST_PATH_S + 0.1)
    # Both A and B are now stale.
    _record_recent_submission(HASH_C, ENTRYPOINT_V7_LC)
    # ...and should have been pruned when C was inserted.
    assert HASH_A.lower() not in _recent_userop_submissions
    assert HASH_B.lower() not in _recent_userop_submissions
    assert HASH_C.lower() in _recent_userop_submissions


def test_record_stops_pruning_at_first_fresh_entry(monotonic_clock):
    """Pruning must walk the head only — once it hits a fresh entry it
    should stop so newer entries are not scanned every insertion."""
    _record_recent_submission(HASH_A, ENTRYPOINT_V7_LC)
    monotonic_clock(RECENT_SUBMISSION_FAST_PATH_S * 0.6)
    _record_recent_submission(HASH_B, ENTRYPOINT_V7_LC)
    # Step so HASH_A is stale but HASH_B is still fresh.
    monotonic_clock(RECENT_SUBMISSION_FAST_PATH_S * 0.5)
    _record_recent_submission(HASH_C, ENTRYPOINT_V7_LC)

    assert HASH_A.lower() not in _recent_userop_submissions
    assert HASH_B.lower() in _recent_userop_submissions
    assert HASH_C.lower() in _recent_userop_submissions


def test_repeated_record_refreshes_timestamp(monotonic_clock):
    """Submitting the same hash twice updates its freshness window —
    otherwise a resubmit (replacement) would be locked into the
    original submission's expiry."""
    _record_recent_submission(HASH_A, ENTRYPOINT_V7_LC)
    monotonic_clock(RECENT_SUBMISSION_FAST_PATH_S * 0.9)
    _record_recent_submission(HASH_A, ENTRYPOINT_V7_LC)
    # Past the original window but well inside the refreshed one.
    monotonic_clock(RECENT_SUBMISSION_FAST_PATH_S * 0.5)
    assert _is_recent_submission(HASH_A) is True


def test_get_recent_submission_entrypoint_returns_stored_entrypoint(
    monotonic_clock,
):
    """The byHash fast path relies on this returning the same entrypoint
    that was recorded at submit time — a wrong entrypoint would steer
    the mempool lookup at the wrong handler/mempool and miss."""
    _record_recent_submission(HASH_A, ENTRYPOINT_V8_LC)
    assert _get_recent_submission_entrypoint(HASH_A) == ENTRYPOINT_V8_LC


def test_get_recent_submission_entrypoint_normalizes_case(monotonic_clock):
    """Submissions arrive as either lowercase or checksummed addresses;
    the stored value must be lowercased so the byHash dispatch can
    string-compare against the LocalMempoolManager*.entrypoint_lowercase
    constants."""
    _record_recent_submission(HASH_A, ENTRYPOINT_V8_LC.upper())
    assert _get_recent_submission_entrypoint(HASH_A) == ENTRYPOINT_V8_LC


def test_get_recent_submission_entrypoint_returns_none_when_stale(
    monotonic_clock,
):
    _record_recent_submission(HASH_A, ENTRYPOINT_V8_LC)
    monotonic_clock(RECENT_SUBMISSION_FAST_PATH_S + 0.1)
    assert _get_recent_submission_entrypoint(HASH_A) is None
    # And the stale entry is evicted as a side effect.
    assert HASH_A.lower() not in _recent_userop_submissions
