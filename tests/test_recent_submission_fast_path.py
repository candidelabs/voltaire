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
    _is_recent_submission,
    _record_recent_submission,
    _recent_userop_submissions,
)


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
    _record_recent_submission(HASH_A)
    assert _is_recent_submission(HASH_A) is True


def test_submission_expires_after_threshold(monotonic_clock):
    _record_recent_submission(HASH_A)
    # Step just past the threshold — strict ``<`` boundary should miss.
    monotonic_clock(RECENT_SUBMISSION_FAST_PATH_S + 0.001)
    assert _is_recent_submission(HASH_A) is False


def test_submission_still_recent_just_before_threshold(monotonic_clock):
    _record_recent_submission(HASH_A)
    monotonic_clock(RECENT_SUBMISSION_FAST_PATH_S - 0.001)
    assert _is_recent_submission(HASH_A) is True


def test_unknown_hash_is_not_recent(monotonic_clock):
    _record_recent_submission(HASH_A)
    assert _is_recent_submission(HASH_B) is False


def test_hash_match_is_case_insensitive(monotonic_clock):
    _record_recent_submission(HASH_A.upper())
    assert _is_recent_submission(HASH_A.lower()) is True


def test_stale_entry_is_dropped_on_lookup(monotonic_clock):
    """A poll that finds a stale entry should evict it as a side effect
    so an endlessly-retried expired hash doesn't camp in memory."""
    _record_recent_submission(HASH_A)
    monotonic_clock(RECENT_SUBMISSION_FAST_PATH_S + 1.0)
    assert HASH_A.lower() in _recent_userop_submissions
    assert _is_recent_submission(HASH_A) is False
    assert HASH_A.lower() not in _recent_userop_submissions


def test_record_prunes_stale_head_entries(monotonic_clock):
    """Recording a new submission should evict everything that has
    already aged past the threshold. This is what keeps the dict's size
    bounded to roughly the submission rate × threshold window."""
    _record_recent_submission(HASH_A)
    _record_recent_submission(HASH_B)
    monotonic_clock(RECENT_SUBMISSION_FAST_PATH_S + 0.1)
    # Both A and B are now stale.
    _record_recent_submission(HASH_C)
    # ...and should have been pruned when C was inserted.
    assert HASH_A.lower() not in _recent_userop_submissions
    assert HASH_B.lower() not in _recent_userop_submissions
    assert HASH_C.lower() in _recent_userop_submissions


def test_record_stops_pruning_at_first_fresh_entry(monotonic_clock):
    """Pruning must walk the head only — once it hits a fresh entry it
    should stop so newer entries are not scanned every insertion."""
    _record_recent_submission(HASH_A)
    monotonic_clock(RECENT_SUBMISSION_FAST_PATH_S * 0.6)
    _record_recent_submission(HASH_B)
    # Step so HASH_A is stale but HASH_B is still fresh.
    monotonic_clock(RECENT_SUBMISSION_FAST_PATH_S * 0.5)
    _record_recent_submission(HASH_C)

    assert HASH_A.lower() not in _recent_userop_submissions
    assert HASH_B.lower() in _recent_userop_submissions
    assert HASH_C.lower() in _recent_userop_submissions


def test_repeated_record_refreshes_timestamp(monotonic_clock):
    """Submitting the same hash twice updates its freshness window —
    otherwise a resubmit (replacement) would be locked into the
    original submission's expiry."""
    _record_recent_submission(HASH_A)
    monotonic_clock(RECENT_SUBMISSION_FAST_PATH_S * 0.9)
    _record_recent_submission(HASH_A)
    # Past the original window but well inside the refreshed one.
    monotonic_clock(RECENT_SUBMISSION_FAST_PATH_S * 0.5)
    assert _is_recent_submission(HASH_A) is True
