"""Unit tests for the executor pool's deterministic sender sharding."""
import pytest

from voltaire_bundler.bundle.executor_pool import ExecutorPool

# 4 lanes with distinct addresses/keys.
SECRETS = [(f"0x{i:040x}", f"0x{i:064x}") for i in range(1, 5)]

# Senders whose low bits land on known shards mod 4.
SENDER_SHARD0 = "0x" + "00" * 19 + "04"  # int % 4 == 0
SENDER_SHARD1 = "0x" + "00" * 19 + "05"  # int % 4 == 1


def _pool():
    return ExecutorPool(SECRETS)


def test_empty_pool_rejected():
    with pytest.raises(ValueError):
        ExecutorPool([])


def test_num_lanes():
    assert _pool().num_lanes == 4


def test_sharding_is_deterministic_and_in_range():
    pool = _pool()
    for sender in (SENDER_SHARD0, SENDER_SHARD1, "0xdeadbeef", "0x1234"):
        s = pool.shard_for_sender(sender)
        assert 0 <= s < pool.num_lanes
        assert pool.shard_for_sender(sender) == s  # stable
        assert pool.lane_for_sender(sender) is pool.lanes[s]


def test_sharding_matches_mod():
    pool = _pool()
    assert pool.shard_for_sender(SENDER_SHARD0) == 0
    assert pool.shard_for_sender(SENDER_SHARD1) == 1


def test_lane_holds_address_and_key():
    pool = _pool()
    assert pool.lanes[0].address == SECRETS[0][0]
    assert pool.lanes[0].private_key == SECRETS[0][1]
