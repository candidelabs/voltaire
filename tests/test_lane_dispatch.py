"""Unit tests for background lane dispatch in BundlerManager._build_send_tasks.

Pool mode must dispatch each lane's shard as an independent background task
(returning [] so the tick never blocks on submission), keep each lane strictly
serial (a busy lane defers its shard), and preserve the legacy awaited path
when no pool is configured.

BundlerManager's constructor pulls in heavy dependencies, so these tests build
a bare instance via object.__new__ and set only the attributes the dispatch
path reads.
"""
import asyncio

import pytest

from voltaire_bundler.bundle.bundle_manager import BundlerManager
from voltaire_bundler.bundle.executor_pool import ExecutorPool

SECRETS = [(f"0x{i:040x}", f"0x{i:064x}") for i in range(1, 5)]

# Senders with known shards mod 4 (see ExecutorPool.shard_for_sender).
SENDER_LANE0 = "0x" + "00" * 19 + "04"
SENDER_LANE1 = "0x" + "00" * 19 + "05"
SENDER_LANE0_B = "0x" + "00" * 19 + "08"  # also int % 4 == 0


class FakeOp:
    def __init__(self, sender_address):
        self.sender_address = sender_address


class FakeMempool:
    pass


def _manager(pool_secrets):
    manager = object.__new__(BundlerManager)
    manager.executor_pool = ExecutorPool(pool_secrets) if pool_secrets else None
    manager._lane_send_tasks = {}
    manager.sent = []  # (senders, mempool, secret) per send_bundle call

    async def record_send(user_operations, mempool, highest_block, secret):
        manager.sent.append(
            ([op.sender_address for op in user_operations], mempool, secret)
        )

    manager.send_bundle = record_send
    return manager


def _job(mempool, *senders):
    return ({f"hash-{s}": FakeOp(s) for s in senders}, mempool, 0)


@pytest.mark.asyncio
async def test_pool_dispatches_background_tasks_and_returns_empty():
    manager = _manager(SECRETS)
    mempool = FakeMempool()

    tasks = manager._build_send_tasks([_job(mempool, SENDER_LANE0, SENDER_LANE1)])

    assert tasks == []  # the tick has nothing to await
    assert len(manager._lane_send_tasks) == 2
    await asyncio.gather(*manager._lane_send_tasks.values())

    assert len(manager.sent) == 2
    sent_by_secret = {secret: senders for senders, _, secret in manager.sent}
    assert sent_by_secret[SECRETS[0]] == [SENDER_LANE0]
    assert sent_by_secret[SECRETS[1]] == [SENDER_LANE1]


@pytest.mark.asyncio
async def test_same_lane_senders_share_one_bundle():
    manager = _manager(SECRETS)
    mempool = FakeMempool()

    manager._build_send_tasks([_job(mempool, SENDER_LANE0, SENDER_LANE0_B)])
    await asyncio.gather(*manager._lane_send_tasks.values())

    assert len(manager.sent) == 1
    senders, _, secret = manager.sent[0]
    assert sorted(senders) == sorted([SENDER_LANE0, SENDER_LANE0_B])
    assert secret == SECRETS[0]


@pytest.mark.asyncio
async def test_busy_lane_defers_shard_until_task_finishes():
    manager = _manager(SECRETS)
    mempool = FakeMempool()
    release = asyncio.Event()
    slow_sends = []

    async def slow_send(user_operations, mempool_arg, highest_block, secret):
        slow_sends.append([op.sender_address for op in user_operations])
        await release.wait()

    manager.send_bundle = slow_send

    # Tick 1: lane 0 starts a send that stays in flight.
    manager._build_send_tasks([_job(mempool, SENDER_LANE0)])
    await asyncio.sleep(0)
    assert slow_sends == [[SENDER_LANE0]]

    # Tick 2: lane 0 is still busy — its new shard must be deferred, not sent
    # concurrently (nonce safety), while free lane 1 dispatches normally.
    manager._build_send_tasks([_job(mempool, SENDER_LANE0_B, SENDER_LANE1)])
    await asyncio.sleep(0)
    assert [SENDER_LANE0_B] not in slow_sends
    assert [SENDER_LANE1] in slow_sends

    # Tick 3, after the in-flight send finished: lane 0 accepts work again.
    release.set()
    await asyncio.gather(*manager._lane_send_tasks.values())
    manager._build_send_tasks([_job(mempool, SENDER_LANE0_B)])
    release.set()
    await asyncio.gather(*manager._lane_send_tasks.values())
    assert [SENDER_LANE0_B] in slow_sends


@pytest.mark.asyncio
async def test_cross_ep_lane_collision_defers_second_ep():
    manager = _manager(SECRETS)
    mempool_a, mempool_b = FakeMempool(), FakeMempool()

    manager._build_send_tasks([
        _job(mempool_a, SENDER_LANE0),
        _job(mempool_b, SENDER_LANE0_B),  # same lane, later EP — deferred
    ])
    await asyncio.gather(*manager._lane_send_tasks.values())

    assert len(manager.sent) == 1
    senders, sent_mempool, _ = manager.sent[0]
    assert senders == [SENDER_LANE0]
    assert sent_mempool is mempool_a


@pytest.mark.asyncio
async def test_legacy_path_returns_awaitable_coroutines():
    manager = _manager(None)
    manager.bundler_secrets_per_ep = {
        label: [SECRETS[0]] for label in ("v6", "v7", "v8", "v9")
    }
    mempool = FakeMempool()

    tasks = manager._build_send_tasks([_job(mempool, SENDER_LANE0)])

    assert len(tasks) == 1
    assert manager._lane_send_tasks == {}  # nothing dispatched in background
    await asyncio.gather(*tasks)
    assert len(manager.sent) == 1
