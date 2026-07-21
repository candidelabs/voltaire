"""Executor pool: the shared set of bundler EOAs used across all entrypoints.

When ``--bundler_secret`` carries more than one key, each tick's bundles are
sharded by sender across these EOAs and submitted in parallel — one bundle per
EOA per tick, each EOA an independent nonce lane.

Sharding is deterministic (``int(sender, 16) % num_lanes``): a given sender
always routes to the same EOA, so its operations serialize on one nonce
sequence and never race across lanes, while different senders spread across the
pool and submit concurrently. Submission itself goes through the bundle
manager's per-EOA ``eth_getTransactionCount("latest")`` + fee-escalation path,
which is gap-proof and self-healing, so the pool holds no nonce state of its
own.
"""
from __future__ import annotations

from voltaire_bundler.bundle.executor_lane import ExecutorLane
from voltaire_bundler.custom_types import Address


class ExecutorPool:
    def __init__(self, secrets: list[tuple[Address, str]]):
        if len(secrets) == 0:
            raise ValueError("executor pool needs at least one bundler EOA")
        self.lanes: list[ExecutorLane] = [
            ExecutorLane(address, private_key) for address, private_key in secrets
        ]

    @property
    def num_lanes(self) -> int:
        return len(self.lanes)

    def shard_for_sender(self, sender: str) -> int:
        """Deterministic sender -> lane index. Same sender always maps to the
        same lane, so its ops serialize on one nonce sequence."""
        return int(sender, 16) % self.num_lanes

    def lane_for_sender(self, sender: str) -> ExecutorLane:
        return self.lanes[self.shard_for_sender(sender)]
