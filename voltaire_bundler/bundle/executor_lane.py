"""A bundler EOA in the executor pool.

Each EOA in the pool is an independent nonce lane. The bundle manager submits
from it via the per-EOA ``eth_getTransactionCount("latest")`` + fee-escalation
path (the same gap-proof mechanism the single-EOA bundler uses), so no explicit
per-lane nonce state is tracked here — a lane is just its address and key.
"""
from dataclasses import dataclass

from voltaire_bundler.custom_types import Address


@dataclass
class ExecutorLane:
    address: Address
    private_key: str
