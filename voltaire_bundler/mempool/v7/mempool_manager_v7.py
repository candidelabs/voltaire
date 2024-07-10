from dataclasses import dataclass

from ..mempool_manager import LocalMempoolManager
from ..mempool_info import DEFAULT_MEMPOOL_INFO
from voltaire_bundler.typing import Address, MempoolId
from voltaire_bundler.user_operation.v7.user_operation_handler_v7 import \
    UserOperationHandlerV7

from voltaire_bundler.mempool.reputation_manager import ReputationManager
from ...validation.v7.validation_manager_v7 import ValidationManagerV7


@dataclass
class LocalMempoolManagerV7(LocalMempoolManager):
    entrypoint = Address("0x0000000071727De22E5E9d8BAf0edAc6f37da032")
    entrypoint_lowercase = Address("0x0000000071727De22E5E9d8BAf0edAc6f37da032")

    def __init__(
        self,
        user_operation_handler: UserOperationHandlerV7,
        ethereum_node_url: str,
        bundler_address: str,
        chain_id: int,
        is_unsafe: bool,
        enforce_gas_price_tolerance: int,
        is_legacy_mode: bool,
        ethereum_node_debug_trace_call_url: str,
    ):
        self.validation_manager = ValidationManagerV7(
            user_operation_handler,
            ethereum_node_url,
            bundler_address,
            chain_id,
            is_unsafe,
            is_legacy_mode,
            enforce_gas_price_tolerance,
            ethereum_node_debug_trace_call_url,
        )
        self.user_operation_handler = user_operation_handler
        self.reputation_manager = ReputationManager()
        self.ethereum_node_url = ethereum_node_url
        self.bundler_address = bundler_address
        self.chain_id = chain_id
        self.is_unsafe = is_unsafe
        self.enforce_gas_price_tolerance = enforce_gas_price_tolerance
        self.senders_to_senders_mempools = {}
        self.entity_to_no_of_ops_in_mempool = {}
        self.verified_useroperations_standard_mempool_gossip_queue = []
        self.seen_user_operation_hashs = set()
        if (
            self.entrypoint in DEFAULT_MEMPOOL_INFO and
            chain_id in DEFAULT_MEMPOOL_INFO[self.entrypoint]
        ):
            self.canonical_mempool_id = MempoolId(
                DEFAULT_MEMPOOL_INFO[self.entrypoint][chain_id])
        else:
            self.canonical_mempool_id = None

        self.paymaster_deposits_cache = dict()
        self.latest_paymaster_deposits_cache_block = 0
