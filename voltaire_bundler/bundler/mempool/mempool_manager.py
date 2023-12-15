from dataclasses import dataclass
import asyncio
from functools import cache
import math
from typing import Any, List
from eth_abi import encode
from voltaire_bundler.bundler.gas_manager import GasManager
from voltaire_bundler.event_bus_manager.endpoint import RequestEvent
from voltaire_bundler.user_operation.user_operation import UserOperation
from .sender_mempool import SenderMempool
from voltaire_bundler.user_operation.user_operation_handler import (
    UserOperationHandler,
)
from ..validation_manager import ValidationManager
from ..reputation_manager import ReputationManager, ReputationStatus
from voltaire_bundler.bundler.exceptions import (
    ValidationException,
    ValidationExceptionCode,
)
from voltaire_bundler.utils.eth_client_utils import (
    get_latest_block_info
)
from voltaire_bundler.typing import Address, MempoolId
from voltaire_bundler.boot import MempoolType

MAX_OPS_PER_REQUEST = 4096

class LocalMempoolManager:
    supported_mempools_types_to_mempools_ids: dict[MempoolType, MempoolId]

@dataclass
class LocalMempoolManagerVersion0Point6(LocalMempoolManager):
    validation_manager: ValidationManager
    user_operation_handler: UserOperationHandler
    reputation_manager: ReputationManager
    gas_manager: GasManager
    ethereum_node_url: str
    bundler_private_key: str
    bundler_address: str
    entrypoint: Address
    chain_id: int
    senders_to_senders_mempools: dict[Address, SenderMempool]
    is_unsafe: bool
    enforce_gas_price_tolerance: int
    entity_to_no_of_ops_in_mempool: dict[Address, int]  # factory and paymaster
    verified_block_to_useroperations_standard_mempool_gossip_queue: dict[str,List[UserOperation]]

    def __init__(
        self,
        validation_manager: ValidationManager,
        user_operation_handler: UserOperationHandler,
        reputation_manager: ReputationManager,
        gas_manager: GasManager,
        ethereum_node_url: str,
        bundler_private_key: str,
        bundler_address: str,
        entrypoint: Address,
        chain_id: int,
        is_unsafe: bool,
        enforce_gas_price_tolerance: int,
        supported_mempools_types_to_mempools_ids: dict[MempoolType, MempoolId],
    ):
        self.validation_manager = validation_manager
        self.user_operation_handler = user_operation_handler
        self.reputation_manager = reputation_manager
        self.gas_manager = gas_manager
        self.ethereum_node_url = ethereum_node_url
        self.bundler_private_key = bundler_private_key
        self.bundler_address = bundler_address
        self.entrypoint = entrypoint
        self.chain_id = chain_id
        self.is_unsafe = is_unsafe
        self.enforce_gas_price_tolerance = enforce_gas_price_tolerance
        self.senders_to_senders_mempools = {}
        self.entity_to_no_of_ops_in_mempool = {}
        self.verified_block_to_useroperations_standard_mempool_gossip_queue = dict()
        self.supported_mempools_types_to_mempools_ids = supported_mempools_types_to_mempools_ids
        self.seen_user_operation_hashs = set()
        # self.supported_mempools_types = [MempoolType.default]
        # self.supported_chains_to_mempools_ids = ["Qmf7P3CuhzSbpJa8LqXPwRzfPqsvoQ6RG7aXvthYTzGxb2"]

    def clear_user_operations(self) -> None:
        self.senders_to_senders_mempools.clear()

    async def add_user_operation(
            self, 
            user_operation: UserOperation,
            ) -> (str, str, List[MempoolId]):
        
        latest_block_number, latest_block_basefee, _ = await get_latest_block_info(self.ethereum_node_url)
        self._verify_entities_reputation(
            user_operation.sender_address,
            user_operation.factory_address_lowercase,
            user_operation.paymaster_address_lowercase,
        )

        await self.gas_manager.verify_preverification_gas_and_verification_gas_limit(
            user_operation, self.entrypoint, latest_block_number, latest_block_basefee
        )
        gas_price_hex = await self.gas_manager.verify_gas_fees_and_get_price(
            user_operation, self.enforce_gas_price_tolerance
        )

        
        (
            is_sender_staked,
            user_operation_hash,
        ) = await self.validation_manager.validate_user_operation(
            user_operation, 
            self.entrypoint, 
            "latest", 
            # latest_block_basefee,
            gas_price_hex,
            # "latest"
        )
        new_sender = None
        new_sender_address = user_operation.sender_address

        if new_sender_address not in self.senders_to_senders_mempools:
            self.senders_to_senders_mempools[new_sender_address] = SenderMempool(
                new_sender_address,
                dict()
            )

        new_sender = self.senders_to_senders_mempools[new_sender_address]

        await new_sender.add_user_operation(
            user_operation,
            user_operation_hash,
            is_sender_staked,
        )

        self.update_all_seen_status(
            user_operation.sender_address,
            user_operation.factory_address_lowercase,
            user_operation.paymaster_address_lowercase,
        )

        if user_operation.factory_address_lowercase is not None:
            self._update_entity_no_of_ops_in_mempool(
                user_operation.factory_address_lowercase
            )

        if user_operation.paymaster_address_lowercase is not None:
            self._update_entity_no_of_ops_in_mempool(
                user_operation.paymaster_address_lowercase
            )
        valid_mempools_ids = self.supported_mempools_types_to_mempools_ids.values()

        user_operation.valid_mempools_ids = valid_mempools_ids
        user_operation.user_operation_hash = user_operation_hash

        return user_operation_hash, latest_block_number, valid_mempools_ids
    
    async def add_user_operation_p2p(
            self, 
            user_operation: UserOperation,
            peer_id: str, 
            verified_at_block_hash: str
            ) -> None:
        latest_block_number, latest_block_basefee, _ = await get_latest_block_info(self.ethereum_node_url)

        try:
            self._verify_entities_reputation(
                user_operation.sender_address,
                user_operation.factory_address_lowercase,
                user_operation.paymaster_address_lowercase,
            ) 
            await self.gas_manager.verify_preverification_gas_and_verification_gas_limit(
                user_operation, self.entrypoint, latest_block_number, latest_block_basefee
            )
            gas_price_hex = await self.gas_manager.verify_gas_fees_and_get_price(
                user_operation, self.enforce_gas_price_tolerance
            )
        except ValidationException as excp:
                return "No"

        try:
            (
                is_sender_staked,
                user_operation_hash,
            ) = await self.validation_manager.validate_user_operation(
                user_operation, 
                self.entrypoint, 
                latest_block_number, 
                # latest_block_basefee,
                gas_price_hex
            )

            if self.is_hash_seen(user_operation_hash):
                return "No"
            else:
                self.seen_user_operation_hashs.add(user_operation_hash)

        except ValidationException as excp:
            try:
                (
                    is_sender_staked,
                    user_operation_hash,
                ) = await self.validation_manager.validate_user_operation(
                    user_operation, 
                    self.entrypoint, 
                    verified_at_block_hash, 
                    # latest_block_basefee,
                    gas_price_hex
                )
            except ValidationException as excp:
                self.reputation_manager.ban_entity(peer_id)

            return "No"

        new_sender = None
        new_sender_address = user_operation.sender_address

        if new_sender_address not in self.senders_to_senders_mempools:
            self.senders_to_senders_mempools[new_sender_address] = SenderMempool(
                new_sender_address, dict()
            )

        new_sender = self.senders_to_senders_mempools[new_sender_address]

        await new_sender.add_user_operation(
            user_operation,
            user_operation_hash,
            is_sender_staked,
        )

        self.update_all_seen_status(
            user_operation.sender_address,
            user_operation.factory_address_lowercase,
            user_operation.paymaster_address_lowercase,
        )

        if user_operation.factory_address_lowercase is not None:
            self._update_entity_no_of_ops_in_mempool(
                user_operation.factory_address_lowercase
            )

        if user_operation.paymaster_address_lowercase is not None:
            self._update_entity_no_of_ops_in_mempool(
                user_operation.paymaster_address_lowercase
            )

        valid_mempools_ids = self.supported_mempools_types_to_mempools_ids.values()

        user_operation.valid_mempools_ids = valid_mempools_ids
        user_operation.user_operation_hash = user_operation_hash

        return "Ok"
    
    def is_hash_seen(self, user_operation_hash:str) -> bool:
        return user_operation_hash in self.seen_user_operation_hashs

    async def get_user_operations_to_bundle(self) -> list[UserOperation]:
        bundle = []
        for sender_address in list(self.senders_to_senders_mempools):
            sender = self.senders_to_senders_mempools[sender_address]
            if len(sender.user_operation_hashs_to_mempool_members) > 0:
                user_operation = sender.user_operation_hashs_to_mempool_members.pop(
                    next(iter(sender.user_operation_hashs_to_mempool_members))
                ).user_operation

                if not self.is_unsafe:
                    new_code_hash = (
                        await self.validation_manager.get_addresses_code_hash(
                            user_operation.associated_addresses
                        )
                    )
                    if new_code_hash != user_operation.code_hash:
                        continue

                bundle.append(user_operation)
                if len(sender.user_operation_hashs_to_mempool_members) == 0:
                    del self.senders_to_senders_mempools[sender.address]

        return bundle

    def get_user_operations_hashes_with_mempool_id(
            self, 
            mempool_id:MempoolId,
            offset: int
    ) -> (List[str], int):
        user_operations_hashs = []
        for sender_address in list(self.senders_to_senders_mempools):
            sender = self.senders_to_senders_mempools[sender_address]
            if len(sender.user_operation_hashs_to_mempool_members) > 0:
                for user_operation_hash, mempool_member in sender.user_operation_hashs_to_mempool_members.items():
                    if mempool_id in mempool_member.user_operation.valid_mempools_ids:
                        user_operations_hashs.append(list(bytes.fromhex(user_operation_hash[2:])))

        start = offset * MAX_OPS_PER_REQUEST
        end = start + MAX_OPS_PER_REQUEST

        user_operations_hashs_len = len(user_operations_hashs)
        if user_operations_hashs_len == 0 or start >= user_operations_hashs_len:
            return [], 0

        more_flag = 0
        if end > user_operations_hashs_len:
            end = user_operations_hashs_len
        else:
            more_flag = math.floor((user_operations_hashs_len - end) / MAX_OPS_PER_REQUEST)

        return user_operations_hashs[start:end], more_flag

    def get_user_operations_by_hashes(
            self, 
            user_operations_hashs:List[str]
    ) -> (List[UserOperation], List[str]):
        user_operations = []
        found_user_operations_hashs = []
        for sender_address in list(self.senders_to_senders_mempools):
            sender = self.senders_to_senders_mempools[sender_address]
            if len(sender.user_operation_hashs_to_mempool_members) > 0:
                for user_operation_hash, mempool_member in sender.user_operation_hashs_to_mempool_members.items():
                    if user_operation_hash in user_operations_hashs:
                        user_operations.append(mempool_member.user_operation.get_user_operation_json())
                        found_user_operations_hashs.append(user_operation_hash)
        
        remaining_user_operation_hashes = set(user_operations_hashs) - set(found_user_operations_hashs)
        return user_operations, list(remaining_user_operation_hashes)

    def get_all_user_operations(self) -> list[UserOperation]:
        user_operations = [
            mempool_member.user_operation
            for sender in self.senders_to_senders_mempools.values()
            for mempool_member in sender.user_operation_hashs_to_mempool_members.values()
        ]
        return user_operations

    def update_all_seen_status(
        self, sender_address: str, factory_address: str, paymaster_address: str
    ) -> None:
        self.reputation_manager.update_seen_status(sender_address)

        if factory_address is not None:
            self.reputation_manager.update_seen_status(factory_address)

        if paymaster_address is not None:
            self.reputation_manager.update_seen_status(paymaster_address)
        
    def queue_useroperations_with_entrypoint_to_gossip_publish(
            self,
            user_operation_json,
            verified_at_block_hash:int,
            valid_mempools: List[str]
        )->None:
        if verified_at_block_hash not in self.verified_block_to_useroperations_standard_mempool_gossip_queue:
            self.verified_block_to_useroperations_standard_mempool_gossip_queue[verified_at_block_hash] = list()

        self.verified_block_to_useroperations_standard_mempool_gossip_queue[verified_at_block_hash].append(
            user_operation_json
            )
            
    def create_p2p_gossip_requests(self)->List[RequestEvent]:
        requestEvents = list()
        for verified_at_block_hash, user_operations_list in self.verified_block_to_useroperations_standard_mempool_gossip_queue.items():
            gossib_to_broadcast = dict()
            useroperations_with_entrypoint = dict()
            useroperations_with_entrypoint["entry_point_contract"] = encode_address(self.entrypoint)
            useroperations_with_entrypoint["verified_at_block_hash"] = encode_uint256(int(verified_at_block_hash,16))
            useroperations_with_entrypoint["chain_id"] = encode_uint256(self.chain_id)
            useroperations_with_entrypoint["user_operations"] = [user_operation for user_operation in user_operations_list]
            gossib_to_broadcast["topics"] = list(self.supported_mempools_types_to_mempools_ids.values())
            gossib_to_broadcast["useroperations_with_entrypoint"] = useroperations_with_entrypoint
            # requestEvent = {
            #     "request_type" : 'send_gossib_useroperations_with_entrypoint', 
            #     "request_arguments" : gossib_to_broadcast,
            # }
            # requestEvents.append(requestEvent)
            requestEvents.append(gossib_to_broadcast)
        self.verified_block_to_useroperations_standard_mempool_gossip_queue.clear()
        return requestEvents

    def _verify_entities_reputation(
        self, sender_address: str, factory_address: str, paymaster_address: str
    ) -> None:
        sender_no_of_ops = 0
        if sender_address in self.senders_to_senders_mempools:
            sender_no_of_ops = len(
                self.senders_to_senders_mempools[sender_address].user_operation_hashs_to_mempool_members
            )
        self._verify_entity_reputation(
            sender_address, "sender", sender_no_of_ops
        )

        if factory_address is not None:
            factory_no_of_ops = 0
            if factory_address in self.entity_to_no_of_ops_in_mempool:
                factory_no_of_ops = self.entity_to_no_of_ops_in_mempool[
                    factory_address
                ]
            self._verify_entity_reputation(
                factory_address,
                "factory",
                factory_no_of_ops,
            )

        if paymaster_address is not None:
            paymaster_no_of_ops = 0
            if paymaster_address in self.entity_to_no_of_ops_in_mempool:
                paymaster_no_of_ops = self.entity_to_no_of_ops_in_mempool[
                    paymaster_address
                ]
            self._verify_entity_reputation(
                paymaster_address,
                "paymaster",
                paymaster_no_of_ops,
            )

    def _verify_entity_reputation(
        self, entity_address: str, entity_name: str, entity_no_of_ops: int
    ) -> None:
        if entity_address not in self.entity_to_no_of_ops_in_mempool:
            self.entity_to_no_of_ops_in_mempool[entity_address] = 0

        entity_no_of_ops = self.entity_to_no_of_ops_in_mempool[entity_address]
        status = self.reputation_manager.get_status(entity_address)
        if status == ReputationStatus.BANNED:
            raise ValidationException(
                ValidationExceptionCode.Reputation,
                " ".join(
                    (
                        "user operation was dropped because ",
                        entity_address,
                        "is banned",
                        entity_name,
                    )
                ),
            )
        elif status == ReputationStatus.THROTTLED and entity_no_of_ops > 0:
            raise ValidationException(
                ValidationExceptionCode.Reputation,
                " ".join(
                    (
                        "user operation was dropped",
                        entity_address,
                        "is throttled",
                        entity_name,
                    )
                ),
            )

    def _update_entity_no_of_ops_in_mempool(self, entity_address: str) -> None:
        no_of_ops = 0
        if entity_address in self.entity_to_no_of_ops_in_mempool:
            no_of_ops = self.entity_to_no_of_ops_in_mempool[entity_address]
        self.entity_to_no_of_ops_in_mempool[entity_address] = no_of_ops + 1

@cache
def encode_uint256(x):
    return encode(["uint256"], [x])

@cache
def encode_address(address):
    return encode(["address"], [address])[12:]