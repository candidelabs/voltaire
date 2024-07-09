import asyncio
import logging
import math
from functools import cache
from dataclasses import dataclass
from typing import Any, List

from eth_abi import encode, decode

from voltaire_bundler.bundle.exceptions import \
        ValidationException, ValidationExceptionCode
from voltaire_bundler.mempool.reputation_manager import \
        ReputationManager, ReputationStatus
from voltaire_bundler.user_operation.models import StakeInfo
from voltaire_bundler.user_operation.user_operation_handler import UserOperationHandler
from voltaire_bundler.event_bus_manager.endpoint import RequestEvent
from voltaire_bundler.validation.validation_manager import ValidationManager
from voltaire_bundler.typing import Address, MempoolId
from voltaire_bundler.utils.eth_client_utils import get_latest_block_info
from voltaire_bundler.user_operation.user_operation import UserOperation
from voltaire_bundler.utils.eth_client_utils import send_rpc_request_to_eth_client

from .sender_mempool import SenderMempool


@dataclass
class LocalMempoolManager():
    entrypoint: Address
    entrypoint_lowercase: Address
    validation_manager: ValidationManager
    user_operation_handler: UserOperationHandler
    reputation_manager: ReputationManager
    ethereum_node_url: str
    bundler_private_key: str
    bundler_address: str
    chain_id: int
    senders_to_senders_mempools: dict[Address, SenderMempool]
    is_unsafe: bool
    enforce_gas_price_tolerance: int
    entity_to_no_of_ops_in_mempool: dict[Address, int]  # factory and paymaster
    verified_useroperations_standard_mempool_gossip_queue: List[Any]
    canonical_mempool_id: MempoolId
    seen_user_operation_hashs: set[str]
    paymaster_deposits_cache: dict[str, int]
    latest_paymaster_deposits_cache_block: int
    MAX_OPS_PER_REQUEST = 4096
    MIN_STAKE = 1
    MIN_UNSTAKE_DELAY = 1

    def clear_user_operations(self) -> None:
        self.senders_to_senders_mempools.clear()

    async def add_user_operation(
        self,
        user_operation: UserOperation,
    ) -> tuple[str, str, List[MempoolId]]:
        latest_block_number, _, _, latest_block_timestamp, latest_block_hash = (
            await get_latest_block_info(self.ethereum_node_url)
        )
        self._verify_banned_and_throttled_entities(
            user_operation.sender_address,
            user_operation.factory_address_lowercase,
            user_operation.paymaster_address_lowercase,
        )
        await asyncio.gather(
            self.user_operation_handler.gas_manager.verify_preverification_gas_and_verification_gas_limit(
                user_operation,
                self.entrypoint,
            ),
            self.user_operation_handler.gas_manager.verify_gas_fees_and_get_price(
                user_operation, self.enforce_gas_price_tolerance
            )
        )

        (
            sender_stake_info,
            factory_stake_info,
            paymaster_stake_info,
            aggregator_stake_info,
            user_operation_hash,
            associated_addresses,
            storage_map
        ) = await self.validation_manager.validate_user_operation(
            user_operation,
            self.entrypoint,
            latest_block_number,
            latest_block_timestamp,
            self.MIN_STAKE,
            self.MIN_UNSTAKE_DELAY
        )
        if associated_addresses is None:
            user_operation.code_hash = None
        else:
            user_operation.code_hash = (
                await self.validation_manager.tracer_manager.get_addresses_code_hash(
                    associated_addresses
                )
            )

        self._verify_max_allowed_user_operations(
            user_operation.sender_address,
            user_operation.factory_address_lowercase,
            user_operation.paymaster_address_lowercase,
            sender_stake_info,
            factory_stake_info,
            paymaster_stake_info,
        )

        await self.validate_paymaster_deposit(
            user_operation, latest_block_number)

        self.validate_multiple_roles_violation(user_operation)

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
            latest_block_hash,
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
        valid_mempools_ids = [self.canonical_mempool_id]

        user_operation.valid_mempools_ids = valid_mempools_ids
        user_operation.user_operation_hash = user_operation_hash

        return user_operation_hash, latest_block_number, valid_mempools_ids

    async def add_user_operation_p2p(
        self,
        user_operation: UserOperation,
        peer_id: str,
        verified_at_block_hash: str
    ) -> None | str:
        try:
            self._verify_banned_and_throttled_entities(
                user_operation.sender_address,
                user_operation.factory_address_lowercase,
                user_operation.paymaster_address_lowercase,
            )
            await self.user_operation_handler.gas_manager.verify_preverification_gas_and_verification_gas_limit(
                user_operation,
                self.entrypoint,
            )
            gas_price_hex = await self.user_operation_handler.gas_manager.verify_gas_fees_and_get_price(
                user_operation, self.enforce_gas_price_tolerance
            )
        except ValidationException:
            return "No"

        latest_block_number, _, _, latest_block_timestamp, latest_block_hash = (
            await get_latest_block_info(self.ethereum_node_url)
        )

        try:
            (
                sender_stake_info,
                factory_stake_info,
                paymaster_stake_info,
                aggregator_stake_info,
                user_operation_hash,
                associated_addresses,
                storage_map
            ) = await self.validation_manager.validate_user_operation(
                user_operation,
                self.entrypoint,
                latest_block_number,
                latest_block_timestamp,
                self.MIN_STAKE,
                self.MIN_UNSTAKE_DELAY
            )
            if associated_addresses is None:
                user_operation.code_hash = None
            else:
                user_operation.code_hash = (
                    await self.validation_manager.tracer_manager.get_addresses_code_hash(
                        associated_addresses
                    )
                )

            if self.is_hash_seen(user_operation_hash):
                return "No"
            else:
                self.seen_user_operation_hashs.add(user_operation_hash)

        except ValidationException:
            try:
                await self.validation_manager.validate_user_operation(
                    user_operation,
                    self.entrypoint,
                    verified_at_block_hash,
                    latest_block_timestamp,
                    self.MIN_STAKE,
                    self.MIN_UNSTAKE_DELAY
                )
            except ValidationException:
                self.reputation_manager.ban_entity(peer_id)

            return "No"

        self._verify_max_allowed_user_operations(
            user_operation.sender_address,
            user_operation.factory_address_lowercase,
            user_operation.paymaster_address_lowercase,
            sender_stake_info,
            factory_stake_info,
            paymaster_stake_info,
        )

        await self.validate_paymaster_deposit(
            user_operation, latest_block_number)

        self.validate_multiple_roles_violation(user_operation)

        new_sender = None
        new_sender_address = user_operation.sender_address

        if new_sender_address not in self.senders_to_senders_mempools:
            self.senders_to_senders_mempools[new_sender_address] = SenderMempool(
                new_sender_address, dict()
            )

        new_sender = self.senders_to_senders_mempools[new_sender_address]

        await new_sender.add_user_operation(
            user_operation, user_operation_hash, latest_block_hash
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

        valid_mempools_ids = [self.canonical_mempool_id]

        user_operation.valid_mempools_ids = valid_mempools_ids
        user_operation.user_operation_hash = user_operation_hash

        return "Ok"

    def is_hash_seen(self, user_operation_hash: str) -> bool:
        return user_operation_hash in self.seen_user_operation_hashs

    async def get_user_operations_to_bundle(
        self, is_conditional_rpc: bool
    ) -> list[UserOperation]:
        bundle = []
        senders_lowercase = [x.lower() for x in self.senders_to_senders_mempools.keys()]
        for sender_address in list(self.senders_to_senders_mempools):
            sender_mempool = self.senders_to_senders_mempools[sender_address]
            if len(sender_mempool.user_operation_hashs_to_verified_user_operation) > 0:
                user_operation_hash = next(
                    iter(sender_mempool.user_operation_hashs_to_verified_user_operation)
                )
                user_operation = sender_mempool.user_operation_hashs_to_verified_user_operation[
                    user_operation_hash].user_operation

                latest_block_number, _, _, latest_block_timestamp, _ = (
                    await get_latest_block_info(self.ethereum_node_url)
                )

                try:
                    (
                        _, _, _, _, _,
                        associated_addresses,
                        storage_map
                    ) = await self.validation_manager.validate_user_operation(
                        user_operation,
                        self.entrypoint,
                        latest_block_number,
                        latest_block_timestamp,
                        self.MIN_STAKE,
                        self.MIN_UNSTAKE_DELAY
                    )
                    if storage_map is not None:
                        to_bundle = True
                        for storage_address_lowercase in storage_map.keys():
                            if (
                                storage_address_lowercase != sender_address.lower() and
                                storage_address_lowercase in senders_lowercase
                            ):
                                to_bundle = False
                                break
                        if is_conditional_rpc:
                            user_operation.storage_map = storage_map

                        if not to_bundle:
                            continue
                    if associated_addresses is None:
                        new_code_hash = None
                    else:
                        new_code_hash = (
                            await self.validation_manager.tracer_manager.get_addresses_code_hash(
                                associated_addresses
                            )
                        )

                    if new_code_hash != user_operation.code_hash:
                        del sender_mempool.user_operation_hashs_to_verified_user_operation[
                            user_operation_hash]
                        continue

                except ValidationException as err:
                    if (
                        user_operation.paymaster_address_lowercase is not None and
                        "AA21" not in err.message  # not the paymaster
                    ):
                        # EREP-015: special case: if it is account/factory failure
                        # then decreases paymaster's opsSeen
                        self.reputation_manager.update_seen_status(
                            user_operation.paymaster_address_lowercase, -1)

                    del sender_mempool.user_operation_hashs_to_verified_user_operation[
                        user_operation_hash]
                    continue

                bundle.append(user_operation)
                del sender_mempool.user_operation_hashs_to_verified_user_operation[
                    user_operation_hash]
                if len(sender_mempool.user_operation_hashs_to_verified_user_operation) == 0:
                    del self.senders_to_senders_mempools[sender_mempool.address]
        return bundle

    def get_user_operations_hashes_with_mempool_id(
        self, mempool_id: MempoolId, offset: int
    ) -> tuple[List[str], int]:
        user_operations_hashs = []
        for sender_address in list(self.senders_to_senders_mempools):
            sender = self.senders_to_senders_mempools[sender_address]
            if len(sender.user_operation_hashs_to_verified_user_operation) > 0:
                for (
                    user_operation_hash,
                    verified_user_operation,
                ) in sender.user_operation_hashs_to_verified_user_operation.items():
                    if (
                        mempool_id
                        in verified_user_operation.user_operation.valid_mempools_ids
                    ):
                        user_operations_hashs.append(
                            list(bytes.fromhex(user_operation_hash[2:]))
                        )

        start = offset * self.MAX_OPS_PER_REQUEST
        end = start + self.MAX_OPS_PER_REQUEST

        user_operations_hashs_len = len(user_operations_hashs)
        if user_operations_hashs_len == 0 or start >= user_operations_hashs_len:
            return [], 0

        next_cursor = 0
        if end > user_operations_hashs_len:
            end = user_operations_hashs_len
        else:
            next_cursor = math.floor(
                (user_operations_hashs_len - end) / self.MAX_OPS_PER_REQUEST
            )

        return user_operations_hashs[start:end], next_cursor

    def get_user_operations_by_hashes(
        self, user_operations_hashs: List[str]
    ) -> tuple[List[UserOperation], List[str]]:
        verified_user_operations_json = []
        found_user_operations_hashs = []
        for sender_address in list(self.senders_to_senders_mempools):
            sender = self.senders_to_senders_mempools[sender_address]
            if len(sender.user_operation_hashs_to_verified_user_operation) > 0:
                for (
                    user_operation_hash,
                    verified_user_operation,
                ) in sender.user_operation_hashs_to_verified_user_operation.items():
                    if user_operation_hash in user_operations_hashs:
                        verified_user_operations_json.append(
                            {
                                "user_operation": verified_user_operation.user_operation.get_user_operation_json(),
                                "verified_at_block_hash": verified_user_operation.verified_at_block_hash,
                                "entry_point": self.entrypoint,
                            }
                        )
                        found_user_operations_hashs.append(user_operation_hash)

        remaining_user_operation_hashes = set(user_operations_hashs) - set(
            found_user_operations_hashs
        )
        return verified_user_operations_json, list(remaining_user_operation_hashes)

    def get_all_user_operations(self) -> list[UserOperation]:
        user_operations = [
            verified_user_operation.user_operation
            for sender in self.senders_to_senders_mempools.values()
            for verified_user_operation in sender.user_operation_hashs_to_verified_user_operation.values()
        ]
        return user_operations

    def update_all_seen_status(
        self, sender_address: str,
        factory_address: str | None,
        paymaster_address: str | None
    ) -> None:
        self.reputation_manager.update_seen_status(sender_address)

        if factory_address is not None:
            self.reputation_manager.update_seen_status(factory_address)

        if paymaster_address is not None:
            self.reputation_manager.update_seen_status(paymaster_address)

    def queue_verified_useroperation_to_gossip_publish(
        self,
        user_operation_json,
        verified_at_block_hash: str,
        valid_mempools: List[MempoolId],
    ) -> None:
        verified_useroperation = dict()
        verified_useroperation["entry_point_contract"] = encode_address(
                self.entrypoint)
        verified_useroperation["verified_at_block_hash"] = encode_uint256(
            int(verified_at_block_hash, 16)
        )
        verified_useroperation["user_operation"] = user_operation_json

        self.verified_useroperations_standard_mempool_gossip_queue.append(
            verified_useroperation
        )

    def create_p2p_gossip_requests(self) -> List[RequestEvent]:
        requestEvents = list()
        for (
            verified_useroperation
        ) in self.verified_useroperations_standard_mempool_gossip_queue:
            gossib_to_broadcast = dict()
            gossib_to_broadcast["topics"] = [self.canonical_mempool_id]
            gossib_to_broadcast["verified_useroperation"] = verified_useroperation

            requestEvents.append(gossib_to_broadcast)
        self.verified_useroperations_standard_mempool_gossip_queue.clear()
        return requestEvents

    def _verify_max_allowed_user_operations(
        self,
        sender_address: Address,
        factory_address: Address | None,
        paymaster_address: Address | None,
        sender_stake_info: StakeInfo,
        factory_stake_info: StakeInfo | None,
        paymaster_stake_info: StakeInfo | None,
    ) -> None:
        self._verify_max_allowed_user_operations_per_entity(
            sender_address,
            "sender",
            sender_stake_info.stake,
            sender_stake_info.unstakeDelaySec
        )

        if factory_address is not None:
            assert factory_stake_info is not None
            self._verify_max_allowed_user_operations_per_entity(
                factory_address,
                "factory",
                factory_stake_info.stake,
                factory_stake_info.unstakeDelaySec
            )

        if paymaster_address is not None:
            assert paymaster_stake_info is not None
            self._verify_max_allowed_user_operations_per_entity(
                paymaster_address,
                "paymaster",
                paymaster_stake_info.stake,
                paymaster_stake_info.unstakeDelaySec
            )

    def _verify_max_allowed_user_operations_per_entity(
        self,
        entity: Address,
        entity_title: str,
        stake: int,
        unstake_delay: int
    ) -> None:
        if entity_title == "sender":
            if entity in self.senders_to_senders_mempools:
                sender_mempool = self.senders_to_senders_mempools[entity]
                entity_no_of_ops = len(
                        sender_mempool.user_operation_hashs_to_verified_user_operation)
            else:
                entity_no_of_ops = 0

            MAX_MEMPOOL_USEROPS_PER_SENDER = 4
            max_allowed_user_operations = MAX_MEMPOOL_USEROPS_PER_SENDER
        else:
            if entity in self.entity_to_no_of_ops_in_mempool:
                entity_no_of_ops = self.entity_to_no_of_ops_in_mempool[entity]
            else:
                entity_no_of_ops = 0

            max_allowed_user_operations = self.get_max_allowed_user_operations_for_unstaked_non_senders(
                entity)
        if entity_no_of_ops >= max_allowed_user_operations:
            self.validate_staked_entity_can_include_more_user_operations(
                entity_title,
                entity,
                stake,
                unstake_delay
            )

    def _verify_banned_and_throttled_entities(
        self,
        sender_address: Address,
        factory_address: Address | None,
        paymaster_address: Address | None
    ) -> None:
        self._verify_banned_and_throttled_entity(sender_address, "sender")

        if factory_address is not None:
            self._verify_banned_and_throttled_entity(factory_address, "factory")

        if paymaster_address is not None:
            self._verify_banned_and_throttled_entity(paymaster_address, "paymaster")

    def _verify_banned_and_throttled_entity(self, entity: Address, entity_title: str) -> None:
        if entity_title == "sender":
            if entity in self.senders_to_senders_mempools:
                sender_mempool = self.senders_to_senders_mempools[entity]
                entity_no_of_ops = len(
                        sender_mempool.user_operation_hashs_to_verified_user_operation)
            else:
                entity_no_of_ops = 0
        else:
            if entity in self.entity_to_no_of_ops_in_mempool:
                entity_no_of_ops = self.entity_to_no_of_ops_in_mempool[entity]
            else:
                entity_no_of_ops = 0

        status = self.reputation_manager.get_status(entity)
        if status == ReputationStatus.BANNED:
            raise ValidationException(
                ValidationExceptionCode.Reputation,
                f"user operation was dropped because {entity} " +
                f"is banned {entity_title}"
            )
        THROTTLED_ENTITY_MEMPOOL_COUNT = 4
        if (
            status == ReputationStatus.THROTTLED and
            entity_no_of_ops >= THROTTLED_ENTITY_MEMPOOL_COUNT
        ):
            raise ValidationException(
                ValidationExceptionCode.Reputation,
                f"user operation was dropped because {entity} " +
                f"is throttled {entity_title}"
            )

    def _update_entity_no_of_ops_in_mempool(
            self, entity_address: Address) -> None:
        no_of_ops = 0
        if entity_address in self.entity_to_no_of_ops_in_mempool:
            no_of_ops = self.entity_to_no_of_ops_in_mempool[entity_address]
        self.entity_to_no_of_ops_in_mempool[entity_address] = no_of_ops + 1

    async def validate_paymaster_deposit(
        self,
        user_operation: UserOperation,
        block_number_hex: str,
    ):
        paymaster = user_operation.paymaster_address_lowercase
        if paymaster is None:
            return
        else:
            remaining_deposit = await self.get_paymaster_deposit(
                paymaster, block_number_hex)
            user_op_max_cost = user_operation.get_max_cost()

        remaining_deposit -= user_op_max_cost
        for sender_address in list(self.senders_to_senders_mempools):
            sender = self.senders_to_senders_mempools[sender_address]
            for verified_user_operation in sender.user_operation_hashs_to_verified_user_operation.values():
                user_op_max_cost = verified_user_operation.user_operation.get_max_cost()
                remaining_deposit -= user_op_max_cost
                if remaining_deposit < 0:
                    raise ValidationException(
                        ValidationExceptionCode.PaymasterDepositTooLow,
                        "paymaster deposit too low for all mempool UserOps",
                    )

    async def get_paymaster_deposit(
            self, paymaster: Address, block_number_hex: str) -> int:
        block_number = int(block_number_hex, 16)
        if block_number > self.latest_paymaster_deposits_cache_block:
            self.paymaster_deposits_cache.clear()
            self.latest_paymaster_deposits_cache_block = block_number

        if paymaster in self.paymaster_deposits_cache:  # cached
            return self.paymaster_deposits_cache[paymaster]
        else:
            function_selector = "0x70a08231"  # balanceOf
            params = encode(["address"], [paymaster])

            call_data = function_selector + params.hex()

            params = [
                {
                    "to": self.entrypoint,
                    "data": call_data,
                },
                block_number_hex,
            ]

            result: Any = await send_rpc_request_to_eth_client(
                self.ethereum_node_url, "eth_call", params
            )
            if "result" in result:
                balance = decode(["uint256"], bytes.fromhex(result["result"][2:]))[0]
                self.paymaster_deposits_cache[paymaster] = balance
                return balance
            else:
                logging.critical("balanceOf eth_call failed")
                if "error" in result:
                    error = str(result["error"])
                    raise ValueError(f"balanceOf eth_call failed - {error}")
                else:
                    raise ValueError("balanceOf eth_call failed")

    def get_known_factories_and_paymasters_lowercase(self) -> list[Address]:
        known_entities = []
        for sender_address in list(self.senders_to_senders_mempools):
            sender = self.senders_to_senders_mempools[sender_address]
            for verified_user_operation in sender.user_operation_hashs_to_verified_user_operation.values():
                if verified_user_operation.user_operation.factory_address_lowercase is not None:
                    known_entities.append(
                        verified_user_operation.user_operation.factory_address_lowercase)
                if verified_user_operation.user_operation.paymaster_address_lowercase is not None:
                    known_entities.append(
                        verified_user_operation.user_operation.paymaster_address_lowercase)

        return known_entities

    def validate_multiple_roles_violation(self, user_operation: UserOperation):
        known_factories_and_paymasters = self.get_known_factories_and_paymasters_lowercase()
        sender = user_operation.sender_address.lower()

        if sender in known_factories_and_paymasters:
            raise ValidationException(
                ValidationExceptionCode.OpcodeValidation,
                f"The sender address {sender} is used as a different entity " +
                "in another UserOperation currently in mempool",
            )
        known_senders_lowercase = [
            sender.lower() for sender in self.senders_to_senders_mempools.keys()]

        factory = user_operation.factory_address_lowercase
        if user_operation.factory_address_lowercase in known_senders_lowercase:
            raise ValidationException(
                ValidationExceptionCode.OpcodeValidation,
                f"A Factory at {factory} in this UserOperation is used " +
                "as a sender entity in another UserOperation currently in mempool."
            )

        paymaster = user_operation.paymaster_address_lowercase
        if user_operation.paymaster_address_lowercase in known_senders_lowercase:
            raise ValidationException(
                ValidationExceptionCode.OpcodeValidation,
                f"A Paymaster at {paymaster} in this UserOperation is used " +
                "as a sender entity in another UserOperation currently in mempool."
            )

    def is_staked(self, stake: int, unstake_delay: int) -> bool:
        return stake >= self.MIN_STAKE and unstake_delay >= self.MIN_UNSTAKE_DELAY

    def validate_staked_entity_can_include_more_user_operations(
        self,
        entity_title: str,
        entity: Address,
        stake: int,
        unstake_delay: int
    ):
        if self.reputation_manager.is_whitelisted(entity):
            return

        if self.reputation_manager.get_status(entity) == ReputationStatus.BANNED:
            raise ValidationException(
                ValidationExceptionCode.Reputation,
                f"{entity_title} {entity} is banned."
            )

        if stake == 0:
            raise ValidationException(
                ValidationExceptionCode.InsufficientStake,
                f"{entity_title} {entity} is unstaked"
            )

        if stake < self.MIN_STAKE:
            raise ValidationException(
                ValidationExceptionCode.InsufficientStake,
                f"{entity_title} {entity} stake {stake} " +
                f"is lower than minimum {self.MIN_STAKE}"
            )

        if unstake_delay < self.MIN_UNSTAKE_DELAY:
            raise ValidationException(
                ValidationExceptionCode.InsufficientStake,
                f"{entity_title} {entity} unstake delay {unstake_delay} " +
                f"is lower than minimum {self.MIN_UNSTAKE_DELAY}"
            )

    def get_max_allowed_user_operations_for_unstaked_non_senders(
            self, entity: Address) -> int:
        SAME_UNSTAKED_ENTITY_MEMPOOL_COUNT = 10

        entity_reputation = self.reputation_manager.get_reputation_entry(
            entity)
        if entity_reputation is None:
            return SAME_UNSTAKED_ENTITY_MEMPOOL_COUNT
        else:
            if entity_reputation.ops_seen < 1:
                inclusion_modifier = 0
            else:
                INCLUSION_RATE_FACTOR = 10
                inclusion_rate = entity_reputation.ops_included / entity_reputation.ops_seen
                inclusion_modifier = math.floor(INCLUSION_RATE_FACTOR * inclusion_rate)
            return (
                SAME_UNSTAKED_ENTITY_MEMPOOL_COUNT +
                inclusion_modifier +
                min(entity_reputation.ops_included, 10_000)
            )


@cache
def encode_uint256(x):
    return encode(["uint256"], [x])


@cache
def encode_address(address):
    return encode(["address"], [address])[12:]
