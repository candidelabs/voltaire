from dataclasses import dataclass
import asyncio
from user_operation.user_operation import UserOperation
from .sender import Sender
from user_operation.user_operation_handler import UserOperationHandler
from .validation_manager import ValidationManager
from .reputation_manager import ReputationManager, ReputationStatus
from bundler.exceptions import ValidationException, ValidationExceptionCode


@dataclass
class MempoolManager:
    validation_manager: ValidationManager
    user_operation_handler: UserOperationHandler
    reputation_manager: ReputationManager
    geth_rpc_url: str
    bundler_private_key: str
    bundler_address: str
    entrypoint: str
    senders: dict[str, Sender]
    entity_no_of_ops_in_mempool: dict[str, int]  # factory and paymaster

    def __init__(
        self,
        validation_manager: ValidationManager,
        user_operation_handler: UserOperationHandler,
        reputation_manager: ReputationManager,
        geth_rpc_url: str,
        bundler_private_key: str,
        bundler_address: str,
        entrypoint: str,
    ):
        self.validation_manager = validation_manager
        self.user_operation_handler = user_operation_handler
        self.reputation_manager = reputation_manager
        self.geth_rpc_url = geth_rpc_url
        self.bundler_private_key = bundler_private_key
        self.bundler_address = bundler_address
        self.entrypoint = entrypoint
        self.senders = {}
        self.entity_no_of_ops_in_mempool = {}

    def clear_user_operations(self) -> None:
        self.senders.clear()

    async def add_user_operation(self, user_operation: UserOperation, is_unsafe: bool) -> str:
        self._verify_entities_reputation(
            user_operation.sender,
            user_operation.factory_address,
            user_operation.factory_address,
        )

        user_operation_hash = (
            await self.user_operation_handler.get_user_operation_hash(
                user_operation
            )
        )

        if not is_unsafe:
            (
                return_info,
                sender_stake_info,
                factory_stake_info,
                paymaster_stake_info,
            ) = await self.validation_manager.simulate_validation_and_decode_result(
                user_operation
            )

            await self.validation_manager.verify_gas_and_return_info(
                user_operation, return_info
            )

            await self.validation_manager.validate_user_operation(
                user_operation,
                sender_stake_info,
                factory_stake_info,
                paymaster_stake_info,
            )

        new_sender = None
        new_sender_address = user_operation.sender

        if new_sender_address not in self.senders:
            self.senders[new_sender_address] = Sender(new_sender_address)

        new_sender = self.senders[new_sender_address]

        await new_sender.add_user_operation(
            user_operation,
            self.entrypoint,
            self.bundler_address,
            self.geth_rpc_url,
        )
        self.update_all_seen_status(
            user_operation.sender,
            user_operation.factory_address,
            user_operation.paymaster_address,
        )

        if user_operation.factory_address is not None:
            self._update_entity_no_of_ops_in_mempool(
                user_operation.factory_address
            )

        if user_operation.paymaster_address is not None:
            self._update_entity_no_of_ops_in_mempool(
                user_operation.paymaster_address
            )

        return user_operation_hash

    async def get_user_operations_to_bundle(self, is_unsafe: bool) -> list[UserOperation]:
        bundle = []
        validation_operations = []
        for sender_address in list(self.senders):
            sender = self.senders[sender_address]
            if len(sender.user_operations) > 0:
                user_operation = sender.user_operations.pop(0)
                if not is_unsafe:
                    (
                        _,
                        sender_stake_info,
                        factory_stake_info,
                        paymaster_stake_info,
                    ) = await self.validation_manager.simulate_validation_and_decode_result(
                        user_operation
                    )

                    validation_operations.append(
                        self.validation_manager.validate_user_operation(
                            user_operation,
                            sender_stake_info,
                            factory_stake_info,
                            paymaster_stake_info,
                        )
                    )
                    bundle.append(user_operation)
                else:
                    bundle.append(user_operation)
                if len(sender.user_operations) == 0:
                    del self.senders[sender.address]

        await asyncio.gather(*validation_operations)

        return bundle

    def get_all_user_operations(self) -> list[UserOperation]:
        user_operations = [
            user_operation
            for sender in self.senders.values()
            for user_operation in sender.user_operations
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

    def _verify_entities_reputation(
        self, sender_address: str, factory_address: str, paymaster_address: str
    ) -> None:
        sender_no_of_ops = 0
        if sender_address in self.senders:
            sender_no_of_ops = len(
                self.senders[sender_address].user_operations
            )
        self._verify_entity_reputation(
            sender_address, "sender", sender_no_of_ops
        )

        if factory_address is not None:
            factory_no_of_ops = 0
            if factory_address in self.entity_no_of_ops_in_mempool:
                factory_no_of_ops = self.entity_no_of_ops_in_mempool[
                    factory_address
                ]
            self._verify_entity_reputation(
                factory_address,
                "factory",
                factory_no_of_ops,
            )

        if paymaster_address is not None:
            paymaster_no_of_ops = 0
            if paymaster_address in self.entity_no_of_ops_in_mempool:
                paymaster_no_of_ops = self.entity_no_of_ops_in_mempool[
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
        if entity_address not in self.entity_no_of_ops_in_mempool:
            self.entity_no_of_ops_in_mempool[entity_address] = 0

        entity_no_of_ops = self.entity_no_of_ops_in_mempool[entity_address]
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
                "",
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
                "",
            )

    def _update_entity_no_of_ops_in_mempool(self, entity_address: str) -> None:
        no_of_ops = 0
        if entity_address in self.entity_no_of_ops_in_mempool:
            no_of_ops = self.entity_no_of_ops_in_mempool[entity_address]
        self.entity_no_of_ops_in_mempool[entity_address] = no_of_ops + 1
