from dataclasses import dataclass, field
from user_operation.user_operation import UserOperation
from .sender import Sender
from user_operation.user_operation_handler import UserOperationHandler
from .validation_manager import ValidationManager


@dataclass
class MempoolManager:
    validation_manager: ValidationManager
    user_operation_handler: UserOperationHandler
    geth_rpc_url: str
    bundler_private_key: str
    bundler_address: str
    entrypoint: str
    entrypoint_abi: str
    senders: list = field(default_factory=list[Sender])

    def __init__(
        self,
        validation_manager,
        user_operation_handler,
        geth_rpc_url,
        bundler_private_key,
        bundler_address,
        entrypoint,
        entrypoint_abi,
    ):
        self.validation_manager = validation_manager
        self.user_operation_handler = user_operation_handler
        self.geth_rpc_url = geth_rpc_url
        self.bundler_private_key = bundler_private_key
        self.bundler_address = bundler_address
        self.entrypoint = entrypoint
        self.entrypoint_abi = entrypoint_abi
        self.senders = []

    def clear_user_operations(self):
        self.senders.clear()

    async def add_user_operation(self, user_operation: UserOperation):
        user_operation_hash = (
            await self.user_operation_handler.get_user_operation_hash(
                user_operation
            )
        )

        await self.validation_manager.validate_user_operation(user_operation)

        new_sender = None
        new_sender_address = user_operation.sender

        for sender in self.senders:
            if sender.address == new_sender_address:
                new_sender = sender

        if new_sender is None:
            new_sender: Sender = Sender(new_sender_address)
            self.senders.append(new_sender)

        await new_sender.add_user_operation(
            user_operation,
            self.entrypoint,
            self.entrypoint_abi,
            self.bundler_address,
            self.geth_rpc_url,
        )
        return user_operation_hash

    def get_user_operations_to_bundle(self):
        bundle = []
        for sender in self.senders:
            bundle.append(sender.user_operations.pop(0))
            if len(sender.user_operations) == 0:
                self.senders.remove(sender)
        return bundle

    def get_all_user_operations(self) -> list[UserOperation]:
        user_operations = [
            user_operation
            for sender in self.senders
            for user_operation in sender.user_operations
        ]
        return user_operations
