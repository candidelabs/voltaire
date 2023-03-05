from dataclasses import dataclass, field
from user_operation.user_operation import UserOperation
from .sender import Sender


@dataclass
class Mempool:
    entrypoint: str
    senders: list = field(default_factory=list[Sender])

    def clear_user_operations(self):
        self.senders.clear()

    async def add_user_operation(
        self,
        new_user_operation: UserOperation,
        entrypoint_address,
        entrypoint_abi,
        bundler_address,
        geth_rpc_url,
    ):
        new_sender = None
        new_sender_address = new_user_operation.sender
        for sender in self.senders:
            if sender.address == new_sender_address:
                new_sender = sender
        if new_sender is None:
            new_sender: Sender = Sender(new_sender_address)
            self.senders.append(new_sender)
        await new_sender.add_user_operation(
            new_user_operation,
            entrypoint_address,
            entrypoint_abi,
            bundler_address,
            geth_rpc_url,
        )

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
