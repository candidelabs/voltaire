from dataclasses import dataclass, field
from user_operation.user_operation import UserOperation


@dataclass
class Mempool:
    entrypoint: str
    user_operations: list = field(default_factory=list)

    def clear_user_operations(self):
        self.user_operations.clear()
