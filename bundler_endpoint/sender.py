from dataclasses import dataclass, field
from user_operation.user_operation import UserOperation
from rpc.exceptions import BundlerException, ExceptionCode

ALLOWED_OPS_PER_UNSTAKED_SENDER = 4


@dataclass
class Sender:
    address: str
    user_operations: list = field(default_factory=list[UserOperation])

    def add_user_operation(self, new_user_operation: UserOperation):
        sender_operations_num = len(self.user_operations)

        if sender_operations_num == 0:
            self.user_operations.append(new_user_operation)
        elif sender_operations_num <= ALLOWED_OPS_PER_UNSTAKED_SENDER:
            existing_user_operation_with_same_nonce = (
                self._get_user_operation_with_same_nonce(
                    new_user_operation.nonce
                )
            )
            if existing_user_operation_with_same_nonce is not None:
                self.replace_user_operation(
                    new_user_operation, existing_user_operation_with_same_nonce
                )
            elif sender_operations_num < ALLOWED_OPS_PER_UNSTAKED_SENDER:
                self.user_operations.append(new_user_operation)
            else:
                raise BundlerException(
                    ExceptionCode.INVALID_FIELDS,
                    "invalid UserOperation struct/fields",
                    "",
                )

    def replace_user_operation(
        self, new_user_operation, existing_user_operation
    ):
        if self._check_if_new_operation_can_replace_existing_operation(
            new_user_operation, existing_user_operation
        ):
            index = self.user_operations.index(existing_user_operation)
            self.user_operations[index] = new_user_operation
        else:
            raise BundlerException(
                ExceptionCode.INVALID_FIELDS,
                "invalid UserOperation struct/fields",
                "",
            )

    def _check_if_new_operation_can_replace_existing_operation(
        self, new_operation: UserOperation, existing_operation: UserOperation
    ):
        if new_operation.nonce != existing_operation.nonce:
            return False
        diff_max_priority_fee_per_gas = (
            new_operation.max_priority_fee_per_gas
            - existing_operation.max_priority_fee_per_gas
        )

        if diff_max_priority_fee_per_gas > 0:
            return True
        else:
            return False

    def _get_user_operation_with_same_nonce(self, nonce):
        for user_operation in self.user_operations:
            if user_operation.nonce == nonce:
                return user_operation
        return None
