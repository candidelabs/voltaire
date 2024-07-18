from dataclasses import dataclass

from voltaire_bundler.typing import Address
from voltaire_bundler.user_operation.user_operation import UserOperation

from voltaire_bundler.bundle.exceptions import \
    ValidationException, ValidationExceptionCode

MIN_PRICE_BUMP = 10


@dataclass
class VerifiedUserOperation:
    user_operation: UserOperation
    verified_at_block_hash: str


@dataclass
class SenderMempool:
    address: Address
    user_operation_hashs_to_verified_user_operation: dict[str, VerifiedUserOperation]

    async def add_user_operation(
        self,
        new_user_operation: UserOperation,
        new_user_operation_hash: str,
        verified_at_block_hash: str,
    ):
        existing_user_operation_hash_with_same_nonce = (
            self._get_user_operation_hash_with_same_nonce(
                new_user_operation.nonce)
        )

        if existing_user_operation_hash_with_same_nonce is not None:
            self.try_replace_user_operation(
                new_user_operation,
                new_user_operation_hash,
                verified_at_block_hash,
                existing_user_operation_hash_with_same_nonce,
            )
        else:
            self.user_operation_hashs_to_verified_user_operation[
                new_user_operation_hash
            ] = VerifiedUserOperation(
                    new_user_operation, verified_at_block_hash)

    def try_replace_user_operation(
        self,
        new_user_operation: UserOperation,
        new_user_operation_hash: str,
        verified_at_block_hash: str,
        existing_user_operation_hash_with_same_nonce: str,
    ) -> None:
        if self._check_if_new_operation_can_replace_existing_operation(
            new_user_operation,
            self.user_operation_hashs_to_verified_user_operation[
                existing_user_operation_hash_with_same_nonce
            ].user_operation,
        ):
            del self.user_operation_hashs_to_verified_user_operation[
                existing_user_operation_hash_with_same_nonce
            ]
            self.user_operation_hashs_to_verified_user_operation[
                new_user_operation_hash
            ] = VerifiedUserOperation(
                    new_user_operation, verified_at_block_hash)
        else:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "invalid UserOperation struct/fields",
            )

    @staticmethod
    def _check_if_new_operation_can_replace_existing_operation(
        new_operation: UserOperation,
        existing_operation: UserOperation,
    ) -> bool:
        if new_operation.nonce != existing_operation.nonce:
            return False

        min_priority_fee_per_gas_to_replace = (
            SenderMempool._calculate_min_fee_to_replace(
                existing_operation.max_priority_fee_per_gas
            )
        )
        min_fee_per_gas_to_replace = SenderMempool._calculate_min_fee_to_replace(
            existing_operation.max_fee_per_gas
        )

        if (
            new_operation.max_priority_fee_per_gas
            >= min_priority_fee_per_gas_to_replace
            and new_operation.max_fee_per_gas >= min_fee_per_gas_to_replace
        ):
            return True
        else:
            return False

    @staticmethod
    def _calculate_min_fee_to_replace(fee: int) -> int:
        return round(fee * (100 + MIN_PRICE_BUMP) / 100)

    def _get_user_operation_hash_with_same_nonce(self, nonce: int) -> str | None:
        for user_operation_hash in self.user_operation_hashs_to_verified_user_operation:
            if (
                self.user_operation_hashs_to_verified_user_operation[
                    user_operation_hash
                ].user_operation.nonce
                == nonce
            ):
                return user_operation_hash
        return None
