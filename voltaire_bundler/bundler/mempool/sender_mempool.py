from dataclasses import dataclass, field
from typing import List

from eth_abi import encode, decode

from voltaire_bundler.user_operation.user_operation import UserOperation
from ..exceptions import ValidationException, ValidationExceptionCode
from voltaire_bundler.user_operation.models import DepositInfo
from .mempool_member import MempoolMember, MempoolMemberStatus

MAX_MEMPOOL_USEROPS_PER_SENDER = 4
MIN_PRICE_BUMP = 10


@dataclass
class SenderMempool:
    address: str
    user_operation_hashs_to_mempool_members: dict[str,MempoolMember]

    async def add_user_operation(
        self, new_user_operation: UserOperation, 
        new_user_operation_hash: str, 
        is_sender_staked: bool
    ):
        new_mempool_member = MempoolMember(
            new_user_operation, 
            MempoolMemberStatus.RECEVIED
        )
        sender_operations_num = len(self.user_operation_hashs_to_mempool_members)

        if sender_operations_num == 0:
            self.user_operation_hashs_to_mempool_members[new_user_operation_hash] = new_mempool_member
        elif (
            is_sender_staked
            or sender_operations_num <= MAX_MEMPOOL_USEROPS_PER_SENDER
        ):
            existing_mempool_member_hash_with_same_nonce = (
                self._get_user_operation_hash_with_same_nonce(
                    new_user_operation.nonce
                )
            )
            if existing_mempool_member_hash_with_same_nonce is not None:
                self.replace_user_operation(
                    new_mempool_member,
                    new_user_operation_hash, 
                    existing_mempool_member_hash_with_same_nonce
                )
            elif (
                is_sender_staked
                or sender_operations_num < MAX_MEMPOOL_USEROPS_PER_SENDER
            ):
                self.user_operation_hashs_to_mempool_members[new_user_operation_hash] = new_mempool_member
            else:
                raise ValidationException(
                    ValidationExceptionCode.InvalidFields,
                    "invalid UserOperation struct/fields",
                )

    def replace_user_operation(
        self,
        new_mempool_member: MempoolMember,
        new_user_operation_hash: str,
        existing_mempool_member_hash_with_same_nonce: str,
    ) -> None:
        if self._check_if_new_operation_can_replace_existing_operation(
            new_mempool_member.user_operation, 
            self.user_operation_hashs_to_mempool_members[existing_mempool_member_hash_with_same_nonce].user_operation
        ):
            del self.user_operation_hashs_to_mempool_members[existing_mempool_member_hash_with_same_nonce]
            self.user_operation_hashs_to_mempool_members[new_user_operation_hash] = new_mempool_member
        else:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "invalid UserOperation struct/fields",
            )

    @staticmethod
    def _check_if_new_operation_can_replace_existing_operation(
        new_operation: UserOperation, existing_operation: UserOperation
    ) -> bool:
        if new_operation.nonce != existing_operation.nonce:
            return False

        min_priority_fee_per_gas_to_replace = (
            SenderMempool._calculate_min_fee_to_replace(
                existing_operation.max_priority_fee_per_gas
            )
        )
        min_fee_per_gas_to_replace = (
            SenderMempool._calculate_min_fee_to_replace(
                existing_operation.max_fee_per_gas
            )
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
    def _calculate_min_fee_to_replace(fee) -> int:
        return round(fee * (100 + MIN_PRICE_BUMP) / 100)

    def _get_user_operation_hash_with_same_nonce(
        self, nonce
    ) -> MempoolMember | None:
        for user_operation_hash in self.user_operation_hashs_to_mempool_members:
            if self.user_operation_hashs_to_mempool_members[user_operation_hash].user_operation.nonce == nonce:
                return user_operation_hash
        return None

    @staticmethod
    def _decode_deposit_info(encodedInfo) -> DepositInfo:
        decoded_result = decode(
            ["(uint112,bool,uint112,uint32,uint64)"],
            bytes.fromhex(encodedInfo),
        )

        deposit_info = DepositInfo(
            decoded_result[0][1],
            decoded_result[0][1],
            decoded_result[0][2],
            decoded_result[0][3],
            decoded_result[0][4],
        )
        return deposit_info