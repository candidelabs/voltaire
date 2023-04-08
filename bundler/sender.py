from dataclasses import dataclass, field

from eth_abi import encode, decode

from user_operation.user_operation import UserOperation
from bundler.exceptions import ValidationException, ValidationExceptionCode
from utils.eth_client_utils import send_rpc_request_to_eth_client
from user_operation.models import DepositInfo

MAX_MEMPOOL_USEROPS_PER_SENDER = 4
MIN_PRICE_BUMP = 10


@dataclass
class Sender:
    address: str
    user_operations: list = field(default_factory=list[UserOperation])

    async def add_user_operation(
        self,
        new_user_operation: UserOperation,
        entrypoint_address: str,
        bundler_address: str,
        geth_rpc_url: str,
    ):
        sender_operations_num = len(self.user_operations)
        is_staked = await self._check_if_stacked(
            entrypoint_address, bundler_address, geth_rpc_url
        )

        if sender_operations_num == 0:
            self.user_operations.append(new_user_operation)
        elif (
            is_staked
            or sender_operations_num <= MAX_MEMPOOL_USEROPS_PER_SENDER
        ):
            existing_user_operation_with_same_nonce = (
                self._get_user_operation_with_same_nonce(
                    new_user_operation.nonce
                )
            )
            if existing_user_operation_with_same_nonce is not None:
                self.replace_user_operation(
                    new_user_operation, existing_user_operation_with_same_nonce
                )
            elif (
                is_staked
                or sender_operations_num < MAX_MEMPOOL_USEROPS_PER_SENDER
            ):
                self.user_operations.append(new_user_operation)
            else:
                raise ValidationException(
                    ValidationExceptionCode.InvalidFields,
                    "invalid UserOperation struct/fields",
                    "",
                )

    def replace_user_operation(
        self,
        new_user_operation: UserOperation,
        existing_user_operation: UserOperation,
    ) -> None:
        if self._check_if_new_operation_can_replace_existing_operation(
            new_user_operation, existing_user_operation
        ):
            index = self.user_operations.index(existing_user_operation)
            self.user_operations[index] = new_user_operation
        else:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "invalid UserOperation struct/fields",
                "",
            )

    def _check_if_new_operation_can_replace_existing_operation(
        self, new_operation: UserOperation, existing_operation: UserOperation
    ) -> bool:
        if new_operation.nonce != existing_operation.nonce:
            return False

        min_priority_fee_per_gas_to_replace = (
            Sender._calculate_min_fee_to_replace(
                existing_operation.max_priority_fee_per_gas
            )
        )
        min_fee_per_gas_to_replace = Sender._calculate_min_fee_to_replace(
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
    def _calculate_min_fee_to_replace(fee) -> int:
        return round(fee * (100 + MIN_PRICE_BUMP) / 100)

    def _get_user_operation_with_same_nonce(
        self, nonce
    ) -> UserOperation | None:
        for user_operation in self.user_operations:
            if user_operation.nonce == nonce:
                return user_operation
        return None

    async def _check_if_stacked(
        self, entrypoint_address: str, bundler_address: str, geth_rpc_url: str
    ) -> bool:
        function_selector = "0x5287ce12"  # getDepositInfo
        params = encode(["address"], [self.address])

        call_data = function_selector + params.hex()

        params = [
            {
                "from": bundler_address,
                "to": entrypoint_address,
                "data": call_data,
            },
            "latest",
        ]

        response = await send_rpc_request_to_eth_client(
            geth_rpc_url, "eth_call", params
        )
        result = response["result"]
        deposit_info: DepositInfo = Sender._decode_deposit_info(result[2:])

        return deposit_info.staked

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
