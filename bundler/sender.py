from dataclasses import dataclass, field
from web3 import Web3
from eth_abi import decode

from user_operation.user_operation import UserOperation
from bundler.exceptions import BundlerException, BundlerExceptionCode
from utils.eth_client_utils import send_rpc_request_to_eth_client
from user_operation.models import DepositInfo

ALLOWED_OPS_PER_UNSTAKED_SENDER = 4


@dataclass
class Sender:
    address: str
    user_operations: list = field(default_factory=list[UserOperation])

    async def add_user_operation(
        self,
        new_user_operation: UserOperation,
        entrypoint_address,
        entrypoint_abi,
        bundler_address,
        geth_rpc_url,
    ):
        sender_operations_num = len(self.user_operations)
        is_staked = await self._check_if_stacked(
            entrypoint_address, entrypoint_abi, bundler_address, geth_rpc_url
        )

        if sender_operations_num == 0:
            self.user_operations.append(new_user_operation)
        elif (
            is_staked
            or sender_operations_num <= ALLOWED_OPS_PER_UNSTAKED_SENDER
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
                or sender_operations_num < ALLOWED_OPS_PER_UNSTAKED_SENDER
            ):
                self.user_operations.append(new_user_operation)
            else:
                raise BundlerException(
                    BundlerExceptionCode.INVALID_FIELDS,
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
                BundlerExceptionCode.INVALID_FIELDS,
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

    async def _check_if_stacked(
        self, entrypoint_address, entrypoint_abi, bundler_address, geth_rpc_url
    ):
        w3_provider = Web3()
        entrypoint_contract = w3_provider.eth.contract(
            address=entrypoint_address, abi=entrypoint_abi
        )

        call_data = entrypoint_contract.encodeABI(
            "getDepositInfo", [self.address]
        )

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
