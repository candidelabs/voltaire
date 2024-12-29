from functools import reduce

from eth_utils import to_checksum_address

from eth_abi import decode
from voltaire_bundler.typing import Address
from voltaire_bundler.user_operation.user_operation_handler import UserOperationHandler
from voltaire_bundler.mempool.sender_mempool import \
    VerifiedUserOperation
from ...gas.v7.gas_manager_v7 import GasManagerV7


class UserOperationHandlerV7(UserOperationHandler):

    def __init__(
        self,
        chain_id: int,
        ethereum_node_url: str,
        bundler_address: Address,
        is_legacy_mode: bool,
        ethereum_node_eth_get_logs_url: str,
        max_fee_per_gas_percentage_multiplier: int,
        max_priority_fee_per_gas_percentage_multiplier: int,
        max_verification_gas: int,
        max_call_data_gas: int,
        logs_incremental_range: int,
        logs_number_of_ranges: int,
    ):
        self.ethereum_node_url = ethereum_node_url
        self.bundler_address = bundler_address
        self.is_legacy_mode = is_legacy_mode
        self.ethereum_node_eth_get_logs_url = ethereum_node_eth_get_logs_url

        self.gas_manager = GasManagerV7(
            self.ethereum_node_url,
            chain_id,
            is_legacy_mode,
            max_fee_per_gas_percentage_multiplier,
            max_priority_fee_per_gas_percentage_multiplier,
            max_verification_gas,
            max_call_data_gas,
        )
        self.logs_incremental_range = logs_incremental_range
        self.logs_number_of_ranges = logs_number_of_ranges

    async def get_user_operation_by_hash(
        self, user_operation_hash: str, entrypoint: str
    ) -> tuple | None:
        event_log_info = await self.get_user_operation_event_log_info(
            user_operation_hash, entrypoint
        )
        if event_log_info is None:
            return None

        (
            log_object,
            userOpHash,
            sender,
            paymaster,
            nonce,
            success,
            actualGasCost,
            actualGasUsed,
            logs,
        ) = event_log_info
        assert userOpHash == user_operation_hash

        transaction_hash = log_object.transactionHash
        transaction = await self.get_transaction_by_hash(transaction_hash)

        block_hash = transaction["blockHash"]
        block_number = transaction["blockNumber"]
        transaction_input = transaction["input"]

        user_operations_lists = decode_handle_op_input(transaction_input)
        for user_operation_list in user_operations_lists:
            if (
                user_operation_list[0] == sender and
                user_operation_list[1] == nonce
            ):
                return user_operation_list, block_number, block_hash, transaction_hash

        assert False  # should not be reached

    async def get_user_operation_by_hash_rpc(
        self,
        user_operation_hash: str,
        entrypoint: str,
        senders_mempools,
    ) -> dict | None:
        user_operation_by_hash = await self.get_user_operation_by_hash(
            user_operation_hash, entrypoint
        )
        if user_operation_by_hash is None:
            user_operation_hashs_to_verified_user_operation: dict[str, VerifiedUserOperation] = reduce(
                lambda a, b: a | b,
                (
                    map(
                        lambda sender_mempool: sender_mempool.user_operation_hashs_to_verified_user_operation,
                        senders_mempools,
                    )
                ),
                dict(),
            )
            if user_operation_hash in user_operation_hashs_to_verified_user_operation:
                user_operation_by_hash_json = {
                    "userOperation": user_operation_hashs_to_verified_user_operation[
                        user_operation_hash
                    ].user_operation.get_user_operation_json(),
                    "entryPoint": entrypoint,
                    "blockNumber": None,
                    "blockHash": None,
                    "transactionHash": None,
                }
                return user_operation_by_hash_json
            else:
                return None
        (
            user_operation_list,
            block_number,
            block_hash,
            transaction_hash,
        ) = user_operation_by_hash

        user_operation_json = {
            "sender": to_checksum_address(user_operation_list[0]),
            "nonce": hex(user_operation_list[1]),
            "callData": "0x" + user_operation_list[3].hex(),
            "callGasLimit": hex(int(user_operation_list[4][16:].hex(), 16)),
            "verificationGasLimit": hex(int(user_operation_list[4][:16].hex(), 16)),
            "preVerificationGas": hex(user_operation_list[5]),
            "maxFeePerGas": hex(int(user_operation_list[6][16:].hex(), 16)),
            "maxPriorityFeePerGas": hex(int(user_operation_list[6][:16].hex(), 16)),
            "signature": "0x" + user_operation_list[8].hex(),
        }

        if user_operation_list[2] != b'':
            user_operation_json["factory"] = to_checksum_address(
                    user_operation_list[2][:20])
            if len(user_operation_list[2]) > 20:
                user_operation_json["factoryData"] = (
                    "0x" + user_operation_list[2][20:].hex())
            else:
                user_operation_json["factoryData"] = "0x"

        if user_operation_list[7] != b'':
            user_operation_json["paymaster"] = to_checksum_address(
                    user_operation_list[7][:20])
            user_operation_json["paymasterVerificationGasLimit"] = hex(
                    int(user_operation_list[7][20:36].hex(), 16))
            user_operation_json["paymasterPostOpGasLimit"] = hex(
                    int(user_operation_list[7][36:52].hex(), 16))
            user_operation_json["paymasterData"] = (
                "0x" + user_operation_list[7][52:].hex())

        user_operation_by_hash_json = {
            "userOperation": user_operation_json,
            "entryPoint": entrypoint,
            "blockNumber": block_number,
            "blockHash": block_hash,
            "transactionHash": transaction_hash,
        }
        return user_operation_by_hash_json


def decode_handle_op_input(handle_op_input) -> list[list]:
    INPUT_ABI = [
        "(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[]",
        "address",
    ]
    input_result = decode(INPUT_ABI, bytes.fromhex(handle_op_input[10:]))
    user_operations_lists = input_result[0]
    return user_operations_lists
