import logging

from eth_utils import to_checksum_address
from eth_abi import decode
from voltaire_bundler.bundle.exceptions import UserOpFoundException
from voltaire_bundler.user_operation.user_operation_handler import UserOperationHandler, del_user_operation_logs_cache_entry, get_transaction_by_hash
from ..gas.gas_manager_v6 import GasManagerV6


class UserOperationHandlerV6(UserOperationHandler):

    def __init__(
        self,
        chain_id: int,
        ethereum_node_urls,
        bundler_address,
        is_legacy_mode,
        ethereum_node_eth_get_logs_urls,
        max_fee_per_gas_percentage_multiplier: int,
        max_priority_fee_per_gas_percentage_multiplier: int,
        max_verification_gas: int,
        max_call_data_gas: int,
        logs_incremental_range: int,
        logs_number_of_ranges: int,
    ):
        self.ethereum_node_urls = ethereum_node_urls
        self.bundler_address = bundler_address
        self.is_legacy_mode = is_legacy_mode
        self.ethereum_node_eth_get_logs_urls = ethereum_node_eth_get_logs_urls
        self.gas_manager = GasManagerV6(
            self.ethereum_node_urls,
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
        transaction = await get_transaction_by_hash(
            self.ethereum_node_urls,
            transaction_hash
        )
        if transaction is None:
            logging.error(
                f"Can't find transaction by hash:{transaction_hash} "
                f"for user operation hash: {user_operation_hash}. Retrying."
            )
            del_user_operation_logs_cache_entry(user_operation_hash, entrypoint)
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
            transaction = await get_transaction_by_hash(
                self.ethereum_node_urls,
                transaction_hash
            )
            if transaction is None:
                logging.error(
                    f"Can't find transaction by hash:{transaction_hash} "
                    f"for user operation hash: {user_operation_hash} "
                    "for the second time."
                )
                return None

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

        logging.error(
            f"Can't find user operation hash: {user_operation_hash} "
            f"with sender: {sender} and nonce: {nonce} in list of user ops:"
            f"{user_operations_lists} returned from transaction hash: {transaction_hash}"
            " .This shouldn't happen."
        )
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
            user_operation_by_hash_json = self.get_user_operation_by_hash_from_local_mempool(
                user_operation_hash,
                entrypoint,
                senders_mempools
            )
            if user_operation_by_hash_json is None:
                return None
            else:
                raise UserOpFoundException(user_operation_by_hash_json)
        (
            user_operation_list,
            block_number,
            block_hash,
            transaction_hash,
        ) = user_operation_by_hash

        user_operation_json = {
            "sender": to_checksum_address(user_operation_list[0]),
            "nonce": hex(user_operation_list[1]),
            "initCode": "0x" + user_operation_list[2].hex(),
            "callData": "0x" + user_operation_list[3].hex(),
            "callGasLimit": hex(user_operation_list[4]),
            "verificationGasLimit": hex(user_operation_list[5]),
            "preVerificationGas": hex(user_operation_list[6]),
            "maxFeePerGas": hex(user_operation_list[7]),
            "maxPriorityFeePerGas": hex(user_operation_list[8]),
            "paymasterAndData": "0x" + user_operation_list[9].hex(),
            "signature": "0x" + user_operation_list[10].hex(),
        }
        user_operation_by_hash_json = {
            "userOperation": user_operation_json,
            "entryPoint": entrypoint,
            "blockNumber": block_number,
            "blockHash": block_hash,
            "transactionHash": transaction_hash,
        }
        raise UserOpFoundException(user_operation_by_hash_json)


def decode_handle_op_input(handle_op_input) -> list[list]:
    INPUT_ABI = [
        "(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)[]",
        "address",
    ]
    input_result = decode(INPUT_ABI, bytes.fromhex(handle_op_input[10:]))
    user_operations_lists = input_result[0]
    return user_operations_lists
