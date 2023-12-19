import asyncio
from functools import reduce
import math

from eth_utils import to_checksum_address, keccak
from eth_abi import encode, decode

from .user_operation import UserOperation
from voltaire_bundler.bundler.exceptions import (
    ValidationException,
    ValidationExceptionCode,
)
from voltaire_bundler.bundler.exceptions import (
    ExecutionException,
    ExecutionExceptionCode,
)
from voltaire_bundler.utils.eth_client_utils import (
    send_rpc_request_to_eth_client,
)

from voltaire_bundler.user_operation.models import (
    Log,
    ReceiptInfo,
    UserOperationReceiptInfo,
)


class UserOperationHandler:
    ethereum_node_url: str
    bundler_private_key: str
    bundler_address: str
    is_legacy_mode: bool

    def __init__(
        self,
        ethereum_node_url,
        bundler_private_key,
        bundler_address,
        is_legacy_mode,
    ):
        self.ethereum_node_url = ethereum_node_url
        self.bundler_private_key = bundler_private_key
        self.bundler_address = bundler_address
        self.is_legacy_mode = is_legacy_mode

    async def get_user_operation_by_hash(
        self, user_operation_hash: str, entrypoint:str
    ) -> tuple:
        event_log_info = await self.get_user_operation_event_log_info(
            user_operation_hash, entrypoint
        )
        log_object = event_log_info[0]
        transaction_hash = log_object.transactionHash

        transaction = await self.get_transaction_by_hash(transaction_hash)

        block_hash = transaction["blockHash"]
        block_number = transaction["blockNumber"]
        user_operation = transaction["input"]

        return user_operation, block_number, block_hash, transaction_hash

    async def get_user_operation_by_hash_rpc(
        self, user_operation_hash: str, entrypoint:str
    ) -> dict:
        (
            handle_op_input,
            block_number,
            block_hash,
            transaction_hash,
        ) = await self.get_user_operation_by_hash(user_operation_hash, entrypoint)

        user_operation = UserOperationHandler.decode_handle_op_input(
            handle_op_input
        )

        user_operation_json = {
            "sender": to_checksum_address(user_operation[0]),
            "nonce": hex(user_operation[1]),
            "initCode": "0x" + user_operation[2].hex(),
            "callData": "0x" + user_operation[3].hex(),
            "callGasLimit": hex(user_operation[4]),
            "verificationGasLimit": hex(user_operation[5]),
            "preVerificationGas": hex(user_operation[6]),
            "maxFeePerGas": hex(user_operation[7]),
            "maxPriorityFeePerGas": hex(user_operation[8]),
            "paymasterAndData": "0x" + user_operation[9].hex(),
            "signature": "0x" + user_operation[10].hex(),
        }
        user_operation_by_hash_json = {
            "userOperation": user_operation_json,
            "entryPoint": entrypoint,
            "blockNumber": block_number,
            "blockHash": block_hash,
            "transactionHash": transaction_hash,
        }
        return user_operation_by_hash_json

    async def get_user_operation_receipt(
        self, user_operation_hash: str, entrypoint:str
    ) -> tuple[ReceiptInfo, UserOperationReceiptInfo]:
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
        ) = await self.get_user_operation_event_log_info(
            user_operation_hash, entrypoint)

        transaction = await self.get_transaction_receipt(
            log_object.transactionHash
        )

        receiptInfo = ReceiptInfo(
            transactionHash=transaction["transactionHash"],
            transactionIndex=log_object.transactionIndex,
            blockHash=transaction["blockHash"],
            blockNumber=transaction["blockNumber"],
            _from=transaction["from"],
            to=transaction["to"],
            cumulativeGasUsed=transaction["cumulativeGasUsed"],
            gasUsed=transaction["gasUsed"],
            contractAddress=transaction["contractAddress"],
            logs=transaction["logs"],
            logsBloom=transaction["logsBloom"],
            # root=transaction['root'],
            status=transaction["status"],
            effectiveGasPrice="0",
        )
        if not self.is_legacy_mode:
            receiptInfo.effectiveGasPrice = transaction["effectiveGasPrice"]

        userOperationReceiptInfo = UserOperationReceiptInfo(
            userOpHash=userOpHash,
            sender=sender,
            paymaster=paymaster,
            nonce=nonce,
            success=success,
            actualGasCost=actualGasCost,
            actualGasUsed=actualGasUsed,
            logs=logs,
            receipt=receiptInfo,
        )

        return receiptInfo, userOperationReceiptInfo

    async def get_user_operation_receipt_rpc(
        self, user_operation_hash: str, entrypoint:str
    ) -> dict:
        (
            receipt_info,
            user_operation_receipt_info,
        ) = await self.get_user_operation_receipt(user_operation_hash, entrypoint)

        receipt_info_json = {
            "blockHash": receipt_info.blockHash,
            "blockNumber": receipt_info.blockNumber,
            "from": receipt_info._from,
            "cumulativeGasUsed": receipt_info.cumulativeGasUsed,
            "gasUsed": receipt_info.gasUsed,
            "logs": receipt_info.logs,
            "logsBloom": receipt_info.logsBloom,
            "transactionHash": receipt_info.transactionHash,
            "transactionIndex": receipt_info.transactionIndex,
        }

        if not self.is_legacy_mode:
            gas_info = {"effectiveGasPrice": receipt_info.effectiveGasPrice}
            receipt_info_json.update(gas_info)

        user_operation_receipt_rpc_json = {
            "userOpHash": user_operation_receipt_info.userOpHash,
            "entryPoint": entrypoint,
            "sender": user_operation_receipt_info.sender,
            "nonce": hex(user_operation_receipt_info.nonce),
            "paymaster": user_operation_receipt_info.paymaster,
            "actualGasCost": user_operation_receipt_info.actualGasCost,
            "actualGasUsed": user_operation_receipt_info.actualGasUsed,
            "success": user_operation_receipt_info.success,
            "logs": user_operation_receipt_info.logs,
            "receipt": receipt_info_json,
        }

        return user_operation_receipt_rpc_json

    async def get_user_operation_event_log_info(
        self, user_operation_hash: str, entrypoint:str
    ) -> tuple:
        res = await self.get_user_operation_logs(user_operation_hash, entrypoint)

        if "result" not in res or len(res["result"]) < 1:
            raise ValidationException(
                ValidationExceptionCode.INVALID_USEROPHASH,
                "can't find user operation with hash : " + user_operation_hash,
            )
        logs = res["result"]
        log = res["result"][0]

        log_object = Log(
            removed=log["removed"],
            logIndex=log["logIndex"],
            transactionIndex=log["transactionIndex"],
            transactionHash=log["transactionHash"],
            blockHash=log["blockHash"],
            blockNumber=log["blockNumber"],
            address=log["address"],
            data=log["data"],
            topics=log["topics"],
        )

        topics = log["topics"]
        data = log["data"]

        userOpHash = topics[1]
        sender = decode(["address"], bytes.fromhex(topics[2][2:]))[0]
        paymaster = decode(["address"], bytes.fromhex(topics[3][2:]))[0]

        data_abi = ["uint256", "bool", "uint256", "uint256"]
        decode_result = decode(data_abi, bytes.fromhex(data[2:]))
        nonce = decode_result[0]
        success = decode_result[1]
        actualGasCost = decode_result[2]
        actualGasUsed = decode_result[3]

        return (
            log_object,
            userOpHash,
            sender,
            paymaster,
            nonce,
            success,
            actualGasCost,
            actualGasUsed,
            logs,
        )

    async def get_transaction_receipt(self, transaction_hash: str) -> dict:
        params = [transaction_hash]
        res = await send_rpc_request_to_eth_client(
            self.ethereum_node_url, "eth_getTransactionReceipt", params
        )
        return res["result"]

    async def get_user_operation_logs(self, user_operation_hash: str, entrypoint:str):
        USER_OPERATIOM_EVENT_DISCRIPTOR = "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f"

        params = [
            {
                "address": entrypoint,
                "topics": [
                    USER_OPERATIOM_EVENT_DISCRIPTOR,
                    user_operation_hash,
                ],
                "fromBlock": "earliest",
            }
        ]
        res = await send_rpc_request_to_eth_client(
            self.ethereum_node_url, "eth_getLogs", params
        )

        return res

    async def get_transaction_by_hash(self, transaction_hash) -> dict:
        params = [transaction_hash]
        res = await send_rpc_request_to_eth_client(
            self.ethereum_node_url, "eth_getTransactionByHash", params
        )
        return res["result"]

    @staticmethod
    def get_user_operation_hash(
        user_operation_list: list(), entrypoint_addr: str, chain_id: int
    ):
        packed_user_operation = keccak(
            UserOperationHandler.pack_user_operation(user_operation_list)
        )

        encoded_user_operation_hash = encode(
            ["(bytes32,address,uint256)"],
            [[packed_user_operation, entrypoint_addr, chain_id]],
        )
        user_operation_hash = "0x" + keccak(encoded_user_operation_hash).hex()
        return user_operation_hash

    @staticmethod
    def pack_user_operation(
        user_operation_list: list(), for_signature: bool = True
    ) -> bytes:
        if for_signature:
            user_operation_list[2] = keccak(user_operation_list[2])
            user_operation_list[3] = keccak(user_operation_list[3])
            user_operation_list[9] = keccak(user_operation_list[9])
            user_operation_list_without_signature = user_operation_list[:-1]

            packed_user_operation = encode(
                [
                    "address",
                    "uint256",
                    "bytes32",
                    "bytes32",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256",
                    "bytes32",
                ],
                user_operation_list_without_signature,
            )
        else:
            packed_user_operation = encode(
                [
                    "address",
                    "uint256",
                    "bytes",
                    "bytes",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256",
                    "bytes",
                    "bytes",
                ],
                user_operation_list,
            )
        return packed_user_operation

    @staticmethod
    def decode_handle_op_input(handle_op_input) -> list:
        INPUT_ABI = [
            "(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)[]",
            "address",
        ]
        inputResult = decode(INPUT_ABI, bytes.fromhex(handle_op_input[10:]))
        return inputResult[0][0]
