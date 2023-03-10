import asyncio
from functools import reduce
import math

from web3 import Web3
from eth_abi import decode

from .user_operation import UserOperation
from bundler.exceptions import BundlerException, BundlerExceptionCode
from utils.eth_client_utils import send_rpc_request_to_eth_client
from eth_abi import encode

from user_operation.models import (
    Log,
    ReceiptInfo,
    UserOperationReceiptInfo,
)


class UserOperationHandler:
    geth_rpc_url: str
    bundler_private_key: str
    bundler_address: str
    entrypoint: str
    entrypoint_abi: str

    def __init__(
        self,
        validation_manager,
        geth_rpc_url,
        bundler_private_key,
        bundler_address,
        entrypoint,
        entrypoint_abi,
    ):
        self.validation_manager = validation_manager
        self.geth_rpc_url = geth_rpc_url
        self.bundler_private_key = bundler_private_key
        self.bundler_address = bundler_address
        self.entrypoint = entrypoint
        self.entrypoint_abi = entrypoint_abi

    async def estimate_user_operation_gas(self, user_operation: UserOperation):
        tasks = await asyncio.gather(
            self.validation_manager.simulate_validation_and_decode_result(
                user_operation
            ),
            self.estimate_call_gas_limit(
                call_data="0x" + user_operation.call_data.hex(),
                _from=self.entrypoint,
                to=user_operation.sender,
            ),
            asyncio.to_thread(
                UserOperationHandler.calc_preverification_gas, user_operation
            ),
        )

        return_info, _, _, _ = tasks[0]
        call_gas_limit = tasks[1]
        pre_verification_gas = tasks[2]

        pre_operation_gas = return_info.preOpGas
        valid_until = return_info.validUntil

        return (
            call_gas_limit,
            pre_verification_gas,
            pre_operation_gas,
            valid_until,
        )

    async def estimate_user_operation_gas_rpc(
        self, user_operation: UserOperation
    ):
        (
            call_gas_limit,
            preverification_gas,
            pre_operation_gas,
            deadline,
        ) = await self.estimate_user_operation_gas(user_operation)

        response_params = {
            "callGasLimit": call_gas_limit,
            "preVerificationGas": preverification_gas,
            "verificationGas": pre_operation_gas,
            "deadline": deadline,
        }

        return response_params

    async def estimate_call_gas_limit(self, call_data, _from, to):
        params = [{"from": _from, "to": to, "data": call_data}]

        result = await send_rpc_request_to_eth_client(
            self.geth_rpc_url, "eth_estimateGas", params
        )
        if "error" in result:
            errorMessage = result["error"]["message"]
            errorData = result["error"]["data"]
            errorParams = errorData[10:]
            raise BundlerException(
                BundlerExceptionCode.EXECUTION_REVERTED,
                errorMessage,
                errorParams,
            )
        call_gas_limit = result["result"]

        return call_gas_limit

    @staticmethod
    def calc_preverification_gas(user_operation: UserOperation) -> int:
        userOp = user_operation

        fixed = 21000
        per_user_operation = 18300
        per_user_operation_word = 4
        zero_byte = 4
        non_zero_byte = 16
        bundle_size = 1
        sigSize = 65

        # userOp.preVerificationGas = fixed
        # userOp.signature = bytes(sigSize)
        packed = UserOperationHandler.pack_user_operation(userOp.to_list())

        cost_list = list(
            map(lambda x: zero_byte if x == b"\x00" else non_zero_byte, packed)
        )
        call_data_cost = reduce(lambda x, y: x + y, cost_list)

        pre_verification_gas = (
            call_data_cost
            + (fixed / bundle_size)
            + per_user_operation
            + per_user_operation_word * len(packed)
        )

        return math.ceil(pre_verification_gas)

    async def get_user_operation_by_hash(self, user_operation_hash):
        (
            log_object,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
        ) = await self.get_user_operation_event_log_info(user_operation_hash)
        transaction_hash = log_object.transactionHash

        transaction = await self.get_transaction_by_hash(transaction_hash)

        block_hash = transaction["blockHash"]
        block_number = transaction["blockNumber"]
        user_operation = transaction["input"]

        return user_operation, block_number, block_hash, transaction_hash

    async def get_user_operation_by_hash_rpc(self, user_operation_hash):
        (
            handle_op_input,
            block_number,
            block_hash,
            transaction_hash,
        ) = await self.get_user_operation_by_hash(user_operation_hash)

        user_operation = UserOperationHandler.decode_handle_op_input(
            handle_op_input
        )

        user_operation_json = {
            "sender": Web3.to_checksum_address(user_operation[0]),
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
            "entryPoint": self.entrypoint,
            "blockNumber": block_number,
            "blockHash": block_hash,
            "transactionHash": transaction_hash,
        }
        return user_operation_by_hash_json

    async def get_user_operation_receipt(self, user_operation_hash):
        (
            log_object,
            userOpHash,
            sender,
            paymaster,
            nonce,
            success,
            actualGasCost,
            actualGasUsed,
        ) = await self.get_user_operation_event_log_info(user_operation_hash)

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
            effectiveGasPrice=transaction["effectiveGasPrice"],
        )

        logs = await self.get_logs(
            log_object.transactionHash, receiptInfo._from
        )

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

    async def get_user_operation_receipt_rpc(self, user_operation_hash):
        (
            receipt_info,
            user_operation_receipt_info,
        ) = await self.get_user_operation_receipt(user_operation_hash)

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
            "effectiveGasPrice": receipt_info.effectiveGasPrice,
        }
        user_operation_receipt_rpc_json = {
            "userOpHash": user_operation_receipt_info.userOpHash,
            "entryPoint": self.entrypoint,
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

    async def get_user_operation_event_log_info(self, user_operation_hash):
        USER_OPERATIOM_EVENT_DISCRIPTOR = "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f"
        params = [
            {
                "address": self.entrypoint,
                "topics": [
                    USER_OPERATIOM_EVENT_DISCRIPTOR,
                    user_operation_hash,
                ],
            }
        ]

        res = await send_rpc_request_to_eth_client(
            self.geth_rpc_url, "eth_getLogs", params
        )

        if len(res["result"]) < 1:
            raise BundlerException(
                BundlerExceptionCode.INVALID_USEROPHASH, "null", ""
            )

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
        )

    async def get_transaction_receipt(self, transaction_hash):
        params = [transaction_hash]
        res = await send_rpc_request_to_eth_client(
            self.geth_rpc_url, "eth_getTransactionReceipt", params
        )
        return res["result"]

    async def get_logs(self, transaction_hash, _from):
        params = [
            {
                "address": _from,
                "transactionHash": transaction_hash,
            }
        ]

        res = await send_rpc_request_to_eth_client(
            self.geth_rpc_url, "eth_getLogs", params
        )
        return res["result"]

    async def get_transaction_by_hash(self, transaction_hash):
        params = [transaction_hash]
        res = await send_rpc_request_to_eth_client(
            self.geth_rpc_url, "eth_getTransactionByHash", params
        )
        return res["result"]

    async def get_user_operation_hash(self, user_operation):
        w3_provider = Web3()
        entrypoint_contract = w3_provider.eth.contract(
            address=self.entrypoint, abi=self.entrypoint_abi
        )

        call_data = entrypoint_contract.encodeABI(
            "getUserOpHash", [user_operation.get_user_operation_dict()]
        )

        params = [
            {
                "from": self.bundler_address,
                "to": self.entrypoint,
                "data": call_data,
            },
            "latest",
        ]

        result = await send_rpc_request_to_eth_client(
            self.geth_rpc_url, "eth_call", params
        )
        return result["result"]

    @staticmethod
    def pack_user_operation(user_operation):
        return encode(
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
            user_operation,
        )[66:-64]

    @staticmethod
    def decode_handle_op_input(handle_op_input):
        INPUT_ABI = [
            "(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)[]",
            "address",
        ]
        inputResult = decode(INPUT_ABI, bytes.fromhex(handle_op_input[10:]))
        return inputResult[0][0]
