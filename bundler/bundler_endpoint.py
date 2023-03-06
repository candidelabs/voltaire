import logging
import re
from eth_abi import decode
from web3 import Web3


from aiohttp import ClientSession

from event_bus_manager.endpoint import Endpoint
from rpc.events import RPCCallRequestEvent, RPCCallResponseEvent
from user_operation.user_operation import UserOperation
from user_operation.estimate_user_operation_gas import (
    estimate_user_operation_gas,
)

from .eth_client_utils import send_rpc_request_to_eth_client

from user_operation.get_user_operation import (
    get_user_operation_receipt,
    get_user_operation_by_hash,
)
from .mempool_manager import Mempool
from user_operation.erc4337_utils import get_user_operation_hash
from rpc.exceptions import BundlerException, ExceptionCode
from .bundle_manager import BundlerManager


class BundlerEndpoint(Endpoint):
    geth_rpc_url: str
    bundler_private_key: str
    bundler_address: str
    entrypoint: str
    entrypoint_abi: str
    bundle_manager: BundlerManager

    def __init__(
        self,
        geth_rpc_url,
        bundler_private_key,
        bundler_address,
        entrypoint,
        entrypoint_abi,
    ):
        super().__init__("bundler_endpoint")

        self.geth_rpc_url = geth_rpc_url
        self.bundler_private_key = bundler_private_key
        self.bundler_address = bundler_address
        self.entrypoint = entrypoint
        self.entrypoint_abi = entrypoint_abi
        self.bundle_manager = BundlerManager(
            geth_rpc_url,
            bundler_private_key,
            bundler_address,
            entrypoint,
            entrypoint_abi)

    async def start_bundler_endpoint(self) -> None:
        self.add_events_and_response_functions_by_prefix(
            prefix="_event_", decorator_func=exception_handler_decorator
        )
        await self.start_server()

    async def _event_rpc_chainId(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        response = await send_rpc_request_to_eth_client(
            self.geth_rpc_url, "eth_chainId"
        )
        return RPCCallResponseEvent(response["result"])

    async def _event_rpc_supportedEntryPoints(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        return RPCCallResponseEvent([self.entrypoint])

    async def _event_rpc_estimateUserOperationGas(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        user_operation: UserOperation = rpc_request.req_arguments[0]
        entrypoint = rpc_request.req_arguments[1]

        (
            call_gas_limit,
            preverification_gas,
            pre_operation_gas,
            deadline,
        ) = await estimate_user_operation_gas(
            user_operation,
            entrypoint,
            self.entrypoint_abi,
            self.geth_rpc_url,
            self.bundler_address,
        )

        response_params = {
            "callGasLimit": call_gas_limit,
            "preVerificationGas": preverification_gas,
            "verificationGas": pre_operation_gas,
            "deadline": deadline,
        }

        return RPCCallResponseEvent(response_params)

    async def _event_rpc_sendUserOperation(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        user_operation: UserOperation = rpc_request.req_arguments[0]
        entrypoint_address = rpc_request.req_arguments[1]

        user_operation_hash = await self.bundle_manager.mempool.add_user_operation(
            user_operation)
        return RPCCallResponseEvent(user_operation_hash)

    async def _event_debug_bundler_sendBundleNow(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        res = await self.bundle_manager.send_next_bundle()

        return RPCCallResponseEvent(res)

    async def _event_debug_bundler_clearState(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        self.bundle_manager.mempool.clear_user_operations()

        return RPCCallResponseEvent("ok")

    async def _event_debug_bundler_dumpMempool(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        entrypoint_address = rpc_request.req_arguments[0]

        user_operations = self.bundle_manager.mempool.get_all_user_operations()

        user_operations_json = [
            user_operation.get_user_operation_json()
            for user_operation in user_operations
        ]
        return RPCCallResponseEvent(user_operations_json)

    async def _event_rpc_getUserOperationByHash(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        user_operation_hash = rpc_request.req_arguments[0]

        if not is_hash(user_operation_hash):
            raise BundlerException(
                ExceptionCode.INVALID_USEROPHASH,
                "Missing/invalid userOpHash",
                "",
            )

        (
            handle_op_input,
            block_number,
            block_hash,
            transaction_hash,
        ) = await get_user_operation_by_hash(
            self.geth_rpc_url, self.entrypoint, user_operation_hash
        )

        user_operation = decode_handle_op_input(handle_op_input)

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
        return RPCCallResponseEvent(user_operation_by_hash_json)

    async def _event_rpc_getUserOperationReceipt(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        user_operation_hash = rpc_request.req_arguments[0]

        if not is_hash(user_operation_hash):
            raise BundlerException(
                ExceptionCode.INVALID_USEROPHASH,
                "Missing/invalid userOpHash",
                "",
            )

        (
            receipt_info,
            user_operation_receipt_info,
        ) = await get_user_operation_receipt(
            self.geth_rpc_url, self.entrypoint, user_operation_hash
        )

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
        user_operation_receipt_info_json = {
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

        return RPCCallResponseEvent(user_operation_receipt_info_json)


async def exception_handler_decorator(
    response_function, rpc_request: RPCCallRequestEvent
) -> RPCCallResponseEvent:
    try:
        response = await response_function(rpc_request)
    except BundlerException as excp:
        response = RPCCallResponseEvent(excp)
        response.is_error = True
    finally:
        return response


def is_hash(user_operation_hash):
    hash_pattern = "^0x[0-9,a-f,A-F]{64}$"
    return (
        isinstance(user_operation_hash, str)
        and re.match(hash_pattern, user_operation_hash) is not None
    )


def decode_handle_op_input(handle_op_input):
    INPUT_ABI = [
        "(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)[]",
        "address",
    ]
    inputResult = decode(INPUT_ABI, bytes.fromhex(handle_op_input[10:]))
    return inputResult[0][0]
