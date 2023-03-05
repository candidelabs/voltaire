import logging
from dataclasses import field
from functools import partial
import re
from eth_abi import decode
from web3 import Web3


from aiohttp import ClientSession

from event_bus_manager.endpoint import Endpoint
from rpc.events import RPCCallRequestEvent, RPCCallResponseEvent
from user_operation.user_operation import UserOperation
from user_operation.estimate_user_operation_gas import (
    estimate_user_operation_gas,
    simulate_validation_and_decode_result,
)
from .bundle_manager import send_bundle
from .eth_client_utils import send_rpc_request_to_eth_client

from user_operation.get_user_operation import (
    get_user_operation_receipt,
    get_user_operation_by_hash,
)
from .mempool_manager import Mempool
from user_operation.erc4337_utils import get_user_operation_hash
from rpc.exceptions import BundlerException, ExceptionCode


class BundlerEndpoint(Endpoint):
    geth_rpc_url: str
    bundler_private_key: str = field()
    bundler_address: str = field()
    entrypoints: list = field(default_factory=list)
    entrypoints_abis: list = field(default_factory=list)
    mempools: list = field(default_factory=list)

    def __init__(
        self,
        geth_rpc_url,
        bundler_private_key,
        bundler_address,
        entrypoints,
        entrypoints_abis,
    ):
        super().__init__("bundler_endpoint")

        self.geth_rpc_url = geth_rpc_url
        self.bundler_private_key = bundler_private_key
        self.bundler_address = bundler_address
        self.entrypoints = entrypoints
        self.entrypoints_abis = entrypoints_abis
        self.mempools = []
        for entrypoint in entrypoints:
            self.mempools.append(Mempool(entrypoint))

    async def start_bundler_endpoint(self) -> None:
        self.add_events_and_response_functions_by_prefix(
            prefix="_event_", decorator_func=exception_handler_decorator
        )
        await self.start_server()

    def _get_entrypoint_abi(self, entrypoint_addr) -> str:
        index = self.entrypoints.index(entrypoint_addr)
        return self.entrypoints_abis[index]

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
        return RPCCallResponseEvent(self.entrypoints)

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
            self._get_entrypoint_abi(entrypoint),
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

        index = self.entrypoints.index(entrypoint_address)

        entrypoint_abi = self.entrypoints_abis[index]

        user_operation_hash_json = await get_user_operation_hash(
            user_operation,
            entrypoint_address,
            entrypoint_abi,
            self.geth_rpc_url,
            self.bundler_address,
        )
        user_operation_hash = user_operation_hash_json["result"]

        await simulate_validation_and_decode_result(
            user_operation,
            entrypoint_address,
            self.geth_rpc_url,
            self.bundler_address,
            entrypoint_abi,
        )
        mempool = self.mempools[index]
        await mempool.add_user_operation(
            user_operation,
            entrypoint_address,
            entrypoint_abi,
            self.bundler_address,
            self.geth_rpc_url,
        )
        return RPCCallResponseEvent(user_operation_hash)

    async def _event_debug_bundler_sendBundleNow(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        index = 0
        user_operations = self.mempools[index].get_user_operations_to_bundle()
        res = await send_bundle(
            user_operations,
            self.entrypoints[index],
            self.entrypoints_abis[index],
            self.geth_rpc_url,
            self.bundler_private_key,
            self.bundler_address,
        )

        return RPCCallResponseEvent(res["result"])

    async def _event_debug_bundler_clearState(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        for mempool in self.mempools:
            mempool.clear_user_operations()

        response = {"jsonrpc": "2.0", "id": 1, "result": "ok"}
        return RPCCallResponseEvent(response)

    async def _event_debug_bundler_dumpMempool(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        entrypoint_address = rpc_request.req_arguments[0]

        index = self.entrypoints.index(entrypoint_address)
        mempool: Mempool = self.mempools[index]
        user_operations = mempool.get_all_user_operations()

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

        entrypoint_add = self.entrypoints[0]

        (
            handle_op_input,
            block_number,
            block_hash,
            transaction_hash,
        ) = await get_user_operation_by_hash(
            self.geth_rpc_url, entrypoint_add, user_operation_hash
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
            "entryPoint": entrypoint_add,
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

        entrypoint_add = self.entrypoints[0]

        (
            receipt_info,
            user_operation_receipt_info,
        ) = await get_user_operation_receipt(
            self.geth_rpc_url, entrypoint_add, user_operation_hash
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
            "entryPoint": entrypoint_add,
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
