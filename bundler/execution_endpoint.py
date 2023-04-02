import asyncio
import logging
import re
from eth_abi import decode
from web3 import Web3


from aiohttp import ClientSession

from event_bus_manager.endpoint import Endpoint
from rpc.events import RPCCallRequestEvent, RPCCallResponseEvent
from user_operation.user_operation import UserOperation

from utils.eth_client_utils import send_rpc_request_to_eth_client

from .mempool_manager import MempoolManager
from user_operation.user_operation_handler import UserOperationHandler
from bundler.exceptions import (
    ValidationException,
    ValidationExceptionCode,
    ExecutionException
)
from .bundle_manager import BundlerManager
from .validation_manager import ValidationManager
from .reputation_manager import ReputationManager

BUNDLE_INTERVAL = 10  # in seconds


class ExecutionEndpoint(Endpoint):
    geth_rpc_url: str
    bundler_private_key: str
    bundler_address: str
    entrypoint: str
    entrypoint_abi: str
    bundle_manager: BundlerManager
    mempool_manager: MempoolManager
    validation_manager: ValidationManager
    user_operation_handler: UserOperationHandler
    reputation_manager: ReputationManager
    bundler_helper_byte_code: str
    chain_id: int

    def __init__(
        self,
        geth_rpc_url,
        bundler_private_key,
        bundler_address,
        entrypoint,
        entrypoint_abi,
        bundler_helper_byte_code,
        chain_id,
    ):
        super().__init__("bundler_endpoint")
        self.geth_rpc_url = geth_rpc_url
        self.bundler_private_key = bundler_private_key
        self.bundler_address = bundler_address
        self.entrypoint = entrypoint
        self.entrypoint_abi = entrypoint_abi
        self.bundler_helper_byte_code = bundler_helper_byte_code
        self.chain_id = chain_id

        self.reputation_manager = ReputationManager()

        self.validation_manager = ValidationManager(
            geth_rpc_url,
            bundler_private_key,
            bundler_address,
            entrypoint,
            entrypoint_abi,
            bundler_helper_byte_code,
        )

        self.user_operation_handler = UserOperationHandler(
            self.validation_manager,
            geth_rpc_url,
            bundler_private_key,
            bundler_address,
            entrypoint,
            entrypoint_abi,
        )

        self.mempool_manager = MempoolManager(
            self.validation_manager,
            self.user_operation_handler,
            self.reputation_manager,
            geth_rpc_url,
            bundler_private_key,
            bundler_address,
            entrypoint,
            entrypoint_abi,
        )

        self.bundle_manager = BundlerManager(
            self.mempool_manager,
            self.user_operation_handler,
            self.reputation_manager,
            geth_rpc_url,
            bundler_private_key,
            bundler_address,
            entrypoint,
            entrypoint_abi,
            chain_id,
        )

        asyncio.ensure_future(self.execute_bundle_cron_job())

    async def execute_bundle_cron_job(self):
        while True:
            try:
                await self.bundle_manager.send_next_bundle()
            except (ValidationException, ExecutionException) as excp:
                logging.exception(excp.message)
            
            await asyncio.sleep(BUNDLE_INTERVAL)

    async def start_execution_endpoint(self) -> None:
        self.add_events_and_response_functions_by_prefix(
            prefix="_event_", decorator_func=exception_handler_decorator
        )
        await self.start_server()

    async def _event_rpc_chainId(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        return RPCCallResponseEvent(hex(self.chain_id))

    async def _event_rpc_supportedEntryPoints(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        return RPCCallResponseEvent([self.entrypoint])

    async def _event_rpc_estimateUserOperationGas(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        user_operation: UserOperation = rpc_request.req_arguments[0]
        entrypoint = rpc_request.req_arguments[1]

        estimated_gas_json = (
            await self.user_operation_handler.estimate_user_operation_gas_rpc(
                user_operation
            )
        )

        return RPCCallResponseEvent(estimated_gas_json)

    async def _event_rpc_sendUserOperation(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        user_operation: UserOperation = rpc_request.req_arguments[0]
        entrypoint_address = rpc_request.req_arguments[1]

        user_operation_hash = await self.mempool_manager.add_user_operation(
            user_operation
        )
        return RPCCallResponseEvent(user_operation_hash)

    async def _event_debug_bundler_sendBundleNow(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        res = await self.bundle_manager.send_next_bundle()

        return RPCCallResponseEvent(res)

    async def _event_debug_bundler_clearState(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        self.mempool_manager.clear_user_operations()

        return RPCCallResponseEvent("ok")

    async def _event_debug_bundler_dumpMempool(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        entrypoint_address = rpc_request.req_arguments[0]

        user_operations = self.mempool_manager.get_all_user_operations()

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
            raise ValidationException(
                ValidationExceptionCode.INVALID_USEROPHASH,
                "Missing/invalid userOpHash",
                "",
            )

        user_operation_by_hash_json = (
            await self.user_operation_handler.get_user_operation_by_hash_rpc(
                user_operation_hash
            )
        )

        return RPCCallResponseEvent(user_operation_by_hash_json)

    async def _event_rpc_getUserOperationReceipt(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        user_operation_hash = rpc_request.req_arguments[0]

        if not is_hash(user_operation_hash):
            raise ValidationException(
                ValidationExceptionCode.INVALID_USEROPHASH,
                "Missing/invalid userOpHash",
                "",
            )

        user_operation_receipt_info_json = (
            await self.user_operation_handler.get_user_operation_receipt_rpc(
                user_operation_hash
            )
        )

        return RPCCallResponseEvent(user_operation_receipt_info_json)


async def exception_handler_decorator(
    response_function, rpc_request: RPCCallRequestEvent
) -> RPCCallResponseEvent:
    try:
        response = await response_function(rpc_request)
    except (ExecutionException, ValidationException) as excp:
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
