import asyncio
import logging

from event_bus_manager.endpoint import Endpoint
from rpc.events import RPCCallRequestEvent, RPCCallResponseEvent
from user_operation.user_operation import UserOperation

from .mempool_manager import MempoolManager
from user_operation.user_operation_handler import UserOperationHandler
from bundler.exceptions import (
    ValidationException,
    ValidationExceptionCode,
    ExecutionException,
)
from .bundle_manager import BundlerManager
from .validation_manager import ValidationManager
from .reputation_manager import ReputationManager


class ExecutionEndpoint(Endpoint):
    ethereum_node_url: str
    bundler_private_key: str
    bundler_address: str
    entrypoint: str
    bundle_manager: BundlerManager
    mempool_manager: MempoolManager
    validation_manager: ValidationManager
    user_operation_handler: UserOperationHandler
    reputation_manager: ReputationManager
    bundler_helper_byte_code: str
    chain_id: int
    is_unsafe: bool
    is_legacy_mode: bool
    is_send_raw_transaction_conditional: bool
    bundle_interval: int

    def __init__(
        self,
        ethereum_node_url: str,
        bundler_private_key: str,
        bundler_address: str,
        entrypoint: str,
        bundler_helper_byte_code: str,
        chain_id: str,
        is_unsafe: bool,
        is_legacy_mode: bool,
        is_send_raw_transaction_conditional: bool,
        bundle_interval: int,
    ):
        super().__init__("bundler_endpoint")
        self.ethereum_node_url = ethereum_node_url
        self.bundler_private_key = bundler_private_key
        self.bundler_address = bundler_address
        self.entrypoint = entrypoint
        self.bundler_helper_byte_code = bundler_helper_byte_code
        self.chain_id = chain_id
        self.is_unsafe = is_unsafe
        self.is_legacy_mode = is_legacy_mode
        self.is_send_raw_transaction_conditional = (
            is_send_raw_transaction_conditional
        )
        self.bundle_interval = bundle_interval

        self.reputation_manager = ReputationManager()

        self.user_operation_handler = UserOperationHandler(
            ethereum_node_url,
            bundler_private_key,
            bundler_address,
            entrypoint,
            is_legacy_mode,
        )

        self.validation_manager = ValidationManager(
            self.user_operation_handler,
            ethereum_node_url,
            bundler_private_key,
            bundler_address,
            entrypoint,
            bundler_helper_byte_code,
            is_unsafe,
            is_legacy_mode,
        )

        self.mempool_manager = MempoolManager(
            self.validation_manager,
            self.user_operation_handler,
            self.reputation_manager,
            ethereum_node_url,
            bundler_private_key,
            bundler_address,
            entrypoint,
            is_unsafe,
        )

        self.bundle_manager = BundlerManager(
            self.mempool_manager,
            self.user_operation_handler,
            self.reputation_manager,
            ethereum_node_url,
            bundler_private_key,
            bundler_address,
            entrypoint,
            chain_id,
            is_legacy_mode,
            is_send_raw_transaction_conditional,
        )
        if self.bundle_interval > 0:
            asyncio.ensure_future(self.execute_bundle_cron_job())

    async def execute_bundle_cron_job(self) -> None:
        while True:
            try:
                await self.bundle_manager.send_next_bundle()
            except (ValidationException, ExecutionException) as excp:
                logging.exception(excp.message)

            await asyncio.sleep(self.bundle_interval)

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
        entrypoint_address = rpc_request.req_arguments[1]

        self._verify_entrypoint(entrypoint_address)

        # set high verification_gas_limit for validtion to succeed while estimating gas
        if user_operation.verification_gas_limit < 1000000000000000000:
            user_operation.verification_gas_limit = 1000000000000000000

        # set gas fee to zero to ignore paying for prefund error while estimating gas
        user_operation.max_fee_per_gas = 0
        user_operation.max_priority_fee_per_gas = 0

        if self.is_legacy_mode:
            pre_operation_gas = 80000
            deadline = 10000000000000000
        else:
            (
                return_info,
                _,
                _,
                _,
            ) = await self.validation_manager.simulate_validation_and_decode_result(
                user_operation
            )

            pre_operation_gas = return_info.preOpGas
            deadline = return_info.validUntil

        estimated_gas_json = (
            await self.user_operation_handler.estimate_user_operation_gas_rpc(
                user_operation
            )
        )

        estimated_gas_json.update(
            {
                "verificationGas": pre_operation_gas,
                "deadline": deadline,
            }
        )

        return RPCCallResponseEvent(estimated_gas_json)

    async def _event_rpc_sendUserOperation(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        user_operation: UserOperation = rpc_request.req_arguments[0]
        entrypoint_address = rpc_request.req_arguments[1]

        self._verify_entrypoint(entrypoint_address)

        user_operation_hash = await self.mempool_manager.add_user_operation(
            user_operation,
        )
        return RPCCallResponseEvent(user_operation_hash)

    async def _event_rpc_getUserOperationByHash(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        user_operation_hash = rpc_request.req_arguments[0]

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

        user_operation_receipt_info_json = (
            await self.user_operation_handler.get_user_operation_receipt_rpc(
                user_operation_hash
            )
        )

        return RPCCallResponseEvent(user_operation_receipt_info_json)

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

    async def _event_debug_bundler_setReputation(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        entitiy = rpc_request.req_arguments[0]
        ops_seen = rpc_request.req_arguments[0]
        ops_included = rpc_request.req_arguments[0]
        status = rpc_request.req_arguments[0]

        self.reputation_manager.set_reputation(
            entitiy, ops_seen, ops_included, status
        )

        return RPCCallResponseEvent("ok")

    async def _event_debug_bundler_dumpReputation(
        self, rpc_request: RPCCallRequestEvent
    ) -> RPCCallResponseEvent:
        entrypoint_address = rpc_request.req_arguments[0]

        entities_reputation_json = (
            self.reputation_manager.get_entities_reputation_json()
        )
        return RPCCallResponseEvent(entities_reputation_json)

    def _verify_entrypoint(self, entrypoint):
        if entrypoint != self.entrypoint:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Unsupported entrypoint",
                "",
            )


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
