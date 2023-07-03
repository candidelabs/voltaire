import asyncio
import logging

from voltaire_bundler.event_bus_manager.endpoint import Endpoint
from voltaire_bundler.rpc.events import (
    RPCCallRequestEvent,
    RPCCallResponseEvent,
)
from voltaire_bundler.user_operation.user_operation import UserOperation

from .mempool_manager import MempoolManager
from voltaire_bundler.user_operation.user_operation_handler import (
    UserOperationHandler,
)
from voltaire_bundler.bundler.exceptions import (
    ValidationException,
    ValidationExceptionCode,
    ExecutionException,
)
from .bundle_manager import BundlerManager
from .validation_manager import ValidationManager
from .reputation_manager import ReputationManager

MAX_VERIFICATION_GAS_LIMIT = 10000000


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
    whitelist_entity_storage_access: list()

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
        whitelist_entity_storage_access: list(),
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
        self.whitelist_entity_storage_access = whitelist_entity_storage_access

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
            chain_id,
            bundler_helper_byte_code,
            is_unsafe,
            is_legacy_mode,
            whitelist_entity_storage_access,
            MAX_VERIFICATION_GAS_LIMIT,
        )

        self.mempool_manager = MempoolManager(
            self.validation_manager,
            self.user_operation_handler,
            self.reputation_manager,
            ethereum_node_url,
            bundler_private_key,
            bundler_address,
            entrypoint,
            chain_id,
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

        estimate_call_gas_limit_and_preverification_gas_operation = self.user_operation_handler.estimate_call_gas_limit_and_preverification_gas(
            user_operation
        )

        #set gas fee to zero to ignore paying for prefund error while estimating gas
        user_operation.max_fee_per_gas = 0
        
        #set high verification_gas_limit for validtion to succeed while estimating gas
        user_operation.verification_gas_limit = MAX_VERIFICATION_GAS_LIMIT

        simulate_validation_operation = self.validation_manager.simulate_validation_without_tracing(
            user_operation
        )

        tasks = await asyncio.gather(estimate_call_gas_limit_and_preverification_gas_operation, simulate_validation_operation)
        
        call_gas_limit, preverification_gas = tasks[0]
        _, solidity_error_params = tasks[1]

        call_gas_limit = int(call_gas_limit, 16)

        decoded_validation_result = ValidationManager.decode_validation_result(
            solidity_error_params
        )

        return_info = decoded_validation_result[0]

        verification_gas = return_info.preOpGas - user_operation.pre_verification_gas

        deadline = return_info.validUntil

        estimated_gas_json = {
            "callGasLimit": call_gas_limit,
            "preVerificationGas": preverification_gas,
            "verificationGas": verification_gas,
            "deadline": deadline,
        }

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
