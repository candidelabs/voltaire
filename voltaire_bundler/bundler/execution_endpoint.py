import asyncio
import logging
import math

from voltaire_bundler.event_bus_manager.endpoint import Endpoint
from voltaire_bundler.rpc.events import (
    RPCCallRequestEvent,
    RPCCallResponseEvent,
)
from eth_abi import decode, encode

from voltaire_bundler.utils.eth_client_utils import (
    send_rpc_request_to_eth_client,
)
from voltaire_bundler.bundler.exceptions import (
    ExecutionException,
    ExecutionExceptionCode,
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
MIN_CALL_GAS_LIMIT = 21000

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

        preverification_gas = self.user_operation_handler.calc_preverification_gas(user_operation)
        preverification_gas_hex = hex(preverification_gas)

        user_operation.pre_verification_gas = preverification_gas
        user_operation.verification_gas_limit = MAX_VERIFICATION_GAS_LIMIT

        latest_block = await self.get_latest_block()
        latest_block_number = latest_block["number"]
        
        call_data = user_operation.call_data
        user_operation.call_data = bytes(0)
        user_operation.max_fee_per_gas = 0

        preOpGas, _, targetSuccess, targetResult = await self.simulate_handle_op(
            user_operation, 
            latest_block_number, 
            latest_block["gasLimit"],
            user_operation.sender_address,
            call_data)

        if(not targetSuccess):
            raise ExecutionException(
                ExecutionExceptionCode.EXECUTION_REVERTED,
                targetResult, ""
            )

        verification_gas_limit = math.ceil((preOpGas - user_operation.pre_verification_gas)*1.1)
        verification_gas_hex = hex(verification_gas_limit)
        user_operation.verification_gas_limit = verification_gas_limit

        preOpGas, _, targetSuccess, targetResult  = await self.simulate_handle_op(
            user_operation,
            latest_block_number,
            latest_block["gasLimit"],
            "0x6E0428608E6857C1f82aB5f1D431c557Bd8D7a27", # a random address where the GasLeft contract is deployed through state
            bytes.fromhex("15e812ad") #getGasLeft will return the remaining gas
        )
        block_gas_limit = int(latest_block["gasLimit"], 16)
        remaining_gas = decode(["uint256"], targetResult)[0]

        call_gas_limit =  block_gas_limit - remaining_gas - preOpGas - 400000
        call_gas_limit = max(MIN_CALL_GAS_LIMIT, call_gas_limit)
        call_gas_limit_hex =  hex(call_gas_limit )

        estimated_gas_json = {
            "callGasLimit": call_gas_limit_hex,
            "preVerificationGas": preverification_gas_hex,
            "verificationGas": verification_gas_hex,
        }

        return RPCCallResponseEvent(estimated_gas_json)
    
    async def get_latest_block(self) -> dict:
        res = await send_rpc_request_to_eth_client(
            self.ethereum_node_url, "eth_getBlockByNumber", ["latest", False]
        )
        return res["result"]

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
        
    async def simulate_handle_op(
                self, user_operation: UserOperation,
                bloch_number_hex:str,
                gasLimit,
                target:str="0x0000000000000000000000000000000000000000", 
                target_call_data:bytes=bytes(0),
            ):
            # simulateHandleOp(entrypoint solidity function) will always revert
            function_selector = "0xd6383f94"
            params = encode(
                [
                    "(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)", #useroperation
                    "address", #target (Optional - to check the )
                    "bytes"    #targetCallData
                ],
                [
                    user_operation.to_list(),
                    target,
                    target_call_data
                ],
            )

            call_data = function_selector + params.hex()

            params = [
                {
                    # "from": self.bundler_address,
                    "to": self.entrypoint,
                    "data": call_data,
                    "gas": gasLimit,
                    # "gasPrice": "0x0",
                },
                bloch_number_hex,
                {
                    "0x6E0428608E6857C1f82aB5f1D431c557Bd8D7a27": # a random address where the GasLeft contract is deployed through state
                    {
                        "code": "0x6080604052348015600f57600080fd5b506004361060285760003560e01c806315e812ad14602d575b600080fd5b60336047565b604051603e91906066565b60405180910390f35b60005a905090565b6000819050919050565b606081604f565b82525050565b6000602082019050607960008301846059565b9291505056fea26469706673582212205a5bd8713997a517191580430600d0387c0a224bc73a9ae59c6ce4e7da11beb064736f6c63430008120033"
                    }
                }
            ]

            result = await send_rpc_request_to_eth_client(
                self.ethereum_node_url, "eth_call", params
            )
            if (
                "error" not in result
                or "execution reverted" not in result["error"]["message"]
            ):
                raise ValueError("simulateHandleOp didn't revert!")

            elif (
                "data" not in result["error"] or len(result["error"]["data"]) < 10
            ):
                raise ValidationException(
                    ValidationExceptionCode.SimulateValidation,
                    result["error"]["message"],
                    "",
                )

            error_data = result["error"]["data"]
            solidity_error_selector = str(error_data[:10])
            solidity_error_params = error_data[10:]

            if solidity_error_selector == "0x8b7ac980":
                preOpGas, paid, targetSuccess, targetResult = self.validation_manager.decode_ExecutionResult(solidity_error_params)
            else:
                (
                    _,
                    reason,
                ) = ValidationManager.decode_FailedOp_event(
                    solidity_error_params
                )
                raise ValidationException(
                    ValidationExceptionCode.SimulateValidation,
                    reason,
                    "",
                )

            return preOpGas, paid, targetSuccess, targetResult


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