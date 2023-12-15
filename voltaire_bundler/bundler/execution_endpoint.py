import asyncio
import logging
import os
from typing import List
import math
from voltaire_bundler.bundler.mempool.mempool_info import DEFAULT_MEMPOOL_INFO

from voltaire_bundler.event_bus_manager.endpoint import Client, Endpoint, RequestEvent

from voltaire_bundler.bundler.exceptions import (
    ExecutionException,
    ExecutionExceptionCode,
)
from voltaire_bundler.user_operation.user_operation import (
    UserOperation,
    is_user_operation_hash,
)

from .mempool.mempool_manager import LocalMempoolManager, LocalMempoolManagerVersion0Point6
from voltaire_bundler.user_operation.user_operation_handler import (
    UserOperationHandler,
)
from voltaire_bundler.bundler.exceptions import (
    ValidationException,
    ValidationExceptionCode,
    ExecutionException,
)
from .bundle.bundle_manager import BundlerManager
from .validation_manager import ValidationManager
from .reputation_manager import ReputationManager, ReputationStatus
from voltaire_bundler.bundler.gas_manager import GasManager
from voltaire_bundler.boot import EntrypointType, MempoolType
from voltaire_bundler.typing import Address, MempoolId

class ExecutionEndpoint(Endpoint):
    ethereum_node_url: str
    bundler_private_key: str
    bundler_address: Address
    bundle_manager: BundlerManager
    validation_manager: ValidationManager
    user_operation_handler: UserOperationHandler
    reputation_manager: ReputationManager
    gas_manager: GasManager
    bundler_helper_byte_code: str
    chain_id: int
    is_unsafe: bool
    is_legacy_mode: bool
    is_send_raw_transaction_conditional: bool
    bundle_interval: int
    whitelist_entity_storage_access: list[str]
    max_fee_per_gas_percentage_multiplier: int
    max_priority_fee_per_gas_percentage_multiplier: int
    enforce_gas_price_tolerance: int
    entrypoints_to_local_mempools: dict[Address,LocalMempoolManager]
    entrypoints_to_mempools_types_to_mempools_ids: dict[Address,dict[MempoolType,MempoolId]]
    entrypoints_lowercase_to_checksummed: dict[Address,Address]
    p2pClient: Client
    peer_ids_to_offset: dict[str,int]
    peer_ids_to_user_ops_hashes_queue: dict[str,List[str]]

    def __init__(
        self,
        ethereum_node_url: str,
        bundler_private_key: str,
        bundler_address: str,
        entrypoints: str,
        bundler_helper_byte_code: str,
        chain_id: str,
        is_unsafe: bool,
        is_legacy_mode: bool,
        is_send_raw_transaction_conditional: bool,
        bundle_interval: int,
        whitelist_entity_storage_access: list(),
        max_fee_per_gas_percentage_multiplier: int,
        max_priority_fee_per_gas_percentage_multiplier: int,
        enforce_gas_price_tolerance:int,
        ethereum_node_debug_trace_call_url:str,
        entrypoints_versions: List[str],
        p2p_mempools_types_per_entrypoint: List[List[str]],
        p2p_mempools_ids_per_entrypoint: List[List[str]],
    ):
        super().__init__("bundler_endpoint")
        self.ethereum_node_url = ethereum_node_url
        self.bundler_private_key = bundler_private_key
        self.bundler_address = bundler_address
        self.entrypoints = entrypoints

        self.bundler_helper_byte_code = bundler_helper_byte_code
        self.chain_id = chain_id
        self.is_unsafe = is_unsafe
        self.is_legacy_mode = is_legacy_mode
        self.is_send_raw_transaction_conditional = (
            is_send_raw_transaction_conditional
        )
        self.bundle_interval = bundle_interval
        self.whitelist_entity_storage_access = whitelist_entity_storage_access
        self.max_fee_per_gas_percentage_multiplier = max_fee_per_gas_percentage_multiplier
        self.max_priority_fee_per_gas_percentage_multiplier = max_priority_fee_per_gas_percentage_multiplier

        self.reputation_manager = ReputationManager()

        self.gas_manager = GasManager(
            self.ethereum_node_url,
            chain_id,
            is_legacy_mode,
            max_fee_per_gas_percentage_multiplier,
            max_priority_fee_per_gas_percentage_multiplier,
        )

        self.user_operation_handler = UserOperationHandler(
            ethereum_node_url,
            bundler_private_key,
            bundler_address,
            is_legacy_mode,
        )

        self.validation_manager = ValidationManager(
            self.user_operation_handler,
            ethereum_node_url,
            self.gas_manager,
            bundler_private_key,
            bundler_address,
            chain_id,
            bundler_helper_byte_code,
            is_unsafe,
            is_legacy_mode,
            whitelist_entity_storage_access,
            enforce_gas_price_tolerance,
            ethereum_node_debug_trace_call_url,
        )
        self.entrypoints_to_local_mempools = dict()
        self.entrypoints_lowercase_to_checksummed = dict()
        self.entrypoints_to_mempools_types_to_mempools_ids = dict()

        for (
                entrypoint,
                entrypoint_version,
                entrypoint_mempools_types,
                entrypoint_mempool_ids,
            ) in zip(
                entrypoints,
                entrypoints_versions,
                p2p_mempools_types_per_entrypoint,
                p2p_mempools_ids_per_entrypoint,
            ):
            mempool_type_to_mempool_id = dict()
            for mempool_type, mempool_id in zip(entrypoint_mempools_types, entrypoint_mempool_ids):
                if mempool_id is not None:
                    mempool_type_to_mempool_id[mempool_type] = mempool_id
                elif mempool_type == MempoolType.default:
                    if entrypoint in DEFAULT_MEMPOOL_INFO:
                        mempool_type_to_mempool_id[mempool_type] = DEFAULT_MEMPOOL_INFO[entrypoint][chain_id]
                    else:
                        logging.error(f"Entrypoint without default mempool ids : {entrypoint}, please specify the mempool id")
                        raise ValueError
                else:
                    logging.error(f"Unsupported mempool type : {mempool_type}")
                    raise ValueError
            self.entrypoints_to_mempools_types_to_mempools_ids[entrypoint] = mempool_type_to_mempool_id

            if entrypoint_version in EntrypointType:
                local_mempool_manager = LocalMempoolManagerVersion0Point6(
                    self.validation_manager,
                    self.user_operation_handler,
                    self.reputation_manager,
                    self.gas_manager,
                    ethereum_node_url,
                    bundler_private_key,
                    bundler_address,
                    entrypoint,
                    chain_id,
                    is_unsafe,
                    enforce_gas_price_tolerance,
                    mempool_type_to_mempool_id
                )
            else:
                logging.error(f"Unsupported entrypoint version : {entrypoint_version}")
                raise ValueError

            self.entrypoints_to_local_mempools[entrypoint] = local_mempool_manager
            self.entrypoints_lowercase_to_checksummed[entrypoint.lower()] = entrypoint

        self.p2pClient: Client = Client("p2p_endpoint")

        self.bundle_manager = BundlerManager(
            self.entrypoints_to_local_mempools,
            self.user_operation_handler,
            self.reputation_manager,
            self.gas_manager,
            ethereum_node_url,
            bundler_private_key,
            bundler_address,
            chain_id,
            is_legacy_mode,
            is_send_raw_transaction_conditional,
            max_fee_per_gas_percentage_multiplier,
            max_priority_fee_per_gas_percentage_multiplier,
        )
        self.peer_ids_to_offset = dict()
        self.peer_ids_to_user_ops_hashes_queue = dict()

        asyncio.ensure_future(self.execute_cron_job())

    async def execute_cron_job(self) -> None:
        heartbeat_counter = 0
        heartbeat_interval = 0.1 #decisecond
        deciseconds_per_bundle = math.floor(self.bundle_interval / heartbeat_interval)
        
        while not os.path.exists("p2p_endpoint.ipc"):
            await asyncio.sleep(1)

        await self.send_pooled_user_op_hashes_to_all_peers()

        while True:
            try:
                await self.update_p2p_gossip()
                await self.update_p2p_peer_ids_to_user_ops_hashes_queue()
                if self.bundle_interval > 0 and (heartbeat_counter % deciseconds_per_bundle == 0):
                    await self.bundle_manager.send_next_bundle()
            except (ValidationException, ExecutionException) as excp:
                logging.exception(excp.message)

            heartbeat_counter = heartbeat_counter + 1
            await asyncio.sleep(heartbeat_interval)

    async def send_pooled_user_op_hashes_to_all_peers(self):
        await self.send_pooled_user_op_hashes_request("", 0)
    
    async def update_p2p_gossip(self) -> None:
        for mempool in self.entrypoints_to_local_mempools.values():
            requestEvents = mempool.create_p2p_gossip_requests()
            for requestEvent in requestEvents:
                await self.p2pClient.broadcast_only(requestEvent)
            mempool.verified_block_to_useroperations_standard_mempool_gossip_queue.clear()

    async def update_p2p_peer_ids_to_user_ops_hashes_queue(self) -> None:
        for peer_id, user_ops_hashes in self.peer_ids_to_user_ops_hashes_queue.items():
            if len(user_ops_hashes) > 0:
                pooled_user_ops_by_hash_request = dict()
                pooled_user_ops_by_hash_request = {"hashes" : user_ops_hashes}
                pooled_user_ops_by_hash_request_message = dict()
                pooled_user_ops_by_hash_request_message["id"] = "0"
                pooled_user_ops_by_hash_request_message["peer_id"] = peer_id
                pooled_user_ops_by_hash_request_message["pooled_user_ops_by_hash_request"] = pooled_user_ops_by_hash_request

                await self.p2pClient.broadcast_only(pooled_user_ops_by_hash_request_message)

                self.peer_ids_to_user_ops_hashes_queue[peer_id] = []

    async def start_execution_endpoint(self) -> None:
        self.add_events_and_response_functions_by_prefix(
            prefix="_event_", decorator_func=exception_handler_decorator
        )
        async with asyncio.TaskGroup() as task_group:
            task_group.create_task(self.start_server("bundler_endpoint.ipc"))
            task_group.create_task(self.start_server("p2p_listen_endpoint.ipc"))

    async def _event_rpc_chainId(
        self, req_arguments: []
    ) -> str:
        return hex(self.chain_id)

    async def _event_rpc_supportedEntryPoints(
        self, req_arguments: []
    ) -> str:
        return list(self.entrypoints_to_local_mempools.keys())

    async def _event_rpc_estimateUserOperationGas(
        self, req_arguments: []
    ) -> dict:
        user_operation: UserOperation = UserOperation(req_arguments[0])
        entrypoint_address = req_arguments[1]
        if entrypoint_address not in self.entrypoints_to_local_mempools:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Unsupported entrypoint",
            )

        (
            call_gas_limit_hex,
            preverification_gas_hex,
            verification_gas_hex,
        ) = await self.gas_manager.estimate_callgaslimit_and_preverificationgas_and_verificationgas(
            user_operation, 
            entrypoint_address,
        )

        estimated_gas_json = {
            "callGasLimit": call_gas_limit_hex,
            "preVerificationGas": preverification_gas_hex,
            "verificationGasLimit": verification_gas_hex,
        }

        return estimated_gas_json

    async def _event_rpc_sendUserOperation(
        self, req_arguments: []
    ) -> str:
        user_operation: UserOperation = UserOperation(req_arguments[0])
        entrypoint_address = req_arguments[1]
        if entrypoint_address not in self.entrypoints_to_local_mempools:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Unsupported entrypoint",
            )

        (
            user_operation_hash, 
            verified_at_block_hash, 
            valid_mempools
        ) = await self.entrypoints_to_local_mempools[entrypoint_address].add_user_operation(
            user_operation
        )
        self.entrypoints_to_local_mempools[entrypoint_address].queue_useroperations_with_entrypoint_to_gossip_publish(
            user_operation.get_user_operation_json(),
            verified_at_block_hash, 
            valid_mempools
        )

        return user_operation_hash
    
    
    
    async def _event_rpc_getUserOperationByHash(
        self, req_arguments: []
    ) -> dict:
        user_operation_hash = req_arguments[0]

        if not is_user_operation_hash(user_operation_hash):
            raise ValidationException(
                ValidationExceptionCode.INVALID_USEROPHASH,
                "Missing/invalid userOpHash",
            )
        for entrypoint in self.entrypoints_to_local_mempools:
            user_operation_by_hash_json = (
                await self.user_operation_handler.get_user_operation_by_hash_rpc(
                    user_operation_hash, entrypoint
                )
            )
        return user_operation_by_hash_json

    async def _event_rpc_getUserOperationReceipt(
        self, req_arguments: []
    ) -> dict:
        user_operation_hash = req_arguments[0]

        if not is_user_operation_hash(user_operation_hash):
            raise ValidationException(
                ValidationExceptionCode.INVALID_USEROPHASH,
                "Missing/invalid userOpHash",
            )
        
        for entrypoint in self.entrypoints_to_local_mempools:
            user_operation_receipt_info_json = (
                await self.user_operation_handler.get_user_operation_receipt_rpc(
                    user_operation_hash, entrypoint
                )
            )

        return user_operation_receipt_info_json

    async def _event_debug_bundler_sendBundleNow(
        self, req_arguments: []
    ) -> None:
        await self.bundle_manager.send_next_bundle()

        return "ok"

    async def _event_debug_bundler_clearState(
        self, req_arguments: []
    ) -> str:
        for mempool_manager in self.entrypoints_to_local_mempools.values():
            mempool_manager.clear_user_operations()

        return "ok"

    async def _event_debug_bundler_dumpMempool(
        self, req_arguments: []
    ) -> str:
        entrypoint_address = req_arguments[0]
        if entrypoint_address not in self.entrypoints_to_local_mempools:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Unsupported entrypoint",
            )

        user_operations = self.entrypoints_to_local_mempools[entrypoint_address].get_all_user_operations()
        user_operations_json = [
            user_operation.get_user_operation_json()
            for user_operation in user_operations
        ]
        return user_operations_json

    async def _event_debug_bundler_setReputation(
        self, req_arguments: []
    ) -> str:
        entitiy = req_arguments[0]
        ops_seen = req_arguments[1]
        ops_included = req_arguments[2]
        status = req_arguments[3]

        self.reputation_manager.set_reputation(
            entitiy, ops_seen, ops_included, status
        )

        return "ok"

    async def _event_debug_bundler_dumpReputation(
        self, req_arguments: []
    ) -> dict:
        entrypoint_address = req_arguments[0]
        if entrypoint_address not in self.entrypoints_to_local_mempools:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Unsupported entrypoint",
            )


        entities_reputation_json = (
            self.reputation_manager.get_entities_reputation_json()
        )
        return entities_reputation_json
    
    async def _event_p2p_received_gossib(
        self, req_arguments: dict
    ) -> None:
        peer_id = req_arguments["peer_id"]
        topic = req_arguments["topic"]
        useroperations_with_entrypoint = req_arguments["useroperations_with_entrypoint"]
        entry_point_contract = useroperations_with_entrypoint["entry_point_contract"]
        verified_at_block_hash = useroperations_with_entrypoint["verified_at_block_hash"]
        chain_id = useroperations_with_entrypoint["chain_id"]

        if entry_point_contract in self.entrypoints_lowercase_to_checksummed:
            entry_point_contract = self.entrypoints_lowercase_to_checksummed[entry_point_contract]
        else:
            logging.debug(
                f"Dropping gossib from unsupported entrypoint : {entry_point_contract}"
            )

        if self.reputation_manager.get_status(peer_id) == ReputationStatus.BANNED:
            logging.debug(
                f"Dropping gossib from banned peer : {peer_id}"
            )

        if chain_id != hex(self.chain_id):
            logging.debug(
                f"Dropping gossib from unsupported chain id : {chain_id}"
            )
        is_ok = True
        for user_operation in useroperations_with_entrypoint["user_operations"]:
            try:
                user_operation_obj = UserOperation(user_operation)
           
                ret = await self.entrypoints_to_local_mempools[entry_point_contract].add_user_operation_p2p(
                            user_operation_obj, peer_id, verified_at_block_hash
                )

            except ValidationException as excp:
                self.reputation_manager.ban_entity(peer_id)
                break
    
    async def _event_p2p_pooled_user_op_hashes_received(
        self, req_arguments: dict
    ) -> None:
        mempool = bytes(req_arguments["mempool"]).decode("ascii")
        offset = req_arguments["offset"]
        
        for local_mempool in self.entrypoints_to_local_mempools.values():
            for mempool_id in local_mempool.supported_mempools_types_to_mempools_ids.values():
                if mempool_id == mempool:
                    user_operations_hashs, more_flag = local_mempool.get_user_operations_hashes_with_mempool_id(
                        mempool,
                        offset
                    )
                    pooled_user_op_hashes = {
                        "more_flag" : more_flag, 
                        "hashes" : user_operations_hashs,
                    }
                    return pooled_user_op_hashes
        return {"more_flag" : 0, "hashes" : []}

    async def _event_p2p_received_pooled_user_op_hashes_response(
        self, req_arguments: dict
    ) -> None:
        peer_id = req_arguments["peer_id"]
        pooled_user_op_hashes = req_arguments["pooled_user_op_hashes"]

        hashes = pooled_user_op_hashes["hashes"]
        more_flag = pooled_user_op_hashes["more_flag"]

        if peer_id not in self.peer_ids_to_offset:
            self.peer_ids_to_offset[peer_id] = 0

        if peer_id not in self.peer_ids_to_user_ops_hashes_queue:
            self.peer_ids_to_user_ops_hashes_queue[peer_id] = []

        if more_flag > 0:
            await self.send_pooled_user_op_hashes_request(
                peer_id,
                self.peer_ids_to_offset[peer_id] + 1
                )

        self.peer_ids_to_user_ops_hashes_queue[peer_id] += hashes
        
    async def _event_p2p_pooled_user_ops_by_hash_received(
        self, req_arguments: dict
    ) -> None:
        user_operations_hashes = list(map(lambda hash: "0x" + bytes(hash).hex(), req_arguments["hashes"]))
        user_operations_to_return = []
        for local_mempool in self.entrypoints_to_local_mempools.values():
            (
                user_operations,
                remaining_user_operation_hashes
            ) = local_mempool.get_user_operations_by_hashes(
                user_operations_hashes
            )
            user_operations_hashes = remaining_user_operation_hashes
            user_operations_to_return += user_operations

        return {"list" : user_operations_to_return}
    
    async def _event_p2p_received_pooled_user_ops_by_hash_response(
        self, req_arguments: dict
    ) -> None:
        useroperations = req_arguments["list"]

        return "Ok"
    
    async def send_pooled_user_op_hashes_request(self, peer_id, offset):
        for mempools_types_to_mempools_ids in self.entrypoints_to_mempools_types_to_mempools_ids.values():
            for mempools_id in mempools_types_to_mempools_ids.values():
                pooled_user_op_hashes_message = dict()
                pooled_user_op_hashes_request = dict()
                pooled_user_op_hashes_request["mempool"] = list(bytes(mempools_id, 'ascii'))
                pooled_user_op_hashes_request["offset"] = offset
                pooled_user_op_hashes_message["id"] = "0"
                pooled_user_op_hashes_message["peer_id"] = peer_id
                pooled_user_op_hashes_message["pooled_user_op_hashes_request"] = pooled_user_op_hashes_request

                await self.p2pClient.broadcast_only(pooled_user_op_hashes_message)

async def exception_handler_decorator(
    response_function, rpc_call_request: dict
) -> dict:
    try:
        rpc_call_response = await response_function(rpc_call_request)
        return rpc_call_response

    except (ExecutionException, ValidationException) as excp:
        rpc_call_response = {
            "payload" : excp,
            "is_error" : True
        }
        return rpc_call_response