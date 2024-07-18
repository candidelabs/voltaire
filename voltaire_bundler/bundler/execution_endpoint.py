import asyncio
import logging
import math
import os
from typing import Any, List

from voltaire_bundler.bundler.exceptions import (ExecutionException,
                                                 ValidationException,
                                                 ValidationExceptionCode)
from voltaire_bundler.bundler.gas_manager import GasManager
from voltaire_bundler.bundler.mempool.mempool_info import DEFAULT_MEMPOOL_INFO
from voltaire_bundler.cli_manager import EntrypointType, MempoolType
from voltaire_bundler.event_bus_manager.endpoint import Client, Endpoint
from voltaire_bundler.typing import Address, MempoolId
from voltaire_bundler.user_operation.user_operation import (
    UserOperation, is_user_operation_hash)
from voltaire_bundler.user_operation.user_operation_handler import \
    UserOperationHandler
from voltaire_bundler.utils.eth_client_utils import get_latest_block_info

from .bundle.bundle_manager import BundlerManager
from .mempool.mempool_manager import (LocalMempoolManager,
                                      LocalMempoolManagerVersion0Point6)
from .reputation_manager import ReputationManager, ReputationStatus
from .validation_manager import ValidationManager


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
    entrypoints_to_local_mempools: dict[Address, LocalMempoolManager]
    entrypoints_to_mempools_types_to_mempools_ids: dict[
        Address, dict[MempoolType, MempoolId]
    ]
    entrypoints_lowercase_to_checksummed: dict[Address, Address]
    p2pClient: Client
    peer_ids_to_cursor: dict[str, int]
    peer_ids_to_user_ops_hashes_queue: dict[str, List[str]]
    disabe_p2p: bool
    max_verification_gas: int
    max_call_data_gas: int

    def __init__(
        self,
        ethereum_node_url: str,
        bundler_private_key: str,
        bundler_address: Address,
        entrypoints: list[Address],
        bundler_helper_byte_code: str,
        entrypoint_mod_byte_code: str,
        chain_id: int,
        is_unsafe: bool,
        is_legacy_mode: bool,
        is_send_raw_transaction_conditional: bool,
        bundle_interval: int,
        whitelist_entity_storage_access: list,
        max_fee_per_gas_percentage_multiplier: int,
        max_priority_fee_per_gas_percentage_multiplier: int,
        enforce_gas_price_tolerance: int,
        ethereum_node_debug_trace_call_url: str,
        entrypoints_versions: List[EntrypointType],
        p2p_mempools_types_per_entrypoint: List[List[MempoolType]],
        p2p_mempools_ids_per_entrypoint: List[List[MempoolId]],
        disable_p2p: bool,
        max_verification_gas: int,
        max_call_data_gas: int,
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
        self.is_send_raw_transaction_conditional = is_send_raw_transaction_conditional
        self.bundle_interval = bundle_interval
        self.whitelist_entity_storage_access = whitelist_entity_storage_access
        self.max_fee_per_gas_percentage_multiplier = (
            max_fee_per_gas_percentage_multiplier
        )
        self.max_priority_fee_per_gas_percentage_multiplier = (
            max_priority_fee_per_gas_percentage_multiplier
        )

        self.reputation_manager = ReputationManager()

        self.gas_manager = GasManager(
            self.ethereum_node_url,
            chain_id,
            is_legacy_mode,
            max_fee_per_gas_percentage_multiplier,
            max_priority_fee_per_gas_percentage_multiplier,
            max_verification_gas,
            max_call_data_gas,
            entrypoint_mod_byte_code,
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
            for mempool_type, mempool_id in zip(
                entrypoint_mempools_types, entrypoint_mempool_ids
            ):
                if mempool_id is not None:
                    mempool_type_to_mempool_id[mempool_type] = mempool_id
                elif mempool_type == MempoolType.default:
                    if entrypoint in DEFAULT_MEMPOOL_INFO:
                        mempool_type_to_mempool_id[mempool_type] = DEFAULT_MEMPOOL_INFO[
                            entrypoint
                        ][chain_id]
                    else:
                        logging.error(
                            f"Entrypoint without default mempool ids : {entrypoint}, please specify the mempool id"
                        )
                        raise ValueError
                else:
                    logging.error(f"Unsupported mempool type : {mempool_type}")
                    raise ValueError
            self.entrypoints_to_mempools_types_to_mempools_ids[entrypoint] = (
                mempool_type_to_mempool_id
            )

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
                    mempool_type_to_mempool_id,
                )
            else:
                logging.error(f"Unsupported entrypoint version : {entrypoint_version}")
                raise ValueError

            self.entrypoints_to_local_mempools[entrypoint] = local_mempool_manager
            self.entrypoints_lowercase_to_checksummed[
                    Address(entrypoint.lower())] = entrypoint

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
        self.peer_ids_to_cursor = dict()
        self.peer_ids_to_user_ops_hashes_queue = dict()
        self.disable_p2p = disable_p2p

        asyncio.ensure_future(self.execute_cron_job())

    async def execute_cron_job(self) -> None:
        if self.disable_p2p:
            if self.bundle_interval > 0:
                while True:
                    try:
                        await self.bundle_manager.update_send_queue()
                        await self.bundle_manager.send_next_bundle()
                    except (ValidationException, ExecutionException) as excp:
                        logging.exception(excp.message)

                    await asyncio.sleep(self.bundle_interval)
        else:
            heartbeat_counter = 0
            heartbeat_interval = 0.1  # decisecond
            deciseconds_per_bundle = math.floor(
                self.bundle_interval / heartbeat_interval
            )

            while not os.path.exists("p2p_endpoint.ipc"):
                await asyncio.sleep(1)

            await self.send_pooled_user_op_hashes_to_all_peers()

            while True:
                try:
                    await self.update_p2p_gossip()
                    await self.update_p2p_peer_ids_to_user_ops_hashes_queue()
                    if self.bundle_interval > 0 and (
                        heartbeat_counter % deciseconds_per_bundle == 0
                    ):
                        await self.bundle_manager.update_send_queue()
                        await self.bundle_manager.send_next_bundle()
                except (ValidationException, ExecutionException) as excp:
                    logging.exception(excp.message)

                heartbeat_counter = heartbeat_counter + 1
                await asyncio.sleep(heartbeat_interval)

    async def send_pooled_user_op_hashes_to_all_peers(self):
        pass
        # await self.send_pooled_user_op_hashes_request("", 0)

    async def update_p2p_gossip(self) -> None:
        for mempool in self.entrypoints_to_local_mempools.values():
            requestEvents = mempool.create_p2p_gossip_requests()
            for requestEvent in requestEvents:
                await self.p2pClient.broadcast_only(requestEvent)
            mempool.verified_useroperations_standard_mempool_gossip_queue.clear()

    async def update_p2p_peer_ids_to_user_ops_hashes_queue(self) -> None:
        for (
            peer_id, user_ops_hashes
        ) in self.peer_ids_to_user_ops_hashes_queue.items():
            if len(user_ops_hashes) > 0:
                pooled_user_ops_by_hash_request = dict()
                pooled_user_ops_by_hash_request = {"hashes": user_ops_hashes}
                pooled_user_ops_by_hash_request_message = dict()
                pooled_user_ops_by_hash_request_message["id"] = "0"
                pooled_user_ops_by_hash_request_message["peer_id"] = peer_id
                pooled_user_ops_by_hash_request_message[
                    "pooled_user_ops_by_hash_request"
                ] = pooled_user_ops_by_hash_request

                await self.p2pClient.broadcast_only(
                    pooled_user_ops_by_hash_request_message
                )

                self.peer_ids_to_user_ops_hashes_queue[peer_id] = []

    async def start_execution_endpoint(self) -> None:
        self.add_events_and_response_functions_by_prefix(
            prefix="_event_", decorator_func=exception_handler_decorator
        )
        async with asyncio.TaskGroup() as task_group:
            task_group.create_task(self.start_server("bundler_endpoint.ipc"))

    async def _event_rpc_chainId(self, req_arguments: list) -> str:
        return hex(self.chain_id)

    async def _event_rpc_supportedEntryPoints(
            self, req_arguments: list) -> list:
        return list(self.entrypoints_to_local_mempools.keys())

    async def _event_rpc_estimateUserOperationGas(
            self, req_arguments: list) -> dict[str, str]:
        user_operation_with_optional_params = (
                fell_user_operation_optional_parameters(req_arguments[0])
        )
        user_operation: UserOperation = UserOperation(
                user_operation_with_optional_params)
        entrypoint_address: str = req_arguments[1]
        state_override_set_dict: dict[str, Any] = {}
        if req_arguments[2] is not None:
            state_override_set_dict: dict[str, Any] = req_arguments[2]

        if entrypoint_address not in self.entrypoints_to_local_mempools:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Unsupported entrypoint",
            )

        if state_override_set_dict is not None and not isinstance(
            state_override_set_dict, dict
        ):
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Invalide state override set",
            )

        (
            call_gas_limit_hex,
            preverification_gas_hex,
            verification_gas_hex,
        ) = await self.gas_manager.estimate_callgaslimit_and_preverificationgas_and_verificationgas(
            user_operation,
            entrypoint_address,
            state_override_set_dict,
        )

        estimated_gas_json = {
            "callGasLimit": call_gas_limit_hex,
            "preVerificationGas": preverification_gas_hex,
            "verificationGasLimit": verification_gas_hex,
        }

        return estimated_gas_json

    async def _event_rpc_sendUserOperation(self, req_arguments: list) -> str:
        user_operation: UserOperation = UserOperation(req_arguments[0])
        entrypoint_address = req_arguments[1]
        if entrypoint_address not in self.entrypoints_to_local_mempools:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Unsupported entrypoint",
            )

        (user_operation_hash, verified_at_block_hash, valid_mempools) = (
            await self.entrypoints_to_local_mempools[
                entrypoint_address
            ].add_user_operation(user_operation)
        )
        if not self.disable_p2p:
            self.entrypoints_to_local_mempools[
                entrypoint_address
            ].queue_verified_useroperation_to_gossip_publish(
                user_operation.get_user_operation_json(),
                verified_at_block_hash,
                valid_mempools,
            )

        return user_operation_hash

    async def _event_rpc_getUserOperationByHash(
            self, req_arguments: list) -> dict | None:
        user_operation_hash = req_arguments[0]

        if not is_user_operation_hash(user_operation_hash):
            raise ValidationException(
                ValidationExceptionCode.INVALID_USEROPHASH,
                "Missing/invalid userOpHash",
            )

        user_operation_by_hash_json = dict()
        for entrypoint in self.entrypoints_to_local_mempools:
            entrypoint_senders_mempools = self.entrypoints_to_local_mempools[
                entrypoint
            ].senders_to_senders_mempools.values()
            user_operation_by_hash_json = (
                await self.user_operation_handler.get_user_operation_by_hash_rpc(
                    user_operation_hash,
                    entrypoint,
                    entrypoint_senders_mempools,
                )
            )
        return user_operation_by_hash_json

    async def _event_rpc_getUserOperationReceipt(
            self, req_arguments: list) -> dict | None:
        user_operation_hash = req_arguments[0]

        if not is_user_operation_hash(user_operation_hash):
            raise ValidationException(
                ValidationExceptionCode.INVALID_USEROPHASH,
                "Missing/invalid userOpHash",
            )

        user_operation_receipt_info_json = dict()
        for entrypoint in self.entrypoints_to_local_mempools:
            user_operation_receipt_info_json = (
                await self.user_operation_handler.get_user_operation_receipt_rpc(
                    user_operation_hash, entrypoint
                )
            )

        return user_operation_receipt_info_json

    async def _event_debug_bundler_sendBundleNow(self, _) -> str:
        await self.bundle_manager.update_send_queue()
        await self.bundle_manager.send_next_bundle()

        return "ok"

    async def _event_debug_bundler_clearState(
            self, req_arguments: list) -> str:
        for mempool_manager in self.entrypoints_to_local_mempools.values():
            mempool_manager.clear_user_operations()

        return "ok"

    async def _event_debug_bundler_dumpMempool(
            self, req_arguments: list) -> list[dict[str, str]]:
        entrypoint_address = req_arguments[0]
        if entrypoint_address not in self.entrypoints_to_local_mempools:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Unsupported entrypoint",
            )

        user_operations = self.entrypoints_to_local_mempools[
            entrypoint_address
        ].get_all_user_operations()
        user_operations_json = [
            user_operation.get_user_operation_json()
            for user_operation in user_operations
        ]
        return user_operations_json

    async def _event_debug_bundler_setReputation(
            self, req_arguments: list) -> str:
        entitiy = req_arguments[0]
        ops_seen = req_arguments[1]
        ops_included = req_arguments[2]
        status = req_arguments[3]

        self.reputation_manager.set_reputation(
                entitiy, ops_seen, ops_included, status)

        return "ok"

    async def _event_debug_bundler_dumpReputation(
            self, req_arguments: list) -> dict:
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

    async def _event_p2p_received_gossib(self, req_arguments: dict) -> None:
        peer_id = req_arguments["peer_id"]
        topic = req_arguments["topic"]
        verified_useroperation = req_arguments["verified_useroperation"]
        entry_point = verified_useroperation["entry_point_contract"]
        verified_at_block_hash = verified_useroperation["verified_at_block_hash"]

        if entry_point in self.entrypoints_lowercase_to_checksummed:
            entry_point = self.entrypoints_lowercase_to_checksummed[entry_point]
        else:
            logging.debug(
                f"Dropping gossib from unsupported entrypoint : {entry_point}"
            )

        if self.reputation_manager.get_status(peer_id) == ReputationStatus.BANNED:
            logging.debug(f"Dropping gossib from banned peer : {peer_id}")

        try:
            user_operation_obj = UserOperation(
                    verified_useroperation["user_operation"])

            await self.entrypoints_to_local_mempools[
                entry_point
            ].add_user_operation_p2p(
                user_operation_obj, peer_id, verified_at_block_hash
            )

        except ValidationException:
            self.reputation_manager.ban_entity(peer_id)

    async def _event_p2p_pooled_user_op_hashes_received(
        self, req_arguments: dict
    ) -> dict:
        cursor = req_arguments["cursor"]

        for local_mempool in self.entrypoints_to_local_mempools.values():
            for (
                mempool_id
            ) in local_mempool.supported_mempools_types_to_mempools_ids.values():
                user_operations_hashs, next_cursor = (
                    local_mempool.get_user_operations_hashes_with_mempool_id(
                        mempool_id, cursor
                    )
                )  # TODO: collect from multiple mempools
                pooled_user_op_hashes = {
                    "next_cursor": next_cursor,
                    "hashes": user_operations_hashs,
                }
                return pooled_user_op_hashes
        return {"next_cursor": 0, "hashes": []}

    async def _event_p2p_received_pooled_user_op_hashes_response(
        self, req_arguments: dict
    ) -> None:
        peer_id = req_arguments["peer_id"]
        pooled_user_op_hashes = req_arguments["pooled_user_op_hashes"]

        hashes = pooled_user_op_hashes["hashes"]
        next_cursor = pooled_user_op_hashes["next_cursor"]

        if peer_id not in self.peer_ids_to_cursor:
            self.peer_ids_to_cursor[peer_id] = 0

        if peer_id not in self.peer_ids_to_user_ops_hashes_queue:
            self.peer_ids_to_user_ops_hashes_queue[peer_id] = []

        if next_cursor > 0:
            await self.send_pooled_user_op_hashes_request(
                peer_id, self.peer_ids_to_cursor[peer_id] + 1
            )

        self.peer_ids_to_user_ops_hashes_queue[peer_id] += hashes

    async def _event_p2p_pooled_user_ops_by_hash_received(
        self, req_arguments: dict
    ) -> dict:
        user_operations_hashes = list(
            map(lambda hash: "0x" + bytes(hash).hex(), req_arguments["hashes"])
        )
        user_operations_to_return = []
        for local_mempool in self.entrypoints_to_local_mempools.values():
            (
                verified_user_operations_json, remaining_user_operation_hashes
            ) = (
                local_mempool.get_user_operations_by_hashes(user_operations_hashes)
            )
            user_operations_hashes = remaining_user_operation_hashes
            user_operations_to_return += verified_user_operations_json

        return {"list": user_operations_to_return}

    async def _event_p2p_received_pooled_user_ops_by_hash_response(
        self, req_arguments: dict
    ) -> str:
        verified_useroperation = req_arguments["list"]
        # TODO
        return "Ok"

    async def _event_p2p_status_received(
            self, _req_arguments: dict) -> dict[str, int | bytes]:
        (
            latest_block_number, _, _, _, latest_block_hash
        ) = await get_latest_block_info(
            self.ethereum_node_url
        )
        return {
            "chain_id": self.chain_id,
            "block_hash": bytes.fromhex(latest_block_hash[2:]),
            "block_number": int(latest_block_number, 16),
        }

    async def send_pooled_user_op_hashes_request(
            self, peer_id, cursor) -> None:
        for (
            mempools_types_to_mempools_ids
        ) in self.entrypoints_to_mempools_types_to_mempools_ids.values():
            for mempools_id in mempools_types_to_mempools_ids.values():
                pooled_user_op_hashes_message = dict()
                pooled_user_op_hashes_request = dict()
                pooled_user_op_hashes_request = {"cursor": cursor}
                pooled_user_op_hashes_message["id"] = "0"
                pooled_user_op_hashes_message["peer_id"] = peer_id
                pooled_user_op_hashes_message["pooled_user_op_hashes_request"] = (
                    pooled_user_op_hashes_request
                )

                # await self.p2pClient.broadcast_only(pooled_user_op_hashes_message)


async def exception_handler_decorator(
    response_function, rpc_call_request: dict
) -> dict:
    try:
        rpc_call_response = await response_function(rpc_call_request)
        return rpc_call_response

    except (ExecutionException, ValidationException) as excp:
        rpc_call_response = {"payload": excp, "is_error": True}
        return rpc_call_response


def fell_user_operation_optional_parameters(
        user_operation_with_optional_params: dict[str, str]) -> dict[str, str]:
    if (
        "preVerificationGas" not in user_operation_with_optional_params
        or
        user_operation_with_optional_params["preVerificationGas"] is None
    ):
        user_operation_with_optional_params["preVerificationGas"] = "0x"
    if (
        "verificationGasLimit" not in user_operation_with_optional_params
        or
        user_operation_with_optional_params["verificationGasLimit"] is None
    ):
        user_operation_with_optional_params["verificationGasLimit"] = "0x"
    if (
        "callGasLimit" not in user_operation_with_optional_params
        or
        user_operation_with_optional_params["callGasLimit"] is None
    ):
        user_operation_with_optional_params["callGasLimit"] = "0x"
    if (
        "maxFeePerGas" not in user_operation_with_optional_params
        or
        user_operation_with_optional_params["maxFeePerGas"] is None
    ):
        user_operation_with_optional_params["maxFeePerGas"] = "0x"
    if (
        "maxPriorityFeePerGas" not in user_operation_with_optional_params
        or
        user_operation_with_optional_params["maxPriorityFeePerGas"] is None
    ):
        user_operation_with_optional_params["maxPriorityFeePerGas"] = "0x"

    return user_operation_with_optional_params
