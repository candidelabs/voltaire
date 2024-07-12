import asyncio
import logging
import math
import os
from typing import Any, Optional

from voltaire_bundler.bundle.exceptions import \
    ExecutionException, ValidationException, ValidationExceptionCode
from voltaire_bundler.cli_manager import ConditionalRpc
from voltaire_bundler.event_bus_manager.endpoint import Client, Endpoint
from voltaire_bundler.typing import Address
from voltaire_bundler.user_operation.user_operation_handler import get_deposit_info
from voltaire_bundler.user_operation.v6.user_operation_v6 import UserOperationV6
from voltaire_bundler.user_operation.v7.user_operation_v7 import UserOperationV7
from voltaire_bundler.user_operation.user_operation import is_user_operation_hash
from voltaire_bundler.user_operation.v6.user_operation_handler_v6 import \
    UserOperationHandlerV6
from voltaire_bundler.user_operation.v7.user_operation_handler_v7 import \
    UserOperationHandlerV7
from voltaire_bundler.user_operation.user_operation_handler import \
    fell_user_operation_optional_parameters
from voltaire_bundler.utils.eth_client_utils import get_latest_block_info

from .bundle.bundle_manager import BundlerManager
from .mempool.v6.mempool_manager_v6 import LocalMempoolManagerV6
from .mempool.v7.mempool_manager_v7 import LocalMempoolManagerV7
from .mempool.reputation_manager import ReputationManager


class ExecutionEndpoint(Endpoint):
    ethereum_node_url: str
    bundle_manager: BundlerManager
    user_operation_handler_v6: Optional[UserOperationHandlerV6]
    user_operation_handler_v7: UserOperationHandlerV7
    reputation_manager: ReputationManager
    chain_id: int
    local_mempool_manager_v6: Optional[LocalMempoolManagerV6]
    local_mempool_manager_v7: LocalMempoolManagerV7
    peer_ids_to_cursor: dict[str, int]
    peer_ids_to_user_ops_hashes_queue: dict[str, list[str]]
    disabe_p2p: bool

    def __init__(
        self,
        ethereum_node_url: str,
        bundler_private_key: str,
        bundler_address: Address,
        chain_id: int,
        is_unsafe: bool,
        is_debug: bool,
        is_legacy_mode: bool,
        conditional_rpc: ConditionalRpc | None,
        bundle_interval: int,
        max_fee_per_gas_percentage_multiplier: int,
        max_priority_fee_per_gas_percentage_multiplier: int,
        enforce_gas_price_tolerance: int,
        ethereum_node_debug_trace_call_url: str,
        ethereum_node_eth_get_logs_url: str,
        disable_p2p: bool,
        max_verification_gas: int,
        max_call_data_gas: int,
        disable_v6: bool,
        logs_incremental_range: int,
        logs_number_of_ranges: int,
    ):
        super().__init__("bundler_endpoint")
        self.ethereum_node_url = ethereum_node_url
        self.chain_id = chain_id

        self.user_operation_handler_v7 = UserOperationHandlerV7(
            chain_id,
            ethereum_node_url,
            bundler_address,
            is_legacy_mode,
            ethereum_node_eth_get_logs_url,
            max_fee_per_gas_percentage_multiplier,
            max_priority_fee_per_gas_percentage_multiplier,
            max_verification_gas,
            max_call_data_gas,
            logs_incremental_range,
            logs_number_of_ranges,
        )

        self.local_mempool_manager_v7 = LocalMempoolManagerV7(
            self.user_operation_handler_v7,
            ethereum_node_url,
            bundler_address,
            chain_id,
            is_unsafe,
            enforce_gas_price_tolerance,
            is_legacy_mode,
            ethereum_node_debug_trace_call_url,
        )

        if disable_v6:
            self.user_operation_handler_v6 = None
            self.local_mempool_manager_v6 = None
        else:
            self.user_operation_handler_v6 = UserOperationHandlerV6(
                chain_id,
                ethereum_node_url,
                bundler_address,
                is_legacy_mode,
                ethereum_node_eth_get_logs_url,
                max_fee_per_gas_percentage_multiplier,
                max_priority_fee_per_gas_percentage_multiplier,
                max_verification_gas,
                max_call_data_gas,
                logs_incremental_range,
                logs_number_of_ranges,
            )

            self.local_mempool_manager_v6 = LocalMempoolManagerV6(
                self.user_operation_handler_v6,
                ethereum_node_url,
                bundler_address,
                chain_id,
                is_unsafe,
                enforce_gas_price_tolerance,
                is_legacy_mode,
                ethereum_node_debug_trace_call_url,
            )

        self.bundle_manager = BundlerManager(
            self.local_mempool_manager_v6,
            self.local_mempool_manager_v7,
            ethereum_node_url,
            bundler_private_key,
            bundler_address,
            chain_id,
            is_legacy_mode,
            conditional_rpc,
            max_fee_per_gas_percentage_multiplier,
            max_priority_fee_per_gas_percentage_multiplier,
        )
        self.peer_ids_to_cursor = dict()
        self.peer_ids_to_user_ops_hashes_queue = dict()
        self.disable_p2p = disable_p2p
        self.disable_v6 = disable_v6

        asyncio.ensure_future(self.execute_cron_job(is_debug, bundle_interval))

    async def execute_cron_job(self, is_debug: bool, bundle_interval: int) -> None:
        if not self.disable_p2p:
            heartbeat_counter = 0
            heartbeat_interval = 0.1  # decisecond
            deciseconds_per_bundle = math.floor(
                bundle_interval / heartbeat_interval
            )

            p2pClient: Client = Client("p2p_endpoint")
            while not os.path.exists("p2p_endpoint.ipc"):
                await asyncio.sleep(1)

            await self.send_pooled_user_op_hashes_to_all_peers()

            while True:
                try:
                    await self.update_p2p_gossip(p2pClient)
                    await self.update_p2p_peer_ids_to_user_ops_hashes_queue(p2pClient)
                    if (not is_debug) and (
                        heartbeat_counter % deciseconds_per_bundle == 0
                    ):
                        await self.bundle_manager.send_next_bundle()
                except (ValidationException, ExecutionException) as excp:
                    logging.exception(excp.message)

                heartbeat_counter = heartbeat_counter + 1
                await asyncio.sleep(heartbeat_interval)
        elif not is_debug:
            while True:
                try:
                    await self.bundle_manager.send_next_bundle()
                except (ValidationException, ExecutionException) as excp:
                    logging.exception(excp.message)

                await asyncio.sleep(bundle_interval)

    async def send_pooled_user_op_hashes_to_all_peers(self) -> None:
        pass
        # await self.send_pooled_user_op_hashes_request("", 0)

    async def update_p2p_gossip(self, p2pClient: Client) -> None:
        requestEvents = self.local_mempool_manager_v7.create_p2p_gossip_requests()
        if self.local_mempool_manager_v6 is not None:
            requestEvents += self.local_mempool_manager_v6.create_p2p_gossip_requests()
        for requestEvent in requestEvents:
            await p2pClient.broadcast_only(requestEvent)
        self.local_mempool_manager_v7.verified_useroperations_standard_mempool_gossip_queue.clear()
        if self.local_mempool_manager_v6 is not None:
            self.local_mempool_manager_v6.verified_useroperations_standard_mempool_gossip_queue.clear()

    async def update_p2p_peer_ids_to_user_ops_hashes_queue(
            self, p2pClient: Client) -> None:
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

                await p2pClient.broadcast_only(
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

    async def _event_rpc_supportedEntryPoints(self, _) -> list:
        entrypoints = [self.local_mempool_manager_v7.entrypoint]
        if self.local_mempool_manager_v6 is not None:
            entrypoints.append(self.local_mempool_manager_v6.entrypoint)
        return entrypoints

    async def _event_rpc_estimateUserOperationGas(
            self, req_arguments: list) -> dict[str, str]:
        state_override_set_dict: dict[str, Any] = {}
        if req_arguments[2] is not None:
            state_override_set_dict: dict[str, Any] = req_arguments[2]
            if not isinstance(state_override_set_dict, dict):
                raise ValidationException(
                    ValidationExceptionCode.InvalidFields,
                    "Invalide state override set",
                )

        entrypoint: Address = req_arguments[1]
        if entrypoint == LocalMempoolManagerV7.entrypoint:
            user_operation_with_optional_params = (
                fell_user_operation_optional_parameters(
                    req_arguments[0]))
            user_operation = UserOperationV7(
                user_operation_with_optional_params)
            gas_manager = self.user_operation_handler_v7.gas_manager
            (
                call_gas_limit_hex,
                preverification_gas_hex,
                verification_gas_hex,
            ) = await gas_manager.estimate_user_operation_gas(
                user_operation,
                entrypoint,
                state_override_set_dict,
            )
            estimated_gas_json = {
                "callGasLimit": call_gas_limit_hex,
                "preVerificationGas": preverification_gas_hex,
                "verificationGasLimit": verification_gas_hex,
            }
        elif (entrypoint == LocalMempoolManagerV6.entrypoint and
              self.user_operation_handler_v6 is not None):
            user_operation_with_optional_params = (
                fell_user_operation_optional_parameters(
                    req_arguments[0])
            )
            user_operation = UserOperationV6(
                user_operation_with_optional_params)
            gas_manager = self.user_operation_handler_v6.gas_manager
            (
                call_gas_limit_hex,
                preverification_gas_hex,
                verification_gas_hex,
            ) = await gas_manager.estimate_user_operation_gas(
                user_operation,
                entrypoint,
                state_override_set_dict,
            )
            estimated_gas_json = {
                "callGasLimit": call_gas_limit_hex,
                "preVerificationGas": preverification_gas_hex,
                "verificationGasLimit": verification_gas_hex,
            }
        else:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Unsupported entrypoint",
            )

        return estimated_gas_json

    async def _event_rpc_sendUserOperation(self, req_arguments: list) -> str:
        useroperation_arg = req_arguments[0]
        entrypoint = req_arguments[1]
        if entrypoint == LocalMempoolManagerV7.entrypoint:
            user_operation = UserOperationV7(useroperation_arg)
            local_mempool = self.local_mempool_manager_v7
        elif (entrypoint == LocalMempoolManagerV6.entrypoint and
                self.local_mempool_manager_v6 is not None):
            user_operation = UserOperationV6(useroperation_arg)
            local_mempool = self.local_mempool_manager_v6
        else:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Unsupported entrypoint",
            )

        (user_operation_hash, verified_at_block_hash, valid_mempools) = (
            await local_mempool.add_user_operation(user_operation)
        )
        if not self.disable_p2p:
            local_mempool.queue_verified_useroperation_to_gossip_publish(
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
                ValidationExceptionCode.InvalidFields,
                "Missing/invalid userOpHash",
            )

        if (self.local_mempool_manager_v6 is not None and
                self.user_operation_handler_v6 is not None):
            senders_mempools = (
                self.local_mempool_manager_v6.senders_to_senders_mempools.values()
            )
            user_operation_by_hash_json = (
                await self.user_operation_handler_v6.get_user_operation_by_hash_rpc(
                    user_operation_hash,
                    LocalMempoolManagerV6.entrypoint,
                    senders_mempools,
                )
            )
            if user_operation_by_hash_json is not None:
                return user_operation_by_hash_json

        senders_mempools = (
            self.local_mempool_manager_v7.senders_to_senders_mempools.values()
        )
        user_operation_by_hash_json = (
            await self.user_operation_handler_v7.get_user_operation_by_hash_rpc(
                user_operation_hash,
                LocalMempoolManagerV7.entrypoint,
                senders_mempools,
            )
        )
        return user_operation_by_hash_json

    async def _event_rpc_getUserOperationReceipt(
            self, req_arguments: list) -> dict | None:
        user_operation_hash = req_arguments[0]

        if not is_user_operation_hash(user_operation_hash):
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Missing/invalid userOpHash",
            )
        if self.user_operation_handler_v6 is not None:
            user_operation_receipt_info_json = (
                    await self.user_operation_handler_v6.get_user_operation_receipt_rpc(
                        user_operation_hash,
                        LocalMempoolManagerV6.entrypoint,
                    )
                )
            if user_operation_receipt_info_json is not None:
                return user_operation_receipt_info_json

        user_operation_receipt_info_json = (
                await self.user_operation_handler_v7.get_user_operation_receipt_rpc(
                    user_operation_hash,
                    LocalMempoolManagerV7.entrypoint,
                )
            )
        return user_operation_receipt_info_json

    async def _event_debug_bundler_sendBundleNow(self, _) -> str:
        await self.bundle_manager.send_next_bundle()

        return "ok"

    async def _event_debug_bundler_clearState(self, _) -> str:

        if self.local_mempool_manager_v6 is not None:
            self.local_mempool_manager_v6.clear_user_operations()
        self.local_mempool_manager_v7.clear_user_operations()

        return "ok"

    async def _event_debug_bundler_dumpMempool(
            self, req_arguments: list) -> list[dict[str, str | None]]:
        entrypoint = req_arguments[0]
        if entrypoint == LocalMempoolManagerV7.entrypoint:
            local_mempool = self.local_mempool_manager_v7
        elif (entrypoint == LocalMempoolManagerV6.entrypoint and
              self.local_mempool_manager_v6 is not None):
            local_mempool = self.local_mempool_manager_v6
        else:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Unsupported entrypoint",
            )

        user_operations = local_mempool.get_all_user_operations()
        user_operations_json = [
            user_operation.get_user_operation_json()
            for user_operation in user_operations
        ]
        return user_operations_json

    async def _event_debug_bundler_setReputation(
            self, req_arguments: list) -> str:
        entrypoint = req_arguments[1]

        if entrypoint == LocalMempoolManagerV7.entrypoint:
            local_mempool = self.local_mempool_manager_v7
        elif (entrypoint == LocalMempoolManagerV6.entrypoint and
              self.local_mempool_manager_v6 is not None):
            local_mempool = self.local_mempool_manager_v6
        else:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Unsupported entrypoint",
            )

        entities_reputation = req_arguments[0]
        for entity_reputation in entities_reputation:
            entity = entity_reputation['address']
            ops_seen_hex = entity_reputation['opsSeen']
            ops_included_hex = entity_reputation['opsIncluded']

            if isinstance(ops_seen_hex, str):
                ops_seen = int(ops_seen_hex, 16)
            else:
                ops_seen = ops_seen_hex

            if isinstance(ops_included_hex, str):
                ops_included = int(ops_included_hex, 16)
            else:
                ops_included = ops_included_hex

            local_mempool.reputation_manager.set_reputation(
                    entity, ops_seen, ops_included)

        return "ok"

    async def _event_debug_bundler_clearReputation(self, _: list) -> str:
        self.local_mempool_manager_v7.reputation_manager.clear_all_repuations()
        if self.local_mempool_manager_v6 is not None:
            self.local_mempool_manager_v6.reputation_manager.clear_all_repuations()

        return "ok"

    async def _event_debug_bundler_dumpReputation(
            self, req_arguments: list) -> list[dict[str, str]]:
        entrypoint = req_arguments[0]

        if entrypoint == LocalMempoolManagerV7.entrypoint:
            local_mempool = self.local_mempool_manager_v7
        elif (entrypoint == LocalMempoolManagerV6.entrypoint and
              self.local_mempool_manager_v6 is not None):
            local_mempool = self.local_mempool_manager_v6
        else:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Unsupported entrypoint",
            )

        entities_reputation_json = (
            local_mempool.reputation_manager.get_entities_reputation_json()
        )
        return entities_reputation_json

    async def _event_debug_bundler_getStakeStatus(
            self, req_arguments: list) -> dict:
        address = req_arguments[0]
        entrypoint = req_arguments[1]
        if entrypoint == LocalMempoolManagerV7.entrypoint:
            local_mempool = self.local_mempool_manager_v7
        elif (entrypoint == LocalMempoolManagerV6.entrypoint and
              self.local_mempool_manager_v6 is not None):
            local_mempool = self.local_mempool_manager_v6
        else:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Unsupported entrypoint",
            )
        (
            _, _, stake, unstake_delay_sec, _
        ) = await get_deposit_info(address, entrypoint, self.ethereum_node_url)

        return {
            "stakeInfo": {
                "addr": address,
                "stake": str(stake),
                "unstakeDelaySec": str(unstake_delay_sec),
            },
            "isStaked": local_mempool.is_staked(stake, unstake_delay_sec)
        }

    async def _event_debug_bundler_setBundlingMode(
            self, req_arguments: list) -> str:
        mode = req_arguments[0]
        # bundling is set to manual by using the --debug flag
        return "OK"

    async def _event_p2p_received_gossib(self, req_arguments: dict) -> None:
        peer_id = req_arguments["peer_id"]
        topic = req_arguments["topic"]
        verified_useroperation = req_arguments["verified_useroperation"]
        entrypoint_lowercase = verified_useroperation["entry_point_contract"]
        verified_at_block_hash = verified_useroperation["verified_at_block_hash"]

        #if self.reputation_manager.get_status(peer_id) == ReputationStatus.BANNED:
        #    logging.debug(f"Dropping gossib from banned peer : {peer_id}")

        try:
            if topic == self.local_mempool_manager_v7.canonical_mempool_id:
                user_operation_obj = UserOperationV7(verified_useroperation[
                    "user_operation"])
                local_mempool = self.local_mempool_manager_v7
                if entrypoint_lowercase != local_mempool.entrypoint_lowercase:
                    logging.debug(
                        "Dropping gossib from unsupported entrypoint : " +
                        f"{entrypoint_lowercase}"
                    )
                    #local_mempool.reputation_manager
                await local_mempool.add_user_operation_p2p(
                    user_operation_obj, peer_id, verified_at_block_hash
                )
            else:
                logging.debug(f"Dropping gossib from unsupported topic : {topic}")
                return

        except ValidationException:
            self.local_mempool_manager_v7.reputation_manager.ban_entity(peer_id)

    async def _event_p2p_pooled_user_op_hashes_received(
        self, req_arguments: dict
    ) -> dict:
        cursor = req_arguments["cursor"]

        user_operations_hashs, next_cursor = (
            self.local_mempool_manager_v7.get_user_operations_hashes_with_mempool_id(
                self.local_mempool_manager_v7.canonical_mempool_id, cursor
            )
        )
        pooled_user_op_hashes = {
            "next_cursor": next_cursor,
            "hashes": user_operations_hashs,
        }
        return pooled_user_op_hashes

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
        (
            verified_user_operations_json, remaining_user_operation_hashes
        ) = (
            self.local_mempool_manager_v7.get_user_operations_by_hashes(
                user_operations_hashes)
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
