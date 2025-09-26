import asyncio
import copy
from datetime import datetime
import logging
import math
from typing import Any, cast

from eth_account import Account
from eth_abi import encode

from voltaire_bundler.cli_manager import ConditionalRpc
from voltaire_bundler.user_operation.models import \
    FailedOp, FailedOpWithRevert
from voltaire_bundler.bundle.exceptions import ExecutionException, ValidationException
from voltaire_bundler.mempool.mempool_manager_v6 import LocalMempoolManagerV6
from voltaire_bundler.mempool.mempool_manager_v7 import LocalMempoolManagerV7
from voltaire_bundler.mempool.mempool_manager_v8 import LocalMempoolManagerV8
from voltaire_bundler.typing import Address
from voltaire_bundler.user_operation.user_operation_handler import \
        decode_failed_op_event, decode_failed_op_with_revert_event, \
        get_deposit_info, get_user_operation_logs_for_block_range
from voltaire_bundler.user_operation.user_operation_v6 import UserOperationV6
from voltaire_bundler.user_operation.user_operation_v7v8 import UserOperationV7V8

from voltaire_bundler.utils.eip7702 import create_and_sign_eip7702_raw_transaction
from voltaire_bundler.utils.eth_client_utils import \
    encode_handleops_calldata_v6, encode_handleops_calldata_v7v8, send_rpc_request_to_eth_client

from ..mempool.reputation_manager import ReputationManager


class BundlerManager:
    ethereum_node_urls: list[str]
    bundle_node_urls: list[str]
    bundler_private_key: str
    bundler_address: Address
    local_mempool_manager_v6: LocalMempoolManagerV6 | None
    local_mempool_manager_v7: LocalMempoolManagerV7
    local_mempool_manager_v8: LocalMempoolManagerV8
    reputation_manager: ReputationManager
    chain_id: int
    is_legacy_mode: bool
    conditional_rpc: ConditionalRpc | None
    flashbots_protect_node_urls: list[str] | None
    max_fee_per_gas_percentage_multiplier: int
    max_priority_fee_per_gas_percentage_multiplier: int
    bundles_to_send_v6: list[dict[str, UserOperationV6]] | None
    bundles_to_send_v7: list[dict[str, UserOperationV7V8]]
    bundles_to_send_v8: list[dict[str, UserOperationV7V8]]
    user_operations_to_monitor_v6: dict[str, UserOperationV6]
    user_operations_to_monitor_v7: dict[str, UserOperationV7V8]
    user_operations_to_monitor_v8: dict[str, UserOperationV7V8]
    user_operations_to_ban: dict[
        str, tuple[UserOperationV6 | UserOperationV7V8, str, Address]]
    gas_price_percentage_multiplier: int

    def __init__(
        self,
        local_mempool_manager_v6: LocalMempoolManagerV6 | None,
        local_mempool_manager_v7: LocalMempoolManagerV7,
        local_mempool_manager_v8: LocalMempoolManagerV8,
        ethereum_node_urls: list[str],
        bundle_node_urls: list[str],
        bundler_private_key: str,
        bundler_address: Address,
        chain_id: int,
        is_legacy_mode: bool,
        conditional_rpc: ConditionalRpc | None,
        flashbots_protect_node_urls: list[str] | None,
        max_fee_per_gas_percentage_multiplier: int,
        max_priority_fee_per_gas_percentage_multiplier: int,
    ):
        self.local_mempool_manager_v6 = local_mempool_manager_v6
        self.local_mempool_manager_v7 = local_mempool_manager_v7
        self.local_mempool_manager_v8 = local_mempool_manager_v8
        self.ethereum_node_urls = ethereum_node_urls
        self.bundle_node_urls = bundle_node_urls
        self.bundler_private_key = bundler_private_key
        self.bundler_address = bundler_address
        self.chain_id = chain_id
        self.is_legacy_mode = is_legacy_mode
        self.conditional_rpc = conditional_rpc
        self.flashbots_protect_node_urls = flashbots_protect_node_urls
        self.max_fee_per_gas_percentage_multiplier = (
            max_fee_per_gas_percentage_multiplier
        )
        self.max_priority_fee_per_gas_percentage_multiplier = (
            max_priority_fee_per_gas_percentage_multiplier
        )
        self.bundles_to_send_v8 = []
        self.bundles_to_send_v7 = []
        if self.local_mempool_manager_v6 is None:
            self.bundles_to_send_v6 = None
        else:
            self.bundles_to_send_v6 = []

        self.user_operations_to_monitor_v8 = {}
        self.user_operations_to_monitor_v7 = {}
        self.user_operations_to_monitor_v6 = {}

        self.gas_price_percentage_multiplier = 100
        self.user_operations_to_ban = {}

    async def send_next_bundle(self) -> None:
        await self.update_send_queue_and_monitor_queue()

        if len(self.bundles_to_send_v8) > 0:
            user_operations_to_send_v8 = self.bundles_to_send_v8.pop(0)
        else:
            user_operations_to_send_v8 = {}
        if len(self.bundles_to_send_v7) > 0:
            user_operations_to_send_v7 = self.bundles_to_send_v7.pop(0)
        else:
            user_operations_to_send_v7 = {}
        highest_verified_at_block_v8 = sorted(map(
            lambda userop: int(userop.validated_at_block_hex, 16)
            if userop.validated_at_block_hex is not None else 0,
            user_operations_to_send_v8.values()
        ))[-1] if user_operations_to_send_v8.values() else 0
        highest_verified_at_block_v7 = sorted(map(
            lambda userop: int(userop.validated_at_block_hex, 16)
            if userop.validated_at_block_hex is not None else 0,
            user_operations_to_send_v7.values()
        ))[-1] if user_operations_to_send_v7.values() else 0

        tasks_arr = [
            self.send_bundle(
                list(user_operations_to_send_v8.values()),
                self.local_mempool_manager_v8,
                highest_verified_at_block_v8
            ),
            self.send_bundle(
                list(user_operations_to_send_v7.values()),
                self.local_mempool_manager_v7,
                highest_verified_at_block_v7
            )
        ]
        if self.bundles_to_send_v6 is not None:
            assert self.local_mempool_manager_v6 is not None
            if len(self.bundles_to_send_v6) > 0:
                user_operations_to_send_v6 = self.bundles_to_send_v6.pop(0)
            else:
                user_operations_to_send_v6 = {}
            highest_verified_at_block_v6 = sorted(map(
                lambda userop: int(userop.validated_at_block_hex, 16)
                if userop.validated_at_block_hex is not None else 0,
                user_operations_to_send_v6.values()
            ))[-1] if user_operations_to_send_v6.values() else 0

            tasks_arr.append(
                self.send_bundle(
                    list(user_operations_to_send_v6.values()),
                    self.local_mempool_manager_v6,
                    highest_verified_at_block_v6
                )
            )
        await asyncio.gather(*tasks_arr)

        useroperation_banning_ops = []
        for user_operation, reason, entrypoint in self.user_operations_to_ban.values():
            useroperation_banning_ops.append(
                self.handle_useroperation_banning(user_operation, reason, entrypoint)
            )
        self.user_operations_to_ban = {}
        await asyncio.gather(*useroperation_banning_ops)

    async def update_send_queue_and_monitor_queue(self) -> None:
        tasks_arr = [
            self.remove_included_and_readd_to_mempool_userops_monitoring(
                self.user_operations_to_monitor_v8,
                self.local_mempool_manager_v8.entrypoint,
                self.local_mempool_manager_v8
            ),
            self.remove_included_and_readd_to_mempool_userops_monitoring(
                self.user_operations_to_monitor_v7,
                self.local_mempool_manager_v7.entrypoint,
                self.local_mempool_manager_v7
            ),
            self.local_mempool_manager_v8.get_user_operations_to_bundle(
                self.conditional_rpc is not None
            ),
            self.local_mempool_manager_v7.get_user_operations_to_bundle(
                self.conditional_rpc is not None
            )
        ]
        if self.local_mempool_manager_v6 is not None:
            tasks_arr += [
                self.remove_included_and_readd_to_mempool_userops_monitoring(
                    self.user_operations_to_monitor_v6,
                    self.local_mempool_manager_v6.entrypoint,
                    self.local_mempool_manager_v6
                ),
                self.local_mempool_manager_v6.get_user_operations_to_bundle(
                    self.conditional_rpc is not None
                ),
            ]
        tasks = await asyncio.gather(*tasks_arr)

        user_operations_to_bundle_v8 = cast(dict[str, UserOperationV7V8], tasks[2])
        self.bundles_to_send_v8.append(user_operations_to_bundle_v8)
        self.user_operations_to_monitor_v8 |= copy.deepcopy(user_operations_to_bundle_v8)

        user_operations_to_bundle_v7 = cast(dict[str, UserOperationV7V8], tasks[3])
        self.bundles_to_send_v7.append(user_operations_to_bundle_v7)
        self.user_operations_to_monitor_v7 |= copy.deepcopy(user_operations_to_bundle_v7)

        if self.local_mempool_manager_v6 is not None:
            if self.bundles_to_send_v6 is None:
                self.bundles_to_send_v6 = []
            user_operations_to_bundle_v6 = cast(dict[str, UserOperationV6], tasks[5])
            self.bundles_to_send_v6.append(user_operations_to_bundle_v6)
            self.user_operations_to_monitor_v6 |= copy.deepcopy(
                user_operations_to_bundle_v6)

    async def send_bundle(
        self,
        user_operations: list[UserOperationV7V8] | list[UserOperationV6],
        mempool_manager: LocalMempoolManagerV8 | LocalMempoolManagerV7 | LocalMempoolManagerV6,
        highest_verified_at_block: int
    ) -> None:
        entrypoint = mempool_manager.entrypoint
        num_of_user_operations = len(user_operations)
        if num_of_user_operations == 0:
            return
        logging.info(
            f"Attempting to send bundle with {num_of_user_operations} user operations."
        )

        call_data_and_call_gas_limit_op = self.create_bundle_calldata_and_estimate_gas(
            user_operations,
            self.bundler_address,
            entrypoint,
            highest_verified_at_block
        )

        block_max_fee_per_gas_op = send_rpc_request_to_eth_client(
            self.ethereum_node_urls, "eth_gasPrice", None, None, "result"
        )

        nonce_op = send_rpc_request_to_eth_client(
            self.ethereum_node_urls,
            "eth_getTransactionCount",
            [self.bundler_address, "latest"], None, "result"
        )

        tasks_arr = [
            call_data_and_call_gas_limit_op,
            block_max_fee_per_gas_op,
            nonce_op,
        ]

        if not self.is_legacy_mode:
            block_max_priority_fee_per_gas_op = send_rpc_request_to_eth_client(
                self.ethereum_node_urls, "eth_maxPriorityFeePerGas",
                None, None, "result"
            )
            tasks_arr.append(block_max_priority_fee_per_gas_op)

        try:
            tasks = await asyncio.gather(*tasks_arr)
        except ExecutionException as err:
            logging.error(f"Sending bundle failed with erro: {err.message}")
            return

        call_data, gas_estimation_hex, merged_storage_map, auth_list = tasks[0]

        if call_data is None or gas_estimation_hex is None:
            logging.debug(
                "Sending bundle failed. failed call data or gas estimation.")
            return

        block_max_fee_per_gas = tasks[1]["result"]
        nonce = tasks[2]["result"]

        block_max_fee_per_gas_dec = int(block_max_fee_per_gas, 16)
        block_max_fee_per_gas_dec_mod = math.ceil(
            block_max_fee_per_gas_dec
            * (self.max_fee_per_gas_percentage_multiplier / 100)
            * (self.gas_price_percentage_multiplier / 100)
        )
        block_max_fee_per_gas_hex = hex(block_max_fee_per_gas_dec_mod)

        block_max_priority_fee_per_gas_hex = "0x"
        if not self.is_legacy_mode:
            block_max_priority_fee_per_gas = tasks[3]["result"]
            block_max_priority_fee_per_gas_dec = int(
                    block_max_priority_fee_per_gas, 16)
            block_max_priority_fee_per_gas_dec_mod = math.ceil(
                block_max_priority_fee_per_gas_dec
                * (self.max_priority_fee_per_gas_percentage_multiplier / 100)
                * (self.gas_price_percentage_multiplier / 100)
            )

           # max priority fee per gas should be atleast 1
            if block_max_priority_fee_per_gas_dec_mod <= 0:
                block_max_priority_fee_per_gas_dec_mod = 1

            block_max_priority_fee_per_gas_hex = hex(
                    block_max_priority_fee_per_gas_dec_mod)

            # max priority fee per gas can't be higher than max fee per gas
            if block_max_priority_fee_per_gas_dec_mod > block_max_fee_per_gas_dec_mod:
                block_max_priority_fee_per_gas_hex = block_max_fee_per_gas_hex

        logging.info(
            f"Sending bundle with {num_of_user_operations} user operations, "
            f"gas: {gas_estimation_hex}, "
            f"maxFeePerGas: {block_max_fee_per_gas_hex}, "
            f"maxPriorityFeePerGas: {block_max_priority_fee_per_gas_hex}"
        )

        if len(auth_list) == 0:
            txnDict = {
                "chainId": self.chain_id,
                "from": self.bundler_address,
                "to": entrypoint,
                "nonce": nonce,
                "gas": gas_estimation_hex,
                "data": call_data,
            }

            if self.is_legacy_mode:
                txnDict.update(
                    {
                        "gasPrice": block_max_fee_per_gas_hex,
                    }
                )
            else:
                txnDict.update(
                    {
                        "maxFeePerGas": block_max_fee_per_gas_hex,
                        "maxPriorityFeePerGas": block_max_priority_fee_per_gas_hex,
                    }
                )
            sign_store_txn = Account.sign_transaction(
                txnDict, private_key=self.bundler_private_key
            )
            raw_transaction = "0x" + sign_store_txn.raw_transaction.hex()
        else:
            raw_transaction = create_and_sign_eip7702_raw_transaction(
                chain_id_hex=hex(self.chain_id),
                nonce_hex=nonce,
                max_priority_fee_per_gas_hex=block_max_priority_fee_per_gas_hex,
                max_fee_per_gas_hex=block_max_fee_per_gas_hex,
                gas_limit_hex=gas_estimation_hex,
                destination=entrypoint,
                value_hex="0x",
                data=call_data,
                authorization_list=auth_list,
                eoa_private_key=self.bundler_private_key
            )

        if self.conditional_rpc is not None and merged_storage_map is not None:
            if self.conditional_rpc == ConditionalRpc.eth:
                method = "eth_sendRawTransactionConditional"
            else:
                method = "pfl_sendRawTransactionConditional"
            result = await send_rpc_request_to_eth_client(
                self.bundle_node_urls,
                method,
                [
                    raw_transaction,
                    {"knownAccounts": merged_storage_map}
                ]
            )
        elif self.flashbots_protect_node_urls is not None:
            result = await send_rpc_request_to_eth_client(
                self.flashbots_protect_node_urls,
                "eth_sendPrivateRawTransaction",
                [
                    raw_transaction,
                    {"fast": True}
                ],
                (self.bundler_address, self.bundler_private_key)
            )
        else:
            result = await send_rpc_request_to_eth_client(
                self.bundle_node_urls,
                "eth_sendRawTransaction",
                [
                    raw_transaction
                ],
            )

        if "error" in result:
            if "message" in result["error"]:
                logging.error("Failed to send bundle." + str(result["error"]))
                # ErrInvalidSender is returned if the transaction
                # contains an invalid signature.
                if "invalid sender" in result["error"]["message"]:
                    pass  # todo
                # ErrAlreadyKnown is returned if the transactions is already
                # contained within the pool.
                # or
                # ErrUnderpriced is returned if a transaction's gas price
                # is below the minimum configured for the transaction pool.
                # or
                # ErrReplaceUnderpriced is returned if a transaction is
                # attempted to be replaced with a different one without
                # the required price bump.
                elif (
                    "already known" in result["error"]["message"] or  # Geth
                    "transaction underpriced" in result["error"]["message"] or  # Geth
                    "replacement transaction underpriced" in result["error"]["message"] or
                    "AlreadyKnown" in result["error"]["message"]  or # nethermind
                    "ReplacementNotAllowed" in result["error"]["message"]  or # nethermind
                    "could not replace existing tx" in result["error"]["message"]  # erigon
                ):
                    # retry sending useroperations with higher gas price
                    # if the gas_price_percentage_multiplier reached 600,
                    # drop all user_operations
                    if self.gas_price_percentage_multiplier <= 600:
                        self.gas_price_percentage_multiplier += 30
                        logging.warning(
                            str(result["error"]["message"]) +
                            " increasing bundle gas price by 30% "
                            "- gas_price_percentage_multiplier now is "
                            f"{self.gas_price_percentage_multiplier}%"
                        )

                        await self.send_bundle(
                            user_operations, mempool_manager, highest_verified_at_block
                        )
                    else:
                        logging.error(
                            "Failed to send bundle. Dropping all user operations"
                            + str(result["error"])
                        )
                # ErrAccountLimitExceeded is returned if a transaction would
                # exceed the number allowed by a pool for a single account.
                elif "account limit exceeded" in result["error"]["message"]:
                    pass  # todo
                # ErrGasLimit is returned if a transaction's requested gas
                # limit exceeds the maximum allowance of the current block.
                elif "exceeds block gas limit" in result["error"]["message"]:
                    pass  # todo
                # ErrNegativeValue is a sanity error to ensure no one is able
                # to specify a transaction with a negative value.
                elif "negative value" in result["error"]["message"]:
                    pass  # todo
                # ErrOversizedData is returned if the input data of
                # a transaction is greater than some meaningful limit a user
                # might use. This is not a consensus error making
                # the transaction invalid, rather a DOS protection.
                elif "oversized data" in result["error"]["message"]:
                    pass  # todo
                # ErrFutureReplacePending is returned if a future transaction
                # replaces a pending one. Future transactions should only
                # be able to replace other future transactions.
                elif (
                    "future transaction tries to replace pending"
                    in result["error"]["message"]
                ):
                    pass  # todo
                else:
                    logging.error(
                        "Failed to send bundle. Dropping all user operations"
                        + str(result["error"])
                    )
            else:
                logging.error(
                    "Failed to send bundle. Dropping all user operations"
                    + str(result["error"])
                )
        else:
            transaction_hash = result["result"]
            logging.info(
                "Bundle was sent with transaction hash : " + transaction_hash)
            self.gas_price_percentage_multiplier = 100

            self.update_monitor_status_transation_hash(
                user_operations,
                transaction_hash,
            )
            # todo : check if bundle was included on chain
            for user_operation in user_operations:
                BundlerManager.update_included_status(
                    mempool_manager,
                    user_operation.sender_address,
                    user_operation.factory_address_lowercase,
                    user_operation.paymaster_address_lowercase,
                )

    async def remove_included_and_readd_to_mempool_userops_monitoring(
            self,
            user_operations_to_monitor: dict[str, UserOperationV7V8] | dict[str, UserOperationV6],
            entrypoint: str,
            local_mempool: LocalMempoolManagerV6 | LocalMempoolManagerV7 | LocalMempoolManagerV8
    ) -> None:
        logs_res_ops = []
        for user_operation_hash, user_operation in user_operations_to_monitor.items():
            assert user_operation.validated_at_block_hex is not None
            earliest_block = user_operation.validated_at_block_hex
            logs_res_op = get_user_operation_logs_for_block_range(
                # not using the ethereum_node_eth_get_logs_urls as the
                # block range can't be large and to role out the possibility
                # that the logs node is slightly behind/out of sync
                self.ethereum_node_urls,
                user_operation_hash,
                entrypoint,
                earliest_block,
                "latest"
            )
            logs_res_ops.append(logs_res_op)
        user_operations_logs = await asyncio.gather(*logs_res_ops)

        user_operations_hashes_to_remove_from_monitoring = []
        for user_operation, user_operation_log in zip(
            list(user_operations_to_monitor.values()), user_operations_logs
        ):
            assert user_operation.last_add_to_mempool_date is not None
            time_diff_sec = (
                datetime.now() - user_operation.last_add_to_mempool_date
            ).total_seconds()
            if user_operation_log is not None:
                logging.info(
                    f"user operation: {user_operation.user_operation_hash} "
                    "was included onchain after adding to mempool for "
                    f"{user_operation.number_of_add_to_mempool_attempts} times"
                )
                user_operations_hashes_to_remove_from_monitoring.append(
                    user_operation.user_operation_hash)
            elif user_operation.number_of_add_to_mempool_attempts > 20:
                logging.warning(
                    f"user operation: {user_operation.user_operation_hash} "
                    "was not included onchain yet after readding to mempool 20 times"
                    "-drooping the userop from the monitoring system"
                )
                user_operations_hashes_to_remove_from_monitoring.append(
                    user_operation.user_operation_hash)
            elif time_diff_sec > 5:
                logging.info(
                    f"user operation: {user_operation.user_operation_hash} "
                    "was not included onchain yet after readding to mempool for no."
                    f"{user_operation.number_of_add_to_mempool_attempts} "
                    "-readding it to the mempool"
                )
                try:
                    user_operations_hashes_to_remove_from_monitoring.append(
                        user_operation.user_operation_hash)
                    await local_mempool.add_user_operation(
                        user_operation)
                except (ValidationException, ExecutionException, ValueError) as exp:
                    logging.info(
                        "failed readding to the mempool "
                        f"user operation: {user_operation.user_operation_hash} "
                        f" - cause : {str(exp)} "
                    )
        for user_operation_hash in user_operations_hashes_to_remove_from_monitoring:
            del user_operations_to_monitor[user_operation_hash]

    def update_monitor_status_transation_hash(
        self,
        user_operations: list[UserOperationV7V8] | list[UserOperationV6],
        transaction_hash: str,
    ) -> None:
        for user_operation in user_operations:
            user_operation_hash = user_operation.user_operation_hash
            if user_operation_hash in self.user_operations_to_monitor_v8:
                user_operation_to_monitor = self.user_operations_to_monitor_v8[
                    user_operation_hash
                ]
                user_operation_to_monitor.attempted_bundle_transaction_hash = transaction_hash
            elif user_operation_hash in self.user_operations_to_monitor_v7:
                user_operation_to_monitor = self.user_operations_to_monitor_v7[
                    user_operation_hash
                ]
                user_operation_to_monitor.attempted_bundle_transaction_hash = transaction_hash
            elif user_operation_hash in self.user_operations_to_monitor_v6:
                user_operation_to_monitor = self.user_operations_to_monitor_v6[
                    user_operation_hash
                ]
                user_operation_to_monitor.attempted_bundle_transaction_hash = transaction_hash
            else:
                logging.error(
                    f"can't find user operation hash: {user_operation_hash} in "
                    "monitoring list"
                )

    @staticmethod
    def update_included_status(
        mempool_manager: LocalMempoolManagerV6 | LocalMempoolManagerV7 | LocalMempoolManagerV8,
        sender_address: str,
        factory_address: str | None,
        paymaster_address: str | None
    ) -> None:
        mempool_manager.reputation_manager.update_included_status(sender_address)

        if factory_address is not None:
            mempool_manager.reputation_manager.update_included_status(factory_address)

        if paymaster_address is not None:
            mempool_manager.reputation_manager.update_included_status(paymaster_address)

    async def create_bundle_calldata_and_estimate_gas(
        self,
        user_operations: list[UserOperationV6] | list[UserOperationV7V8],
        bundler: Address,
        entrypoint: Address,
        highest_verified_at_block: int,
        recursion_depth: int = 0
    ) -> tuple[
            str | None,
            int | None,
            dict[str, str | dict[str, str]] | None,
            list,
    ]:
        recursion_depth = recursion_depth + 1
        if recursion_depth > 100:
            # this shouldn't happen
            logging.error(
                "create_bundle_calldata_and_estimate_gas recursion too deep."
            )
            return None, None, None, []

        user_operations_list = []
        auth_list = []

        if (
            entrypoint == self.local_mempool_manager_v8.entrypoint or
            entrypoint == self.local_mempool_manager_v7.entrypoint
        ):
            for user_operation in user_operations:
                user_operations_list.append(user_operation.to_list())
                if user_operation.eip7702_auth is not None:
                    auth_list.append(user_operation.eip7702_auth)
            call_data = encode_handleops_calldata_v7v8(
                user_operations_list, self.bundler_address
            )
        else:
            for user_operation in user_operations:
                user_operations_list.append(user_operation.to_list())
            call_data = encode_handleops_calldata_v6(
                user_operations_list, self.bundler_address
            )

        bundle_calldata_init_gas = calculate_bundle_calldata_init_gas(call_data)
        bundle_gas_limit = 0
        for user_operation in user_operations:
            bundle_gas_limit += user_operation.get_max_gas_with_pre_verification_gas()

        bundle_gas_limit += 50_000 + bundle_calldata_init_gas

        # see EntryPointMinBlock.sol
        entrypoint_proxy_bytecode = (
            "0x60806040527f" +
            encode(["uint256"], [highest_verified_at_block]).hex() +
            "4311610066576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161005d90610119565b60405180910390fd5b5f54365f5f375f5f365f5f73" +
            entrypoint[2:] +
            "5af13d5f5f3e80610095573d5ffd5b3d5ff35b5f82825260208201905092915050565b7f63757272656e7420626c6f636b206e756d626572206973206e6f7420686967685f8201527f6572207468616e206d696e426c6f636b00000000000000000000000000000000602082015250565b5f610103603083610099565b915061010e826100a9565b604082019050919050565b5f6020820190508181035f830152610130816100f7565b905091905056fea2646970667358221220fdaf8cdf14134724b4c557e94fe297425c83ef6bba7e4741a52b5f093f2324b464736f6c634300081b0033"
        )
        params = {
            "from": bundler,
            "to": "0x0000000000000000000000000000000000000000",
            "data": call_data,
        }
        if (len(auth_list) > 0):
            params["authorizationList"] = auth_list

        result = await send_rpc_request_to_eth_client(
            self.ethereum_node_urls,
            "eth_call",
            [
                params,
                "pending",
                {
                    "0x0000000000000000000000000000000000000000": {
                        "code": entrypoint_proxy_bytecode
                    }
                }
            ]
        )
        if "result" in result:
            merged_storage_map = None
            if self.conditional_rpc is not None:
                senders_root_hashs_operations = list()
                merged_storage_map = dict()
                for user_operation in user_operations:
                    if user_operation.storage_map is not None:
                        merged_storage_map |= user_operation.storage_map
                    senders_root_hashs_operations.append(
                        send_rpc_request_to_eth_client(
                            self.ethereum_node_urls,
                            "eth_getProof",
                            [user_operation.sender_address, [], "latest"],
                            None, "result"
                        )
                    )
                senders_root_hashes = await asyncio.gather(
                        *senders_root_hashs_operations)

                for user_operation, root_hash_result in zip(
                    user_operations, senders_root_hashes
                ):
                    merged_storage_map[
                        user_operation.sender_address
                    ] = root_hash_result["result"]["storageHash"]
            return call_data, bundle_gas_limit, merged_storage_map, auth_list
        # the bundler performs the third validation of the entire UserOperations
        # bundle. If any of the UserOperations fail validation,
        # the bundler drops them, and updates their reputation,
        # as described in ERC-7562 in detail.
        elif "error" in result:
            if "message" in result["error"] and (
                "current block number is not higher than minBlock" in
                result["error"]["message"]
            ):
                # reattempt to estimate gas if current node is lagging
                # as we can't assume that the bundler is connected to the same
                # node during validation and bundle gas estimation
                logging.debug(
                    "reattempt to estimate gas because of a lagging node."
                    f"current node latest block is less than: {highest_verified_at_block}."
                )
                return await self.create_bundle_calldata_and_estimate_gas(
                    user_operations,
                    bundler,
                    entrypoint,
                    recursion_depth
                )

            if "data" in result["error"]:
                error_data = result["error"]["data"]
                selector = error_data[:10]
                error_params = error_data[10:]
                if selector == FailedOp.SELECTOR:
                    (
                        operation_index,
                        reason,
                    ) = decode_failed_op_event(error_params)
                elif selector == FailedOpWithRevert.SELECTOR:
                    operation_index, reason, inner = decode_failed_op_with_revert_event(
                        error_params
                    )
                    reason += str(inner)
                else:
                    logging.error(
                        "Unexpected error during gas estimation for bundle." +
                        "Dropping all user operations."
                        + str(result["error"])
                    )
                    return None, None, None, []

                user_operation = user_operations[operation_index]
                if user_operation.number_of_add_to_mempool_attempts > 1:
                    logging.warning(
                        "Not banning a useroperation that failed third validation "
                        "after the first bundle attempt."
                        f"useroperation: {user_operation.user_operation_hash}"
                    )
                else:
                    self.user_operations_to_ban[
                        user_operation.user_operation_hash
                    ] = (user_operation, reason, entrypoint)

                logging.debug(
                    "Dropping user operation that failed third validation."
                    f"useroperation: {user_operation.user_operation_hash}."
                    f"reason: {reason}"
                )
                del user_operations[operation_index]
                if len(user_operations) > 0:
                    return await self.create_bundle_calldata_and_estimate_gas(
                        user_operations,
                        bundler,
                        entrypoint,
                        recursion_depth
                    )
                else:
                    logging.info("No useroperations to bundle")
                    return None, None, None, []

        logging.error(
            "Unexpected error during gas estimation for bundle." +
            "Dropping all user operations."
            + str(result["error"])
        )
        return None, None, None, []

    async def handle_useroperation_banning(
        self,
        user_operation: UserOperationV6 | UserOperationV7V8,
        reason: str,
        entrypoint: Address
    ):
        if "AA25 invalid account nonce" == reason:
            logging.debug(
                "Not banning a useroperation for invalid nonce."
                f"useroperation: {user_operation.user_operation_hash}"
            )
            return

        if entrypoint == self.local_mempool_manager_v8.entrypoint:
            mempool_manager = self.local_mempool_manager_v8
        elif entrypoint == self.local_mempool_manager_v7.entrypoint:
            mempool_manager = self.local_mempool_manager_v7
        else:
            mempool_manager = self.local_mempool_manager_v6

        # check if userop was already executed if userop caused bundle
        # gas estimation to fail
        if user_operation.validated_at_block_hex is not None:
            earliest_block = user_operation.validated_at_block_hex
        else:
            raise ValueError(
                "useroperation without validated_at_block_hex")

        logs_res = await get_user_operation_logs_for_block_range(
            # not using the ethereum_node_eth_get_logs_urls as the
            # block range can't be large and to role out the possibility
            # that the logs node is slightly behind/out of sync
            self.ethereum_node_urls,
            user_operation.user_operation_hash,
            entrypoint,
            earliest_block,
            "latest"
        )

        # if there is a UserOperationEvent for the user_operation_hash,
        # that means userop was already executed
        if logs_res is not None:
            logging.warning(
                "Not banning a useroperation that was already included."
                f"useroperation: {user_operation.user_operation_hash}"
            )
            return
        if entrypoint == self.local_mempool_manager_v8.entrypoint:
            mempool_manager = self.local_mempool_manager_v8
        elif entrypoint == self.local_mempool_manager_v7.entrypoint:
            mempool_manager = self.local_mempool_manager_v7
        else:
            assert self.local_mempool_manager_v6 is not None
            mempool_manager = self.local_mempool_manager_v6
        entity_to_ban = None
        if "AA3" in reason:
            (
                _, _, stake, unstake_delay_sec, _
            ) = await get_deposit_info(
                user_operation.sender_address,
                entrypoint,
                self.ethereum_node_urls
            )
            is_sender_staked = mempool_manager.is_staked(
                stake, unstake_delay_sec)
            if is_sender_staked or user_operation.paymaster_address_lowercase is None:
                entity_to_ban = user_operation.sender_address
                reason_to_ban = (
                    "Ban the sender if AA3 and "
                    "(sender is staked or paymaster is None)"
                )
            else:
                entity_to_ban = user_operation.paymaster_address_lowercase
                reason_to_ban = (
                    "Ban the paymaster if AA3 and "
                    "(sender is not staked and paymaster is not None)"
                )
        elif "AA2" in reason:
            if user_operation.factory_address_lowercase is not None:
                (
                    _, _, stake, unstake_delay_sec, _
                ) = await get_deposit_info(
                    user_operation.factory_address_lowercase,
                    entrypoint,
                    self.ethereum_node_urls
                )

                is_factory_staked = mempool_manager.is_staked(
                    stake, unstake_delay_sec)
                if is_factory_staked:
                    entity_to_ban = user_operation.factory_address_lowercase
                    reason_to_ban = (
                        "Ban the factory if AA2 and "
                        "factory is staked"
                    )
                else:
                    entity_to_ban = user_operation.sender_address
                    reason_to_ban = (
                        "Ban the sender if AA2 and  "
                        "factory is not staked"
                    )

            else:
                entity_to_ban = user_operation.sender_address
                reason_to_ban = (
                    "Ban the sender if AA2 and "
                    "factory is None"
                )
        elif (
            "AA1" in reason
            and user_operation.factory_address_lowercase is not None
        ):
            entity_to_ban = user_operation.factory_address_lowercase
            reason_to_ban = "Ban the factory if AA1"
        else:
            logging.error(
                "FailedOp during bundle gas estimation with unexpected error."
                f"with error: {reason}"
            )
            reason_to_ban = None
        if entity_to_ban is not None:
            logging.debug(
                f"banning {entity_to_ban} that caused bundle crash - "
                f"reason to ban:{reason_to_ban} - error: {reason}"
            )
            mempool_manager.reputation_manager.ban_entity(entity_to_ban)


def calculate_bundle_calldata_init_gas(bundle_call_data: str) -> int:
    bundle_call_data_bytes = bytes.fromhex(bundle_call_data[2:])
    zero_byte = 4
    non_zero_byte = 16

    packed_length = len(bundle_call_data_bytes)
    zero_byte_count = bundle_call_data_bytes.count(b"\x00")
    non_zero_byte_count = packed_length - zero_byte_count
    call_data_cost = (
        zero_byte_count * zero_byte + non_zero_byte_count * non_zero_byte
    )

    return 21000 + call_data_cost
