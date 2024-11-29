import asyncio
import logging
import math
from typing import Any, cast

from eth_account import Account
from eth_abi import encode

from voltaire_bundler.cli_manager import ConditionalRpc
from voltaire_bundler.user_operation.models import \
    FailedOp, FailedOpWithRevert
from voltaire_bundler.bundle.exceptions import ExecutionException
from voltaire_bundler.mempool.v6.mempool_manager_v6 import LocalMempoolManagerV6
from voltaire_bundler.mempool.v7.mempool_manager_v7 import LocalMempoolManagerV7
from voltaire_bundler.typing import Address
from voltaire_bundler.user_operation.user_operation_handler import \
        decode_failed_op_event, decode_failed_op_with_revert_event, get_deposit_info
from voltaire_bundler.user_operation.v6.user_operation_v6 import UserOperationV6
from voltaire_bundler.user_operation.v7.user_operation_v7 import UserOperationV7

from voltaire_bundler.utils.eth_client_utils import \
    send_rpc_request_to_eth_client

from ..mempool.reputation_manager import ReputationManager


class BundlerManager:
    ethereum_node_url: str
    bundler_private_key: str
    bundler_address: Address
    local_mempool_manager_v6: LocalMempoolManagerV6 | None
    local_mempool_manager_v7: LocalMempoolManagerV7
    reputation_manager: ReputationManager
    chain_id: int
    is_legacy_mode: bool
    conditional_rpc: ConditionalRpc | None
    flashbots_protect_node_url: str | None
    max_fee_per_gas_percentage_multiplier: int
    max_priority_fee_per_gas_percentage_multiplier: int
    gas_price_percentage_multiplier: int

    def __init__(
        self,
        local_mempool_manager_v6: LocalMempoolManagerV6 | None,
        local_mempool_manager_v7: LocalMempoolManagerV7,
        ethereum_node_url: str,
        bundler_private_key: str,
        bundler_address: Address,
        chain_id: int,
        is_legacy_mode: bool,
        conditional_rpc: ConditionalRpc | None,
        flashbots_protect_node_url: str | None,
        max_fee_per_gas_percentage_multiplier: int,
        max_priority_fee_per_gas_percentage_multiplier: int,
    ):
        self.local_mempool_manager_v6 = local_mempool_manager_v6
        self.local_mempool_manager_v7 = local_mempool_manager_v7
        self.ethereum_node_url = ethereum_node_url
        self.bundler_private_key = bundler_private_key
        self.bundler_address = bundler_address
        self.chain_id = chain_id
        self.is_legacy_mode = is_legacy_mode
        self.conditional_rpc = conditional_rpc
        self.flashbots_protect_node_url = flashbots_protect_node_url
        self.max_fee_per_gas_percentage_multiplier = (
            max_fee_per_gas_percentage_multiplier
        )
        self.max_priority_fee_per_gas_percentage_multiplier = (
            max_priority_fee_per_gas_percentage_multiplier
        )
        self.gas_price_percentage_multiplier = 100

    async def send_next_bundle(self) -> None:
        tasks_arr = [
            self.local_mempool_manager_v7.get_user_operations_to_bundle(
                self.conditional_rpc is not None
            )
        ]
        if self.local_mempool_manager_v6 is not None:
            tasks_arr.append(
                self.local_mempool_manager_v6.get_user_operations_to_bundle(
                    self.conditional_rpc is not None
                )
            )
        tasks = await asyncio.gather(*tasks_arr)

        bundle_to_send_v7 = cast(list[UserOperationV7], tasks[0])
        bundle_to_send_v6 = None
        if self.local_mempool_manager_v6 is not None:
            bundle_to_send_v6 = cast(list[UserOperationV6], tasks[1])

        tasks_arr = [
            self.send_bundle(
                bundle_to_send_v7,
                self.local_mempool_manager_v7
            )
        ]
        if bundle_to_send_v6 is not None:
            assert self.local_mempool_manager_v6 is not None
            tasks_arr.append(
                    self.send_bundle(
                        bundle_to_send_v6,
                        self.local_mempool_manager_v6
                    )
            )
        await asyncio.gather(*tasks_arr)

    async def send_bundle(
        self,
        user_operations: list[UserOperationV7] | list[UserOperationV6],
        mempool_manager: LocalMempoolManagerV7 | LocalMempoolManagerV6
    ) -> None:
        entrypoint = mempool_manager.entrypoint
        num_of_user_operations = len(user_operations)
        if num_of_user_operations == 0:
            return
        logging.info(
            f"Sending bundle with {num_of_user_operations} user operations"
        )

        call_data_and_call_gas_limit_op = self.create_bundle_calldata_and_estimate_gas(
            user_operations,
            self.bundler_address,
            entrypoint,
        )

        block_max_fee_per_gas_op = send_rpc_request_to_eth_client(
            self.ethereum_node_url, "eth_gasPrice"
        )

        nonce_op = send_rpc_request_to_eth_client(
            self.ethereum_node_url,
            "eth_getTransactionCount",
            [self.bundler_address, "latest"],
        )

        tasks_arr = [
            call_data_and_call_gas_limit_op,
            block_max_fee_per_gas_op,
            nonce_op,
        ]

        if not self.is_legacy_mode:
            block_max_priority_fee_per_gas_op = send_rpc_request_to_eth_client(
                self.ethereum_node_url, "eth_maxPriorityFeePerGas"
            )
            tasks_arr.append(block_max_priority_fee_per_gas_op)

        try:
            tasks = await asyncio.gather(*tasks_arr)
        except ExecutionException as err:
            logging.error(f"Sending bundle failed with erro: {err.message}") 
            return

        call_data, gas_estimation_hex, merged_storage_map = tasks[0]

        if call_data is None or gas_estimation_hex is None:
            logging.error(f"Sending bundle failed. failed call data or gas estimation.") 
            return

        gas_estimation_hex = hex(math.ceil(
            int(gas_estimation_hex, 16) * 1.2))  # 20% buffer

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
            block_max_priority_fee_per_gas_hex = hex(
                    block_max_priority_fee_per_gas_dec_mod)

            # max priority fee per gas can't be higher than max fee per gas
            if block_max_priority_fee_per_gas_dec_mod > block_max_fee_per_gas_dec_mod:
                block_max_priority_fee_per_gas_hex = block_max_fee_per_gas_hex

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

        if self.conditional_rpc is not None and merged_storage_map is not None:
            if self.conditional_rpc == ConditionalRpc.eth:
                method = "eth_sendRawTransactionConditional"
                result = await send_rpc_request_to_eth_client(
                    self.ethereum_node_url,
                    method,
                    [
                        "0x" + sign_store_txn.raw_transaction.hex(),
                        {"knownAccounts": merged_storage_map}
                    ]
                )
            elif self.conditional_rpc == ConditionalRpc.optimism:
                method = "eth_sendRawTransactionConditional"
                result = await send_rpc_request_to_eth_client(
                    self.ethereum_node_url,
                    method,
                    [
                        "0x" + sign_store_txn.raw_transaction.hex(),
                        {"knownAccounts": merged_storage_map}
                    ],
                    (self.bundler_address, self.bundler_private_key),
                    "X-Optimism-Signature"
                )
            else:
                method = "pfl_sendRawTransactionConditional"
                result = await send_rpc_request_to_eth_client(
                    self.ethereum_node_url,
                    method,
                    [
                        "0x" + sign_store_txn.raw_transaction.hex(),
                        {"knownAccounts": merged_storage_map}
                    ]
                )
        elif self.flashbots_protect_node_url is not None:
            result = await send_rpc_request_to_eth_client(
                self.flashbots_protect_node_url,
                "eth_sendPrivateRawTransaction",
                [
                    "0x" + sign_store_txn.raw_transaction.hex(),
                    {"fast": True}
                ],
                (self.bundler_address, self.bundler_private_key),
                "X-Flashbots-Signature"
            )
        else:
            result = await send_rpc_request_to_eth_client(
                self.ethereum_node_url,
                "eth_sendRawTransaction",
                ["0x" + sign_store_txn.raw_transaction.hex()],
            )

        if "error" in result:
            if "message" in result["error"]:
                logging.error("Failed to send bundle." + str(result["error"]))
                # ErrAlreadyKnown is returned if the transactions is already
                # contained within the pool.
                if "already known" in result["error"]["message"]:
                    return
                # ErrInvalidSender is returned if the transaction
                # contains an invalid signature.
                elif "invalid sender" in result["error"]["message"]:
                    pass  # todo
                # ErrUnderpriced is returned if a transaction's gas price
                # is below the minimum configured for the transaction pool.
                elif "transaction underpriced" in result["error"]["message"]:
                    # retry sending useroperations with higher gas price
                    # if the gas_price_percentage_multiplier reached 200,
                    # drop all user_operations
                    if self.gas_price_percentage_multiplier <= 200:
                        self.gas_price_percentage_multiplier += 10
                        logging.warning(
                            "transaction underprices, increasing bundle gas price "
                            "by 10%  - gas_price_percentage_multiplier now is "
                            f"{self.gas_price_percentage_multiplier}%"
                        )
                        await self.send_bundle(user_operations, mempool_manager)
                    else:
                        logging.error(
                            "Failed to send bundle. Dropping all user operations"
                            + str(result["error"])
                        )
                # ErrReplaceUnderpriced is returned if a transaction is
                # attempted to be replaced with a different one without
                # the required price bump.
                elif (
                    "replacement transaction underpriced" in result["error"]["message"]
                ):
                    if self.gas_price_percentage_multiplier <= 200:
                        self.gas_price_percentage_multiplier += 10
                        logging.warning(
                            "replacement transaction underprices, increasing bundle gas price "
                            "by 10%  - gas_price_percentage_multiplier now is "
                            f"{self.gas_price_percentage_multiplier}%"
                        )

                        await self.send_bundle(user_operations, mempool_manager)
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

            # todo : check if bundle was included on chain
            for user_operation in user_operations:
                BundlerManager.update_included_status(
                    mempool_manager,
                    user_operation.sender_address,
                    user_operation.factory_address_lowercase,
                    user_operation.paymaster_address_lowercase,
                )

    @staticmethod
    def update_included_status(
        mempool_manager: LocalMempoolManagerV6 | LocalMempoolManagerV7,
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
        user_operations: list[UserOperationV6] | list[UserOperationV7],
        bundler: Address,
        entrypoint: Address,
    ) -> tuple[str | None, int | None, dict[str, str | dict[str, str]] | None]:
        user_operations_list = []
        for user_operation in user_operations:
            user_operations_list.append(user_operation.to_list())

        if len(user_operations_list[0]) == 9:
            call_data = BundlerManager.encode_handleops_calldata_v7(
                user_operations_list, self.bundler_address
            )
            mempool_manager = self.local_mempool_manager_v7
        else:
            call_data = BundlerManager.encode_handleops_calldata_v6(
                user_operations_list, self.bundler_address
            )
            assert self.local_mempool_manager_v6 is not None
            mempool_manager = self.local_mempool_manager_v6

        params = [
            {
                "from": bundler,
                "to": entrypoint,
                "data": call_data
            }
        ]

        result = await send_rpc_request_to_eth_client(
            self.ethereum_node_url, "eth_estimateGas", params
        )
        if "error" in result:
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
                    return None, None, None

                user_operation = user_operations[operation_index]

                # check if userop was already executed if userop caused bundle
                # gas estimation to fail
                if user_operation.validated_at_block_hex is not None:
                    earliest_block = user_operation.validated_at_block_hex
                else:
                    raise ValueError(
                        "useroperation without validated_at_block_hex")

                logs_res = await mempool_manager.user_operation_handler.get_logs(
                    user_operation.user_operation_hash,
                    entrypoint,
                    earliest_block,
                    "latest"
                )

                # if there is a UserOperationEvent for the user_operation_hash,
                # that means userop was already executed
                if "result" in logs_res and len(logs_res["result"]) > 0:
                    logging.warning(
                        "Dropping user operation that was already executed from bundle."
                        f"useroperation: {user_operation}"
                    )
                    del user_operations[operation_index]

                    if len(user_operations) > 0:
                        return await self.create_bundle_calldata_and_estimate_gas(
                            user_operations,
                            bundler,
                            entrypoint,
                        )
                    else:
                        logging.info("No useroperations to bundle")
                        return None, None, None

                entity_to_ban = None
                if "AA3" in reason:
                    (
                        _, _, stake, unstake_delay_sec, _
                    ) = await get_deposit_info(
                        user_operation.sender_address,
                        entrypoint,
                        self.ethereum_node_url
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
                            self.ethereum_node_url
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

                logging.warning(
                    "Dropping user operation that caused bundle crash - "
                    f"error: {reason}"
                )
                del user_operations[operation_index]

                if len(user_operations) > 0:
                    return await self.create_bundle_calldata_and_estimate_gas(
                        user_operations,
                        bundler,
                        entrypoint,
                    )
                else:
                    logging.info("No useroperations to bundle")
                    return None, None, None
            else:
                logging.error(
                    "Unexpected error during gas estimation for bundle." +
                    "Dropping all user operations."
                    + str(result["error"])
                )
                return None, None, None

        call_gas_limit = result["result"]

        merged_storage_map = None
        if self.conditional_rpc is not None:
            senders_root_hashs_operations = list()
            merged_storage_map = dict()
            for user_operation in user_operations:
                if user_operation.storage_map is not None:
                    merged_storage_map |= user_operation.storage_map
                senders_root_hashs_operations.append(
                    send_rpc_request_to_eth_client(
                        self.ethereum_node_url,
                        "eth_getProof",
                        [user_operation.sender_address, [], "latest"]
                    )
                )
            senders_root_hashes = await asyncio.gather(
                    *senders_root_hashs_operations)

            for user_operation, root_hash_result in zip(
                user_operations, senders_root_hashes
            ):
                merged_storage_map[
                    user_operation.sender_address] = root_hash_result["result"]["storageHash"]
        return call_data, call_gas_limit, merged_storage_map

    @staticmethod
    def encode_handleops_calldata_v6(
        user_operations_list: list[list[Any]], bundler_address: str
    ) -> str:
        function_selector = "0x1fad948c"  # handleOps
        params = encode(
            [
                "(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)[]",
                "address",
            ],
            [user_operations_list, bundler_address],
        )

        call_data = function_selector + params.hex()
        return call_data

    @staticmethod
    def encode_handleops_calldata_v7(
            user_operations_list: list[list[Any]], bundler_address: str) -> str:
        function_selector = "0x765e827f"  # handleOps
        params = encode(
            [
                "(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[]",
                "address",
            ],
            [user_operations_list, bundler_address],
        )

        call_data = function_selector + params.hex()
        return call_data
