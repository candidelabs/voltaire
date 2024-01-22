import asyncio
import logging
import math
from typing import List

from eth_account import Account

from voltaire_bundler.utils.eth_client_utils import (
    send_rpc_request_to_eth_client,
)
from voltaire_bundler.user_operation.user_operation import UserOperation
from voltaire_bundler.user_operation.user_operation_handler import (
    UserOperationHandler,
)
from voltaire_bundler.utils.encode import encode_handleops_calldata

from ..mempool.mempool_manager import LocalMempoolManagerVersion0Point6
from ..reputation_manager import ReputationManager
from ..validation_manager import ValidationManager
from ..gas_manager import GasManager


class BundlerManager:
    ethereum_node_url: str
    bundler_private_key: str
    bundler_address: str
    entrypoints_addresses_to_local_mempools: dict[str,str]
    user_operation_handler: UserOperationHandler
    reputation_manager: ReputationManager
    chain_id: int
    is_legacy_mode: bool
    is_send_raw_transaction_conditional: bool
    max_fee_per_gas_percentage_multiplier: int
    max_priority_fee_per_gas_percentage_multiplier: int
    entrypoints_addresses_to_send_queue:dict[str,List[UserOperation]]
    entrypoints_addresses_to_verify_inclusion_queue:dict[str,List[UserOperation]]
    gas_price_percentage_multiplier:int

    def __init__(
        self,
        entrypoints_addresses_to_local_mempools: dict[str,str],
        user_operation_handler: UserOperationHandler,
        reputation_manager: ReputationManager,
        gas_manager: GasManager,
        ethereum_node_url: str,
        bundler_private_key: str,
        bundler_address: str,
        chain_id: str,
        is_legacy_mode: bool,
        is_send_raw_transaction_conditional: bool,
        max_fee_per_gas_percentage_multiplier: int,
        max_priority_fee_per_gas_percentage_multiplier: int,
    ):
        self.entrypoints_addresses_to_local_mempools = entrypoints_addresses_to_local_mempools
        self.user_operation_handler = user_operation_handler
        self.reputation_manager = reputation_manager
        self.gas_manager = gas_manager
        self.ethereum_node_url = ethereum_node_url
        self.bundler_private_key = bundler_private_key
        self.bundler_address = bundler_address
        self.chain_id = chain_id
        self.is_legacy_mode = is_legacy_mode
        self.is_send_raw_transaction_conditional = (
            is_send_raw_transaction_conditional
        )
        self.max_fee_per_gas_percentage_multiplier = max_fee_per_gas_percentage_multiplier
        self.max_priority_fee_per_gas_percentage_multiplier = max_priority_fee_per_gas_percentage_multiplier
        self.entrypoints_addresses_to_send_queue = dict()
        self.gas_price_percentage_multiplier = 100

    async def send_next_bundle(self) -> None:
        for entrypoint, send_queue in self.entrypoints_addresses_to_send_queue.items():
            user_operations = send_queue
            numbder_of_user_operations = len(send_queue)

            if numbder_of_user_operations > 0:
                await self.send_bundle(user_operations, entrypoint)
                logging.info(
                    f"Sending bundle with {len(user_operations)} user operations"
                )
            self.entrypoints_addresses_to_send_queue[entrypoint] = []

    async def update_send_queue(self) -> None:
        for entrypoint, mempool_manager in self.entrypoints_addresses_to_local_mempools.items():
            user_operations = (
                await mempool_manager.get_user_operations_to_bundle()
            )
            if entrypoint not in self.entrypoints_addresses_to_send_queue:
                self.entrypoints_addresses_to_send_queue[entrypoint] = []
            self.entrypoints_addresses_to_send_queue[entrypoint] += user_operations

    async def send_bundle(
            self, 
            user_operations: list[UserOperation],
            entrypoint:str
            ) -> None:
        user_operations_list = []
        for user_operation in user_operations:
            user_operations_list.append(user_operation.to_list())

        call_data = encode_handleops_calldata(
            user_operations_list, self.bundler_address
        )

        gas_estimation_op = self.gas_manager.estimate_call_gas_limit_using_eth_estimate(
            bytes.fromhex(call_data[2:]),
            _from=self.bundler_address,
            to=entrypoint,
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
            gas_estimation_op,
            block_max_fee_per_gas_op,
            nonce_op,
        ]

        if not self.is_legacy_mode:
            block_max_priority_fee_per_gas_op = send_rpc_request_to_eth_client(
                self.ethereum_node_url, "eth_maxPriorityFeePerGas"
            )
            tasks_arr.append(block_max_priority_fee_per_gas_op)

        tasks = await asyncio.gather(*tasks_arr)

        gas_estimation = tasks[0]
        block_max_fee_per_gas = tasks[1]["result"]
        nonce = tasks[2]["result"]

        block_max_fee_per_gas_dec = int(block_max_fee_per_gas, 16)
        block_max_fee_per_gas_dec_mod = math.ceil(block_max_fee_per_gas_dec * (self.max_fee_per_gas_percentage_multiplier/100) * (self.gas_price_percentage_multiplier/100))
        block_max_fee_per_gas = hex(block_max_fee_per_gas_dec_mod)

        block_max_priority_fee_per_gas = 0
        if not self.is_legacy_mode:
            block_max_priority_fee_per_gas = tasks[3]["result"]
            block_max_priority_fee_per_gas_dec = int(block_max_priority_fee_per_gas, 16)
            block_max_priority_fee_per_gas_dec_mod = math.ceil(block_max_priority_fee_per_gas_dec * (self.max_priority_fee_per_gas_percentage_multiplier/100) * (self.gas_price_percentage_multiplier/100))
            block_max_priority_fee_per_gas = hex(block_max_priority_fee_per_gas_dec_mod)

        txnDict = {
            "chainId": self.chain_id,
            "from": self.bundler_address,
            "to": entrypoint,
            "nonce": nonce,
            "gas": int(gas_estimation, 16),
            "data": call_data,
        }

        if self.is_legacy_mode:
            txnDict.update(
                {
                    "gasPrice": block_max_fee_per_gas,
                }
            )
        else:
            txnDict.update(
                {
                    "maxFeePerGas": block_max_fee_per_gas,
                    "maxPriorityFeePerGas": block_max_priority_fee_per_gas,
                }
            )

        sign_store_txn = Account.sign_transaction(
            txnDict, private_key=self.bundler_private_key
        )
        rpc_call = "eth_sendRawTransaction"
        if self.is_send_raw_transaction_conditional:
            rpc_call = "eth_sendRawTransactionConditional"

        result = await send_rpc_request_to_eth_client(
            self.ethereum_node_url,
            rpc_call,
            [sign_store_txn.rawTransaction.hex()],
        )
        if "error" in result:
            if "data" in result[
                "error"
            ] and ValidationManager.check_if_failed_op_error(
                solidity_error_selector
            ):
                # raise ValueError("simulateValidation didn't revert!")
                error_data = result["error"]["data"]
                solidity_error_selector = str(error_data[:10])

                solidity_error_params = error_data[10:]
                (
                    operation_index,
                    reason,
                ) = ValidationManager.decode_FailedOp_event(
                    solidity_error_params
                )

                if (
                    "AA3" in reason
                    and user_operation.paymaster_address_lowercase is not None
                ):
                    self.reputation_manager.ban_entity(
                        user_operation.paymaster_address_lowercase
                    )
                elif "AA2" in reason:
                    self.reputation_manager.ban_entity(
                        user_operation.sender_address
                    )
                elif (
                    "AA1" in reason
                    and user_operation.factory_address_lowercase is not None
                ):
                    self.reputation_manager.ban_entity(
                        user_operation.factory_address_lowercase
                    )

                logging.info(
                    "Dropping user operation that caused bundle crash"
                )
                del user_operations[operation_index]

                if len(user_operations) > 0:
                    self.send_bundle(user_operations)
            elif "message" in result["error"]:
                # ErrAlreadyKnown is returned if the transactions is already contained
                # within the pool.
                if "already known" in result["error"]["message"]:
                    pass #todo
                #ErrInvalidSender is returned if the transaction contains an invalid signature.
                elif "invalid sender" in result["error"]["message"]:
                    pass #todo
                # ErrUnderpriced is returned if a transaction's gas price is below the minimum
                # configured for the transaction pool.
                elif "transaction underpriced" in result["error"]["message"]:
                    #retry sending useroperations with higher gas price
                    #if the gas_price_percentage_multiplier reached 200, drop the user_operations
                    if self.gas_price_percentage_multiplier <= 200:
                        self.gas_price_percentage_multiplier += 10
                        self.entrypoints_addresses_to_send_queue[entrypoint] += user_operations
                    else:
                        logging.info(
                            "Failed to send bundle. Dropping all user operations" + str(result["error"])
                        )
                # ErrReplaceUnderpriced is returned if a transaction is attempted to be replaced
                # with a different one without the required price bump.
                elif "replacement transaction underpriced" in result["error"]["message"]:
                    if self.gas_price_percentage_multiplier <= 200:
                        self.gas_price_percentage_multiplier += 10
                        self.entrypoints_addresses_to_send_queue[entrypoint] += user_operations
                    else:
                        logging.info(
                            "Failed to send bundle. Dropping all user operations" + str(result["error"])
                        )
                # ErrAccountLimitExceeded is returned if a transaction would exceed the number
                # allowed by a pool for a single account.
                elif "account limit exceeded" in result["error"]["message"]:
                    pass #todo
                # ErrGasLimit is returned if a transaction's requested gas limit exceeds the
                # maximum allowance of the current block.
                elif "exceeds block gas limit" in result["error"]["message"]:
                    pass #todo
                # ErrNegativeValue is a sanity error to ensure no one is able to specify a
                # transaction with a negative value.
                elif "negative value" in result["error"]["message"]:
                    pass #todo
                # ErrOversizedData is returned if the input data of a transaction is greater
                # than some meaningful limit a user might use. This is not a consensus error
                # making the transaction invalid, rather a DOS protection.
                elif "oversized data" in result["error"]["message"]:
                    pass #todo
                # ErrFutureReplacePending is returned if a future transaction replaces a pending
                # one. Future transactions should only be able to replace other future transactions.
                elif "future transaction tries to replace pending" in result["error"]["message"]:
                    pass #todo
                else:
                    logging.info(
                    "Failed to send bundle. Dropping all user operations" + str(result["error"])
                )
            else:
                logging.info(
                    "Failed to send bundle. Dropping all user operations" + str(result["error"])
                )

        else:
            transaction_hash = result["result"]
            logging.info(
                "Bundle was sent with transaction hash : " + transaction_hash
            )
            self.gas_price_percentage_multiplier = 100

            # todo : check if bundle was included on chain
            for user_operation in user_operations:
                self.update_included_status(
                    user_operation.sender_address,
                    user_operation.factory_address_lowercase,
                    user_operation.paymaster_address_lowercase,
                )

    def update_included_status(
        self, sender_address: str, factory_address: str, paymaster_address: str
    ) -> None:
        self.reputation_manager.update_included_status(sender_address)

        if factory_address is not None:
            self.reputation_manager.update_included_status(factory_address)

        if paymaster_address is not None:
            self.reputation_manager.update_included_status(paymaster_address)
