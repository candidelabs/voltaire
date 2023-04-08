import asyncio
import logging

from eth_abi import encode
from eth_account import Account

from utils.eth_client_utils import send_rpc_request_to_eth_client
from user_operation.user_operation import UserOperation
from user_operation.user_operation_handler import UserOperationHandler
from .mempool_manager import MempoolManager
from .reputation_manager import ReputationManager
from .validation_manager import ValidationManager


class BundlerManager:
    geth_rpc_url: str
    bundler_private_key: str
    bundler_address: str
    entrypoint: str
    mempool_manager: MempoolManager
    user_operation_handler: UserOperationHandler
    reputation_manager: ReputationManager
    chain_id: int

    def __init__(
        self,
        mempool_manager: MempoolManager,
        user_operation_handler: UserOperationHandler,
        reputation_manager: ReputationManager,
        geth_rpc_url: str,
        bundler_private_key: str,
        bundler_address: str,
        entrypoint: str,
        chain_id: str,
    ):
        self.mempool_manager = mempool_manager
        self.user_operation_handler = user_operation_handler
        self.reputation_manager = reputation_manager
        self.geth_rpc_url = geth_rpc_url
        self.bundler_private_key = bundler_private_key
        self.bundler_address = bundler_address
        self.entrypoint = entrypoint
        self.chain_id = chain_id

    async def send_next_bundle(self) -> None:
        user_operations = (
            await self.mempool_manager.get_user_operations_to_bundle()
        )
        numbder_of_user_operations = len(user_operations)

        if numbder_of_user_operations > 0:
            await self.send_bundle(user_operations)
            logging.info(
                f"Sending bundle with {len(user_operations)} user operations"
            )

    async def send_bundle(self, user_operations: list[UserOperation]) -> None:
        user_operations_list = []
        for user_operation in user_operations:
            user_operations_list.append(user_operation.to_list())

        function_selector = "0x1fad948c"  # handleOps
        params = encode(
            [
                "(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)[]",
                "address",
            ],
            [user_operations_list, self.bundler_address],
        )

        call_data = function_selector + params.hex()

        gas_estimation_op = (
            self.user_operation_handler.estimate_call_gas_limit(
                call_data,
                _from=self.bundler_address,
                to=self.entrypoint,
            )
        )

        gas_price_op = send_rpc_request_to_eth_client(
            self.geth_rpc_url, "eth_gasPrice"
        )

        nonce_op = send_rpc_request_to_eth_client(
            self.geth_rpc_url,
            "eth_getTransactionCount",
            [self.bundler_address, "latest"],
        )

        tasks = await asyncio.gather(gas_estimation_op, gas_price_op, nonce_op)

        gas_estimation = tasks[0]
        gas_price = tasks[1]["result"]
        nonce = tasks[2]["result"]

        txnDict = {
            "chainId": self.chain_id,
            "from": self.bundler_address,
            "to": self.entrypoint,
            "nonce": nonce,
            "gas": int(gas_estimation, 16),
            "maxFeePerGas": gas_price,
            "maxPriorityFeePerGas": gas_price,
            "data": call_data,
        }

        sign_store_txn = Account.sign_transaction(
            txnDict, private_key=self.bundler_private_key
        )
        result = await send_rpc_request_to_eth_client(
            self.geth_rpc_url,
            "eth_sendRawTransaction",
            [sign_store_txn.rawTransaction.hex()],
        )
        if "error" in result:
            # raise ValueError("simulateValidation didn't revert!")
            error_data = result["error"]["data"]

            solidity_error_selector = str(error_data[:10])
            if ValidationManager.check_if_failed_op_error(
                solidity_error_selector
            ):
                solidity_error_params = error_data[10:]
                (
                    operation_index,
                    reason,
                ) = ValidationManager.decode_FailedOp_event(
                    solidity_error_params
                )

                if (
                    "AA3" in reason
                    and user_operation.paymaster_address is not None
                ):
                    self.reputation_manager.ban_entity(
                        user_operation.paymaster_address
                    )
                elif "AA2" in reason:
                    self.reputation_manager.ban_entity(user_operation.sender)
                elif (
                    "AA1" in reason
                    and user_operation.factory_address is not None
                ):
                    self.reputation_manager.ban_entity(
                        user_operation.factory_address
                    )

                logging.info(
                    "Dropping user operation that caused bundle crash"
                )
                del user_operations[operation_index]

                if len(user_operations) > 0:
                    self.send_bundle(user_operations)
            else:
                logging.info("Failed to send bundle.")
                for user_operation in user_operations:
                    sender = self.mempool_manager.senders[
                        user_operation.sender
                    ]
                    sender.user_operations.append(user_operation)

        else:
            transaction_hash = result["result"]
            logging.info(
                "Bundle was sent with transaction hash : " + transaction_hash
            )

            # todo : check if bundle was included on chain
            for user_operation in user_operations:
                self.update_included_status(
                    user_operation.sender,
                    user_operation.factory_address,
                    user_operation.paymaster_address,
                )

    def update_included_status(
        self, sender_address: str, factory_address: str, paymaster_address: str
    ) -> None:
        self.reputation_manager.update_included_status(sender_address)

        if factory_address is not None:
            self.reputation_manager.update_included_status(factory_address)

        if paymaster_address is not None:
            self.reputation_manager.update_included_status(paymaster_address)
