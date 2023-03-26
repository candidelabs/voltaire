import asyncio
import logging
from web3 import Web3

from utils.eth_client_utils import send_rpc_request_to_eth_client
from user_operation.user_operation import UserOperation
from user_operation.user_operation_handler import UserOperationHandler
from .mempool_manager import MempoolManager
from .reputation_manager import ReputationManager


class BundlerManager:
    geth_rpc_url: str
    bundler_private_key: str
    bundler_address: str
    entrypoint: str
    entrypoint_abi: str
    mempool_manager: MempoolManager
    user_operation_handler: UserOperationHandler
    reputation_manager: ReputationManager
    chain_id: int

    def __init__(
        self,
        mempool_manager,
        user_operation_handler,
        reputation_manager,
        geth_rpc_url,
        bundler_private_key,
        bundler_address,
        entrypoint,
        entrypoint_abi,
        chain_id,
    ):
        self.mempool_manager = mempool_manager
        self.user_operation_handler = user_operation_handler
        self.reputation_manager = reputation_manager
        self.geth_rpc_url = geth_rpc_url
        self.bundler_private_key = bundler_private_key
        self.bundler_address = bundler_address
        self.entrypoint = entrypoint
        self.entrypoint_abi = entrypoint_abi
        self.chain_id = chain_id

    async def send_next_bundle(self):
        user_operations = (
            await self.mempool_manager.get_user_operations_to_bundle()
        )
        numbder_of_user_operations = len(user_operations)

        if numbder_of_user_operations > 0:
            await self.send_bundle(user_operations)
            logging.info(
                f"Sending bundle with {len(user_operations)} user operations"
            )
        else:
            logging.info(f"Waiting for user operations to send bundle")

    async def send_bundle(self, user_operations: list[UserOperation]):
        w3Provider = Web3()
        entrypoint_contract = w3Provider.eth.contract(
            address=self.entrypoint, abi=self.entrypoint_abi
        )

        user_operation_dict = []
        for user_operation in user_operations:
            user_operation_dict.append(
                user_operation.get_user_operation_dict()
            )

        args = [user_operation_dict, self.bundler_address]
        call_data = entrypoint_contract.encodeABI("handleOps", args)
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

        sign_store_txn = w3Provider.eth.account.sign_transaction(
            txnDict, private_key=self.bundler_private_key
        )
        result = await send_rpc_request_to_eth_client(
            self.geth_rpc_url,
            "eth_sendRawTransaction",
            [sign_store_txn.rawTransaction.hex()],
        )
        transaction_hash = result["result"]

        # todo : check if bundle was included on chain
        for user_operation in user_operations:
            self.update_included_status(
                user_operation.sender,
                user_operation.factory_address,
                user_operation.paymaster_address,
            )

        return transaction_hash

    def update_included_status(
        self, sender_address, factory_address, paymaster_address
    ):
        self.reputation_manager.update_included_status(sender_address)

        if factory_address is not None:
            self.reputation_manager.update_included_status(factory_address)

        if paymaster_address is not None:
            self.reputation_manager.update_included_status(paymaster_address)
