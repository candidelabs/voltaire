from web3 import Web3

from utils.eth_client_utils import send_rpc_request_to_eth_client
from user_operation.user_operation_handler import UserOperationHandler
from .mempool_manager import MempoolManager

class BundlerManager():
    geth_rpc_url: str
    bundler_private_key: str
    bundler_address: str
    entrypoint: str
    entrypoint_abi: str
    mempool_manager: MempoolManager
    user_operation_handler: UserOperationHandler

    def __init__(
        self,
        mempool_manager,
        user_operation_handler,
        geth_rpc_url,
        bundler_private_key,
        bundler_address,
        entrypoint,
        entrypoint_abi,
    ):
        self.mempool_manager = mempool_manager
        self.user_operation_handler = user_operation_handler
        self.geth_rpc_url = geth_rpc_url
        self.bundler_private_key = bundler_private_key
        self.bundler_address = bundler_address
        self.entrypoint = entrypoint
        self.entrypoint_abi = entrypoint_abi

    async def send_next_bundle(self):
        user_operations = self.mempool_manager.get_user_operations_to_bundle()
        return await self.send_bundle(user_operations)

    async def send_bundle(self, user_operations):
        w3Provider = Web3()
        entrypoint_contract = w3Provider.eth.contract(
            address=self.entrypoint, abi=self.entrypoint_abi
        )

        transactions_dict = []
        for transaction in user_operations:
            transactions_dict.append(transaction.get_user_operation_dict())

        args = [transactions_dict, self.bundler_address]
        call_data = entrypoint_contract.encodeABI("handleOps", args)
        gasEstimation = await self.user_operation_handler.estimate_call_gas_limit(
            call_data,
            _from=self.bundler_address,
            to=self.entrypoint,
        )

        gasPrice = await send_rpc_request_to_eth_client(
            self.geth_rpc_url, "eth_gasPrice"
        )

        txnDict = {
            "chainId": w3Provider.eth.chain_id,
            "from": self.bundler_address,
            "to": self.entrypoint,
            "nonce": w3Provider.eth.get_transaction_count(self.bundler_address),
            "gas": int(gasEstimation, 16),
            "maxFeePerGas": gasPrice["result"],
            "maxPriorityFeePerGas": gasPrice["result"],
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
        return result['result']
