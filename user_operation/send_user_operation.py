from web3 import Web3

from bundler_endpoint.eth_client_utils import send_rpc_request_to_eth_client
from .estimate_user_operation_gas import estimate_call_gas_limit


async def send_bundle(
    transactions,
    entrypoint_address,
    entrypoint_abi,
    geth_rpc_url,
    bundler_private_key,
    bundler_address,
):
    w3Provider = Web3()
    entrypoint_contract = w3Provider.eth.contract(
        address=entrypoint_address, abi=entrypoint_abi
    )

    transactions_dict = []
    for transaction in transactions:
        transactions_dict.append(transaction.get_user_operation_dict())

    args = [transactions_dict, bundler_address]
    call_data = entrypoint_contract.encodeABI("handleOps", args)
    gasEstimation = await estimate_call_gas_limit(
        call_data,
        _from=bundler_address,
        to=entrypoint_address,
        geth_rpc_url=geth_rpc_url,
    )

    gasPrice = await send_rpc_request_to_eth_client(
        geth_rpc_url, "eth_gasPrice"
    )

    txnDict = {
        "chainId": w3Provider.eth.chain_id,
        "from": bundler_address,
        "to": entrypoint_address,
        "nonce": w3Provider.eth.get_transaction_count(bundler_address),
        "gas": int(gasEstimation, 16),
        "maxFeePerGas": gasPrice["result"],
        "maxPriorityFeePerGas": gasPrice["result"],
        "data": call_data,
    }

    sign_store_txn = w3Provider.eth.account.sign_transaction(
        txnDict, private_key=bundler_private_key
    )
    result = await send_rpc_request_to_eth_client(
        geth_rpc_url,
        "eth_sendRawTransaction",
        [sign_store_txn.rawTransaction.hex()],
    )
    return result
