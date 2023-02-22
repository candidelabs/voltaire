from aiohttp import ClientSession
import json
from eth_abi import decode
from user_operation.receipt_models import (
    Log,
    ReceiptInfo,
    UserOperationReceiptInfo,
)
from bundler_endpoint.eth_client_utils import send_rpc_request_to_eth_client


async def get_user_operation_by_hash(
    geth_rpc_url, entrypoint_add, user_operation_hash
):
    (
        log_object,
        _,
        _,
        _,
        _,
        _,
        _,
        _,
    ) = await get_user_operation_event_log_info(
        entrypoint_add, user_operation_hash, geth_rpc_url
    )
    transaction_hash = log_object.transactionHash

    transaction = await get_transaction_by_hash(transaction_hash, geth_rpc_url)

    block_hash = transaction["blockHash"]
    block_number = transaction["blockNumber"]
    user_operation = transaction["input"]

    return user_operation, block_number, block_hash, transaction_hash


async def get_user_operation_receipt(
    geth_rpc_url, entrypoint_add, user_operation_hash
):
    (
        log_object,
        userOpHash,
        sender,
        paymaster,
        nonce,
        success,
        actualGasCost,
        actualGasUsed,
    ) = await get_user_operation_event_log_info(
        entrypoint_add, user_operation_hash, geth_rpc_url
    )

    transaction = await get_transaction_receipt(
        log_object.transactionHash, geth_rpc_url
    )

    receiptInfo = ReceiptInfo(
        transactionHash=transaction["transactionHash"],
        transactionIndex=log_object.transactionIndex,
        blockHash=transaction["blockHash"],
        blockNumber=transaction["blockNumber"],
        _from=transaction["from"],
        to=transaction["to"],
        cumulativeGasUsed=transaction["cumulativeGasUsed"],
        gasUsed=transaction["gasUsed"],
        contractAddress=transaction["contractAddress"],
        logs=transaction["logs"],
        logsBloom=transaction["logsBloom"],
        # root=transaction['root'],
        status=transaction["status"],
        effectiveGasPrice=transaction["effectiveGasPrice"],
    )

    logs = await get_logs(
        log_object.transactionHash, receiptInfo._from, geth_rpc_url
    )

    userOperationReceiptInfo = UserOperationReceiptInfo(
        userOpHash=userOpHash,
        sender=sender,
        paymaster=paymaster,
        nonce=nonce,
        success=success,
        actualGasCost=actualGasCost,
        actualGasUsed=actualGasUsed,
        logs=logs,
        receipt=receiptInfo,
    )

    return receiptInfo, userOperationReceiptInfo


async def get_user_operation_event_log_info(
    entrypoint_add, user_operation_hash, geth_rpc_url
):
    USER_OPERATIOM_EVENT_DISCRIPTOR = (
        "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f"
    )
    params = [
        {
            "address": entrypoint_add,
            "topics": [USER_OPERATIOM_EVENT_DISCRIPTOR, user_operation_hash],
        }
    ]

    res = await send_rpc_request_to_eth_client(
        geth_rpc_url, "eth_getLogs", params
    )
    log = res["result"][0]

    log_object = Log(
        removed=log["removed"],
        logIndex=log["logIndex"],
        transactionIndex=log["transactionIndex"],
        transactionHash=log["transactionHash"],
        blockHash=log["blockHash"],
        blockNumber=log["blockNumber"],
        address=log["address"],
        data=log["data"],
        topics=log["topics"],
    )

    topics = log["topics"]
    data = log["data"]

    userOpHash = topics[1]
    sender = decode(["address"], bytes.fromhex(topics[2][2:]))[0]
    paymaster = decode(["address"], bytes.fromhex(topics[3][2:]))[0]

    data_abi = ["uint256", "bool", "uint256", "uint256"]
    decode_result = decode(data_abi, bytes.fromhex(data[2:]))
    nonce = decode_result[0]
    success = decode_result[1]
    actualGasCost = decode_result[2]
    actualGasUsed = decode_result[3]

    return (
        log_object,
        userOpHash,
        sender,
        paymaster,
        nonce,
        success,
        actualGasCost,
        actualGasUsed,
    )


async def get_transaction_receipt(transaction_hash, geth_rpc_url):
    params = [transaction_hash]
    res = await send_rpc_request_to_eth_client(
        geth_rpc_url, "eth_getTransactionReceipt", params
    )
    return res["result"]


async def get_logs(transaction_hash, _from, geth_rpc_url):
    params = [
        {
            "address": _from,
            "transactionHash": transaction_hash,
        }
    ]

    res = await send_rpc_request_to_eth_client(
        geth_rpc_url, "eth_getLogs", params
    )
    return res["result"]


async def get_transaction_by_hash(transaction_hash, geth_rpc_url):
    params = [transaction_hash]
    res = await send_rpc_request_to_eth_client(
        geth_rpc_url, "eth_getTransactionByHash", params
    )
    return res["result"]
