from abc import ABC
from functools import cache
import logging

from eth_abi import encode, decode
from voltaire_bundler.typing import Address
from voltaire_bundler.utils.eth_client_utils import \
        get_latest_block_info, send_rpc_request_to_eth_client
from typing import Any
from ..gas.gas_manager import GasManager
from .models import (Log, ReceiptInfo, UserOperationReceiptInfo)


class UserOperationHandler(ABC):
    ethereum_node_url: str
    bundler_address: Address
    is_legacy_mode: bool
    ethereum_node_eth_get_logs_url: str
    gas_manager: GasManager
    logs_incremental_range: int
    logs_number_of_ranges: int

    async def get_user_operation_receipt(
        self, user_operation_hash: str, entrypoint: str
    ) -> tuple[ReceiptInfo, UserOperationReceiptInfo] | None:
        event_log_info = await self.get_user_operation_event_log_info(
            user_operation_hash, entrypoint
        )
        if event_log_info is None:
            return None
        (
            log_object,
            userOpHash,
            sender,
            paymaster,
            nonce,
            success,
            actualGasCost,
            actualGasUsed,
            logs,
        ) = event_log_info

        transaction = await self.get_transaction_receipt(
                log_object.transactionHash)

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
            effectiveGasPrice="0",
        )
        if not self.is_legacy_mode:
            receiptInfo.effectiveGasPrice = transaction["effectiveGasPrice"]

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

    async def get_user_operation_receipt_rpc(
        self, user_operation_hash: str, entrypoint: str
    ) -> dict | None:
        user_operation_receipt = await self.get_user_operation_receipt(
            user_operation_hash, entrypoint
        )

        if user_operation_receipt is None:
            return None
        (
            receipt_info,
            user_operation_receipt_info,
        ) = user_operation_receipt

        receipt_info_json = {
            "blockHash": receipt_info.blockHash,
            "blockNumber": receipt_info.blockNumber,
            "from": receipt_info._from,
            "cumulativeGasUsed": receipt_info.cumulativeGasUsed,
            "gasUsed": receipt_info.gasUsed,
            "logs": receipt_info.logs,
            "logsBloom": receipt_info.logsBloom,
            "transactionHash": receipt_info.transactionHash,
            "transactionIndex": receipt_info.transactionIndex,
        }

        if not self.is_legacy_mode:
            gas_info = {"effectiveGasPrice": receipt_info.effectiveGasPrice}
            receipt_info_json.update(gas_info)

        user_operation_receipt_rpc_json = {
            "userOpHash": user_operation_receipt_info.userOpHash,
            "entryPoint": entrypoint,
            "sender": user_operation_receipt_info.sender,
            "nonce": hex(user_operation_receipt_info.nonce),
            "paymaster": user_operation_receipt_info.paymaster,
            "actualGasCost": user_operation_receipt_info.actualGasCost,
            "actualGasUsed": user_operation_receipt_info.actualGasUsed,
            "success": user_operation_receipt_info.success,
            "logs": user_operation_receipt_info.logs,
            "receipt": receipt_info_json,
        }

        return user_operation_receipt_rpc_json

    async def get_user_operation_event_log_info(
        self, user_operation_hash: str, entrypoint: str
    ) -> tuple | None:
        logs: Any = await self.get_user_operation_logs(
            user_operation_hash,
            entrypoint,
            self.logs_incremental_range,
            self.logs_number_of_ranges,
        )
        if logs is None:
            return None
        log = logs[0]

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
            logs,
        )

    async def get_transaction_receipt(self, transaction_hash: str) -> dict:
        params = [transaction_hash]
        res: Any = await send_rpc_request_to_eth_client(
            self.ethereum_node_url, "eth_getTransactionReceipt", params
        )
        return res["result"]

    async def get_user_operation_logs(
        self,
        user_operation_hash: str,
        entrypoint: str,
        logs_incremental_range: int,
        logs_number_of_ranges: int,
    ):
        if logs_incremental_range > 0:
            block_info = await get_latest_block_info(
                self.ethereum_node_eth_get_logs_url)

            latest_block_number = int(block_info[0], 16)
            earliest_block_number = latest_block_number - (
                logs_incremental_range * logs_number_of_ranges)
            if earliest_block_number < 0:
                earliest_block_number = 0
            for earliest_block in range(earliest_block_number,
                                        latest_block_number,
                                        logs_incremental_range):
                latest_block = earliest_block + logs_incremental_range
                if latest_block <= earliest_block:
                    break
                res = await self.get_logs(
                    user_operation_hash,
                    entrypoint,
                    hex(earliest_block),
                    hex(latest_block)
                )
                if "result" in res and len(res["result"]) > 0:
                    return res['result']
            return None
        else:
            res = await self.get_logs(
                user_operation_hash,
                entrypoint,
                "earliest",
                "latest"
            )
            if "result" in res and len(res["result"]) > 0:
                return res['result']
            else:
                return None

    async def get_logs(
        self,
        user_operation_hash: str,
        entrypoint: str,
        from_block_hex: str,
        to_block_hex: str,
    ):
        USER_OPERATIOM_EVENT_DISCRIPTOR = (
            "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f"
        )

        params = [
            {
                "address": entrypoint,
                "topics": [
                    USER_OPERATIOM_EVENT_DISCRIPTOR,
                    user_operation_hash,
                ],
                "fromBlock": from_block_hex,
                "toBlock": to_block_hex,
            }
        ]
        res = await send_rpc_request_to_eth_client(
            self.ethereum_node_eth_get_logs_url, "eth_getLogs", params
        )
        return res

    async def get_transaction_by_hash(self, transaction_hash) -> dict:
        params = [transaction_hash]
        res: Any = await send_rpc_request_to_eth_client(
            self.ethereum_node_url, "eth_getTransactionByHash", params
        )
        return res["result"]


async def get_deposit_info(
    address: Address, entrypoint: Address, node_url: str
) -> tuple[int, bool, int, int, int]:
    function_selector = "0x5287ce12"  # getDepositInfo
    params = encode(["address"], [address])

    call_data = function_selector + params.hex()

    params = [
        {
            "to": entrypoint,
            "data": call_data,
        },
        "latest",
    ]

    result: Any = await send_rpc_request_to_eth_client(
        node_url, "eth_call", params
    )
    if "result" in result:
        (deposit, staked, stake, unstake_delay_sec, withdraw_time) = decode(
            ["(uint256,bool,uint112,uint32,uint48)"],
            bytes.fromhex(result["result"][2:])
        )[0]
        return deposit, staked, stake, unstake_delay_sec, withdraw_time
    else:
        logging.critical("balanceOf eth_call failed")
        if "error" in result:
            error = str(result["error"])
            raise ValueError(f"balanceOf eth_call failed - {error}")
        else:
            raise ValueError("balanceOf eth_call failed")


@cache
def decode_failed_op_event(solidity_error_params: str) -> tuple[int, str]:
    FAILED_OP_PARAMS_API = ["uint256", "string"]
    failed_op_params_res = decode(
        FAILED_OP_PARAMS_API, bytes.fromhex(solidity_error_params)
    )
    operation_index = failed_op_params_res[0]
    reason = failed_op_params_res[1]

    return operation_index, reason


@cache
def decode_failed_op_with_revert_event(
        solidity_error_params: str) -> tuple[int, str, bytes]:
    FAILED_OP_PARAMS_API = ["uint256", "string", "bytes"]
    failed_op_params_res = decode(
        FAILED_OP_PARAMS_API, bytes.fromhex(solidity_error_params)
    )
    operation_index = failed_op_params_res[0]
    reason = failed_op_params_res[1]
    inner = failed_op_params_res[2]

    return operation_index, reason, inner


def fell_user_operation_optional_parameters_for_estimateUserOperationGas(
    user_operation_with_optional_params: dict[str, str]
 ) -> dict[str, str]:
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
