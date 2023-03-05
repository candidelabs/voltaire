import asyncio
from functools import reduce
import math

from web3 import Web3
from eth_abi import decode

from user_operation.user_operation import UserOperation
from user_operation.entrypoint_structs import ReturnInfo, StakeInfo, FailedOpRevertData
from rpc.exceptions import BundlerException, ExceptionCode
from bundler.eth_client_utils import send_rpc_request_to_eth_client


async def simulate_validation_and_decode_result(
    user_operation: UserOperation,
    entrypoint_address: str,
    geth_rpc_url: str,
    bundler_address: str,
    entrypoint_abi,
) -> ReturnInfo:
    # simulateValidation(entrypoint solidity function) will always revert
    solidity_error_selector, solidity_error_params = await simulate_validation(
        user_operation,
        entrypoint_address,
        geth_rpc_url,
        bundler_address,
        entrypoint_abi,
    )

    if check_if_failed_op_error(solidity_error_selector):
        _, _, reason = decode_FailedOp_event(solidity_error_params)
        raise BundlerException(
            ExceptionCode.REJECTED_BY_EP_OR_ACCOUNT,
            "revert reason : " + reason,
            solidity_error_params,
        )

    return_info, sender_info, factory_info, paymaster_info = decode_validation_result_event(
        solidity_error_params
    )

    return return_info, sender_info, factory_info, paymaster_info


def check_if_failed_op_error(solidity_error_selector) -> bool:
    return solidity_error_selector == FailedOpRevertData.SELECTOR


def decode_validation_result_event(solidity_error_params) -> ReturnInfo:
    VALIDATION_RESULT_ABI = [
        "(uint256,uint256,bool,uint64,uint64,bytes)",
        "(uint256,uint256)",
        "(uint256,uint256)",
        "(uint256,uint256)",
    ]
    validation_result_decoded = decode(
        VALIDATION_RESULT_ABI, bytes.fromhex(solidity_error_params)
    )
    return_info_arr = validation_result_decoded[0]
    return_info = ReturnInfo(
        preOpGas=return_info_arr[0],
        prefund=return_info_arr[1],
        sigFailed=return_info_arr[2],
        validAfter=return_info_arr[3],
        validUntil=return_info_arr[4],
    )

    sender_info_arr = validation_result_decoded[1]
    sender_info = StakeInfo(
        stake=sender_info_arr[0], unstakeDelaySec=sender_info_arr[1]
    )

    factory_info_arr = validation_result_decoded[2]
    factory_info = StakeInfo(
        stake=factory_info_arr[0], unstakeDelaySec=factory_info_arr[1]
    )

    paymaster_info_arr = validation_result_decoded[3]
    paymaster_info = StakeInfo(
        stake=paymaster_info_arr[0], unstakeDelaySec=paymaster_info_arr[1]
    )

    return return_info, sender_info, factory_info, paymaster_info


def decode_FailedOp_event(solidity_error_params):
    FAILED_OP_PARAMS_API = ["uint256", "address", "string"]
    failed_op_params_res = decode(
        FAILED_OP_PARAMS_API, bytes.fromhex(solidity_error_params)
    )
    operation_index = failed_op_params_res[0]
    paymaster_address = failed_op_params_res[1]
    reason = failed_op_params_res[2]

    return operation_index, paymaster_address, reason


async def simulate_validation(
    user_operation: UserOperation,
    entrypoint_address: str,
    geth_rpc_url: str,
    bundler_address: str,
    entrypoint_abi,
):
    w3_provider = Web3()
    entrypoint_contract = w3_provider.eth.contract(
        address=entrypoint_address, abi=entrypoint_abi
    )
    call_data = entrypoint_contract.encodeABI(
        "simulateValidation", [user_operation.get_user_operation_dict()]
    )

    params = [
        {
            "from": bundler_address,
            "to": entrypoint_address,
            "data": call_data,
        },
        "latest",
    ]

    result = await send_rpc_request_to_eth_client(
        geth_rpc_url, "eth_call", params
    )
    if (
        "error" not in result
        or result["error"]["message"] != "execution reverted"
    ):
        raise ValueError("simulateValidation didn't revert!")

    error_data = result["error"]["data"]

    solidity_error_selector = str(error_data[:10])
    solidity_error_params = error_data[10:]

    return solidity_error_selector, solidity_error_params