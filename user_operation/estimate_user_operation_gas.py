import asyncio
from functools import reduce
import math

from web3 import Web3
from eth_abi import decode

from .user_operation import UserOperation
from .erc4337_utils import pack_user_operation
from rpc.exceptions import BundlerException, ExceptionCode
from bundler.eth_client_utils import send_rpc_request_to_eth_client
from bundler.validation_manager import simulate_validation_and_decode_result

async def estimate_user_operation_gas(
    user_operation: UserOperation,
    entrypoint_address,
    entrypoint_abi,
    geth_rpc_url,
    bundler_address,
):
    tasks = await asyncio.gather(
        simulate_validation_and_decode_result(
            user_operation,
            entrypoint_address,
            geth_rpc_url,
            bundler_address,
            entrypoint_abi,
        ),
        estimate_call_gas_limit(
            call_data="0x" + user_operation.call_data.hex(),
            _from=entrypoint_address,
            to=user_operation.sender,
            geth_rpc_url=geth_rpc_url,
        ),
        asyncio.to_thread(calc_preverification_gas, user_operation),
    )

    return_info, _, _, _ = tasks[0]
    call_gas_limit = tasks[1]
    pre_verification_gas = tasks[2]

    pre_operation_gas = return_info.preOpGas
    valid_until = return_info.validUntil

    return call_gas_limit, pre_verification_gas, pre_operation_gas, valid_until


async def estimate_call_gas_limit(call_data, _from, to, geth_rpc_url):
    params = [{"from": _from, "to": to, "data": call_data}]

    result = await send_rpc_request_to_eth_client(
        geth_rpc_url, "eth_estimateGas", params
    )
    if "error" in result:
        errorMessage = result["error"]["message"]
        errorData = result["error"]["data"]
        errorParams = errorData[10:]
        raise BundlerException(
            ExceptionCode.EXECUTION_REVERTED, errorMessage, errorParams
        )
    call_gas_limit = result["result"]

    return call_gas_limit


def calc_preverification_gas(user_operation: UserOperation) -> int:
    userOp = user_operation

    fixed = 21000
    per_user_operation = 18300
    per_user_operation_word = 4
    zero_byte = 4
    non_zero_byte = 16
    bundle_size = 1
    sigSize = 65

    # userOp.preVerificationGas = fixed
    # userOp.signature = bytes(sigSize)
    packed = pack_user_operation(userOp.to_list())

    cost_list = list(
        map(lambda x: zero_byte if x == b"\x00" else non_zero_byte, packed)
    )
    call_data_cost = reduce(lambda x, y: x + y, cost_list)

    pre_verification_gas = (
        call_data_cost
        + (fixed / bundle_size)
        + per_user_operation
        + per_user_operation_word * len(packed)
    )

    return math.ceil(pre_verification_gas)
