from eth_abi import decode
from functools import cache

@cache
@staticmethod
def decode_FailedOp_event(solidity_error_params: str) -> tuple[str, str]:
    FAILED_OP_PARAMS_API = ["uint256", "string"]
    failed_op_params_res = decode(
        FAILED_OP_PARAMS_API, bytes.fromhex(solidity_error_params)
    )
    operation_index = failed_op_params_res[0]
    reason = failed_op_params_res[1]

    return operation_index, reason


@staticmethod
def decode_ExecutionResult(
    solidity_error_params: str,
) -> tuple[str, str, bool, str]:
    EXECUTION_RESULT_PARAMS_API = [
        "uint256",  # preOpGas
        "uint256",  # paid
        "uint48",  # validAfter
        "uint48",  # validUntil
        "bool",  # targetSuccess
        "bytes",  # targetResult
    ]
    execution_result__params_res = decode(
        EXECUTION_RESULT_PARAMS_API, bytes.fromhex(solidity_error_params)
    )
    preOpGas = execution_result__params_res[0]
    paid = execution_result__params_res[1]
    targetSuccess = execution_result__params_res[4]
    targetResult = execution_result__params_res[5]

    return preOpGas, paid, targetSuccess, targetResult


@staticmethod
def decode_gasEstimateL1Component_result(raw_gas_results: str) -> int:
    decoded_results = decode(
        [
            "uint64",  # gasEstimateForL1
            "uint256",  # baseFee
            "uint256",  # l1BaseFeeEstimate
        ],
        bytes.fromhex(raw_gas_results[2:]),
    )

    gas_estimate_for_l1 = decoded_results[0]

    return gas_estimate_for_l1
