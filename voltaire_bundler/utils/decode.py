from eth_abi import decode

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
def decode_ExecutionResult(solidity_error_params: str) -> tuple[str, str, bool, str]:
    EXECUTION_RESULT_PARAMS_API = [
        "uint256", #preOpGas
        "uint256", #paid
        "uint48",  #validAfter
        "uint48",  #validUntil
        "bool",    #targetSuccess
        "bytes"    #targetResult
    ]
    execution_result__params_res = decode(
        EXECUTION_RESULT_PARAMS_API, bytes.fromhex(solidity_error_params)
    )
    preOpGas = execution_result__params_res[0]
    paid = execution_result__params_res[1]
    targetSuccess = execution_result__params_res[4]
    targetResult = execution_result__params_res[5]

    return preOpGas, paid, targetSuccess, targetResult