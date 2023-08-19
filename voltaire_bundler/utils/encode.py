from eth_abi import encode
from voltaire_bundler.user_operation.user_operation import UserOperation


@staticmethod
def encode_handleops_calldata(
    user_operations_list: [], bundler_address: str
) -> str:
    function_selector = "0x1fad948c"  # handleOps
    params = encode(
        [
            "(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)[]",
            "address",
        ],
        [user_operations_list, bundler_address],
    )

    call_data = function_selector + params.hex()
    return call_data


@staticmethod
def encode_simulate_validation_calldata(user_operation: UserOperation) -> str:
    # simulateValidation(entrypoint solidity function) will always revert
    function_selector = "0xee219423"
    params = encode(
        [
            "(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)"
        ],
        [user_operation.to_list()],
    )

    call_data = function_selector + params.hex()
    return call_data


@staticmethod
def encode_gasEstimateL1Component_calldata(
    entrypoint: str, is_init: bool, handleops_calldata: str
) -> str:
    function_selector = "0x77d488a2"  # gasEstimateL1Component
    params = encode(
        ["address", "bool", "bytes"],  # to  # contractCreation  # data
        [entrypoint, is_init, bytes.fromhex(handleops_calldata[2:])],
    )

    call_data = function_selector + params.hex()
    return call_data
