from eth_abi import encode
from voltaire_bundler.user_operation.user_operation import UserOperation

@staticmethod
def encode_handleops_calldata(user_operations_list:[], bundler_address:str)->str:
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
def encode_simulate_validation_calldata(user_operation:UserOperation)->str:
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