from eth_abi import encode

from web3 import Web3
from eth_abi import decode

from bundler.eth_client_utils import send_rpc_request_to_eth_client


async def get_user_operation_hash(
    user_operation,
    entrypoint_address,
    entrypoint_abi,
    geth_rpc_url,
    bundler_address,
):
    w3_provider = Web3()
    entrypoint_contract = w3_provider.eth.contract(
        address=entrypoint_address, abi=entrypoint_abi
    )

    call_data = entrypoint_contract.encodeABI(
        "getUserOpHash", [user_operation.get_user_operation_dict()]
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
    return result['result']


def pack_user_operation(user_operation):
    return encode(
        [
            "address",
            "uint256",
            "bytes",
            "bytes",
            "uint256",
            "uint256",
            "uint256",
            "uint256",
            "uint256",
            "bytes",
            "bytes",
        ],
        user_operation,
    )[66:-64]
