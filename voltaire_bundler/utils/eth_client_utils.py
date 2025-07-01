import asyncio
import json
import logging
import traceback
from typing import Any
from eth_abi import encode

from aiohttp import ClientSession

from eth_account import Account, messages
from eth_utils import keccak


def create_flashbots_signature(
    request_data: str,
    signer: str,
    private_key: str
) -> str:
    message = messages.encode_defunct(
        text='0x' + keccak(text=request_data).hex()
    )
    signed_message = Account.sign_message(
        message, private_key=private_key
    )
    return f"{signer}:0x{signed_message.signature.hex()}"


async def send_rpc_request_to_eth_client(
    nodes_urls: list[str],
    method: str,
    params=None,
    flashbots_signer_private_key_pair: tuple[str, str] | None = None,
    expected_key: str | None = None
) -> Any:
    json_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }
    headers = {
        "content-type": "application/json",
        "connection": "keep-alive"
    }
    if flashbots_signer_private_key_pair is not None:
        signer, private_key = flashbots_signer_private_key_pair
        headers["X-Flashbots-Signature"] = create_flashbots_signature(
            json.dumps(json_request),
            signer,
            private_key
        )
    NUMBER_OF_RETRY_ATTEMPTS = 60
    json_result = None
    nodes_len = len(nodes_urls)
    for i in range(NUMBER_OF_RETRY_ATTEMPTS):
        node_index = i % nodes_len
        if nodes_len > 1 and i > 0:
            logging.info(f'retrying with node no: {node_index + 1}.')
        chosen_node_url = nodes_urls[node_index]  # iterate through nodes
        try:
            async with ClientSession() as session:
                async with session.post(
                    chosen_node_url,
                    json=json_request,
                    headers=headers
                ) as response:
                    resp = await response.read()
                    json_result = json.loads(resp)
        except json.decoder.JSONDecodeError:
            logging.error(
                f"Attempt No. {i+1} to call node rpc failed."
                "Invalid json response from eth client."
            )
            await asyncio.sleep(1)
        except Exception as excp:
            logging.error(
                f"Attempt No. {i+1} to call node rpc failed."
                f"error: {str(excp)}"
            )
            logging.error(f"traceback: {str(traceback.format_exc())}")
            await asyncio.sleep(1)
        except:
            logging.error(
                f"Attempt No. {i+1} to call node rpc failed."
            )
            logging.error(f"traceback: {str(traceback.format_exc())}")
            await asyncio.sleep(1)
        else:
            if "error" in json_result:
                if "message" in json_result["error"]:
                    err_message = json_result["error"]["message"]
                else:
                    err_message = ""
                if (
                    "code" in json_result["error"] and
                    json_result["error"]["code"] != 3 and
                    json_result["error"]["code"] != -32000 and
                    json_result["error"]["code"] != -32603
                ) or (
                    # special case for erpc errors like:
                    # "upstream circuit breaker open" or "upstream server errors"
                    # assuming erpc is the first url in the node list
                    "upstream" in err_message and node_index == 0
                ):
                    err_code = json_result["error"]["code"]
                    logging.error(
                        f"Attempt No. {i+1} to call node rpc failed."
                        f"the request: {str(json_request)}"
                        f" with error code: {err_code}"
                        f" and error message: {err_message}."
                    )
                    continue
                elif expected_key is not None and expected_key not in json_result:
                    logging.error(
                        f"Attempt No. {i+1} to call node rpc failed."
                        f"the request: {str(json_request)}"
                        f"as the key {expected_key} is not in the result: {str(json_result)}"
                    )
                    continue
            return json_result
    raise ValueError("Failed rpc request to rpc node client")


async def send_rpc_request_to_eth_client_no_retry(
    ethereum_node_url,
    method,
    params=None,
) -> Any:
    json_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }
    headers = {
        "content-type": "application/json",
        "connection": "keep-alive"
    }
    async with ClientSession() as session:
        async with session.post(
            ethereum_node_url,
            json=json_request,
            headers=headers
        ) as response:
            try:
                resp = await response.read()
                return json.loads(resp)
            except json.decoder.JSONDecodeError:
                logging.critical("Invalid json response from eth client")
                raise ValueError("Invalid json response from eth client")
            except Exception as excp:
                logging.error(
                    "Call to node rpc failed." +
                    str(traceback.format_exc()) +
                    str(excp)
                )
                await asyncio.sleep(1)
            except:
                logging.error(
                    str(traceback.format_exc())
                )
                await asyncio.sleep(1)


async def get_block_info(
    ethereum_node_urls, block_number_hex: str = "latest"
) -> tuple[str, int, str, int, str]:
    raw_res: Any = await send_rpc_request_to_eth_client(
        ethereum_node_urls,
        "eth_getBlockByNumber",
        [block_number_hex, False],
        None,
        "result"
    )
    latest_block = raw_res["result"]

    latest_block_number = latest_block["number"]

    if "baseFeePerGas" in latest_block:
        latest_block_basefee = int(latest_block["baseFeePerGas"], 16)
    else:  # for block requested before the EIP-1559 upgrade
        latest_block_basefee = 0

    latest_block_gas_limit_hex = latest_block["gasLimit"]
    latest_block_timestamp = int(latest_block["timestamp"], 16)
    latest_block_hash = latest_block["hash"]

    return (
        latest_block_number,
        latest_block_basefee,
        latest_block_gas_limit_hex,
        latest_block_timestamp,
        latest_block_hash,
    )


@staticmethod
def encode_handleops_calldata_v6(
    user_operations_list: list[list[Any]], bundler_address: str
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
def encode_handleops_calldata_v7v8(
        user_operations_list: list[list[Any]], bundler_address: str) -> str:
    function_selector = "0x765e827f"  # handleOps
    params = encode(
        [
            "(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[]",
            "address",
        ],
        [user_operations_list, bundler_address],
    )

    call_data = function_selector + params.hex()
    return call_data
