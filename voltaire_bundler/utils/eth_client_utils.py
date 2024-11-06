import json
import logging
from typing import Any

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
    ethereum_node_url,
    method,
    params=None,
    signer_private_key_pair: tuple[str, str] | None = None,
    signature_header_key: str | None = None
) -> Any:
    json_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }
    headers = {"content-type": "application/json"}
    if signer_private_key_pair is not None:
        if signature_header_key is None:
            logging.critical(
                "signature_header_key can't be null "
                "if signer_private_key_pair is not null"
            )
            raise ValueError(
                "signature_header_key can't be null "
                "if signer_private_key_pair is not null"
            )

        signer, private_key = signer_private_key_pair
        headers[signature_header_key] = create_flashbots_signature(
            json.dumps(json_request),
            signer,
            private_key
        )
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
                logging.critical("Invalide json response from eth client")
                raise ValueError("Invalide json response from eth client")


async def get_latest_block_info(
        ethereum_node_url) -> tuple[str, int, str, int, str]:
    raw_res: Any = await send_rpc_request_to_eth_client(
        ethereum_node_url, "eth_getBlockByNumber", ["latest", False]
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
