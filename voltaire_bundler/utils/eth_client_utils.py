import asyncio
import json
import logging
import random
import traceback
from typing import Any
from eth_abi import encode

from aiohttp import ClientSession, ClientTimeout, TCPConnector

from eth_account import Account, messages
from eth_utils import keccak


# Retry backoff parameters for send_rpc_request_to_eth_client.
# Full-jitter exponential backoff per AWS guidance: each retry waits a
# uniform random delay in [0, min(base * 2**attempt, max)]. The jitter
# prevents many concurrent failures from retrying in lockstep.
_RETRY_BASE_DELAY_S = 0.1   # initial backoff window, in seconds
_RETRY_MAX_DELAY_S = 2.0    # cap on the backoff window, in seconds


def _retry_backoff_delay(attempt: int) -> float:
    """Full-jitter exponential backoff. `attempt` is 0-indexed."""
    window = min(_RETRY_BASE_DELAY_S * (2 ** attempt), _RETRY_MAX_DELAY_S)
    return random.uniform(0, window)


_session: ClientSession | None = None


def get_eth_client_session() -> ClientSession:
    """Return the process-wide aiohttp ClientSession for outbound RPC calls.

    Lazily created on first call so it binds to the running event loop.
    Reused across all callers to enable HTTP keep-alive, DNS caching, and
    connection pooling against each Ethereum node.

    HTTP transport tuned for a bundler that fans out many small requests to
    a handful of Ethereum providers per bundle round:
      - `total=60` seconds: accommodates slow calls (debug_traceCall, wide
        eth_getLogs) without letting a hung connection pin a coroutine
        indefinitely.
      - `connect=10` seconds: generous enough for TLS handshakes to remote
        providers on slow networks.
    """
    global _session
    if _session is None or _session.closed:
        connector = TCPConnector(
            limit=200,                  # max total open connections (all hosts)
            limit_per_host=50,          # max concurrent connections per host
            ttl_dns_cache=300,          # DNS cache TTL, in seconds
            enable_cleanup_closed=True,
        )
        _session = ClientSession(
            connector=connector,
            timeout=ClientTimeout(total=60, connect=10),  # values in seconds
        )
    return _session


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
    expected_key: str | None = None,
    max_attempts: int = 60,
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
    json_result = None
    nodes_len = len(nodes_urls)
    for i in range(max_attempts):
        node_index = i % nodes_len
        if nodes_len > 1 and i > 0:
            logging.info(f'retrying with node no: {node_index + 1}.')
        chosen_node_url = nodes_urls[node_index]  # iterate through nodes
        try:
            session = get_eth_client_session()
            async with session.post(
                chosen_node_url,
                json=json_request,
                headers=headers
            ) as response:
                resp = await response.read()
                if response.status != 200:
                    logging.warning(
                        f"Attempt No. {i+1}: non-200 status {response.status} "
                        f"from {chosen_node_url} for {method}: {resp[:200]!r}"
                    )
                json_result = json.loads(resp)
        except json.decoder.JSONDecodeError:
            logging.error(
                f"Attempt No. {i+1} to call node rpc failed."
                "Invalid json response from eth client."
            )
            await asyncio.sleep(_retry_backoff_delay(i))
        except Exception as excp:
            logging.error(
                f"Attempt No. {i+1} to call node rpc failed."
                f"error: {str(excp)}"
            )
            logging.error(f"traceback: {str(traceback.format_exc())}")
            await asyncio.sleep(_retry_backoff_delay(i))
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
                    json_result["error"]["code"] != -32015 and  # nethermind https://github.com/NethermindEth/nethermind/pull/8951
                    json_result["error"]["code"] != -32010 and  # nethermind TransactionRejected
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
                    await asyncio.sleep(_retry_backoff_delay(i))
                    continue
                elif expected_key is not None and expected_key not in json_result:
                    logging.error(
                        f"Attempt No. {i+1} to call node rpc failed."
                        f"the request: {str(json_request)}"
                        f"as the key {expected_key} is not in the result: {str(json_result)}"
                    )
                    await asyncio.sleep(_retry_backoff_delay(i))
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
    session = get_eth_client_session()
    async with session.post(
        ethereum_node_url,
        json=json_request,
        headers=headers
    ) as response:
        resp = await response.read()
        if response.status != 200:
            logging.warning(
                f"Non-200 status {response.status} from {ethereum_node_url} "
                f"for {method}: {resp[:200]!r}"
            )
        return json.loads(resp)


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


def encode_handleops_calldata_v7v8v9(
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
