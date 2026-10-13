import asyncio
import json
import logging
import traceback
from typing import Any
from eth_abi import encode

from aiohttp import ClientSession, ClientTimeout, TCPConnector

from eth_account import Account, messages
from eth_utils import keccak


_session: ClientSession | None = None


# --- per-method outbound concurrency cap ---------------------------------
# Caller-side backpressure: cap concurrent in-flight requests per RPC
# method so a thundering herd against the upstream node can't keep
# escalating. Excess callers wait inside the semaphore.
#
# Limits sized conservatively — the right value is "what the node can
# serve at acceptable tail latency", which is provider-dependent. Tune
# upward if the node serves a method comfortably under load, downward
# if tails grow with concurrency.
_METHOD_CONCURRENCY_LIMITS: dict[str, int] = {
    "eth_call": 32,
    "eth_getLogs": 16,
    "eth_getBlockByNumber": 8,
    "eth_getTransactionReceipt": 32,
    "eth_getTransactionByHash": 32,
    "eth_getTransactionCount": 16,
    "eth_sendRawTransaction": 8,
    "debug_traceCall": 16,
    "eth_gasPrice": 4,
    "eth_maxPriorityFeePerGas": 4,
    "eth_getProof": 16,
    "eth_getCode": 8,
    "eth_getBalance": 4,
    "trace_transaction": 8,
}
_DEFAULT_METHOD_CONCURRENCY_LIMIT = 16
_method_semaphores: dict[str, asyncio.Semaphore] = {}


def _get_method_semaphore(method: str) -> asyncio.Semaphore:
    """Return the per-method semaphore, creating it on first use.

    Lazy creation so the Semaphore binds to whichever event loop is
    actually running this call. Safe to call from any async context."""
    sem = _method_semaphores.get(method)
    if sem is None:
        limit = _METHOD_CONCURRENCY_LIMITS.get(
            method, _DEFAULT_METHOD_CONCURRENCY_LIMIT
        )
        sem = asyncio.Semaphore(limit)
        _method_semaphores[method] = sem
    return sem
# --------------------------------------------------------------------------


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
            keepalive_timeout=120,      # idle keepalive socket TTL, in seconds
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
            session = get_eth_client_session()
            # Per-method semaphore caps concurrent in-flight requests for
            # this RPC method so the bundler can't pile thousands of
            # eth_calls onto an upstream node that can serve only tens at
            # a time. Held only around session.post — released before the
            # retry sleep on failure so a busy slot doesn't block retries.
            async with _get_method_semaphore(method):
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
            await asyncio.sleep(1)
        except Exception as excp:
            logging.error(
                f"Attempt No. {i+1} to call node rpc failed."
                f"error: {str(excp)}"
            )
            logging.error(f"traceback: {str(traceback.format_exc())}")
            await asyncio.sleep(1)
        # No bare except: CancelledError / KeyboardInterrupt / SystemExit
        # are BaseException subclasses and propagate untouched by design.
        # Without this, a wait_for(...) timeout on a caller (very common
        # while queued on the per-method semaphore under load) was being
        # logged as a node-RPC failure, swamping operator logs with
        # misleading errors when nothing on the node was actually wrong.
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
                    await asyncio.sleep(1)
                    continue
            # Checked independently of the "error" branch: a response
            # carrying neither "error" nor the expected key (flaky
            # proxies, load balancers returning bare {"jsonrpc","id"})
            # must retry too, not be returned for the caller to
            # KeyError on.
            if expected_key is not None and expected_key not in json_result:
                logging.error(
                    f"Attempt No. {i+1} to call node rpc failed."
                    f"the request: {str(json_request)}"
                    f"as the key {expected_key} is not in the result: {str(json_result)}"
                )
                await asyncio.sleep(1)
                continue
            return json_result
    raise ValueError("Failed rpc request to rpc node client")


class RpcRequestError(Exception):
    """One JSON-RPC request did not yield a usable ``result``: transport
    failure, non-200 status, malformed body, a JSON-RPC error object, or a
    response without ``result``. The message is a single line naming the
    method and the cause, suitable for a caller's own log policy."""


async def send_rpc_request_once(
    node_url: str,
    method: str,
    params: Any = None,
) -> Any:
    """One HTTP attempt against one node: no retry, no logging.

    Returns the JSON-RPC ``result``; raises ``RpcRequestError`` otherwise.
    For callers that run their own deadline, failover and log policy
    (GasPriceCache). ``send_rpc_request_to_eth_client`` logs an error plus a
    traceback on every one of its retries, which is the right thing for a
    one-off call on the hot path but turns a periodic probe of a dead node
    into thousands of log lines an hour.
    """
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
    try:
        session = get_eth_client_session()
        async with _get_method_semaphore(method):
            async with session.post(
                node_url, json=json_request, headers=headers
            ) as response:
                status = response.status
                body = await response.read()
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        # %r: str() of a TimeoutError / ClientConnectorError can be empty
        raise RpcRequestError(f"{method}: {exc!r}") from exc
    return _rpc_result_or_raise(method, status, body)


def _rpc_result_or_raise(method: str, status: int, body: bytes) -> Any:
    """``result`` of a JSON-RPC response body, or RpcRequestError naming
    what was wrong with it (see send_rpc_request_once)."""
    if status != 200:
        raise RpcRequestError(f"{method}: HTTP {status}: {body[:200]!r}")
    try:
        payload = json.loads(body)
    except ValueError:
        raise RpcRequestError(f"{method}: invalid JSON response: {body[:200]!r}")
    if not isinstance(payload, dict):
        raise RpcRequestError(f"{method}: unexpected response: {body[:200]!r}")
    if "error" in payload:
        error = payload["error"]
        if isinstance(error, dict):
            raise RpcRequestError(
                f"{method}: node error {error.get('code')}: "
                f"{error.get('message')}"
            )
        raise RpcRequestError(f"{method}: node error: {error!r}")
    if "result" not in payload:
        raise RpcRequestError(f"{method}: response without result: {body[:200]!r}")
    return payload["result"]


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
    # Same per-method cap as the retry path. No-retry callers share the
    # upstream capacity with everyone else.
    async with _get_method_semaphore(method):
        async with session.post(
            ethereum_node_url,
            json=json_request,
            headers=headers
        ) as response:
            try:
                resp = await response.read()
                if response.status != 200:
                    logging.warning(
                        f"Non-200 status {response.status} from {ethereum_node_url} "
                        f"for {method}: {resp[:200]!r}"
                    )
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
                # Re-raise so the semaphore slot is freed immediately and
                # callers see an explicit error instead of a silent None.
                # CancelledError / KeyboardInterrupt / SystemExit are
                # BaseException subclasses and propagate untouched by design.
                raise


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
