import asyncio
import json
import logging
import time
import traceback
from collections import defaultdict
from typing import Any
from eth_abi import encode

from aiohttp import ClientSession, ClientTimeout, TCPConnector

from eth_account import Account, messages
from eth_utils import keccak


_session: ClientSession | None = None


# --- per-method concurrency / latency profiler (outbound) ----------------
# Mirrors the inbound profiler in rpc_http_server.py. Tracks every outbound
# RPC method (eth_call, eth_getLogs, eth_sendRawTransaction, etc.) and dumps
# a per-method table every 5s. Each retry attempt is recorded as its own
# sample so a method that's silently bouncing off retries shows up here.
_out_inflight: dict[str, int] = defaultdict(int)
_out_samples: dict[str, list[float]] = defaultdict(list)
_out_peak_inflight_window: dict[str, int] = defaultdict(int)
_out_sum_inflight_at_start: dict[str, int] = defaultdict(int)
_profiler_started: bool = False


def _out_record_sample(method: str, duration: float, inflight_at_start: int) -> None:
    _out_samples[method].append(duration)
    _out_sum_inflight_at_start[method] += inflight_at_start
    if inflight_at_start > _out_peak_inflight_window[method]:
        _out_peak_inflight_window[method] = inflight_at_start


def _out_percentile(sorted_values: list[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    k = max(0, min(len(sorted_values) - 1, int(round(p * (len(sorted_values) - 1)))))
    return sorted_values[k]


def _out_fmt_ms(s: float) -> str:
    return f"{s * 1000:.1f}ms"


async def _outbound_profiler_logger(interval: float = 5.0) -> None:
    """Periodically log per-method outbound latency stats + concurrency."""
    while True:
        await asyncio.sleep(interval)
        methods = sorted(set(_out_samples.keys()) | set(_out_inflight.keys()))
        if not methods:
            continue

        lines = [
            f"[rpc-outbound-profile window={interval:.0f}s] "
            f"{'method':<38} {'reqs':>5} {'inflight_now':>12} "
            f"{'peak_inflight':>13} {'avg_inflight':>12} "
            f"{'p50':>9} {'p95':>9} {'p99':>9} {'max':>9}"
        ]
        for method in methods:
            samples = _out_samples.get(method, [])
            count = len(samples)
            inflight_now = _out_inflight.get(method, 0)
            peak = _out_peak_inflight_window.get(method, 0)
            avg_inflight = (
                _out_sum_inflight_at_start.get(method, 0) / count if count else 0.0
            )
            if samples:
                samples.sort()
                p50 = _out_percentile(samples, 0.50)
                p95 = _out_percentile(samples, 0.95)
                p99 = _out_percentile(samples, 0.99)
                mx = samples[-1]
            else:
                p50 = p95 = p99 = mx = 0.0

            lines.append(
                f"[rpc-outbound-profile] {method:<38} {count:>5d} {inflight_now:>12d} "
                f"{peak:>13d} {avg_inflight:>12.2f} "
                f"{_out_fmt_ms(p50):>9} {_out_fmt_ms(p95):>9} "
                f"{_out_fmt_ms(p99):>9} {_out_fmt_ms(mx):>9}"
            )

        logging.info("\n".join(lines))

        _out_samples.clear()
        _out_peak_inflight_window.clear()
        _out_sum_inflight_at_start.clear()


def _ensure_outbound_profiler_started() -> None:
    """Start the outbound profiler task once, on the running event loop."""
    global _profiler_started
    if _profiler_started:
        return
    _profiler_started = True
    asyncio.create_task(_outbound_profiler_logger(interval=5.0))
# --------------------------------------------------------------------------


def get_eth_client_session() -> ClientSession:
    """Return the process-wide aiohttp ClientSession for outbound RPC calls.

    Lazily created on first call so it binds to the running event loop.
    Reused across all callers to enable HTTP keep-alive, DNS caching, and
    connection pooling against each Ethereum node.

    HTTP transport tuned for a bundler that fans out many small requests to
    a handful of Ethereum providers per bundle round:
      - Pool sized for high sendUserOperation concurrency. Each inbound op
        triggers several outbound RPCs (validation, eth_call simulations,
        fee fetches, receipt polling); at low limits, requests queue inside
        aiohttp and get cancelled by the wire timeout before ever leaving.
      - `sock_read=60` / `sock_connect=10`: the wire timeouts only start
        ticking once a connection is acquired and an HTTP exchange is in
        progress, so a saturated pool no longer silently consumes the
        request's deadline.
    """
    global _session
    if _session is None or _session.closed:
        connector = TCPConnector(
            limit=1000,                 # max total open connections (all hosts)
            limit_per_host=500,         # max concurrent connections per host
            ttl_dns_cache=300,          # DNS cache TTL, in seconds
            keepalive_timeout=120,      # idle keepalive socket TTL, in seconds
            enable_cleanup_closed=True,
        )
        _session = ClientSession(
            connector=connector,
            timeout=ClientTimeout(
                total=None,             # don't count pool-wait time against the request
                connect=10,              # acquiring a pooled connection
                sock_connect=10,         # TCP/TLS handshake
                sock_read=60,            # max idle between bytes mid-response
            ),
        )
    _ensure_outbound_profiler_started()
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
    # Profiler: record total observed latency (including any retries).
    _t0 = time.perf_counter()
    _inflight_at_start = _out_inflight[method]
    _out_inflight[method] = _inflight_at_start + 1
    try:
        return await _send_rpc_request_to_eth_client_inner(
            nodes_urls, method, params,
            flashbots_signer_private_key_pair, expected_key,
        )
    finally:
        _out_inflight[method] -= 1
        _out_record_sample(method, time.perf_counter() - _t0, _inflight_at_start)


async def _send_rpc_request_to_eth_client_inner(
    nodes_urls: list[str],
    method: str,
    params,
    flashbots_signer_private_key_pair: tuple[str, str] | None,
    expected_key: str | None,
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
        except asyncio.CancelledError:
            # Caller (e.g. the inbound HTTP handler) gave up — don't retry,
            # let cancellation propagate so backpressure works correctly.
            raise
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
                elif expected_key is not None and expected_key not in json_result:
                    logging.error(
                        f"Attempt No. {i+1} to call node rpc failed."
                        f"the request: {str(json_request)}"
                        f"as the key {expected_key} is not in the result: {str(json_result)}"
                    )
                    await asyncio.sleep(1)
                    continue
            return json_result
    raise ValueError("Failed rpc request to rpc node client")


async def send_rpc_request_to_eth_client_no_retry(
    ethereum_node_url,
    method,
    params=None,
) -> Any:
    # Profiler: tag no-retry calls so they're distinguishable in the table.
    _profile_key = f"{method} (no_retry)"
    _t0 = time.perf_counter()
    _inflight_at_start = _out_inflight[_profile_key]
    _out_inflight[_profile_key] = _inflight_at_start + 1
    try:
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
            try:
                resp = await response.read()
                if response.status != 200:
                    logging.warning(
                        f"Non-200 status {response.status} from {ethereum_node_url} "
                        f"for {method}: {resp[:200]!r}"
                    )
                return json.loads(resp)
            except asyncio.CancelledError:
                raise
            except json.decoder.JSONDecodeError:
                logging.critical("Invalid json response from eth client")
                raise ValueError("Invalid json response from eth client")
            except Exception as excp:
                logging.error(
                    "Call to node rpc failed." +
                    str(traceback.format_exc()) +
                    str(excp)
                )
                await asyncio.sleep(1)  # in seconds
    finally:
        _out_inflight[_profile_key] -= 1
        _out_record_sample(
            _profile_key, time.perf_counter() - _t0, _inflight_at_start
        )


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
