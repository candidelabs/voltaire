import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass
from functools import partial
import logging
import json
from importlib.metadata import version
from typing import Any, Callable
from contextvars import ContextVar

import aiohttp_cors
from aiohttp import web
from prometheus_client import Summary

from voltaire_bundler.bundle.exceptions import (ExecutionException,
                                                 ValidationException)
from voltaire_bundler.event_bus_manager.endpoint import Client, RequestEvent
from voltaire_bundler.rpc.health import check_bundlers_balance, check_nodes_health
from voltaire_bundler.rpc.jsonrpc import \
    RPCFault, RPCInvalidMethodParams, validate_and_load_json_rpc_request
from voltaire_bundler.custom_types import Address

from aiohttp.abc import AbstractAccessLogger

RESPONSE_LOG = ContextVar('RESPONSE_LOG', default=dict())


class AccessLogger(AbstractAccessLogger):
    def log(self, request, response, time):
        if time >= 1:
            time_str = f"{round(time, 3)}s"
        elif time >= 0.001:
            time_str = f"{round(time*1000, 3)}ms"
        else:
            time_str = f"{round(time*1000_000, 3)}μs"

        log_obj = RESPONSE_LOG.get()

        referer = request.headers.get('Referer')
        agent = request.headers.get('User-Agent')
        base_log = (
            f'{request.remote} '
            f'"{request.method} {request.path}" '
            f'done in {time_str}: {response.status} '
            f'"{referer}" "{agent}" '
        )
        if "is_error" in log_obj:
            if log_obj["is_error"]:
                method = log_obj["method"]
                id = log_obj["id"]
                error_code = log_obj["error_code"]
                error_message = log_obj["error_message"]
                self.logger.warning(
                    base_log +
                    f"{method} RPC served - reqId:{id} - "
                    f"error code:{error_code} - error message:{error_message}"
                )
            else:
                method = log_obj["method"]
                id = log_obj["id"]
                self.logger.info(
                    base_log +
                    f"{method} RPC served - reqId:{id}"
                )
        else:
            self.logger.info(base_log)


@dataclass
class Success:
    payload: Any


@dataclass
class Error:
    error_code: int
    error_message: str


REQUEST_TIME_eth_chainId = Summary(
    "request_processing_seconds_eth_chainId",
    "Time spent processing request eth_chainId",
)
REQUEST_TIME_eth_supportedEntryPoints = Summary(
    "request_processing_seconds_eth_supportedEntryPoints",
    "Time spent processing request eth_supportedEntryPoints",
)
REQUEST_TIME_eth_estimateUserOperationGas = Summary(
    "request_processing_seconds_eth_estimateUserOperationGas",
    "Time spent processing request eth_estimateUserOperationGas",
)
REQUEST_TIME_chainId_eth_sendUserOperation = Summary(
    "request_processing_seconds_eth_sendUserOperation",
    "Time spent processing request eth_sendUserOperation",
)
REQUEST_TIME_chainId_eth_getUserOperationReceipt = Summary(
    "request_processing_seconds_eth_getUserOperationReceipt",
    "Time spent processing request eth_getUserOperationReceipt",
)
REQUEST_TIME_chainId_eth_getUserOperationByHash = Summary(
    "request_processing_seconds_eth_getUserOperationByHash",
    "Time spent processing request eth_getUserOperationByHash",
)


rpcClient: Client = Client("bundler_endpoint")


# --- per-method concurrency / latency profiler ---------------------------
# Tracks in-flight count and per-window latency samples per RPC method so we
# can see which method's tail latency degrades as concurrency rises.
_inflight: dict[str, int] = defaultdict(int)
_samples: dict[str, list[float]] = defaultdict(list)
# peak in-flight observed during the current window, per method
_peak_inflight_window: dict[str, int] = defaultdict(int)
# sum of inflight_at_start across samples in the window, per method (for avg)
_sum_inflight_at_start: dict[str, int] = defaultdict(int)


def _record_sample(method: str, duration: float, inflight_at_start: int) -> None:
    _samples[method].append(duration)
    _sum_inflight_at_start[method] += inflight_at_start
    if inflight_at_start > _peak_inflight_window[method]:
        _peak_inflight_window[method] = inflight_at_start


def _percentile(sorted_values: list[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    # nearest-rank
    k = max(0, min(len(sorted_values) - 1, int(round(p * (len(sorted_values) - 1)))))
    return sorted_values[k]


def _fmt_ms(s: float) -> str:
    return f"{s * 1000:.1f}ms"


async def _profiler_logger(interval: float = 5.0) -> None:
    """Periodically log per-method latency stats + concurrency. Resets window."""
    while True:
        await asyncio.sleep(interval)
        # Snapshot + clear under no-await guarantee (asyncio is cooperative)
        methods = sorted(set(_samples.keys()) | set(_inflight.keys()))
        if not methods:
            continue

        lines = [
            f"[rpc-profile window={interval:.0f}s] "
            f"{'method':<38} {'reqs':>5} {'inflight_now':>12} "
            f"{'peak_inflight':>13} {'avg_inflight':>12} "
            f"{'p50':>9} {'p95':>9} {'p99':>9} {'max':>9}"
        ]
        for method in methods:
            samples = _samples.get(method, [])
            count = len(samples)
            inflight_now = _inflight.get(method, 0)
            peak = _peak_inflight_window.get(method, 0)
            avg_inflight = (
                _sum_inflight_at_start.get(method, 0) / count if count else 0.0
            )
            if samples:
                samples.sort()
                p50 = _percentile(samples, 0.50)
                p95 = _percentile(samples, 0.95)
                p99 = _percentile(samples, 0.99)
                mx = samples[-1]
            else:
                p50 = p95 = p99 = mx = 0.0

            lines.append(
                f"[rpc-profile] {method:<38} {count:>5d} {inflight_now:>12d} "
                f"{peak:>13d} {avg_inflight:>12.2f} "
                f"{_fmt_ms(p50):>9} {_fmt_ms(p95):>9} {_fmt_ms(p99):>9} {_fmt_ms(mx):>9}"
            )

        logging.info("\n".join(lines))

        # Reset window. Keep _inflight (live counter) as-is.
        _samples.clear()
        _peak_inflight_window.clear()
        _sum_inflight_at_start.clear()
# --------------------------------------------------------------------------


async def _handle_rpc_request(
    endpoint_id: str, request_type: str, request_arguments: Any = ""
) -> Any:
    requestEvent: RequestEvent = {
        "request_type": request_type,
        "request_arguments": request_arguments,
    }
    resp = await rpcClient.request(requestEvent)

    if resp is not None and "is_error" in resp and resp["is_error"]:
        error: ValidationException | ExecutionException = resp["payload"]
        error_code = error.exception_code.value
        error_message = str(error.message)

        return Error(error_code, error_message)
    else:
        return Success(resp)


@REQUEST_TIME_eth_chainId.time()
async def eth_chainId(*args):
    if len(args) > 0:
        raise RPCInvalidMethodParams()
    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="rpc_chainId",
    )
    return result


@REQUEST_TIME_eth_supportedEntryPoints.time()
async def eth_supportedEntryPoints(*args):
    if len(args) > 0:
        raise RPCInvalidMethodParams()
    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="rpc_supportedEntryPoints",
    )
    return result


@REQUEST_TIME_eth_estimateUserOperationGas.time()
async def eth_estimateUserOperationGas(
    userOperationJson: dict[str, Any],
    entrypoint: str,
    state_override_set: dict[str, Any] | None = None,
):
    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="rpc_estimateUserOperationGas",
        request_arguments=[userOperationJson, entrypoint, state_override_set],
    )
    return result


@REQUEST_TIME_chainId_eth_sendUserOperation.time()
async def eth_sendUserOperation(
    userOperationJson: dict[str, Any], entrypoint: str
):
    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="rpc_sendUserOperation",
        request_arguments=[userOperationJson, entrypoint],
    )
    return result


@REQUEST_TIME_chainId_eth_getUserOperationReceipt.time()
async def eth_getUserOperationReceipt(userOperationHash: str):
    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="rpc_getUserOperationReceipt",
        request_arguments=[userOperationHash],
    )
    return result


@REQUEST_TIME_chainId_eth_getUserOperationByHash.time()
async def eth_getUserOperationByHash(userOperationHash: str):
    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="rpc_getUserOperationByHash",
        request_arguments=[userOperationHash],
    )
    return result


async def debug_bundler_sendBundleNow():
    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="debug_bundler_sendBundleNow",
    )
    return result


async def debug_bundler_clearState():
    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="debug_bundler_clearState",
    )
    return result


async def debug_bundler_dumpMempool(entrypoint: str):
    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="debug_bundler_dumpMempool",
        request_arguments=[entrypoint],
    )
    return result


async def debug_bundler_setReputation(
    entity_reputation: dict[str, str], entrypoint: str
):
    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="debug_bundler_setReputation",
        request_arguments=[entity_reputation, entrypoint],
    )
    return result


async def debug_bundler_clearReputation():
    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="debug_bundler_clearReputation",
    )
    return result


async def debug_bundler_dumpReputation(entrypoint: str):
    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="debug_bundler_dumpReputation",
        request_arguments=[entrypoint],
    )
    return result


async def debug_bundler_getStakeStatus(address: str, entrypoint: str):
    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="debug_bundler_getStakeStatus",
        request_arguments=[address, entrypoint],
    )
    return result


async def debug_bundler_setBundlingMode(mode: str):
    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="debug_bundler_setBundlingMode",
        request_arguments=[mode],
    )
    return result


async def web3_bundlerVersion():
    return Success(version("voltaire_bundler"))


async def voltaire_feesPerGas():
    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="voltaire_feesPerGas",
        request_arguments=[],
    )
    return result

METHODS: dict[str, Callable] = {
    "eth_chainId": eth_chainId,
    "eth_supportedEntryPoints": eth_supportedEntryPoints,
    "eth_estimateUserOperationGas": eth_estimateUserOperationGas,
    "eth_sendUserOperation": eth_sendUserOperation,
    "eth_getUserOperationReceipt": eth_getUserOperationReceipt,
    "eth_getUserOperationByHash": eth_getUserOperationByHash,
    "web3_bundlerVersion": web3_bundlerVersion,
    "voltaire_feesPerGas": voltaire_feesPerGas,
}


async def handle(request: web.Request) -> web.Response:
    req_str = await request.text()
    method = None
    profiled_method: str | None = None
    inflight_at_start = 0
    t0 = time.perf_counter()
    try:
        res = validate_and_load_json_rpc_request(req_str, METHODS)
        logging.debug(f"request: {res}")
        try:
            method = res[0]
            params = res[1]
            # Bump in-flight counter BEFORE dispatch so concurrent peers see us.
            profiled_method = method
            inflight_at_start = _inflight[profiled_method]
            _inflight[profiled_method] = inflight_at_start + 1
            response = await METHODS[method](*params)
        except TypeError as err:
            raise RPCInvalidMethodParams(err)
        id = res[2]
        if id is None or id == "null":  # no or "null" id is assumed to be a notification
            return web.Response()  # return an emoty response
    except RPCFault as err:
        response = Error(err.error_code, err.error_message)
        id = "null"
    finally:
        if profiled_method is not None:
            _inflight[profiled_method] -= 1
            _record_sample(
                profiled_method,
                time.perf_counter() - t0,
                inflight_at_start,
            )

    json_response = {
        "jsonrpc": "2.0",
        "id": id
    }

    if isinstance(response, Success):
        RESPONSE_LOG.set(
            {
                "is_error": False,
                "id": id,
                "method": method
            }
        )
        json_response["result"] = response.payload
        logging.debug(f"response: {response.payload}")
    elif isinstance(response, Error):
        RESPONSE_LOG.set(
            {
                "is_error": True,
                "id": id,
                "method": method,
                "error_code": response.error_code,
                "error_message": response.error_message,
            }
        )
        json_response["error"] = {
            "code": response.error_code,
            "message": response.error_message
        }
    else:
        logging.critical("unexpected response type returned.")

    return web.Response(
        text=json.dumps(json_response),
        content_type="application/json",
    )


async def check_health(
    node_urls_to_check: list[str],
    target_chain_id_hex: str,
    bundlers: list[Address],
    min_balance: int,
    _: web.Request
) -> web.Response:
    nodes_success, nodes_results = await check_nodes_health(
        node_urls_to_check, target_chain_id_hex)

    all_ok = nodes_success

    results = dict()
    results["nodes_status"] = nodes_results
    if nodes_success:
        bundler_balance_success, bundler_balance_results = await check_bundlers_balance(
            node_urls_to_check[0], bundlers, min_balance)
        results["bundler_balance"] = bundler_balance_results
        all_ok = nodes_success and bundler_balance_success

    results_str = json.dumps(results)

    if all_ok:
        return web.Response(text=results_str)
    else:
        return web.Response(text=results_str, status=503)


async def run_rpc_http_server(
    node_urls_to_check: list[str],
    target_chain_id_hex: str,
    bundlers: list[Address],
    min_balance: int,
    host: str = "localhost",
    rpc_cors_domain: str = "*",
    port: int = 3000,
    rpc_path: str = "/rpc",
    is_debug: bool = False,
) -> None:
    if is_debug:
        debug_methods = {
            "debug_bundler_sendBundleNow": debug_bundler_sendBundleNow,
            "debug_bundler_clearState": debug_bundler_clearState,
            "debug_bundler_dumpMempool": debug_bundler_dumpMempool,
            "debug_bundler_setReputation": debug_bundler_setReputation,
            "debug_bundler_clearReputation": debug_bundler_clearReputation,
            "debug_bundler_dumpReputation": debug_bundler_dumpReputation,
            "debug_bundler_getStakeStatus": debug_bundler_getStakeStatus,
            "debug_bundler_setBundlingMode": debug_bundler_setBundlingMode,
        }
        METHODS.update(debug_methods)

    logging.info(f"Starting HTTP RPC Server at: {host}:{port}{rpc_path}")
    app = web.Application()
    app.router.add_post(rpc_path, handle)

    app.router.add_post(
        "/health",
        partial(
            check_health,
            node_urls_to_check,
            target_chain_id_hex,
            bundlers,
            min_balance
        )
    )

    cors = aiohttp_cors.setup(
        app,
        defaults={
            rpc_cors_domain: aiohttp_cors.ResourceOptions(
                allow_credentials=True, expose_headers="*", allow_headers="*"
            )
        },
    )
    for route in list(app.router.routes()):
        cors.add(route)
    runner = web.AppRunner(
        app,
        access_log_class=AccessLogger
    )
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()

    # Background per-method latency/concurrency profiler.
    asyncio.create_task(_profiler_logger(interval=5.0))
