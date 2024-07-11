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
from voltaire_bundler.rpc.health import check_bundler_balance, check_node_health
from voltaire_bundler.rpc.jsonrpc import \
    RPCFault, RPCInvalidMethodParams, validate_and_load_json_rpc_request
from voltaire_bundler.typing import Address

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

METHODS: dict[str, Callable] = {
    "eth_chainId": eth_chainId,
    "eth_supportedEntryPoints": eth_supportedEntryPoints,
    "eth_estimateUserOperationGas": eth_estimateUserOperationGas,
    "eth_sendUserOperation": eth_sendUserOperation,
    "eth_getUserOperationReceipt": eth_getUserOperationReceipt,
    "eth_getUserOperationByHash": eth_getUserOperationByHash,
    "web3_bundlerVersion": web3_bundlerVersion,
}


async def handle(request: web.Request) -> web.Response:
    req_str = await request.text()
    method = None
    try:
        res = validate_and_load_json_rpc_request(req_str, METHODS)
        logging.debug(f"request: {res}")
        try:
            method = res[0]
            params = res[1]
            response = await METHODS[method](*params)
        except TypeError as err:
            raise RPCInvalidMethodParams(err)
        id = res[2]
        if id is None or id == "null":  # no or "null" id is assumed to be a notification
            return web.Response()  # return an emoty response
    except RPCFault as err:
        response = Error(err.error_code, err.error_message)
        id = "null"

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
    bundler: Address,
    min_balance: int,
    _: web.Request
) -> web.Response:
    nodes_success, nodes_results = await check_node_health(
        node_urls_to_check, target_chain_id_hex)

    bundler_balance_success, bundler_balance_results = await check_bundler_balance(
        node_urls_to_check[0], bundler, min_balance)

    results = dict()
    results["nodes_status"] = nodes_results
    results["bundler_balance"] = bundler_balance_results
    results_str = json.dumps(results)

    all_ok = nodes_success and bundler_balance_success
    if all_ok:
        return web.Response(text=results_str)
    else:
        return web.Response(text=results_str, status=503)


async def run_rpc_http_server(
    node_urls_to_check: list[str],
    target_chain_id_hex: str,
    bundler: Address,
    min_balance: int,
    host: str = "localhost",
    rpc_cors_domain: str = "*",
    port: int = 3000,
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

    logging.info(f"Starting HTTP RPC Server at: {host}:{port}/rpc")
    app = web.Application()
    app.router.add_post("/rpc", handle)

    app.router.add_post(
        "/health",
        partial(
            check_health,
            node_urls_to_check,
            target_chain_id_hex,
            bundler,
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
