import asyncio
import logging
from aiohttp import web
from jsonrpcserver import method, Result, Success, async_dispatch, Error
from typing import Any

from event_bus_manager.endpoint import Client
from rpc.events import RPCCallRequestEvent, RPCCallResponseEvent
from user_operation.user_operation import UserOperation
from bundler.exceptions import BundlerException


async def _handle_rpc_request(
    endpoint_id: str, request_type: str, request_arguments: Any
) -> Any:
    rpcClient: Client = Client(endpoint_id)
    requestEvent = RPCCallRequestEvent(request_type, request_arguments)
    resp: RPCCallResponseEvent = await rpcClient.request(requestEvent)

    logging.debug(f"{request_type} RPC served")
    if resp.is_error:
        error: BundlerException = resp.payload
        error_code = error.exception_code.value
        error_message = str(error.message)
        revert_message = bytes.fromhex(error.data[-64:]).decode("ascii")
        return Error(error_code, error_message + " " + revert_message)
    else:
        return Success(resp.payload)


@method
async def eth_chainId() -> Result:
    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="rpc_chainId",
        request_arguments="",
    )
    return result


@method
async def eth_supportedEntryPoints() -> Result:
    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="rpc_supportedEntryPoints",
        request_arguments="",
    )
    return result


@method
async def eth_estimateUserOperationGas(
    userOperationJson, entrypoint
) -> Result:
    userOperation: UserOperation = UserOperation(userOperationJson)

    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="rpc_estimateUserOperationGas",
        request_arguments=[userOperation, entrypoint],
    )
    return result


@method
async def eth_sendUserOperation(userOperationJson, entrypoint) -> Result:
    userOperation: UserOperation = UserOperation(userOperationJson)
    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="rpc_sendUserOperation",
        request_arguments=[userOperation, entrypoint],
    )
    return result


@method
async def debug_bundler_sendBundleNow() -> Result:
    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="debug_bundler_sendBundleNow",
        request_arguments="",
    )
    return result


@method
async def debug_bundler_clearState() -> Result:
    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="debug_bundler_clearState",
        request_arguments="",
    )
    return result


@method
async def debug_bundler_dumpMempool(entrypoint) -> Result:
    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="debug_bundler_dumpMempool",
        request_arguments=[entrypoint],
    )
    return result


@method
async def eth_getUserOperationReceipt(userOperationHash) -> Result:
    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="rpc_getUserOperationReceipt",
        request_arguments=[userOperationHash],
    )
    return result


@method
async def eth_getUserOperationByHash(userOperationHash) -> Result:
    result = await _handle_rpc_request(
        endpoint_id="bundler_endpoint",
        request_type="rpc_getUserOperationByHash",
        request_arguments=[userOperationHash],
    )
    return result


async def handle(request):
    # logging.info(await request.text())
    res = await request.text()
    # logging.info(res)
    return web.Response(
        text=await async_dispatch(res), content_type="application/json"
    )


async def run_rpc_http_server(host="localhost", port=3000):
    logging.info(f"Starting HTTP RPC Server at: {host}:{port}/rpc")
    app = web.Application()
    app.router.add_post("/rpc", handle)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
