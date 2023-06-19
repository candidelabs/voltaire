import asyncio
import uvloop
from functools import partial
from signal import SIGINT, SIGTERM

from init import initialize
from rpc.rpc_http_server import run_rpc_http_server
from init import InitData
from bundler.execution_endpoint import ExecutionEndpoint
from utils.SignalHaltError import immediate_exit


async def main() -> None:
    initData: InitData = initialize()

    loop = asyncio.get_running_loop()

    for signal_enum in [SIGINT, SIGTERM]:
        exit_func = partial(immediate_exit, signal_enum=signal_enum, loop=loop)
        loop.add_signal_handler(signal_enum, exit_func)

    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

    # loop.set_debug(True)
    async with asyncio.TaskGroup() as task_group:
        execution_endpoint: ExecutionEndpoint = ExecutionEndpoint(
            initData.ethereum_node_url,
            initData.bundler_pk,
            initData.bundler_address,
            initData.entrypoint,
            initData.bundler_helper_byte_code,
            initData.chain_id,
            initData.is_unsafe,
            initData.is_legacy_mode,
            initData.is_send_raw_transaction_conditional,
            initData.bundle_interval,
            initData.whitelist_entity_storage_access,
        )
        task_group.create_task(execution_endpoint.start_execution_endpoint())
        task_group.create_task(
            run_rpc_http_server(host=initData.rpc_url, port=initData.rpc_port, is_debug=initData.is_debug)
        )


if __name__ == "__main__":
    asyncio.run(main())
