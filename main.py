import asyncio
import uvloop
from functools import partial
from signal import SIGINT, SIGTERM

from boot import init
from rpc.rpc_http_server import run_rpc_http_server
from utils.helper import InitData
from bundler_endpoint.bundler_endpoint import BundlerEndpoint
from erros.SignalHaltError import immediate_exit


async def main():
    initData: InitData = init()

    loop = asyncio.get_running_loop()

    for signal_enum in [SIGINT, SIGTERM]:
        exit_func = partial(immediate_exit, signal_enum=signal_enum, loop=loop)
        loop.add_signal_handler(signal_enum, exit_func)

    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

    # loop.set_debug(True)
    async with asyncio.TaskGroup() as tg:
        gch: BundlerEndpoint = BundlerEndpoint(
            initData.geth_url,
            initData.bundler_pk,
            initData.bundler_address,
            initData.entrypoints,
            initData.entrypoint_abis,
        )
        tg.create_task(gch.start_bundler_endpoint())
        tg.create_task(
            run_rpc_http_server(host=initData.rpc_url, port=initData.rpc_port)
        )


if __name__ == "__main__":
    asyncio.run(main())
