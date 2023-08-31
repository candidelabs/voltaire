import asyncio
import uvloop
from functools import partial
from signal import SIGINT, SIGTERM
from argparse import ArgumentParser
import sys

from .boot import initialize_argument_parser, InitData, get_init_data
from .rpc.rpc_http_server import run_rpc_http_server
from voltaire_bundler.bundler.execution_endpoint import ExecutionEndpoint
from voltaire_bundler.utils.SignalHaltError import immediate_exit
from voltaire_bundler.metrics.metrics import run_metrics_server


async def main(cmd_args=sys.argv[1:], loop=None) -> None:
    argument_parser: ArgumentParser = initialize_argument_parser()
    parsed_args = argument_parser.parse_args(cmd_args)
    init_data = get_init_data(parsed_args)
    if loop == None:
        loop = asyncio.get_running_loop()

    for signal_enum in [SIGINT, SIGTERM]:
        exit_func = partial(immediate_exit, signal_enum=signal_enum, loop=loop)
        loop.add_signal_handler(signal_enum, exit_func)

    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

    async with asyncio.TaskGroup() as task_group:
        execution_endpoint: ExecutionEndpoint = ExecutionEndpoint(
            init_data.ethereum_node_url,
            init_data.bundler_pk,
            init_data.bundler_address,
            init_data.entrypoint,
            init_data.bundler_helper_byte_code,
            init_data.chain_id,
            init_data.is_unsafe,
            init_data.is_legacy_mode,
            init_data.is_send_raw_transaction_conditional,
            init_data.bundle_interval,
            init_data.whitelist_entity_storage_access,
            init_data.max_fee_per_gas_percentage_multiplier,
            init_data.max_priority_fee_per_gas_percentage_multiplier,
            init_data.enforce_gas_price_tolerance,
        )
        task_group.create_task(execution_endpoint.start_execution_endpoint())
        task_group.create_task(
            run_rpc_http_server(
                host=init_data.rpc_url,
                rpc_cors_domain=init_data.rpc_cors_domain,
                port=init_data.rpc_port,
                is_debug=init_data.is_debug,
            )
        )
        if init_data.is_metrics:
            run_metrics_server(
                host=init_data.rpc_url,
            )
