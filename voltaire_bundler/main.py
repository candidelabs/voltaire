import asyncio
import os
import sys
from argparse import ArgumentParser
from functools import partial
from signal import SIGINT, SIGTERM

import uvloop

from voltaire_bundler.execution_endpoint import ExecutionEndpoint
from voltaire_bundler.metrics.metrics import run_metrics_server
from voltaire_bundler.p2p_boot import p2p_boot
from voltaire_bundler.rpc.health import periodic_health_check_cron_job
from voltaire_bundler.utils.SignalHaltError import immediate_exit

from .cli_manager import get_init_data, initialize_argument_parser
from .rpc.rpc_http_server import run_rpc_http_server


async def main(cmd_args=sys.argv[1:], loop=None) -> None:
    argument_parser: ArgumentParser = initialize_argument_parser()
    parsed_args = argument_parser.parse_args(cmd_args)
    init_data = await get_init_data(parsed_args)
    if loop is None:
        loop = asyncio.get_running_loop()
    if os.path.exists("p2p_endpoint.ipc"):
        os.remove("p2p_endpoint.ipc")

    # this release doesn't support p2p
    if False and not init_data.disable_p2p:
        p2p_process = p2p_boot(
            init_data.p2p_enr_tcp_port,
            init_data.p2p_enr_udp_port,
            init_data.p2p_target_peers_number,
            init_data.p2p_enr_address,
            [],
            init_data.p2p_boot_nodes_enr,
            init_data.p2p_upnp_enabled,
            init_data.p2p_metrics_enabled,
        )
    else:
        p2p_process = None

    for signal_enum in [SIGINT, SIGTERM]:
        exit_func = partial(
            immediate_exit, signal_enum=signal_enum, loop=loop, p2p=p2p_process
        )
        loop.add_signal_handler(signal_enum, exit_func)

    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

    async with asyncio.TaskGroup() as task_group:
        execution_endpoint: ExecutionEndpoint = ExecutionEndpoint(
            init_data.ethereum_node_url,
            init_data.bundler_pk,
            init_data.bundler_address,
            init_data.chain_id,
            init_data.is_unsafe,
            init_data.is_debug,
            init_data.is_legacy_mode,
            init_data.conditional_rpc,
            init_data.bundle_interval,
            init_data.max_fee_per_gas_percentage_multiplier,
            init_data.max_priority_fee_per_gas_percentage_multiplier,
            init_data.enforce_gas_price_tolerance,
            init_data.ethereum_node_debug_trace_call_url,
            init_data.ethereum_node_eth_get_logs_url,
            init_data.disable_p2p,
            init_data.max_verification_gas,
            init_data.max_call_data_gas,
            init_data.disable_v6,
            init_data.logs_incremental_range,
            init_data.logs_number_of_ranges,
        )
        task_group.create_task(execution_endpoint.start_execution_endpoint())

        node_urls_to_check = [init_data.ethereum_node_url]
        if init_data.ethereum_node_url != init_data.ethereum_node_debug_trace_call_url:
            node_urls_to_check.append(init_data.ethereum_node_debug_trace_call_url)
        if init_data.ethereum_node_url != init_data.ethereum_node_eth_get_logs_url:
            node_urls_to_check.append(init_data.ethereum_node_eth_get_logs_url)

        task_group.create_task(
            run_rpc_http_server(
                node_urls_to_check=node_urls_to_check,
                target_chain_id_hex=hex(init_data.chain_id),
                bundler=init_data.bundler_address,
                min_balance=init_data.min_bundler_balance,
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
        if init_data.health_check_interval > 0:
            await asyncio.ensure_future(
                periodic_health_check_cron_job(
                    node_urls_to_check=node_urls_to_check,
                    target_chain_id_hex=hex(init_data.chain_id),
                    bundler=init_data.bundler_address,
                    min_balance=init_data.min_bundler_balance,
                    interval=init_data.health_check_interval
                )
            )
