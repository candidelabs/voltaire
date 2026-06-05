import asyncio
import logging
import os
import shutil
import sys
from functools import partial
from pathlib import Path
from signal import SIGINT, SIGTERM
import platform
if platform.system() != "Windows":
    import uvloop
from voltaire_bundler.execution_endpoint import ExecutionEndpoint
from voltaire_bundler.mempool.mempool_info import DEFAULT_MEMPOOL_INFO
from voltaire_bundler.metrics.metrics import run_metrics_server
from voltaire_bundler.p2p_boot import p2p_boot
from voltaire_bundler.rpc.health import periodic_health_check_cron_job
from voltaire_bundler.utils.cache import (
    PersistentFIFOCache,
    PostgresConfig,
    SQLiteConfig,
)
from voltaire_bundler.utils.SignalHaltError import immediate_exit

from .cli_manager import parse_args
from .rpc.rpc_http_server import run_rpc_http_server


async def main(cmd_args=sys.argv[1:], loop=None) -> None:
    init_data = await parse_args(cmd_args)
    if loop is None:
        loop = asyncio.get_running_loop()
    if sys.platform == "win32":
        if os.path.exists("p2p_endpoint.port"):
            os.remove("p2p_endpoint.port")
    else:
        if os.path.exists("p2p_endpoint.ipc"):
            os.remove("p2p_endpoint.ipc")

    if not init_data.disable_p2p:
        p2p_process = p2p_boot(
            init_data.p2p_enr_tcp_port,
            init_data.p2p_enr_udp_port,
            init_data.p2p_target_peers_number,
            init_data.p2p_enr_address,
            [[
                init_data.p2p_canonical_mempool_id_08,
                init_data.p2p_canonical_mempool_id_07,
                init_data.p2p_canonical_mempool_id_06
            ]],
            init_data.p2p_boot_nodes_enr,
            init_data.p2p_upnp_enabled,
            init_data.p2p_metrics_enabled,
        )
    else:
        p2p_process = None

    if platform.system() != "Windows":
        for signal_enum in [SIGINT, SIGTERM]:
            exit_func = partial(
                immediate_exit, signal_enum=signal_enum,
                loop=loop, p2p=p2p_process
            )
            loop.add_signal_handler(signal_enum, exit_func)
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

    # Apply the size multipliers BEFORE start_all so warm-on-start observes
    # the scaled memory cap.
    PersistentFIFOCache.apply_capacity_multipliers(
        memory_mult=init_data.cache_memory_size,
        disk_mult=init_data.cache_disk_size,
    )

    # Start the RPC-result caches. By default the caches run
    # memory-only; --enable_persistent_cache opts into mirroring each
    # cache to a SQLite file (default) or Postgres database so state
    # survives a restart.
    if init_data.enable_persistent_cache:
        backend_config: PostgresConfig | SQLiteConfig
        if init_data.cache_backend == "postgres":
            backend_config = PostgresConfig(url=init_data.cache_postgres_url)
        else:
            cache_dir = (
                Path(init_data.cache_dir).expanduser()
                if init_data.cache_dir
                else Path.home() / ".voltaire" / "cache" /
                    str(init_data.chain_id)
            )
            if init_data.clear_cache and cache_dir.exists():
                logging.info("clearing persistent cache at %s", cache_dir)
                shutil.rmtree(cache_dir)
            backend_config = SQLiteConfig(cache_dir=cache_dir)
        await PersistentFIFOCache.start_all(backend_config)
    else:
        await PersistentFIFOCache.start_all(None)

    # Synchronous part is free; the follow-up disk-row totals run in a
    # background task so the COUNT(*) work doesn't extend startup.
    PersistentFIFOCache.log_startup_status()

    try:
        async with asyncio.TaskGroup() as task_group:
            execution_endpoint: ExecutionEndpoint = ExecutionEndpoint(
                init_data.ethereum_node_urls,
                init_data.bundle_node_urls,
                init_data.bundler_secrets_per_ep,
                init_data.chain_id,
                init_data.is_unsafe,
                init_data.is_debug,
                init_data.is_legacy_mode,
                init_data.conditional_rpc,
                init_data.flashbots_protect_node_urls,
                init_data.bundle_interval,
                init_data.max_fee_per_gas_percentage_multiplier,
                init_data.max_priority_fee_per_gas_percentage_multiplier,
                init_data.enforce_gas_price_tolerance,
                init_data.enforce_pre_verification_gas_tolerance,
                init_data.ethereum_node_debug_trace_call_urls,
                init_data.ethereum_node_eth_get_logs_urls,
                init_data.disable_p2p,
                init_data.max_verification_gas,
                init_data.max_call_data_gas,
                init_data.disable_v6,
                init_data.logs_incremental_range,
                init_data.logs_number_of_ranges,
                init_data.reputation_whitelist,
                init_data.reputation_blacklist,
                init_data.is_eip7702,
                init_data.min_stake,
                init_data.min_unstake_delay,
                init_data.bundle_gas_estimation_multiplier,
                init_data.enable_banning,
                init_data.logs_fallback_recent_window,
            )
            task_group.create_task(execution_endpoint.start_execution_endpoint())

            node_urls_to_check = init_data.ethereum_node_urls
            if init_data.ethereum_node_urls != init_data.ethereum_node_debug_trace_call_urls:
                node_urls_to_check += init_data.ethereum_node_debug_trace_call_urls
            if init_data.ethereum_node_urls != init_data.ethereum_node_eth_get_logs_urls:
                node_urls_to_check += init_data.ethereum_node_eth_get_logs_urls

            # When --disable_v6 is set the v6 EOA is parsed but never used,
            # so don't burn an eth_getBalance call on it.
            labels_to_check = ("v7", "v8", "v9") if init_data.disable_v6 \
                else ("v6", "v7", "v8", "v9")
            bundler_addresses_to_check = sorted({
                init_data.bundler_secrets_per_ep[label][0]
                for label in labels_to_check
            })
            task_group.create_task(
                run_rpc_http_server(
                    node_urls_to_check=node_urls_to_check,
                    target_chain_id_hex=hex(init_data.chain_id),
                    bundlers=bundler_addresses_to_check,
                    min_balance=init_data.min_bundler_balance,
                    host=init_data.rpc_url,
                    rpc_cors_domain=init_data.rpc_cors_domain,
                    port=init_data.rpc_port,
                    rpc_path=init_data.rpc_path,
                    is_debug=init_data.is_debug,
                )
            )
            if init_data.is_metrics:
                run_metrics_server(
                    host=init_data.rpc_url,
                )
            if init_data.health_check_interval > 0:
                try:
                    await asyncio.ensure_future(
                        periodic_health_check_cron_job(
                            node_urls_to_check=node_urls_to_check,
                            target_chain_id_hex=hex(init_data.chain_id),
                            bundlers=bundler_addresses_to_check,
                            min_balance=init_data.min_bundler_balance,
                            interval=init_data.health_check_interval
                        )
                    )
                except ValueError as excp:
                    logging.exception(str(excp))
    except asyncio.exceptions.CancelledError:
        pass
    finally:
        # Drain queued disk writes and close SQLite handles cleanly. This only
        # actually runs on a programmatic TaskGroup exit — the SIGTERM/SIGINT
        # path goes through ``immediate_exit`` which stops the loop and raises
        # SystemExit, so this ``await`` never resumes on a real shutdown.
        #
        # That's deliberate. The cached values are derived from chain state, so
        # losing the asyncio.Queue's tail (typically <1 ms of writes, at most a
        # few hundred ms under burst) just means a small cache-warm window on
        # the next start. A synchronous drain on SIGTERM would add up to a few
        # seconds of "RPC server frozen + new connections rejected" before exit
        # for marginal durability gain, so we accept the loss instead.
        await PersistentFIFOCache.aclose_all()
