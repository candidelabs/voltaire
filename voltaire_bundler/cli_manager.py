import os
from enum import Enum
import logging
import re
import socket
import sys
from argparse import ArgumentParser, Namespace, ArgumentTypeError
from dataclasses import dataclass
from importlib.metadata import version

import aiohttp

from voltaire_bundler.mempool.mempool_info import DEFAULT_MEMPOOL_INFO
from voltaire_bundler.utils.eth_client_utils import \
    send_rpc_request_to_eth_client

from .typing import Address, MempoolId
from .utils.import_key import (import_bundler_account,
                               public_address_from_private_key)

VOLTAIRE_HEADER = "\n".join(
    (
        r" _    ______  __  _________    ________  ______",
        r"| |  / / __ \/ / /_  __/   |  /  _/ __ \/ ____/",
        r"| | / / / / / /   / / / /| |  / // /_/ / __/   ",
        r"| |/ / /_/ / /___/ / / ___ |_/ // _, _/ /___   ",
        r"|___/\____/_____/_/ /_/  |_/___/_/ |_/_____/   ",
    )
)
__version__ = version("voltaire_bundler")


class ConditionalRpc(Enum):
    eth = "eth"
    fastlane = "pfl"
    optimism = "opt"

    def __str__(self):
        return self.value


class Tracer(Enum):
    unsafe = "unsafe"
    javascript = "javascript"
    native = "native"

    def __str__(self):
        return self.value


@dataclass()
class InitData:
    rpc_url: str
    rpc_port: int
    ethereum_node_url: str
    bundler_pk: str
    bundler_address: Address
    chain_id: int
    is_debug: bool
    tracer: Tracer
    is_legacy_mode: bool
    conditional_rpc: ConditionalRpc | None
    flashbots_protect_node_url: str | None
    bundle_interval: int
    max_fee_per_gas_percentage_multiplier: int
    max_priority_fee_per_gas_percentage_multiplier: int
    is_metrics: bool
    rpc_cors_domain: str
    enforce_gas_price_tolerance: int
    ethereum_node_debug_trace_call_url: str
    ethereum_node_eth_get_logs_url: str
    p2p_enr_address: str
    p2p_enr_tcp_port: int
    p2p_enr_udp_port: int
    p2p_target_peers_number: int
    p2p_boot_nodes_enr: str
    p2p_upnp_enabled: bool
    p2p_metrics_enabled: bool
    client_version: str
    disable_p2p: bool
    max_verification_gas: int
    max_call_data_gas: int
    disable_v6: bool
    min_bundler_balance: int
    logs_incremental_range: int
    logs_number_of_ranges: int
    health_check_interval: int
    reputation_whitelist: list[str]
    reputation_blacklist: list[str]
    p2p_canonical_mempool_id_07: str | None
    p2p_canonical_mempool_id_06: str | None
    native_tracer_node_url: str
    min_stake: int
    min_unstake_delay: int
    max_bundle_gas_limit: int


def address(ep: str):
    address_pattern = "^0x[0-9,a-f,A-F]{40}$"
    if not isinstance(ep, str) or re.match(address_pattern, ep) is None:
        raise ArgumentTypeError(f"Wrong address format : {ep}")
    return ep


def unsigned_int(value):
    ivalue = int(value)
    if ivalue < 0:
        raise ArgumentTypeError(
                "%s is an invalid unsigned int value" % value)
    return ivalue


def url_no_port(ep: str):
    address_pattern = "^(((https|http)://)?((?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}|(?:\\d{1,3}\\.){3}\\d{1,3}))$"
    if not isinstance(ep, str) or re.match(address_pattern, ep) is None:
        raise ArgumentTypeError(f"Wrong url format : {ep}")
    return ep

def _get_env_or_default(env_var, default, value_type):
    """
    Helper function to get the value from an environment variable or return the default value.
    Supports single values or lists (for nargs="+" arguments).
    """
    value = os.getenv(env_var, None)
    if value is not None:
        if value_type == list:
            return value.split(",")
        return value_type(value)
    return default

def initialize_argument_parser() -> ArgumentParser:
    parser = ArgumentParser(
        prog="Voltaire",
        description="EIP-4337 python Bundler",
        epilog=(
            "Candide Labs : https://candide.dev/ - "
            "Github : https://github.com/candidelabs"
        ),
    )

    group = parser.add_mutually_exclusive_group(required=False)

    group.add_argument(
        "--bundler_secret",
        type=str,
        help="Bundler private key",
        nargs="?",
        default=_get_env_or_default("VOLTAIRE_BUNDLER_SECRET", None, str),
    )

    group.add_argument(
        "--keystore_file_path",
        type=str,
        help=(
            "Bundler Keystore file path - "
            "defaults to first file in keystore folder"
        ),
        nargs="?",
        default=_get_env_or_default("VOLTAIRE_KEYSTORE_FILE_PATH", None, str),
    )

    parser.add_argument(
        "--keystore_file_password",
        type=str,
        help="Bundler Keystore file password - defaults to no password",
        nargs="?",
        const="",
        default=_get_env_or_default("VOLTAIRE_KEYSTORE_FILE_PASSWORD", "", str),
    )

    parser.add_argument(
        "--rpc_url",
        type=url_no_port,
        help="RPC serve url - defaults to localhost",
        nargs="?",
        const="127.0.0.1",
        default=_get_env_or_default("VOLTAIRE_RPC_URL", "127.0.0.1", str),
    )

    parser.add_argument(
        "--rpc_cors_domain",
        type=str,
        help="rpc cors allowed domain - defaults to *",
        nargs="?",
        const="*",
        default=_get_env_or_default("VOLTAIRE_RPC_CORS_DOMAIN", "*", str),
    )

    parser.add_argument(
        "--rpc_port",
        type=unsigned_int,
        help="RPC serve port - defaults to 3000",
        nargs="?",
        const=3000,
        default=_get_env_or_default("VOLTAIRE_RPC_PORT", 3000, unsigned_int),
    )

    parser.add_argument(
        "--ethereum_node_url",
        type=str,
        help="Eth Client JSON-RPC Url - defaults to http://0.0.0.0:8545",
        nargs="?",
        const="http://0.0.0.0:8545",
        default=_get_env_or_default("VOLTAIRE_ETHEREUM_NODE_URL", "http://0.0.0.0:8545", str),
    )

    parser.add_argument(
        "--chain_id",
        type=unsigned_int,
        help="chain id",
        nargs="?",
        default=_get_env_or_default("VOLTAIRE_CHAIN_ID", 1337, unsigned_int),
    )

    parser.add_argument(
        "--verbose",
        help="show debug log",
        nargs="?",
        const=True,
        default=_get_env_or_default("VOLTAIRE_VERBOSE", False, lambda v: v.lower() == "true"),
    )

    parser.add_argument(
        "--debug",
        help="expose _debug rpc namespace for testing",
        nargs="?",
        const=True,
        default=_get_env_or_default("VOLTAIRE_DEBUG", False, lambda v: v.lower() == "true"),
    )

    parser.add_argument(
        "--ethereum_node_debug_trace_call_url",
        type=str,
        help=(
            "An Eth Client JSON-RPC Url for debug_traceCall only - "
            "defaults to ethereum_node_url value"
        ),
        nargs="?",
        const=None,
        default=_get_env_or_default("VOLTAIRE_ETHEREUM_NODE_DEBUG_TRACE_CALL_URL", None, str),
    )

    parser.add_argument(
        "--tracer",
        help="set which tracer to use, default to javascript",
        nargs="?",
        type=Tracer,
        const=Tracer.javascript,
        choices=list(Tracer),
        default=_get_env_or_default("VOLTAIRE_UNSAFE", Tracer.javascript, Tracer),
    )

    parser.add_argument(
        "--ethereum_node_eth_get_logs_url",
        type=str,
        help=(
            "An Eth Client JSON-RPC Url for eth_getLogs only - "
            "defaults to ethereum_node_url value"
        ),
        nargs="?",
        const=None,
        default=_get_env_or_default("VOLTAIRE_ETHEREUM_NODE_ETH_GET_LOGS_URL", None, str),
    )

    parser.add_argument(
        "--legacy_mode",
        help="for networks that doesn't support EIP-1559",
        nargs="?",
        const=True,
        default=_get_env_or_default("VOLTAIRE_LEGACY_MODE", False, str),
    )

    group3 = parser.add_mutually_exclusive_group()
    group3.add_argument(
        "--conditional_rpc",
        help="use sendRawTransactionConditional",
        nargs="?",
        type=ConditionalRpc,
        const=ConditionalRpc.eth,
        default=_get_env_or_default("VOLTAIRE_CONDITIONAL_RPC", None, str),
        choices=list(ConditionalRpc)
    )

    group3.add_argument(
        "--flashbots_protect_node_url",
        type=str,
        help="Flashbots JSON-RPC Url",
        nargs="?",
        default=_get_env_or_default("VOLTAIRE_FLASHBOTS_PROTECT_NODE_URL", None, str),
    )

    parser.add_argument(
        "--bundle_interval",
        type=int,
        help=(
            "set the bundle interval in seconds for the auto bundle mode - "
            "set to zero for manual mode"
        ),
        nargs="?",
        const=1,
        default=_get_env_or_default("VOLTAIRE_BUNDLE_INTERVAL", 1, int),
    )

    parser.add_argument(
        "--max_fee_per_gas_percentage_multiplier",
        type=unsigned_int,
        help=(
            "modify the bundle max_fee_per_gas value as the following formula "
            "[bundle_max_fee_per_gas = block_max_fee_per_gas * "
            "max_fee_per_gas_percentage_multiplier /100], defaults to 110"
        ),
        nargs="?",
        const=110,
        default=_get_env_or_default("VOLTAIRE_MAX_FEE_PER_GAS_PERCENTAGE_MULTIPLIER", 110, unsigned_int),
    )

    parser.add_argument(
        "--max_priority_fee_per_gas_percentage_multiplier",
        type=unsigned_int,
        help=(
            "modify the bundle max_priority_fee_per_gas value as the following formula "
            "[bundle_max_priority_fee_per_gas = block_max_priority_fee_per_gas * "
            "max_priority_fee_per_gas_percentage_multiplier /100], defaults to 100"
        ),
        nargs="?",
        const=110,
        default=_get_env_or_default("VOLTAIRE_MAX_PRIORITY_FEE_PER_GAS_PERCENTAGE_MULTIPLIER", 110, unsigned_int),
    )

    parser.add_argument(
        "--enforce_gas_price_tolerance",
        type=unsigned_int,
        help=(
            "eth_sendUserOperation will return an error if the useroperation "
            "gas price is less than min_max_fee_per_gas, "
            "takes a tolerance percentage as a paramter as the following formula "
            "min_max_fee_per_gas = block_max_fee_per_gas * (1-tolerance/100), "
            "tolerance defaults to 10"
        ),
        nargs="?",
        const=10,
        default=_get_env_or_default("VOLTAIRE_ENFORCE_GAS_PRICE_TOLERANCE", 10, unsigned_int),
    )

    parser.add_argument(
        "--metrics",
        type=bool,
        help="enable metrics collection",
        nargs="?",
        const=True,
        default=_get_env_or_default("VOLTAIRE_METRICS", False, lambda v: v.lower() == "true"),
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s " + "version " + __version__,
    )

    parser.add_argument(
        "--disable_v6",
        type=bool,
        help="disable support for entrypoint v0.06",
        nargs="?",
        const=True,
        default=_get_env_or_default("VOLTAIRE_DISABLE_V6", False, lambda v: v.lower() == "true"),
    )

    parser.add_argument(
        "--p2p_enr_address",
        type=str,
        help=(
            "P2P - The address to broadcast to peers about which address"
            " the bundler is listening on."
        ),
        default=_get_env_or_default("VOLTAIRE_P2P_ENR_ADDRESS", None, str),
    )

    parser.add_argument(
        "--p2p_enr_tcp_port",
        type=unsigned_int,
        help=(
            "P2P - The tcp ipv4 port to broadcast to peers in order to reach "
            "back for discovery."
        ),
        default=_get_env_or_default("VOLTAIRE_P2P_ENR_TCP_PORT", 9000, unsigned_int),
    )

    parser.add_argument(
        "--p2p_enr_udp_port",
        type=unsigned_int,
        help=(
            "P2P - The udp ipv4 port to broadcast to peers in order to reach "
            "back for discovery."
        ),
        default=_get_env_or_default("VOLTAIRE_P2P_ENR_UDP_PORT", 9000, unsigned_int),
    )

    parser.add_argument(
        "--p2p_target_peers_number",
        type=unsigned_int,
        help="P2P - Target number of connected peers.",
        default=_get_env_or_default("VOLTAIRE_P2P_TARGET_PEERS_NUMBER", 16, unsigned_int),
    )

    parser.add_argument(
        "--p2p_boot_nodes_enr",
        type=str,
        help=(
            "P2P - One or more comma-delimited base64-encoded ENR's to "
            "bootstrap the p2p network. Multiaddr is also supported."
        ),
        default=_get_env_or_default("VOLTAIRE_P2P_BOOT_NODES_ENR", None, list),
    )

    parser.add_argument(
        "--p2p_upnp_enabled",
        help="Attempt to construct external port mappings with UPnP.",
        nargs="?",
        const=True,
        default=_get_env_or_default("VOLTAIRE_P2P_UPNP_ENABLED", False, lambda v: v.lower() == "true"),
    )

    parser.add_argument(
        "--p2p_metrics_enabled",
        help="Whether metrics are enabled.",
        nargs="?",
        const=True,
        default=_get_env_or_default("VOLTAIRE_P2P_METRICS_ENABLED", False, lambda v: v.lower() == "true"),
    )

    parser.add_argument(
        "--disable_p2p",
        type=bool,
        help="disable p2p",
        nargs="?",
        const=True,
        default=_get_env_or_default("VOLTAIRE_DISABLE_P2P", False, lambda v: v.lower() == "true"),
    )

    parser.add_argument(
        "--max_verification_gas",
        type=int,
        help="Maximimum allowed verification gas",
        nargs="?",
        const=10_000_000,
        default=_get_env_or_default("VOLTAIRE_MAX_VERIFICATION_GAS", 10_000_000, int),
    )

    parser.add_argument(
        "--max_call_data_gas",
        type=int,
        help="Maximimum allowed calldata gas",
        nargs="?",
        const=30_000_000,
        default=_get_env_or_default("VOLTAIRE_MAX_CALL_DATA_GAS", 30_000_000, int),
    )

    parser.add_argument(
        "--min_bundler_balance",
        type=int,
        help=(
            "Minimum bundler balance in wei, "
            "if crossed the bundler will create warining logs"
        ),
        nargs="?",
        const=1_000_000_000_000_000_000,
        default=_get_env_or_default("VOLTAIRE_MIN_BUNDLER_BALANCE", 1_000_000_000_000_000_000, int),
    )

    parser.add_argument(
        "--logs_incremental_range",
        type=int,
        help=(
            "eth_getLogs block range per request, affects eth_getUserOperationByHash "
            "and eth_getUserOperationReceipt. Defaults to 0 which mean earliest"
        ),
        nargs="?",
        const=0,
        default=_get_env_or_default("VOLTAIRE_LOGS_INCREMENTAL_RANGE", 0, int),
    )

    parser.add_argument(
        "--logs_number_of_ranges",
        type=int,
        help=(
            "number of ranges to search eth_getLogs. needs to be set with "
            "--logs_incremental_range"
        ),
        nargs="?",
        const=10,
        default=_get_env_or_default("VOLTAIRE_LOGS_NUMBER_OF_RANGES", 10, int),
    )

    parser.add_argument(
        "--health_check_interval",
        type=int,
        help=(
            "Interval in seconds to execute health checks. "
            "Defaults to 600 seconds(10 minutes)"
        ),
        nargs="?",
        const=600,
        default=_get_env_or_default("VOLTAIRE_HEALTH_CHECK_INTERVAL", 600, int),
    )

    parser.add_argument(
        "--reputation_whitelist",
        help="Entities that will not be banned or throttled.",
        type=str,
        nargs="+",
        default=_get_env_or_default("VOLTAIRE_REPUTATION_WHITELIST", None, list),
    )

    parser.add_argument(
        "--reputation_blacklist",
        help="Entities that are always banned.",
        type=str,
        nargs="+",
        default=_get_env_or_default("VOLTAIRE_REPUTATION_BLACKLIST", None, list),
    )

    parser.add_argument(
        "--p2p_canonical_mempool_id_07",
        type=str,
        help= "Canonical mempool id for entrypoint v0.07",
        nargs="?",
        const=None,
        default=None,
    )

    parser.add_argument(
        "--p2p_canonical_mempool_id_06",
        type=str,
        help= "Canonical mempool id for entrypoint v0.06",
        nargs="?",
        const=None,
        default=None,
    )

    parser.add_argument(
        "--native_tracer_node_url",
        type=str,
        help="Eth Client JSON-RPC Url - defaults to http://0.0.0.0:8888",
        nargs="?",
        const="http://0.0.0.0:8888",
        default="http://0.0.0.0:8888",
    )

    parser.add_argument(
        "--min_stake",
        type=unsigned_int,
        help="minimum stake.",
        default=1,
    )

    parser.add_argument(
        "--min_unstake_delay",
        type=unsigned_int,
        help="minimum unstake delay.",
        default=1,
    )

    parser.add_argument(
        "--max_bundle_gas_limit",
        type=int,
        help=(
            "Limit for maximum bundle gas cost."
        ),
        nargs="?",
        const=15_000_000,
        default=15_000_000,
    )

    return parser

async def parse_args(cmd_args: [str]) -> InitData:
    argument_parser: ArgumentParser = initialize_argument_parser()
    args = argument_parser.parse_args(cmd_args)
    # Required mutually exclusive arguments
    if not args.bundler_secret and not args.keystore_file_path:
        argument_parser.error("You must specify either --bundler_secret or --keystore_file_path, or set VOLTAIRE_BUNDLER_SECRET or VOLTAIRE_KEYSTORE_FILE_PATH environment variables.")
    if args.bundler_secret and args.keystore_file_path:
        argument_parser.error("You can only specify either --bundler_secret or --keystore_file_path but not both at the same time")
    # Non-required mutually exclusive arguments
    if args.conditional_rpc and args.flashbots_protect_node_url:
        argument_parser.error("You can only specify either --conditional_rpc or --flashbots_protect_node_url but not both at the same time")
    if args.ethereum_node_debug_trace_call_url and args.tracer == Tracer.unsafe:
        argument_parser.error("You can only specify either --ethereum_node_debug_trace_call_url or --unsafe but not both at the same time")
    init_data = await get_init_data(args)
    return init_data

def init_logging(args: Namespace):
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s.%(msecs)03d %(levelname)s %(message)s",
        datefmt="%b %d %H:%M:%S",
    )

    logging.getLogger("Voltaire")


def init_bundler_address_and_secret(args: Namespace):
    bundler_address = ""
    bundler_pk = ""

    if args.keystore_file_path is not None:
        bundler_address, bundler_pk = import_bundler_account(
            args.keystore_file_password, args.keystore_file_path
        )
    else:
        bundler_pk = args.bundler_secret
        bundler_address = public_address_from_private_key(bundler_pk)
    return bundler_address, bundler_pk


def check_if_valid_rpc_url_and_port(rpc_url, rpc_port) -> None:
    try:
        socket.getaddrinfo(rpc_url, rpc_port)
    except socket.gaierror:
        logging.critical(f"Invalid RPC url {rpc_url} and port {rpc_port}")
        sys.exit(1)

    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        soc.bind((rpc_url, rpc_port))
    except socket.error as message:
        logging.critical(
            f"Bind failed. {str(message)} for RPC url {rpc_url} and port {rpc_port}"
        )
        sys.exit(1)


async def check_valid_ethereum_rpc_and_get_chain_id(ethereum_node_url) -> str:
    try:
        chain_id_hex = await send_rpc_request_to_eth_client(
            ethereum_node_url,
            "eth_chainId",
            [],
        )
        if "result" not in chain_id_hex:
            logging.critical(f"Invalid Eth node {ethereum_node_url}")
            sys.exit(1)
        else:
            return chain_id_hex["result"]
    except aiohttp.client_exceptions.ClientConnectorError:
        logging.critical(f"Connection refused for Eth node {ethereum_node_url}")
        sys.exit(1)
    except Exception:
        logging.critical(f"Error when connecting to Eth node {ethereum_node_url}")
        sys.exit(1)


async def check_valid_entrypoint(ethereum_node_url: str, entrypoint: Address):
    entrypoint_code = await send_rpc_request_to_eth_client(
        ethereum_node_url,
        "eth_getCode",
        [entrypoint, "latest"],
    )
    if "result" not in entrypoint_code or len(entrypoint_code["result"]) < 10:
        logging.critical(f"entrypoint not deployed at {entrypoint}")
        sys.exit(1)


async def check_valid_entrypoints(ethereum_node_url: str, disable_v6: bool):
    if not disable_v6:
        await check_valid_entrypoint(
            ethereum_node_url,
            Address("0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789")
        )
    await check_valid_entrypoint(
        ethereum_node_url,
        Address("0x0000000071727De22E5E9d8BAf0edAc6f37da032")
    )


async def get_init_data(args: Namespace) -> InitData:
    init_logging(args)

    check_if_valid_rpc_url_and_port(args.rpc_url, args.rpc_port)

    ethereum_node_chain_id_hex = await check_valid_ethereum_rpc_and_get_chain_id(
        args.ethereum_node_url
    )

    if hex(args.chain_id) != ethereum_node_chain_id_hex.lower():
        logging.critical(
            f"Invalid chain id {args.chain_id} with Eth node {args.ethereum_node_url}"
        )
        sys.exit(1)

    bundler_address, bundler_pk = init_bundler_address_and_secret(args)

    if args.ethereum_node_debug_trace_call_url is None:
        args.ethereum_node_debug_trace_call_url = args.ethereum_node_url
    if args.ethereum_node_eth_get_logs_url is None:
        args.ethereum_node_eth_get_logs_url = args.ethereum_node_url

    if args.ethereum_node_debug_trace_call_url != args.ethereum_node_url:
        ethereum_node_debug_chain_id_hex = (
            await check_valid_ethereum_rpc_and_get_chain_id(
                args.ethereum_node_debug_trace_call_url
            )
        )
        if ethereum_node_chain_id_hex != ethereum_node_debug_chain_id_hex:
            logging.critical(
                f"Eth node chain id {ethereum_node_chain_id_hex} not eqaul " +
                f"Eth node debug chain id {ethereum_node_debug_chain_id_hex}"
            )
            sys.exit(1)

    if args.ethereum_node_eth_get_logs_url != args.ethereum_node_url:
        eth_get_logs_url_chain_id_hex = (
            await check_valid_ethereum_rpc_and_get_chain_id(
                args.ethereum_node_eth_get_logs_url
            )
        )
        if ethereum_node_chain_id_hex != eth_get_logs_url_chain_id_hex:
            logging.critical(
                f"Eth node chain id {ethereum_node_chain_id_hex} not eqaul " +
                f"Eth node debug chain id {eth_get_logs_url_chain_id_hex}"
            )
            sys.exit(1)

    if args.tracer == Tracer.unsafe:
        if args.conditional_rpc is not None:
            logging.critical(
                "conditional_rpc sendRawTransactionalConditional "
                "can't work with unsafe mode."
            )
            sys.exit(1)

    elif args.tracer == "native":
        try:
            trace_call_res = await send_rpc_request_to_eth_client(
                args.native_tracer_node_url,
                "debug_traceCall",
                [{}, 'latest', {"tracer": "bundlerCollectorTracer"}],
            )
            if "result" not in trace_call_res:
                logging.critical(
                    "Native tracer doesn't support bundlerCollectorTracer")
                sys.exit(1)
        except aiohttp.client_exceptions.ClientConnectorError:
            logging.critical(
                f"Connection refused for Eth node {args.native_tracer_node_url}")
            sys.exit(1)
        except Exception:
            logging.critical(
                f"Error when connecting to Eth node {args.native_tracer_node_url}")
            sys.exit(1)

    if not args.debug:
        await check_valid_entrypoints(args.ethereum_node_url, args.disable_v6)

    if not args.disable_p2p:
        if args.p2p_canonical_mempool_id_07 is None:
            if args.chain_id not in DEFAULT_MEMPOOL_INFO["0x0000000071727De22E5E9d8BAf0edAc6f37da032"]:
                logging.warning(
                    "p2p is disabled because p2p_canonical_mempool_id_07 "
                    "not provided and no default value for the target chain."
                )
                args.disable_p2p = True
            else:
                args.p2p_canonical_mempool_id_07 = DEFAULT_MEMPOOL_INFO["0x0000000071727De22E5E9d8BAf0edAc6f37da032"][args.chain_id]
        if not args.disable_v6 and args.p2p_canonical_mempool_id_06 is None:
            if args.chain_id not in DEFAULT_MEMPOOL_INFO["0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"]:
                logging.warning(
                    "p2p is disabled because p2p_canonical_mempool_id_06 "
                    "not provided and no default value for the target chain."
                )
                args.disable_p2p = True
            else:
                args.p2p_canonical_mempool_id_06 = DEFAULT_MEMPOOL_INFO["0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"][args.chain_id]

    ret = InitData(
        args.rpc_url,
        args.rpc_port,
        args.ethereum_node_url,
        bundler_pk,
        bundler_address,
        args.chain_id,
        args.debug,
        args.tracer,
        args.legacy_mode,
        args.conditional_rpc,
        args.flashbots_protect_node_url,
        args.bundle_interval,
        args.max_fee_per_gas_percentage_multiplier,
        args.max_priority_fee_per_gas_percentage_multiplier,
        args.metrics,
        args.rpc_cors_domain,
        args.enforce_gas_price_tolerance,
        args.ethereum_node_debug_trace_call_url,
        args.ethereum_node_eth_get_logs_url,
        args.p2p_enr_address,
        args.p2p_enr_tcp_port,
        args.p2p_enr_udp_port,
        args.p2p_target_peers_number,
        args.p2p_boot_nodes_enr,
        args.p2p_upnp_enabled,
        args.p2p_metrics_enabled,
        __version__,
        args.disable_p2p,
        args.max_verification_gas,
        args.max_call_data_gas,
        args.disable_v6,
        args.min_bundler_balance,
        args.logs_incremental_range,
        args.logs_number_of_ranges,
        args.health_check_interval,
        args.reputation_whitelist,
        args.reputation_blacklist,
        args.p2p_canonical_mempool_id_07,
        args.p2p_canonical_mempool_id_06,
        args.native_tracer_node_url,
        args.min_stake,
        args.min_unstake_delay,
        args.max_bundle_gas_limit
    )

    if args.verbose:
        print(VOLTAIRE_HEADER)
        print("version : " + __version__)

    logging.info("Starting *** Voltaire *** - Python 4337 Bundler")

    return ret
