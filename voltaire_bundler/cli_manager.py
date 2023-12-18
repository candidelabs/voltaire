from enum import Enum
import os
import logging
import argparse
import re
import json
from dataclasses import dataclass
from importlib.metadata import version
from argparse import ArgumentParser, Namespace
import sys

from .typing import Address, MempoolId
from .utils.import_key import (
    import_bundler_account,
    public_address_from_private_key,
)
from voltaire_bundler.bundler.mempool.mempool_info import DEFAULT_MEMPOOL_INFO


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

class EntrypointType(Enum):
    v_0_6 = "0.6"

class MempoolType(Enum):
    default = "default"

@dataclass()
class InitData:
    entrypoints: list[Address]
    entrypoints_versions: list[EntrypointType]
    rpc_url: str
    rpc_port: int
    ethereum_node_url: str
    bundler_pk: str
    bundler_address: Address
    bundler_helper_byte_code: str
    chain_id: int
    is_debug: bool
    is_unsafe: bool
    is_legacy_mode: bool
    is_send_raw_transaction_conditional: bool
    bundle_interval: int
    whitelist_entity_storage_access: list[str]
    max_fee_per_gas_percentage_multiplier: int
    max_priority_fee_per_gas_percentage_multiplier: int
    is_metrics: bool
    rpc_cors_domain: str
    enforce_gas_price_tolerance:int
    ethereum_node_debug_trace_call_url: str
    p2p_enr_address: str
    p2p_enr_tcp_port: int
    p2p_enr_udp_port: int
    p2p_mempools_types:list[list[MempoolType]]
    p2p_mempools_ids:list[list[MempoolId]]
    p2p_target_peers_number: int
    p2p_boot_nodes_enr: str
    p2p_upnp_enabled: bool
    p2p_metrics_enabled: bool
    client_version: str

def address(ep: str):
    address_pattern = "^0x[0-9,a-f,A-F]{40}$"
    if not isinstance(ep, str) or re.match(address_pattern, ep) is None:
        logging.error(f"Wrong address format : {ep}")
        raise ValueError
    return ep

# def entrypoints_versions(entrypoint_version: str):
#     supported_entrypoint_version = ["v0.6"]
#     if entrypoint_version not in ["v0.6"]:
#         logging.error(f"Unsupported entrypoint version : {entrypoint_version}, supported entrypoints version are {supported_entrypoint_version}")
#         raise ValueError

#     return entrypoint_version


def initialize_argument_parser() -> ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="Voltaire",
        description="EIP-4337 python Bundler",
        epilog="Candide Labs : https://candide.dev/ - Github : https://github.com/candidelabs",
    )
    parser.add_argument(
        "--entrypoints",
        type=address,
        nargs="+",
        help="Supported entrypoints addresses.",
        default=["0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"],
    )

    parser.add_argument(
        "--entrypoints_versions",
        type=EntrypointType,
        nargs="+",
        help="Supported entrypoints version.",
        default=[EntrypointType.v_0_6],
    )

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "--bundler_secret",
        type=str,
        help="Bundler private key",
        nargs="?",
    )

    group.add_argument(
        "--keystore_file_path",
        type=str,
        help="Bundler Keystore file path - defaults to first file in keystore folder",
        nargs="?",
    )

    parser.add_argument(
        "--keystore_file_password",
        type=str,
        help="Bundler Keystore file password - defaults to no password",
        nargs="?",
        const="",
        default="",
    )

    parser.add_argument(
        "--rpc_url",
        type=str,
        help="RPC serve url - defaults to localhost",
        nargs="?",
        const="127.0.0.1",
        default="127.0.0.1",
    )

    parser.add_argument(
        "--rpc_cors_domain",
        type=str,
        help="rpc cors allowed domain - defaults to *",
        nargs="?",
        const="*",
        default="*",
    )

    parser.add_argument(
        "--rpc_port",
        type=int,
        help="RPC serve port - defaults to 3000",
        nargs="?",
        const=3000,
        default=3000,
    )

    parser.add_argument(
        "--ethereum_node_url",
        type=str,
        help="Eth Client JSON-RPC Url - defaults to http://0.0.0.0:8545",
        nargs="?",
        const="http://0.0.0.0:8545",
        default="http://0.0.0.0:8545",
    )

    parser.add_argument(
        "--chain_id",
        type=int,
        help="chain id",
        nargs="?",
    )

    parser.add_argument(
        "--verbose",
        help="show debug log",
        nargs="?",
        const=True,
        default=False,
    )

    parser.add_argument(
        "--debug",
        help="expose _debug rpc namespace for testing",
        nargs="?",
        const=True,
        default=False,
    )

    group2 = parser.add_mutually_exclusive_group()

    group2.add_argument(
        "--ethereum_node_debug_trace_call_url",
        type=str,
        help="An Eth Client JSON-RPC Url for debug_traceCall only - defaults to ethereum_node_url value",
        nargs="?",
        const=None,
        default=None,
    )

    group2.add_argument(
        "--unsafe",
        help="UNSAFE mode: no storage or opcode checks - when debug_traceCall is not available",
        nargs="?",
        const=True,
        default=False,
    )

    parser.add_argument(
        "--legacy_mode",
        help="for netwroks that doesn't support EIP-1559",
        nargs="?",
        const=True,
        default=False,
    )

    parser.add_argument(
        "--send_raw_transaction_conditional",
        help="use eth_SendRawTransactionConditional with comptaible rollups",
        nargs="?",
        const=True,
        default=False,
    )

    parser.add_argument(
        "--bundle_interval",
        type=int,
        help="set the bundle interval in seconds for the auto bundle mode - set to zero for manual mode",
        nargs="?",
        const=1,
        default=1,
    )

    parser.add_argument(
        "--whitelist_entity_storage_access",
        type=address,
        nargs="+",
        help="list of entities to whitelist for storage access rules",
        default=[],
    )

    parser.add_argument(
        "--max_fee_per_gas_percentage_multiplier",
        type=int,
        help="modify the bundle max_fee_per_gas value as the following formula [bundle_max_fee_per_gas = block_max_fee_per_gas * max_fee_per_gas_percentage_multiplier /100], defaults to 100",
        nargs="?",
        const=100,
        default=100,
    )

    parser.add_argument(
        "--max_priority_fee_per_gas_percentage_multiplier",
        type=int,
        help="modify the bundle max_priority_fee_per_gas value as the following formula [bundle_max_priority_fee_per_gas = block_max_priority_fee_per_gas * max_priority_fee_per_gas_percentage_multiplier /100], defaults to 100",
        nargs="?",
        const=100,
        default=100,
    )

    parser.add_argument(
        "--enforce_gas_price_tolerance",
        type=int,
        help="eth_sendUserOperation will return an error if the useroperation gas price is less than min_max_fee_per_gas, takes a tolerance percentage as a paramter as the following formula min_max_fee_per_gas = block_max_fee_per_gas * (1-tolerance/100), tolerance defaults to 10",
        nargs="?",
        const=10,
        default=10,
    )

    parser.add_argument(
        "--metrics",
        help="enable metrics collection",
        nargs="?",
        const=True,
        default=False,
    )

    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s " + "version " + __version__,
    )

    parser.add_argument(
        "--p2p_enr_address",
        type=str,
        help="P2P - The address to broadcast to peers about which address we are listening on.",
    )

    parser.add_argument(
        "--p2p_enr_tcp_port",
        type=int,
        help="P2P - The tcp ipv4 port to broadcast to peers in order to reach back for discovery.",
        default=9000,
    )

    parser.add_argument(
        "--p2p_enr_udp_port",
        type=int,
        help="P2P - The udp ipv4 port to broadcast to peers in order to reach back for discovery.",
        default=9000,
    )

    parser.add_argument(
        "--p2p_mempools_types",
        type=MempoolType,
        nargs="+",
        action='append',
        default=[[MempoolType.default]],
        help="P2P - List of mempool types per entrypoint.",
    )

    parser.add_argument(
        "--p2p_mempools_ids",
        type=MempoolId,
        nargs="+",
        action='append',
        default=[[None]],
        help="P2P - List of supported mempools ids per mempool type.",
    )

    parser.add_argument(
        "--p2p_target_peers_number",
        type=int,
        help="P2P - Target number of connected peers.",
        default=16,
    )

    parser.add_argument(
        "--p2p_boot_nodes_enr",
        nargs="+",
        type=str,
        default=[],
        help="P2P - List of nodes Enr to initially connect to.",
    )

    parser.add_argument(
        "--p2p_upnp_enabled",
        help="Attempt to construct external port mappings with UPnP.",
        nargs="?",
        const=True,
        default=False,
    )

    parser.add_argument(
        "--p2p_metrics_enabled",
        help="Whether metrics are enabled.",
        nargs="?",
        const=True,
        default=False,
    )

    return parser

def get_init_data(args:Namespace)-> InitData:
    bundler_address = ""
    bundler_pk = ""

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%m-%d %H:%M:%S",
    )

    logging.getLogger("Voltaire")

    if args.keystore_file_path is not None:
        bundler_address, bundler_pk = import_bundler_account(
            args.keystore_file_password, args.keystore_file_path
        )
    else:
        bundler_pk = args.bundler_secret
        bundler_address = public_address_from_private_key(bundler_pk)

    package_directory = os.path.dirname(os.path.abspath(__file__))
    BundlerHelper_file = os.path.join(
        package_directory, "utils", "BundlerHelper.json"
    )

    bundler_helper_byte_code_file = open(BundlerHelper_file)
    data = json.load(bundler_helper_byte_code_file)
    bundler_helper_byte_code = data["bytecode"]

    if args.ethereum_node_debug_trace_call_url == None:
        args.ethereum_node_debug_trace_call_url = args.ethereum_node_url

    for (
            entrypoint,
            entrypoint_mempools_types,
            entrypoint_mempool_ids,
        ) in zip(
            args.entrypoints,
            args.p2p_mempools_types,
            args.p2p_mempools_ids,
        ):
        index = 0
        for mempool_type, mempool_id in zip(entrypoint_mempools_types, entrypoint_mempool_ids):
            if mempool_id is None and mempool_type == MempoolType.default:
                if entrypoint in DEFAULT_MEMPOOL_INFO:
                    if args.chain_id in DEFAULT_MEMPOOL_INFO[entrypoint]:
                        entrypoint_mempool_ids[index] = DEFAULT_MEMPOOL_INFO[entrypoint][args.chain_id]
                    else:
                        logging.error(f"Chain without default mempool ids : {entrypoint}, please specify the mempool id")
                        sys.exit(1)
                else:
                    logging.error(f"Entrypoint without default mempool ids : {entrypoint}, please specify the mempool id")
                    sys.exit(1)  
                index = index + 1

    ret = InitData(
        args.entrypoints,
        args.entrypoints_versions,
        args.rpc_url,
        args.rpc_port,
        args.ethereum_node_url,
        bundler_pk,
        bundler_address,
        bundler_helper_byte_code,
        args.chain_id,
        args.debug,
        args.unsafe,
        args.legacy_mode,
        args.send_raw_transaction_conditional,
        args.bundle_interval,
        args.whitelist_entity_storage_access,
        args.max_fee_per_gas_percentage_multiplier,
        args.max_priority_fee_per_gas_percentage_multiplier,
        args.metrics,
        args.rpc_cors_domain,
        args.enforce_gas_price_tolerance,
        args.ethereum_node_debug_trace_call_url,
        args.p2p_enr_address,
        args.p2p_enr_tcp_port,
        args.p2p_enr_udp_port,
        args.p2p_mempools_types,
        args.p2p_mempools_ids,
        args.p2p_target_peers_number,
        args.p2p_boot_nodes_enr,
        args.p2p_upnp_enabled,
        args.p2p_metrics_enabled,
        __version__
    )

    if args.verbose:
        print(VOLTAIRE_HEADER)
        print("version : " + __version__)

    logging.info("Starting *** Voltaire *** - Python 4337 Bundler")

    return ret
