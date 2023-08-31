import os
import logging
import argparse
import re
import json
from dataclasses import dataclass
from importlib.metadata import version
from argparse import ArgumentParser, Namespace

from .utils.import_key import (
    import_bundler_account,
    public_address_from_private_key,
)


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


@dataclass()
class InitData:
    entrypoint: list()
    rpc_url: str
    rpc_port: int
    ethereum_node_url: str
    bundler_pk: str
    bundler_address: str
    bundler_helper_byte_code: str
    chain_id: int
    is_debug: bool
    is_unsafe: bool
    is_legacy_mode: bool
    is_send_raw_transaction_conditional: bool
    bundle_interval: int
    whitelist_entity_storage_access: list()
    max_fee_per_gas_percentage_multiplier: int
    max_priority_fee_per_gas_percentage_multiplier: int
    is_metrics: bool
    rpc_cors_domain: str
    enforce_gas_price_tolerance:int


def address(ep):
    address_pattern = "^0x[0-9,a-f,A-F]{40}$"
    if not isinstance(ep, str) or re.match(address_pattern, ep) is None:
        raise ValueError
    return ep


def initialize_argument_parser() -> ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="Voltaire",
        description="EIP-4337 python Bundler",
        epilog="Candide Labs : http://candidewallet.com - Github : https://github.com/candidelabs",
    )
    parser.add_argument(
        "--entrypoint",
        type=address,
        help="supported entrypoints addresses",
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
        help="Geth Client Http Url - defaults to http://0.0.0.0:8545",
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

    parser.add_argument(
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

    return parser

def get_init_data(args:Namespace)-> InitData:
    bundler_address = ""
    bundler_pk = ""

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

    ret = InitData(
        args.entrypoint,
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
    )

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%m-%d %H:%M:%S",
    )

    logger = logging.getLogger("Voltaire")
    if args.verbose:
        print(VOLTAIRE_HEADER)
        print("version : " + __version__)

    logging.info("Starting *** Voltaire *** - Python 4337 Bundler")

    return ret
