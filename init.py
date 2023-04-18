import logging
import argparse
import re
import json
from dataclasses import dataclass

from utils.import_key import import_bundler_account, public_address_from_private_key

VOLTAIRE_HEADER = "\n".join(
    (
        r" _    ______  __  _________    ________  ______",
        r"| |  / / __ \/ / /_  __/   |  /  _/ __ \/ ____/",
        r"| | / / / / / /   / / / /| |  / // /_/ / __/   ",
        r"| |/ / /_/ / /___/ / / ___ |_/ // _, _/ /___   ",
        r"|___/\____/_____/_/ /_/  |_/___/_/ |_/_____/   ",
    )
)


@dataclass()
class InitData:
    entrypoint: list()
    rpc_url: str
    rpc_port: int
    geth_url: str
    bundler_pk: str
    bundler_address: str
    bundler_helper_byte_code: str
    chain_id: int
    is_debug: bool
    is_unsafe: bool
    is_gas_estimation_without_simulation: bool
    is_send_raw_transaction_conditional: bool


def address(ep):
    address_pattern = "^0x[0-9,a-f,A-F]{40}$"
    if not isinstance(ep, str) or re.match(address_pattern, ep) is None:
        raise ValueError
    return ep


def initialize() -> InitData:
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
        "--rpc_port",
        type=int,
        help="RPC serve port - defaults to 3000",
        nargs="?",
        const=3000,
        default=3000,
    )

    parser.add_argument(
        "--geth_url",
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
        "--gas_estimation_without_simulation",
        help="perform gas estimation without calling simulateValidation to be compatible with optimism rollup before the bedrock update",
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

    args = parser.parse_args()

    bundler_address="" 
    bundler_pk=""

    if args.keystore_file_path is not None:
        bundler_address, bundler_pk = import_bundler_account(
            args.keystore_file_password, args.keystore_file_path
        )
    else:
        bundler_pk = args.bundler_secret
        bundler_address = public_address_from_private_key(bundler_pk)

    bundler_helper_byte_code_file = open("utils/BundlerHelper.json")
    data = json.load(bundler_helper_byte_code_file)
    bundler_helper_byte_code = data["bytecode"]

    ret = InitData(
        args.entrypoint,
        args.rpc_url,
        args.rpc_port,
        args.geth_url,
        bundler_pk,
        bundler_address,
        bundler_helper_byte_code,
        args.chain_id,
        args.debug,
        args.unsafe,
        args.gas_estimation_without_simulation,
        args.send_raw_transaction_conditional
    )

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%m-%d %H:%M:%S",
    )

    logger = logging.getLogger("Voltaire")
    if args.verbose:
        print(VOLTAIRE_HEADER)

    logging.info("Starting *** Voltaire *** - Python 4337 Bundler")

    return ret
