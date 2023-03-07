import logging
import argparse
import re
import json
from dataclasses import dataclass

from utils.import_key import import_bundler_account

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
    entrypoint_abi: list()
    rpc_url: str
    rpc_port: int
    geth_url: str
    bundler_pk: str
    bundler_address: str

def entrypoint(ep):
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
        "entrypoint",
        metavar="--entrypoint",
        type=entrypoint,
        help="supported entrypoints addresses",
    )

    parser.add_argument(
        "rpc_url",
        metavar="--rpc-url",
        type=str,
        help="RPC serve url - defaults to localhost",
        nargs="?",
        const="localhost",
        default="localhost",
    )

    parser.add_argument(
        "rpc_port",
        metavar="--rpc-port",
        type=int,
        help="RPC serve port - defaults to 3000",
        nargs="?",
        const=3000,
        default=3000,
    )

    parser.add_argument(
        "geth_url",
        metavar="--geth-url",
        type=str,
        help="Geth Client Http Url - defaults to http://0.0.0.0:8545",
        nargs="?",
        const="http://0.0.0.0:8545",
        default="http://0.0.0.0:8545",
    )

    parser.add_argument(
        "--verbose",
        metavar="verbose",
        help="show debug log",
        nargs="?",
        const=True,
        default=False,
    )

    parser.add_argument(
        "keystoreFilePath",
        metavar="--keystore-file-path",
        type=str,
        help="Bundler Keystore file path - defaults to first file in keystore folder",
        nargs="?",
        const="keystore/*",
        default="keystore/*",
    )

    parser.add_argument(
        "keystoreFilePaassword",
        metavar="--keystore-file-password",
        type=str,
        help="Bundler Keystore file password - defaults to no password",
        nargs="?",
        const="",
        default="",
    )

    args = parser.parse_args()

    bundler_address, bundler_pk = import_bundler_account(
        args.keystoreFilePaassword, args.keystoreFilePath
    )

    entrypoint_abi_file = open("utils/EntryPoint.json")
    data = json.load(entrypoint_abi_file)
    entrypoint_abi = data["abi"]

    ret = InitData(
        args.entrypoint,
        entrypoint_abi,
        args.rpc_url,
        args.rpc_port,
        args.geth_url,
        bundler_pk,
        bundler_address,
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
