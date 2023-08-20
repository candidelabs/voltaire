#!/user/bin/python3

import pytest_asyncio
import pytest
import asyncio
from threading import Thread
from voltaire_bundler.main import main
import docker

from utils import entrypoint_bytecode

@pytest.fixture(scope="session")
def event_loop():
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
    yield loop
    asyncio.get_event_loop().close()


@pytest_asyncio.fixture(scope="module", autouse=True)
async def gethDockerContainer():
    client = docker.from_env()

    container = client.containers.run(
        "ethereum/client-go:v1.10.26", 
        [
            "--miner.gaslimit", "12000000",
            "--http", "--http.api", "personal,eth,net,web3,debug",
            "--http.vhosts", "'*,localhost,host.docker.internal'",
            "--http.addr", "0.0.0.0",
            "--ignore-legacy-receipts",
            "--allow-insecure-unlock",
            "--rpc.allow-unprotected-txs",
            "--dev",
            "--nodiscover",
            "--maxpeers", "0",
            "--mine",
            "--miner.threads", "1",
            "--networkid", "1337"
        ], 
        ports={"8545/tcp": "8545"},
        detach=True
    )
    await asyncio.sleep(3)
    client.containers.run(
        "ethereum/client-go:v1.10.26", network_mode="host",
        entrypoint="geth --exec \"eth.sendTransaction({from: eth.accounts[0], to: '0x084178a5fd956e624fcb61c3c2209e3dcf42c8e8', value: 10000000000000000000000})\" attach http://0.0.0.0:8545"
    )
    client.containers.run(
        "ethereum/client-go:v1.10.26", network_mode="host",
        entrypoint="geth --exec \"personal.importRawKey('897368deaa9f3797c02570ef7d3fa4df179b0fc7ad8d8fc2547d04701604eb72', '')\" attach http://0.0.0.0:8545"
    )
    client.containers.run(
        "ethereum/client-go:v1.10.26", network_mode="host",
        entrypoint="geth --exec \"personal.unlockAccount('0x084178a5fd956e624fcb61c3c2209e3dcf42c8e8', '')\" attach http://0.0.0.0:8545"
    )

    client.containers.run(
        "ethereum/client-go:v1.10.26", network_mode="host",
        entrypoint="geth --exec \"eth.sendTransaction({from:'0x084178a5fd956e624fcb61c3c2209e3dcf42c8e8', data: '" + entrypoint_bytecode + "', gas: 10000000 })\" attach http://0.0.0.0:8545"
    )

    yield container

@pytest_asyncio.fixture(scope="module", autouse=True)
async def bundlerInstance(event_loop, gethDockerContainer):
    """
    Run a bundler instance
    """
    args = [
        "--entrypoint","0x4AC842ABD525EEC0094951f892A8013Af1c78764",
        "--bundler_secret","0x897368deaa9f3797c02570ef7d3fa4df179b0fc7ad8d8fc2547d04701604eb72",
        "--chain_id","1337",
        "--verbose",
        "--debug",
        "--bundle_interval","0"
    ]
    
    asyncio.create_task(main(args, event_loop))

    yield
    gethDockerContainer.stop()