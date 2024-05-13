#!/user/bin/python3

import math
import pytest_asyncio
import pytest
import asyncio
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

    # Deterministic factory
    factoryAddress = '0x4e59b44847b379578588920ca78fbf26c0b4956c'
    factoryTx = '0xf8a58085174876e800830186a08080b853604580600e600039806000f350fe7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf31ba02222222222222222222222222222222222222222222222222222222222222222a02222222222222222222222222222222222222222222222222222222222222222'
    factoryDeployer = '0x3fab184622dc19b6109349b94811493bf2a45362'
    deploymentGasPrice = 100e9
    deploymentGasLimit = 100000
    factoryDeploymentFee = str(math.ceil(deploymentGasPrice * deploymentGasLimit))

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
        ports={"8545/tcp": "58545"},
        detach=True
    )
    await asyncio.sleep(3)

    # Fund factoryDeployer
    client.containers.run(
        "ethereum/client-go:v1.10.26", network_mode="host",
        entrypoint="geth --exec \"eth.sendTransaction({from: eth.coinbase, to:'" + factoryDeployer + "', value: " + factoryDeploymentFee + "})\" attach http://0.0.0.0:58545"
    )

    # Deploy deterministic factory
    client.containers.run(
        "ethereum/client-go:v1.10.26", network_mode="host",
        entrypoint="geth --exec \"eth.sendRawTransaction('" + factoryTx + "')\" attach http://0.0.0.0:58545"
    )

    # Fund signer
    client.containers.run(
        "ethereum/client-go:v1.10.26", network_mode="host",
        entrypoint="geth --exec \"eth.sendTransaction({from: eth.coinbase, to: '0x084178a5fd956e624fcb61c3c2209e3dcf42c8e8', value: 10000000000000000000000})\" attach http://0.0.0.0:58545"
    )

    # Unlock signer
    client.containers.run(
        "ethereum/client-go:v1.10.26", network_mode="host",
        entrypoint="geth --exec \"personal.importRawKey('897368deaa9f3797c02570ef7d3fa4df179b0fc7ad8d8fc2547d04701604eb72', '')\" attach http://0.0.0.0:58545"
    )
    client.containers.run(
        "ethereum/client-go:v1.10.26", network_mode="host",
        entrypoint="geth --exec \"personal.unlockAccount('0x084178a5fd956e624fcb61c3c2209e3dcf42c8e8', '')\" attach http://0.0.0.0:58545"
    )

    # Deploy Entrypoint
    client.containers.run(
        "ethereum/client-go:v1.10.26", network_mode="host",
        entrypoint="geth --exec \"eth.sendTransaction({from:'0x084178a5fd956e624fcb61c3c2209e3dcf42c8e8', to: '" + factoryAddress + "', data: '" + entrypoint_bytecode + "', gas: 10000000 })\" attach http://0.0.0.0:58545"
    )

    yield container


@pytest_asyncio.fixture(scope="module", autouse=True)
async def bundlerInstance(event_loop, gethDockerContainer):
    """
    Run a bundler instance
    """
    args = [
        "--entrypoints", "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789",
        "--bundler_secret", "0x897368deaa9f3797c02570ef7d3fa4df179b0fc7ad8d8fc2547d04701604eb72",
        "--chain_id", "1337",
        "--rpc_port", "53000",
        "--ethereum_node_url", "http://0.0.0.0:58545",
        "--verbose",
        "--debug",
        "--bundle_interval", "0",
        "--disable_p2p"
    ]

    asyncio.create_task(main(args, event_loop))
    await asyncio.sleep(3)

    yield
    gethDockerContainer.stop()
