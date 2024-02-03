import pytest
from voltaire_bundler.utils.eth_client_utils import send_rpc_request_to_eth_client

@pytest.mark.asyncio
async def test_eth_chain_id(bundlerInstance):
    """
    Test eth_chainId
    """
    chain_id = await send_rpc_request_to_eth_client(
        "http://127.0.0.1:3000/rpc",
        "eth_chainId",
        [],
    )

    assert chain_id['result'] == "0x539"

@pytest.mark.asyncio
async def test_eth_supportedEntryPoints(bundlerInstance):
    """
    Test eth_chainId
    """
    supportedEntryPoints = await send_rpc_request_to_eth_client(
        "http://127.0.0.1:3000/rpc",
        "eth_supportedEntryPoints",
        [],
    )
    assert supportedEntryPoints['result'] == ["0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"]

@pytest.mark.asyncio
async def test_eth_estimateUserOperationGas(bundlerInstance):
    """
    Test eth_estimateUserOperationGas
    """
    result = await send_rpc_request_to_eth_client(
        "http://127.0.0.1:3000/rpc",
        "eth_estimateUserOperationGas",
        [{
            "sender":"0xEed01c4FfA9f88096b77d2f16c2e143a94D71298",
            "nonce":"0x1",
            "initCode":"0x",
            "callData":"0x18dfb3c7000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001000000000000000000000000e7bc9b3a936f122f08aac3b1fac3c3ec29a78874000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000044a9059cbb00000000000000000000000026409e498023b57f5b10d6ce1677113e1326683c0000000000000000000000000000000000000000000000022b1c8c1227a0000000000000000000000000000000000000000000000000000000000000",
            "callGasLimit":"0x44",
            "verificationGasLimit":"0xffffff",
            "preVerificationGas":"0x18d08",
            "maxFeePerGas":"0x2b8f4e",
            "maxPriorityFeePerGas":"0x2b8f4e",
            "paymasterAndData":"0x",
            "signature":"0x22a1f0d5746116becb77cb47a047cd61a71c4e69defa945680e7b1e468d3297f34d4a343bec3289de1337d264beea73c6c78c35eb15beb1f250b5122ec5957691c"
        },
    "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789"],
    )
    assert result["error"]["message"] == 'AA20 account not deployed'