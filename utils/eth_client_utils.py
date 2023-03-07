from aiohttp import ClientSession
import json
from eth_abi import decode


async def send_rpc_request_to_eth_client(geth_rpc_url, method, params=None):
    json_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }

    if params is not None:
        json_request["params"] = params
    async with ClientSession() as session:
        async with session.post(
            geth_rpc_url,
            data=json.dumps(json_request),
            headers={"content-type": "application/json"},
        ) as response:
            resp = await response.read()
            return json.loads(resp)
