import json
from dataclasses import dataclass
from typing import Any

from aiohttp import ClientSession


async def send_rpc_request_to_eth_client(
    ethereum_node_url, method, params=None
) -> Any:
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
            ethereum_node_url,
            data=json.dumps(json_request),
            headers={"content-type": "application/json"},
        ) as response:
            resp = await response.read()
            return json.loads(resp)


async def get_latest_block_info(
        ethereum_node_url) -> tuple[str, int, str, int, str]:
    raw_res: Any = await send_rpc_request_to_eth_client(
        ethereum_node_url, "eth_getBlockByNumber", ["latest", False]
    )
    latest_block = raw_res["result"]

    latest_block_number = latest_block["number"]

    if "baseFeePerGas" in latest_block:
        latest_block_basefee = int(latest_block["baseFeePerGas"], 16)
    else:  # for block requested before the EIP-1559 upgrade
        latest_block_basefee = 0

    latest_block_gas_limit_hex = latest_block["gasLimit"]
    latest_block_timestamp = int(latest_block["timestamp"], 16)
    latest_block_hash = latest_block["hash"]

    return (
        latest_block_number,
        latest_block_basefee,
        latest_block_gas_limit_hex,
        latest_block_timestamp,
        latest_block_hash,
    )


@dataclass
class DebugEntityData:
    access: dict[str, dict[str, list[str]]]
    opcodes: dict[str, int]
    contract_size: dict[str, int]


@dataclass
class DebugTraceCallData:
    factory_data: DebugEntityData
    account_data: DebugEntityData
    paymaster_data: DebugEntityData
    keccak: list[str]
    logs: list
    calls: list
    debug: list


@dataclass
class Call:
    _to: str = ""
    _from: str = ""
    _type: str = ""
    _method: str = ""
    _value: str = ""
    _gas: str = ""
    _data: str = ""
    _gas_used: str = ""
    _return_type: str = ""  # RETURN or REVERT
