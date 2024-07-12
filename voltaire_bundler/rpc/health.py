import aiohttp
import asyncio
import logging
from voltaire_bundler.typing import Address
from voltaire_bundler.utils.eth_client_utils import send_rpc_request_to_eth_client


async def periodic_health_check_cron_job(
    node_urls_to_check: list[str],
    target_chain_id_hex: str,
    bundler: Address,
    min_balance: int,
    interval: int
):
    while True:
        await periodic_health_check(
            node_urls_to_check,
            target_chain_id_hex,
            bundler,
            min_balance,
        )
        await asyncio.sleep(interval)


async def periodic_health_check(
    node_urls_to_check: list[str],
    target_chain_id_hex: str,
    bundler: Address,
    min_balance: int,
):
    nodes_success, _ = await check_node_health(
        node_urls_to_check, target_chain_id_hex)
    if nodes_success:
        await check_bundler_balance(
            node_urls_to_check[0], bundler, min_balance)


async def check_bundler_balance(
    ethereum_node_url: str, bundler: Address, min_balance: int
) -> tuple[bool, dict]:
    bundler_balance_res = await send_rpc_request_to_eth_client(
        ethereum_node_url,
        "eth_getBalance",
        [bundler, "latest"],
    )
    if "result" not in bundler_balance_res:
        error_message = f"eth_getBalance failed {ethereum_node_url}"
        logging.critical(error_message)
        return False, {
                "status": "ERROR",
                "message": error_message
            }
    else:
        bundler_balance = bundler_balance_res["result"]
        if int(bundler_balance, 16) >= min_balance:
            return True, {
                "status": "OK",
                "message": (
                    f"Bundler {bundler} balance {bundler_balance}" +
                    f" is equal or more than minimum balance {hex(min_balance)}"
                 )
            }
        else:
            error_message = (
                f"Bundler {bundler} balance {bundler_balance}" +
                f" is less than minimum balance {hex(min_balance)}"
            )

            error_dict = {
                "status": "ERROR",
                "message": error_message
            }

            logging.warning(error_message)
            return False, error_dict


async def check_node_health(
    node_urls_to_check: list[str],
    target_chain_id_hex: str,
) -> tuple[bool, dict]:
    all_ok = True
    results = dict()
    for node_url in node_urls_to_check:
        success, message = await check_live_ethereum_rpc(
                node_url, target_chain_id_hex)

        if success:
            results[node_url] = {"status": "OK", "message": message}
        else:
            logging.critical(message)
            all_ok = False
            results[node_url] = {"status": "ERROR", "message": message}

    return all_ok, results


async def check_live_ethereum_rpc(
    ethereum_node_url: str, target_chain_id_hex: str
) -> tuple[bool, str]:
    try:
        chain_id_hex = await send_rpc_request_to_eth_client(
            ethereum_node_url,
            "eth_chainId",
            [],
        )
        if "result" not in chain_id_hex:
            return False, f"Invalide Eth node {ethereum_node_url}"
        else:
            if chain_id_hex["result"] == target_chain_id_hex.lower():
                return True, "eth_chainId successful"
            else:
                return False, (
                    f"Invalide chain id {chain_id_hex["result"]} returned by " +
                    f"{ethereum_node_url}"
                )

    except aiohttp.client_exceptions.ClientConnectorError:
        return False, f"Connection refused for Eth node {ethereum_node_url}"
    except Exception:
        return False, f"Error when connecting to Eth node {ethereum_node_url}"
