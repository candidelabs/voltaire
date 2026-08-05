import aiohttp
import asyncio
import logging
from voltaire_bundler.custom_types import Address
from voltaire_bundler.utils.eth_client_utils import \
        send_rpc_request_to_eth_client_no_retry


async def periodic_health_check_cron_job(
    node_urls_to_check: list[str],
    target_chain_id_hex: str,
    bundlers: list[Address],
    min_balance: int,
    interval: int
):
    while True:
        await periodic_health_check(
            node_urls_to_check,
            target_chain_id_hex,
            bundlers,
            min_balance,
        )
        await asyncio.sleep(interval)


async def periodic_health_check(
    node_urls_to_check: list[str],
    target_chain_id_hex: str,
    bundlers: list[Address],
    min_balance: int,
):
    nodes_success, _ = await check_nodes_health(
        node_urls_to_check, target_chain_id_hex)
    if nodes_success:
        await check_bundlers_balance(
            node_urls_to_check[0], bundlers, min_balance)


async def check_bundlers_balance(
    ethereum_node_url: str, bundlers: list[Address], min_balance: int
) -> tuple[bool, dict[str, dict[str, str]]]:
    """Check that every distinct bundler EOA holds at least ``min_balance``.
    Returns aggregate success plus a per-address result map so the /health
    endpoint can surface which EOA is short."""
    per_bundler: dict[str, dict[str, str]] = {}
    all_ok = True
    for bundler in bundlers:
        ok, result = await _check_single_bundler_balance(
            ethereum_node_url, bundler, min_balance)
        per_bundler[bundler] = result
        all_ok = all_ok and ok
    return all_ok, per_bundler


async def _check_single_bundler_balance(
    ethereum_node_url: str, bundler: Address, min_balance: int
) -> tuple[bool, dict[str, str]]:
    try:
        bundler_balance_res = await send_rpc_request_to_eth_client_no_retry(
            ethereum_node_url,
            "eth_getBalance",
            [bundler, "latest"],
        )
    except (aiohttp.ClientConnectionError, TimeoutError) as e:
        error_message = (
            f"Connection error for Eth node {ethereum_node_url} "
            f"for eth_getBalance: {e}"
        )
        logging.critical(error_message)
        return False, {"status": "ERROR", "message": error_message}
    except Exception:
        error_message = (
            f"Error when connecting to Eth node {ethereum_node_url} "
            f"for eth_getBalance"
        )
        logging.critical(error_message)
        return False, {"status": "ERROR", "message": error_message}

    if bundler_balance_res is None or "result" not in bundler_balance_res:
        error_message = f"eth_getBalance failed {ethereum_node_url}"
        logging.critical(error_message)
        return False, {"status": "ERROR", "message": error_message}

    bundler_balance = bundler_balance_res["result"]
    try:
        bundler_balance_int = int(bundler_balance, 16)
    except (ValueError, TypeError):
        # A misbehaving node can put anything in "result" (null, a number,
        # non-hex garbage); treat it as a failed check instead of letting
        # the exception kill the health-check cron loop.
        error_message = (
            f"eth_getBalance returned malformed balance "
            f"{bundler_balance!r} from {ethereum_node_url}"
        )
        logging.critical(error_message)
        return False, {"status": "ERROR", "message": error_message}
    if bundler_balance_int >= min_balance:
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
        logging.warning(error_message)
        return False, {"status": "ERROR", "message": error_message}


async def check_nodes_health(
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
        chain_id_hex = await send_rpc_request_to_eth_client_no_retry(
            ethereum_node_url,
            "eth_chainId",
            [],
        )
        if "result" not in chain_id_hex:
            return False, f"Invalid Eth node {ethereum_node_url}"
        else:
            if chain_id_hex["result"] == target_chain_id_hex.lower():
                return True, "eth_chainId successful"
            else:
                return False, (
                    f"Invalid chain id {chain_id_hex["result"]} returned by " +
                    f"{ethereum_node_url}"
                )

    except (aiohttp.ClientConnectionError, TimeoutError) as e:
        return False, f"Connection error for Eth node {ethereum_node_url}: {e}"
    except Exception:
        return False, f"Error when connecting to Eth node {ethereum_node_url}"
