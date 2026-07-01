from abc import ABC
import asyncio
from functools import cache
import logging
from functools import reduce

from eth_abi import encode, decode
from voltaire_bundler.bundle.exceptions import UserOpReceiptFoundException
from voltaire_bundler.mempool.sender_mempool import VerifiedUserOperation
from voltaire_bundler.custom_types import Address
from voltaire_bundler.utils.cache import PersistentFIFOCache
from voltaire_bundler.utils.eth_client_utils import \
        send_rpc_request_to_eth_client
from voltaire_bundler.utils import latest_block_cache
from typing import Any
from ..gas.gas_manager import GasManager
from .models import (Log, ReceiptInfo, UserOperationReceiptInfo)


HANDLE_OPS_SELECTOR_V6 = "0x1fad948c"
HANDLE_OPS_SELECTOR_V7V8V9 = "0x765e827f"


class UserOperationHandler(ABC):
    ethereum_node_urls: list[str]
    bundler_address: Address
    is_legacy_mode: bool
    ethereum_node_eth_get_logs_urls: list[str]
    gas_manager: GasManager
    logs_incremental_range: int
    logs_number_of_ranges: int
    logs_fallback_recent_window: int

    async def _find_handle_ops_calldata(
        self,
        transaction_hash: str,
        transaction_input: str,
        handle_ops_selector: str,
        entrypoint: str,
    ) -> str:
        """Return the handleOps calldata from a transaction.

        Fast path: if transaction_input starts with the expected selector,
        return it directly.

        Fallback: call trace_transaction to walk the call trace and find
        the internal call to ``entrypoint`` whose input starts with the
        selector.
        """
        if transaction_input.startswith(handle_ops_selector):
            return transaction_input

        logging.info(
            f"Transaction {transaction_hash} input does not start "
            f"with {handle_ops_selector}, tracing to find internal "
            "handleOps call."
        )

        params = [transaction_hash]
        res: Any = await send_rpc_request_to_eth_client(
            self.ethereum_node_urls,
            "trace_transaction",
            params,
        )

        if "result" not in res:
            error_msg = str(res.get("error", res))
            raise ValueError(
                f"trace_transaction failed for "
                f"{transaction_hash}: {error_msg}"
            )

        trace = res["result"]
        calldata = _find_handle_ops_input_in_trace(
            trace, handle_ops_selector, entrypoint
        )
        if calldata is None:
            raise ValueError(
                f"No internal call with selector "
                f"{handle_ops_selector} found in trace "
                f"for transaction {transaction_hash}"
            )

        return calldata

    async def get_user_operation_receipt(
        self, user_operation_hash: str,
        entrypoint: str,
        validated_at_block_hex: str | None
    ) -> tuple[ReceiptInfo, UserOperationReceiptInfo] | None:
        event_log_info = await self.get_user_operation_event_log_info(
            user_operation_hash, entrypoint, validated_at_block_hex
        )
        if event_log_info is None:
            return None
        (
            log_object,
            userOpHash,
            sender,
            paymaster,
            nonce,
            success,
            actualGasCost,
            actualGasUsed,
            logs,
        ) = event_log_info

        transaction = await self.get_transaction_receipt(
                log_object.transactionHash)

        if transaction is None:  # pending — caller will retry
            return None

        if "effectiveGasPrice" in transaction:
            effective_gas_price = transaction["effectiveGasPrice"]
        else:
            effective_gas_price = "0x"

        receiptInfo = ReceiptInfo(
            transactionHash=transaction["transactionHash"],
            transactionIndex=log_object.transactionIndex,
            blockHash=transaction["blockHash"],
            blockNumber=transaction["blockNumber"],
            _from=transaction["from"],
            to=transaction["to"],
            cumulativeGasUsed=transaction["cumulativeGasUsed"],
            gasUsed=transaction["gasUsed"],
            contractAddress=transaction["contractAddress"],
            logs=transaction["logs"],
            logsBloom=transaction["logsBloom"],
            # root=transaction['root'],
            status=transaction["status"],
            effectiveGasPrice=effective_gas_price,
        )
        if not self.is_legacy_mode:
            receiptInfo.effectiveGasPrice = transaction["effectiveGasPrice"]

        userOperationReceiptInfo = UserOperationReceiptInfo(
            userOpHash=userOpHash,
            sender=sender,
            paymaster=paymaster,
            nonce=nonce,
            success=success,
            actualGasCost=actualGasCost,
            actualGasUsed=actualGasUsed,
            logs=logs,
            receipt=receiptInfo,
        )

        return receiptInfo, userOperationReceiptInfo

    async def get_user_operation_receipt_rpc(
        self,
        user_operation_hash: str,
        entrypoint: str,
        validated_at_block_hex: str | None,
    ) -> dict | None:
        user_operation_receipt = await self.get_user_operation_receipt(
            user_operation_hash, entrypoint, validated_at_block_hex
        )

        if user_operation_receipt is None:
            return None
        (
            receipt_info,
            user_operation_receipt_info,
        ) = user_operation_receipt

        receipt_info_json = {
            "blockHash": receipt_info.blockHash,
            "blockNumber": receipt_info.blockNumber,
            "from": receipt_info._from,
            "cumulativeGasUsed": receipt_info.cumulativeGasUsed,
            "gasUsed": receipt_info.gasUsed,
            "logs": receipt_info.logs,
            "logsBloom": receipt_info.logsBloom,
            "transactionHash": receipt_info.transactionHash,
            "transactionIndex": receipt_info.transactionIndex,
        }

        if not self.is_legacy_mode:
            gas_info = {"effectiveGasPrice": receipt_info.effectiveGasPrice}
            receipt_info_json.update(gas_info)

        user_operation_receipt_rpc_json = {
            "userOpHash": user_operation_receipt_info.userOpHash,
            "entryPoint": entrypoint,
            "sender": user_operation_receipt_info.sender,
            "nonce": hex(user_operation_receipt_info.nonce),
            "paymaster": user_operation_receipt_info.paymaster,
            "actualGasCost": user_operation_receipt_info.actualGasCost,
            "actualGasUsed": user_operation_receipt_info.actualGasUsed,
            "success": user_operation_receipt_info.success,
            "logs": user_operation_receipt_info.logs,
            "receipt": receipt_info_json,
        }
        raise UserOpReceiptFoundException(user_operation_receipt_rpc_json)

    async def get_user_operation_event_log_info(
        self, user_operation_hash: str,
        entrypoint: str,
        validated_at_block_hex: str | None
    ) -> tuple | None:
        logs: Any = await self.get_user_operation_logs(
            user_operation_hash,
            entrypoint,
            validated_at_block_hex,
            self.logs_incremental_range,
            self.logs_number_of_ranges,
        )
        if logs is None:
            return None
        log = logs[0]

        log_object = Log(
            removed=log.get("removed", False),
            logIndex=log["logIndex"],
            transactionIndex=log["transactionIndex"],
            transactionHash=log["transactionHash"],
            blockHash=log["blockHash"],
            blockNumber=log["blockNumber"],
            address=log["address"],
            data=log["data"],
            topics=log["topics"],
        )

        topics = log["topics"]
        data = log["data"]

        userOpHash = topics[1]
        sender = decode(["address"], bytes.fromhex(topics[2][2:]))[0]
        paymaster = decode(["address"], bytes.fromhex(topics[3][2:]))[0]

        data_abi = ["uint256", "bool", "uint256", "uint256"]
        decode_result = decode(data_abi, bytes.fromhex(data[2:]))
        nonce = decode_result[0]
        success = decode_result[1]
        actualGasCost = hex(decode_result[2])
        actualGasUsed = hex(decode_result[3])

        return (
            log_object,
            userOpHash,
            sender,
            paymaster,
            nonce,
            success,
            actualGasCost,
            actualGasUsed,
            logs,
        )

    async def get_transaction_receipt(
        self, transaction_hash: str
    ) -> dict | None:
        cached = await transaction_receipts_cache.get(transaction_hash)
        if cached is not None:
            return cached

        params = [transaction_hash]
        # Same safety net as eth_getLogs: cap wall time and swallow every
        # error mode (timeout, network error, non-standard response shape,
        # RPC-level error after retries). A missed receipt is just a "not
        # yet confirmed" signal to the caller; nothing here should bubble
        # up and fail the RPC handler.
        try:
            res = await asyncio.wait_for(
                send_rpc_request_to_eth_client(
                    self.ethereum_node_urls, "eth_getTransactionReceipt",
                    params, None, "result",
                ),
                timeout=ETH_RPC_LOOKUP_TIMEOUT_S,
            )
            # Same guard as get_transaction_by_hash: even with
            # expected_key="result", the RPC layer can return a response
            # whose error code short-circuits the retry (-32000, -32603,
            # etc.) and leaves us with only "error". Surface that as a
            # miss with a useful log line instead of a KeyError.
            if "result" not in res:
                if "error" in res:
                    logging.error(
                        "eth_getTransactionReceipt(%s) failed. error: %s",
                        transaction_hash, str(res["error"]),
                    )
                else:
                    logging.error(
                        "eth_getTransactionReceipt(%s) failed. response: %s",
                        transaction_hash, str(res),
                    )
                return None
            transaction = res["result"]
            if (  # pending or missing receipt — don't cache, let the caller retry
                transaction is None or
                transaction.get("blockNumber") is None or
                transaction.get("transactionHash") is None or
                transaction.get("transactionIndex") is None or
                "blockHash" not in transaction
            ):
                return None

            trimmed = {
                field: transaction[field]
                for field in TRANSACTION_RECEIPT_CACHED_FIELDS
                if field in transaction
            }
            transaction_receipts_cache.set(transaction_hash, trimmed)
            return trimmed
        except asyncio.TimeoutError:
            logging.error(
                "eth_getTransactionReceipt(%s) timed out after %ss; "
                "treating as miss",
                transaction_hash, ETH_RPC_LOOKUP_TIMEOUT_S,
            )
            return None
        except Exception:
            logging.error(
                "eth_getTransactionReceipt(%s) failed; treating as miss",
                transaction_hash, exc_info=True,
            )
            return None

    async def get_user_operation_logs(
        self,
        user_operation_hash: str,
        entrypoint: str,
        validated_at_block_hex: str | None,
        logs_incremental_range: int,
        logs_number_of_ranges: int,
    ):
        if logs_incremental_range > 0:
            # Route the chain-head lookup through latest_block_cache so a
            # burst of concurrent eth_getUserOperationReceipt / ByHash polls
            # (each fanning out across v6/v7/v8/v9 EPs) doesn't translate to
            # one eth_getBlockByNumber per (poll x EP) against the node.
            # Validation publishes the head into the same cache, so under
            # any inbound sendUserOperation load this returns cached.
            cached_latest = await latest_block_cache.get_or_fetch(
                self.ethereum_node_eth_get_logs_urls,
            )
            if cached_latest is None:
                # Cache miss + RPC failure — preserve the previous failure
                # mode (caller treats None as "no logs found") rather than
                # crashing with TypeError below.
                return None
            latest_block_number = cached_latest
            if validated_at_block_hex is None:
                earliest_block_number = latest_block_number - (
                    logs_incremental_range * logs_number_of_ranges)
            else:
                validated_at_block_number = int(validated_at_block_hex, 16)
                if latest_block_number - validated_at_block_number > logs_incremental_range:
                    earliest_block_number = latest_block_number - (
                        logs_incremental_range * logs_number_of_ranges)
                    if earliest_block_number < validated_at_block_number:
                        earliest_block_number = validated_at_block_number
                else:
                    earliest_block_number = validated_at_block_number

            # Clamp into [0, latest_block_number]. Upper-clamp guards
            # against the validation RPC being ahead of the logs RPC
            # (e.g. multi-node setup where the logs endpoint is
            # mid-sync) — without it, validated > latest would produce
            # an empty range() below and we'd return None without
            # making a single eth_getLogs call, even though the logs
            # node may catch up in the next millisecond.
            earliest_block_number = max(
                0, min(earliest_block_number, latest_block_number),
            )
            # range stop is exclusive; bumping by 1 makes the final iteration
            # include latest_block_number, which is otherwise dropped when
            # validated_at_block_hex == latest (a common poll-just-after-
            # inclusion case where the head block would yield no eth_getLogs).
            for earliest_block in range(earliest_block_number,
                                        latest_block_number + 1,
                                        logs_incremental_range):
                # Clamp toBlock to the chain head. Without this, the final
                # iteration requests earliest_block + logs_incremental_range,
                # which overshoots latest_block_number by up to one full
                # window — a toBlock that isn't on-chain yet. Tolerant nodes
                # silently clamp it to head; stricter ones (and multi-node
                # setups where the logs endpoint lags the head read) reject it
                # with "missing block data", spamming errors and making
                # eth_getUserOperationReceipt miss freshly included userops.
                # eth_getLogs is inclusive on both ends, so a [head, head]
                # window is a valid single-block query and loses no coverage.
                latest_block = min(
                    earliest_block + logs_incremental_range,
                    latest_block_number,
                )
                if latest_block < earliest_block:
                    break
                res = await get_user_operation_logs_for_block_range(
                    self.ethereum_node_eth_get_logs_urls,
                    user_operation_hash,
                    entrypoint,
                    hex(earliest_block),
                    hex(latest_block),
                    self.logs_fallback_recent_window,
                )
                if res is not None:
                    return res
            return None
        else:
            if validated_at_block_hex is not None:
                earliest_block_hex = validated_at_block_hex
            else:
                earliest_block_hex = "earliest"

            return await get_user_operation_logs_for_block_range(
                self.ethereum_node_eth_get_logs_urls,
                user_operation_hash,
                entrypoint,
                earliest_block_hex,
                "latest",
                self.logs_fallback_recent_window,
            )

    def get_user_operation_by_hash_from_local_mempool(
        self,
        user_operation_hash: str,
        entrypoint: str,
        senders_mempools,
    ) -> dict | None:
        user_operation_hashs_to_verified_user_operation: dict[
            str, VerifiedUserOperation
        ] = reduce(lambda a, b: a | b, map(
                lambda sender_mempool: sender_mempool.user_operation_hashs_to_verified_user_operation,
                senders_mempools),
            dict(),
        )
        if user_operation_hash in user_operation_hashs_to_verified_user_operation:
            user_operation_by_hash_json = {
                "userOperation": user_operation_hashs_to_verified_user_operation[
                    user_operation_hash
                ].user_operation.get_user_operation_json(),
                "entryPoint": entrypoint,
                "blockNumber": None,
                "blockHash": None,
                "transactionHash": None,
            }
            return user_operation_by_hash_json
        else:
            return None


def _find_handle_ops_input_in_trace(
    trace: Any,
    handle_ops_selector: str,
    entrypoint: str,
) -> str | None:
    """Walk a trace_transaction result to find a call to ``entrypoint``
    whose input starts with the given handleOps selector.
    Returns the input string or None."""
    entrypoint_lower = entrypoint.lower()
    if isinstance(trace, list):
        for entry in trace:
            action = entry.get("action", {})
            to_addr = action.get("to", "")
            input_data = action.get("input", "")
            if (
                to_addr.lower() == entrypoint_lower
                and input_data.startswith(handle_ops_selector)
            ):
                return input_data
    return None


async def get_deposit_info(
    address: Address, entrypoint: Address, node_urls: list[str]
) -> tuple[int, bool, int, int, int]:
    function_selector = "0x5287ce12"  # getDepositInfo
    params = encode(["address"], [address])

    call_data = function_selector + params.hex()

    params = [
        {
            "to": entrypoint,
            "data": call_data,
        },
        "latest",
    ]

    result: Any = await send_rpc_request_to_eth_client(
        node_urls, "eth_call", params, None, "result"
    )
    if "result" in result:
        (deposit, staked, stake, unstake_delay_sec, withdraw_time) = decode(
            ["(uint256,bool,uint112,uint32,uint48)"],
            bytes.fromhex(result["result"][2:])
        )[0]
        return deposit, staked, stake, unstake_delay_sec, withdraw_time
    else:
        logging.critical("balanceOf eth_call failed")
        if "error" in result:
            error = str(result["error"])
            raise ValueError(f"balanceOf eth_call failed - {error}")
        else:
            raise ValueError("balanceOf eth_call failed")

# Composite-key cache: "{entrypoint_lowercase}:{userOpHash}" -> eth_getLogs result.
# Flattens the previous per-entrypoint nested dict (which also had a broken
# eviction path: ``logs_cache = {}`` rebound a local, never the outer dict).
user_operation_logs_cache = PersistentFIFOCache(name="user_operation_logs")

# Wall-clock budget for a single RPC lookup against an Ethereum node
# (eth_getLogs / eth_getTransactionReceipt / eth_getTransactionByHash).
# The shared RPC helper retries up to 60× with 1 s sleeps and a 60 s
# per-attempt aiohttp timeout, which can stretch a single lookup into
# minutes on a slow or misbehaving node. Capping here means a hash lookup
# degrades to "miss" quickly instead of stalling the RPC handler.
#
# Operators on a slow or remote RPC provider that legitimately needs more
# than 2 s per call: bump this constant. It isn't surfaced as a CLI/env
# knob yet; promote it if more than one deployment ends up patching it.
ETH_RPC_LOOKUP_TIMEOUT_S = 2.0

# When the caller asks for ``fromBlock="earliest"``, try a narrower recent
# window first. The vast majority of getUserOperationByHash/Receipt calls
# are clients polling a userop submitted seconds ago, which lives well
# within this window — and many nodes either time out or return invalid
# responses for a full-history eth_getLogs scan.
#
# Default size of that probe window when the caller doesn't pass an
# explicit value. The CLI surfaces this as --logs_fallback_recent_window;
# handler-driven calls override it with the operator-configured value.
EARLIEST_FALLBACK_RECENT_WINDOW = 5_000

# Maximum number of blocks per single eth_getLogs call in the coalesced
# monitor-sweep helper. Most providers cap eth_getLogs at either a block-
# range limit (Alchemy: 500, Infura: 1000) or a response-size limit
# (~10k logs). 1000 blocks is the widest range that fits both without
# triggering provider errors; wider ranges are split into parallel chunks.
COALESCED_LOGS_CHUNK_BLOCKS = 1_000

# Maximum number of chunk requests in flight at once. Prevents a post-
# restart backfill spanning tens of thousands of blocks from fanning
# out into 100+ parallel eth_getLogs calls, which would trip provider
# 429s and starve the per-method outbound semaphore queue for every
# other RPC (validation, eth_getTransactionCount, etc.).
COALESCED_LOGS_MAX_CONCURRENT_CHUNKS = 8

# Maximum number of userOpHash values in a single eth_getLogs topics[1]
# OR-filter. JSON-RPC supports an array of values per topic slot, so we
# can ask the node to return only the userops we're actively monitoring
# instead of every UserOperationEvent in the block range. Alchemy is the
# strictest popular provider here (~10 entries per slot); Infura and
# QuickNode are more generous. Stay at 10 for portability; larger
# monitor sets fan out into multiple parallel calls (bounded by the
# chunk semaphore above).
COALESCED_LOGS_MAX_HASHES_PER_FILTER = 10

# Whether the userop-logs cache reorg revalidation runs on every cache
# hit (one eth_getBlockByNumber per poll to confirm the cached block is
# still canonical). Off by default — on a busy bundler the per-poll RPC
# overhead outweighs the rare correctness win, and the monitor sweep
# evicts stale entries on its own cadence. Toggled from cli_manager at
# startup via --enable_logs_reorg_check.
ENABLE_LOGS_REORG_CHECK = False


def del_user_operation_logs_cache_entry(
    user_operation_hash: str,
    entrypoint: str,
) -> None:
    user_operation_logs_cache.delete(
        f"{entrypoint.lower()}:{user_operation_hash.lower()}"
    )


USER_OPERATION_EVENT_DESCRIPTOR = (
    "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f"
)


async def _eth_getLogs_once(
    ethereum_node_eth_get_logs_urls: list[str],
    user_operation_hash: str,
    entrypoint: str,
    from_block_hex: str,
    to_block_hex: str,
) -> list | None:
    """Single eth_getLogs round trip with timeout + broad safety.
    Returns the logs list on a non-empty hit, ``None`` on miss or any failure
    (timeout, network error, non-standard response shape, RPC-level error
    after retries). Nothing here bubbles up — the caller decides whether to
    retry with a different range or fall through to "not found"."""
    params = [
        {
            "address": entrypoint,
            "topics": [
                USER_OPERATION_EVENT_DESCRIPTOR,
                user_operation_hash,
            ],
            "fromBlock": from_block_hex,
            "toBlock": to_block_hex,
        }
    ]
    try:
        res = await asyncio.wait_for(
            send_rpc_request_to_eth_client(
                ethereum_node_eth_get_logs_urls, "eth_getLogs", params,
            ),
            timeout=ETH_RPC_LOOKUP_TIMEOUT_S,
        )
        if (
            isinstance(res, dict)
            and isinstance(res.get("result"), list)
            and len(res["result"]) > 0
        ):
            return res["result"]
        return None
    except asyncio.TimeoutError:
        logging.error(
            "eth_getLogs (%s -> %s) timed out after %ss; treating as miss",
            from_block_hex, to_block_hex, ETH_RPC_LOOKUP_TIMEOUT_S,
        )
        return None
    except Exception:
        logging.error(
            "eth_getLogs (%s -> %s) failed; treating as miss",
            from_block_hex, to_block_hex, exc_info=True,
        )
        return None


async def _cached_logs_block_still_canonical(
    ethereum_node_urls: list[str],
    cached_logs: list,
) -> bool:
    """Confirm the cached log set's block is still on the canonical chain.

    The userop-logs cache is keyed by ``entrypoint:userOpHash``. After a
    reorg the same userop hash can land in a different block, but a hit
    in the cache would otherwise return the orphaned block's logs forever
    (the cache key never changes). One ``eth_getBlockByNumber`` per cache
    hit is cheap relative to the eth_getLogs scan it shields, and
    eth_getBlockByNumber always returns the canonical block at that
    height — so a hash mismatch is a definitive reorg signal.

    Returns False on reorg, on the block disappearing, on a malformed
    cached payload, and on any RPC failure (so the caller drops the
    entry and re-fetches rather than serving stale data)."""
    if not cached_logs:
        return False
    first = cached_logs[0]
    if not isinstance(first, dict):
        return False
    block_hash = first.get("blockHash")
    block_number = first.get("blockNumber")
    if not isinstance(block_hash, str) or not isinstance(block_number, str):
        return False
    try:
        res = await asyncio.wait_for(
            send_rpc_request_to_eth_client(
                ethereum_node_urls,
                "eth_getBlockByNumber",
                [block_number, False],
            ),
            timeout=ETH_RPC_LOOKUP_TIMEOUT_S,
        )
    except asyncio.TimeoutError:
        logging.warning(
            "eth_getBlockByNumber(%s) timed out during reorg revalidation; "
            "treating cached userop-logs entry as stale",
            block_number,
        )
        return False
    except Exception:
        logging.warning(
            "eth_getBlockByNumber(%s) failed during reorg revalidation; "
            "treating cached userop-logs entry as stale",
            block_number, exc_info=True,
        )
        return False
    if not isinstance(res, dict):
        return False
    result = res.get("result")
    if not isinstance(result, dict):
        return False
    return result.get("hash") == block_hash


async def _fetch_latest_block_number(
    ethereum_node_urls: list[str],
) -> int | None:
    """Return a recent chain-head block number as int, or ``None`` on
    failure. Reuses validation's already-observed head when fresh (<=2s
    old) instead of issuing its own eth_getBlockByNumber; falls back to a
    real RPC when the cache is stale. Same total exception safety as the
    eth_getLogs path; used to size the recent-window fallback below."""
    return await latest_block_cache.get_or_fetch(ethereum_node_urls)


async def get_user_operation_logs_for_block_range(
    ethereum_node_eth_get_logs_urls: list[str],
    user_operation_hash: str,
    entrypoint: str,
    from_block_hex: str,
    to_block_hex: str,
    earliest_fallback_recent_window: int = EARLIEST_FALLBACK_RECENT_WINDOW,
) -> list | None:
    # Both halves are lowercased to match the writer in
    # get_user_operation_logs_for_many_hashes (which derives the userop
    # hash from topics[1].lower()); without it, a client polling with a
    # checksummed/mixed-case hash misses the warmed entry.
    cache_key = f"{entrypoint.lower()}:{user_operation_hash.lower()}"
    cached = await user_operation_logs_cache.get(cache_key)
    if cached is not None:
        if not ENABLE_LOGS_REORG_CHECK:
            # Reorg revalidation off (default): trust the cache. Eviction
            # is opportunistic — only del_user_operation_logs_cache_entry
            # (called from get_user_operation_receipt when the cached
            # log's tx hash returns null from eth_getTransactionReceipt)
            # removes stale entries. A reorged-out userop that no one
            # ever polls stays cached; turn on --enable_logs_reorg_check
            # for end-user-facing setups on reorg-prone chains.
            return cached
        if await _cached_logs_block_still_canonical(
            ethereum_node_eth_get_logs_urls, cached,
        ):
            return cached
        # Cached block was reorged out (or revalidation failed). Drop the
        # entry so we don't keep serving stale data, then fall through to
        # the fresh eth_getLogs path below.
        user_operation_logs_cache.delete(cache_key)

    # If the caller asked for the whole chain, first probe the last
    # ``earliest_fallback_recent_window`` blocks — that covers the
    # typical "client polling a freshly submitted userop" pattern at a
    # fraction of the wide-scan cost. Fall through to the full "earliest"
    # scan only if the narrow window misses.
    if from_block_hex == "earliest":
        latest = await _fetch_latest_block_number(
            ethereum_node_eth_get_logs_urls,
        )
        if latest is not None:
            window_from = hex(
                max(0, latest - earliest_fallback_recent_window)
            )
            result = await _eth_getLogs_once(
                ethereum_node_eth_get_logs_urls,
                user_operation_hash, entrypoint,
                window_from, to_block_hex,
            )
            if result is not None:
                user_operation_logs_cache.set(cache_key, result)
                return result

    result = await _eth_getLogs_once(
        ethereum_node_eth_get_logs_urls,
        user_operation_hash, entrypoint,
        from_block_hex, to_block_hex,
    )
    if result is not None:
        user_operation_logs_cache.set(cache_key, result)
        return result
    return None


async def get_user_operation_logs_for_many_hashes(
    ethereum_node_eth_get_logs_urls: list[str],
    user_operation_hashes: list[str],
    entrypoint: str,
    from_block_hex: str,
    to_block_hex: str = "latest",
) -> dict[str, list[Any]]:
    """One eth_getLogs across the entire monitored set, indexed by userop hash.

    Instead of N parallel eth_getLogs (one per monitored userop, each filtered
    to that userop's hash topic), issue a single broad query covering the
    UserOperationEvent topic on the entrypoint for the full block range, then
    bucket the results client-side by topic[1] (userOpHash).

    Each hit is also written through to the per-userop logs cache so the
    eth_getUserOperationByHash / Receipt RPCs served to clients hit cache
    instead of re-issuing eth_getLogs.

    Returns ``{userop_hash: [log_entry]}`` for hashes present in the result;
    misses are absent from the dict (callers check membership).
    """
    if not user_operation_hashes:
        return {}

    wanted = {h.lower() for h in user_operation_hashes}

    # Resolve "latest" to a concrete block so the chunking below has a
    # known upper bound. On failure, fall back to a single unchunked
    # request — the helper is best-effort and the caller treats all
    # misses as "still pending".
    if to_block_hex == "latest":
        latest_block = await latest_block_cache.get_or_fetch(
            ethereum_node_eth_get_logs_urls,
        )
        to_block_int = latest_block
    else:
        try:
            to_block_int = int(to_block_hex, 16)
        except (TypeError, ValueError):
            to_block_int = None
    try:
        from_block_int = int(from_block_hex, 16) if from_block_hex != "earliest" else 0
    except (TypeError, ValueError):
        from_block_int = None

    if to_block_int is None or from_block_int is None:
        # Couldn't resolve bounds (e.g. transient latest_block_cache
        # failure). Fall back to a single call with the original strings
        # and let the node decide — better than swallowing the round.
        chunks = [(from_block_hex, to_block_hex)]
    elif to_block_int < from_block_int:
        # latest_block_cache returned a stale head older than the userop's
        # validation block. Issuing a backwards-range eth_getLogs is a
        # provider error / empty-result depending on the node; skip the
        # sweep cleanly so the next tick can retry once the cache catches
        # up. Don't fall back to "latest" — that re-introduces the
        # provider-block-range-cap bug 44842a0 was added to fix.
        logging.debug(
            "coalesced eth_getLogs skipped: stale latest_block_cache "
            "(from=%s > to=%s); next tick will retry",
            hex(from_block_int), hex(to_block_int),
        )
        return {}
    else:
        # Always pin the call to the resolved upper bound (hex(to_block_int)),
        # NOT the original "latest" string. If we passed "latest", the node
        # would interpret it against its own head — and on fast chains
        # (Arbitrum's 250ms blocks vs the cache's TTL) the cached head can
        # be several blocks behind real head, tipping a "fits in 1000"
        # decision into a wider node-side range and triggering provider
        # block-range caps.
        # eth_getLogs is inclusive on both ends: the span
        # [from_block_int, to_block_int] covers (to - from + 1) blocks.
        # Compare against (chunk_size - 1) so the single-chunk path
        # enforces the same 1000-block cap as the multi-chunk path
        # (which uses chunk_end = cursor + chunk_size - 1).
        if to_block_int - from_block_int <= COALESCED_LOGS_CHUNK_BLOCKS - 1:
            chunks = [(hex(from_block_int), hex(to_block_int))]
        else:
            # Split into parallel chunks of COALESCED_LOGS_CHUNK_BLOCKS each.
            # eth_getLogs is inclusive on both ends, so adjacent chunks must
            # not overlap — use a stride equal to the chunk size and a
            # toBlock of (start + chunk_size - 1).
            chunks = []
            cursor = from_block_int
            while cursor <= to_block_int:
                chunk_end = min(cursor + COALESCED_LOGS_CHUNK_BLOCKS - 1, to_block_int)
                chunks.append((hex(cursor), hex(chunk_end)))
                cursor = chunk_end + 1

    # Split the wanted-hashes set into provider-portable batches and
    # cross-product with the block-range chunks. Each (block_chunk,
    # hash_batch) becomes one eth_getLogs call with both filters applied
    # — the node returns ONLY the userops we care about in that range.
    # On a typical busy mainnet EP this replaces "fetch every
    # UserOperationEvent in the range" with "fetch only the K we
    # actually monitor", collapsing multi-MB responses to bytes.
    wanted_list = sorted(wanted)  # deterministic batch boundaries help debugging
    hash_batches: list[list[str]] = [
        wanted_list[i:i + COALESCED_LOGS_MAX_HASHES_PER_FILTER]
        for i in range(0, len(wanted_list), COALESCED_LOGS_MAX_HASHES_PER_FILTER)
    ]
    work: list[tuple[str, str, list[str]]] = [
        (cf, ct, batch)
        for (cf, ct) in chunks
        for batch in hash_batches
    ]

    chunk_semaphore = asyncio.Semaphore(COALESCED_LOGS_MAX_CONCURRENT_CHUNKS)

    async def _one_chunk(cf: str, ct: str, hashes: list[str]) -> list[Any]:
        async with chunk_semaphore:
            params = [
                {
                    "address": entrypoint,
                    # topics[1] is an OR-match over the listed userOpHashes;
                    # the node returns only logs matching at least one.
                    "topics": [USER_OPERATION_EVENT_DESCRIPTOR, hashes],
                    "fromBlock": cf,
                    "toBlock": ct,
                }
            ]
            try:
                res = await asyncio.wait_for(
                    send_rpc_request_to_eth_client(
                        ethereum_node_eth_get_logs_urls, "eth_getLogs", params,
                    ),
                    timeout=ETH_RPC_LOOKUP_TIMEOUT_S,
                )
            except asyncio.TimeoutError:
                logging.error(
                    "coalesced eth_getLogs (%s -> %s, %d hashes) timed out after %ss; "
                    "treating chunk as miss",
                    cf, ct, len(hashes), ETH_RPC_LOOKUP_TIMEOUT_S,
                )
                return []
            except Exception:
                logging.error(
                    "coalesced eth_getLogs (%s -> %s) failed; treating chunk as miss",
                    cf, ct, exc_info=True,
                )
                return []
            if not (isinstance(res, dict) and isinstance(res.get("result"), list)):
                return []
            return res["result"]

    chunk_results = await asyncio.gather(
        *(_one_chunk(cf, ct, batch) for cf, ct, batch in work)
    )

    found: dict[str, list[Any]] = {}
    for chunk_logs in chunk_results:
        for log_entry in chunk_logs:
            topics = log_entry.get("topics") or []
            if len(topics) < 2:
                continue
            userop_hash = topics[1].lower()
            if userop_hash in wanted:
                found.setdefault(userop_hash, []).append(log_entry)

    # Warm the per-userop logs cache for each hit so the client's next
    # getUserOperationByHash/Receipt poll hits memory/disk instead of
    # re-issuing eth_getLogs.
    ep_lower = entrypoint.lower()
    for userop_hash, log_list in found.items():
        user_operation_logs_cache.set(
            f"{ep_lower}:{userop_hash}", log_list,
        )

    # Return keys matched to the caller's casing so callers can look up by
    # the same hash string they passed in.
    by_caller_hash: dict[str, list[Any]] = {}
    for h in user_operation_hashes:
        hit = found.get(h.lower())
        if hit is not None:
            by_caller_hash[h] = hit
    return by_caller_hash


transactions_cache = PersistentFIFOCache(name="transactions")


# Only the fields the two callers (``get_user_operation_by_hash`` in v6 and
# v7v8v9) actually read. Trimming the rest (gas/gasPrice/v/r/s/accessList/
# nonce/value/chainId/etc.) keeps disk + RAM footprint down without losing
# anything we'd ever use.
TRANSACTION_CACHED_FIELDS = (
    "blockHash",
    "blockNumber",
    "input",
)


TRANSACTION_RECEIPT_CACHED_FIELDS = (
    "blockHash",
    "blockNumber",
    "transactionHash",
    "transactionIndex",
    "from",
    "to",
    "cumulativeGasUsed",
    "gasUsed",
    "contractAddress",
    "logs",
    "logsBloom",
    "status",
    "effectiveGasPrice",
)

transaction_receipts_cache = PersistentFIFOCache(name="transaction_receipts")


async def get_transaction_by_hash(
    ethereum_node_urls: list[str],
    transaction_hash: str,
    recursion_depth: int = 0
) -> dict | None:
    recursion_depth = recursion_depth + 1
    if recursion_depth > 100:
        # this shouldn't happen
        logging.error("get_transaction_by_hash recursion too deep.")
        return None

    cached = await transactions_cache.get(transaction_hash)
    if cached is not None:
        return cached
    params = [transaction_hash]
    # Same safety net as eth_getLogs/eth_getTransactionReceipt: cap wall
    # time and treat any failure as a miss. The pending-tx retry loop
    # below still runs on its own 1 s cadence.
    try:
        res: Any = await asyncio.wait_for(
            send_rpc_request_to_eth_client(
                ethereum_node_urls, "eth_getTransactionByHash", params,
            ),
            timeout=ETH_RPC_LOOKUP_TIMEOUT_S,
        )
    except asyncio.TimeoutError:
        logging.error(
            "eth_getTransactionByHash(%s) timed out after %ss; "
            "treating as miss",
            transaction_hash, ETH_RPC_LOOKUP_TIMEOUT_S,
        )
        return None
    except Exception:
        logging.error(
            "eth_getTransactionByHash(%s) failed; treating as miss",
            transaction_hash, exc_info=True,
        )
        return None
    if "result" in res:
        transaction = res['result']
        if (  # check if pending transaction result
            transaction is None or
            "blockHash" not in transaction or transaction["blockHash"] is None or
            "blockNumber" not in transaction or transaction["blockNumber"] is None or
            "input" not in transaction
        ):
            # if pending transaction, retry in one second
            await asyncio.sleep(1)
            transaction = await get_transaction_by_hash(
                ethereum_node_urls, transaction_hash, recursion_depth
            )
        else:
            # Trim to the fields the caller actually reads before caching.
            # Subsequent cache hits return this same shape; the in-flight
            # caller below also gets the trimmed dict so cache-hit vs.
            # cache-miss paths return identical objects.
            transaction = {
                field: transaction[field]
                for field in TRANSACTION_CACHED_FIELDS
                if field in transaction
            }
            transactions_cache.set(transaction_hash, transaction)
        return transaction
    else:
        if "error" in res:
            logging.error(
                f"eth_getTransactionByHash failed. error: {str(res['error'])}")
        else:
            logging.error(
                f"eth_getTransactionByHash failed. error: {str(res)}")
        return None


@cache
def decode_failed_op_event(solidity_error_params: str) -> tuple[int, str]:
    FAILED_OP_PARAMS_API = ["uint256", "string"]
    failed_op_params_res = decode(
        FAILED_OP_PARAMS_API, bytes.fromhex(solidity_error_params)
    )
    operation_index = failed_op_params_res[0]
    reason = failed_op_params_res[1]

    return operation_index, reason


@cache
def decode_failed_op_with_revert_event(
        solidity_error_params: str) -> tuple[int, str, bytes]:
    FAILED_OP_PARAMS_API = ["uint256", "string", "bytes"]
    failed_op_params_res = decode(
        FAILED_OP_PARAMS_API, bytes.fromhex(solidity_error_params)
    )
    operation_index = failed_op_params_res[0]
    reason = failed_op_params_res[1]
    inner = failed_op_params_res[2]

    return operation_index, reason, inner


def fell_user_operation_optional_parameters_for_estimateUserOperationGas(
    user_operation_with_optional_params: dict[str, str]
 ) -> dict[str, str]:
    if (
        "preVerificationGas" not in user_operation_with_optional_params
        or
        user_operation_with_optional_params["preVerificationGas"] is None
    ):
        user_operation_with_optional_params["preVerificationGas"] = "0x"
    if (
        "verificationGasLimit" not in user_operation_with_optional_params
        or
        user_operation_with_optional_params["verificationGasLimit"] is None
    ):
        user_operation_with_optional_params["verificationGasLimit"] = "0x"
    if (
        "callGasLimit" not in user_operation_with_optional_params
        or
        user_operation_with_optional_params["callGasLimit"] is None
    ):
        user_operation_with_optional_params["callGasLimit"] = "0x"
    if (
        "maxFeePerGas" not in user_operation_with_optional_params
        or
        user_operation_with_optional_params["maxFeePerGas"] is None
    ):
        user_operation_with_optional_params["maxFeePerGas"] = "0x"
    if (
        "maxPriorityFeePerGas" not in user_operation_with_optional_params
        or
        user_operation_with_optional_params["maxPriorityFeePerGas"] is None
    ):
        user_operation_with_optional_params["maxPriorityFeePerGas"] = "0x"

    return user_operation_with_optional_params
