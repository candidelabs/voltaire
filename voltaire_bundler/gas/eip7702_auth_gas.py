"""Per-class EIP-7702 authorization gas, measured once per chain.

The bundle transaction pays an intrinsic cost for every authorization
tuple it carries. It is charged before any EVM execution, so no simulation
contract can observe it, and it has to be added to the operation's
preVerificationGas explicitly. On most chains it is a flat 25,000 per
tuple (PER_EMPTY_ACCOUNT_COST, charged up front whatever the refund).
Under EIP-8037 (Glamsterdam; Sepolia since 2026-10-06) delegating also
creates state, and the cost depends on the authority's state. Measured on
Sepolia: empty account ~239k, existing undelegated account ~53k, already
delegated account ~17k.

The cost depends only on which of those three classes the sender is in,
never on the sender itself, so the expensive part runs once:

- ``measure()``: once per chain, per class, with a throwaway key whose
  account is overridden into that class (the tuple needs a valid
  signature, which the stub-signed tuple of an estimation request cannot
  provide), as ``eth_estimateGas`` with minus without the tuple. Six
  calls at startup, cached for the life of the process: the values only
  change at a hard fork, and the bundler is restarted for those. On a
  chain without EIP-8037 this naturally yields 25,000 for every class,
  so no chain list is needed.
- ``auth_gas_for(sender)``: one ``eth_getProof`` (empty key list, so no
  storage proofs) to classify the sender, then a table lookup. Falls
  back to the three plain state calls when the node does not serve
  ``eth_getProof``, decided once.

When the node rejects the measurement call shape (no state overrides on
``eth_estimateGas``, no type-4 estimation) the table stays at 25,000 per
class with one warning until the bundler is restarted. When a sender
cannot be classified at all, the most expensive class is assumed:
the bundler must never pay a tuple out of pocket, an overpaid
preVerificationGas is the lesser harm.

A sender only ever moves toward cheaper classes (funding makes an empty
account existing, the first bundled op makes it delegated), so the class
observed at estimation is an upper bound at inclusion.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from eth_account import Account

from voltaire_bundler.custom_types import Address
from voltaire_bundler.utils.eth_client_utils import (
    RpcRequestError,
    send_rpc_request_once,
)

AUTHORITY_EMPTY = "empty"
AUTHORITY_EXISTING = "existing"
AUTHORITY_DELEGATED = "delegated"
AUTHORITY_CLASSES = (AUTHORITY_EMPTY, AUTHORITY_EXISTING, AUTHORITY_DELEGATED)

# EIP-7702 PER_EMPTY_ACCOUNT_COST: the per-tuple intrinsic charge on chains
# without EIP-8037, and the fallback when the measurement is unavailable.
PER_EMPTY_ACCOUNT_COST = 25_000

# keccak256 of empty code, what eth_getProof reports for an account without
# code; some clients report the zero hash for an account that does not
# exist at all.
EMPTY_CODE_HASH = \
    "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
ZERO_HASH = "0x" + "00" * 32

# Any address works as the delegation target of the measurement tuples;
# the cost does not depend on it (re-delegating to a different target
# measured the same as re-delegating to the same one).
_MEASUREMENT_DELEGATE = "0x7702000000000000000000000000000000007702"

# Per-node deadline for one measurement or classification RPC. Walks the
# node list on failure, like GasPriceCache.
_PER_NODE_TIMEOUT_SECONDS = 10.0

# Stand-in account state per class: (nonce, balance, code).
_CLASS_OVERRIDES: dict[str, tuple[int, int, str]] = {
    AUTHORITY_EMPTY: (0, 0, "0x"),
    AUTHORITY_EXISTING: (1, 1, "0x"),
    AUTHORITY_DELEGATED: (1, 1, "0xef0100" + _MEASUREMENT_DELEGATE[2:].lower()),
}


def classify_authority(nonce: int, balance: int, has_code: bool) -> str:
    """EIP-161 emptiness drives the EIP-7702 cost: an account with code
    (a delegation, in practice) is cheapest, an existing account without
    code pays for the delegation designator, an empty account also pays
    for its creation."""
    if has_code:
        return AUTHORITY_DELEGATED
    if nonce == 0 and balance == 0:
        return AUTHORITY_EMPTY
    return AUTHORITY_EXISTING


class Eip7702AuthGas:
    def __init__(
        self,
        ethereum_node_urls: list[str],
        bundler_address: Address,
        chain_id: int,
    ):
        if not ethereum_node_urls:
            raise ValueError("Eip7702AuthGas needs at least one node URL")
        self._ethereum_node_urls = ethereum_node_urls
        self._bundler_address = bundler_address
        self._chain_id = chain_id
        self.costs: dict[str, int] = {
            cls: PER_EMPTY_ACCOUNT_COST for cls in AUTHORITY_CLASSES
        }
        self.measured = False
        # None until the first classification decides which path works.
        self._get_proof_supported: bool | None = None

    # ---------------------------------------------------------------- rpc
    async def _rpc(self, method: str, params: list[Any]) -> Any:
        """One attempt per node under a deadline, first success wins."""
        last_exc: Exception | None = None
        for node_url in self._ethereum_node_urls:
            try:
                return await asyncio.wait_for(
                    send_rpc_request_once(node_url, method, params),
                    timeout=_PER_NODE_TIMEOUT_SECONDS,
                )
            except (RpcRequestError, asyncio.TimeoutError) as exc:
                last_exc = exc
        assert last_exc is not None
        raise last_exc

    # -------------------------------------------------------- measurement
    async def measure(self) -> dict[str, int]:
        """Measure all three classes and install the table. Raises if the
        node cannot serve the measurement; the table is left untouched."""
        costs = {}
        for cls in AUTHORITY_CLASSES:
            costs[cls] = await self._measure_class(cls)
        self.costs = costs
        self.measured = True
        logging.info(
            "EIP-7702 authorization gas on chain %s: empty authority %d, "
            "existing %d, delegated %d",
            self._chain_id, costs[AUTHORITY_EMPTY],
            costs[AUTHORITY_EXISTING], costs[AUTHORITY_DELEGATED],
        )
        return costs

    async def _measure_class(self, cls: str) -> int:
        nonce, balance, code = _CLASS_OVERRIDES[cls]
        stand_in = Account.create()
        signed = Account.sign_authorization(
            {
                "chainId": self._chain_id,
                "address": _MEASUREMENT_DELEGATE,
                "nonce": nonce,
            },
            stand_in.key,
        )
        overrides = {
            stand_in.address: {
                "nonce": hex(nonce),
                "balance": hex(balance),
                "code": code,
            },
            # the bundler's real balance is irrelevant to the measurement
            self._bundler_address: {"balance": hex(10 ** 21)},
        }
        tx = {
            "from": self._bundler_address,
            "to": self._bundler_address,
            "data": "0x",
        }
        tx_with_auth = tx | {
            "type": "0x4",
            "authorizationList": [{
                "chainId": hex(signed.chain_id),
                "address": _MEASUREMENT_DELEGATE,
                "nonce": hex(signed.nonce),
                "yParity": hex(signed.y_parity),
                "r": hex(signed.r),
                "s": hex(signed.s),
            }],
        }
        without_auth, with_auth = await asyncio.gather(
            self._rpc("eth_estimateGas", [tx, "latest", overrides]),
            self._rpc("eth_estimateGas", [tx_with_auth, "latest", overrides]),
        )
        return max(int(with_auth, 16) - int(without_auth, 16), 0)

    # ------------------------------------------------------ classification
    async def classify(self, sender: Address) -> str:
        if self._get_proof_supported is not False:
            try:
                proof = await self._rpc("eth_getProof", [sender, [], "latest"])
                nonce = int(proof.get("nonce", "0x0"), 16)
                balance = int(proof.get("balance", "0x0"), 16)
                code_hash = str(proof.get("codeHash", ZERO_HASH)).lower()
                self._get_proof_supported = True
                return classify_authority(
                    nonce, balance,
                    code_hash not in (EMPTY_CODE_HASH, ZERO_HASH),
                )
            except (RpcRequestError, asyncio.TimeoutError, ValueError,
                    AttributeError, TypeError) as exc:
                if self._get_proof_supported is True:
                    raise
                logging.warning(
                    "eth_getProof unavailable (%r); classifying EIP-7702 "
                    "authorities with eth_getTransactionCount / "
                    "eth_getBalance / eth_getCode instead", exc,
                )
                self._get_proof_supported = False
        nonce_hex, balance_hex, code = await asyncio.gather(
            self._rpc("eth_getTransactionCount", [sender, "latest"]),
            self._rpc("eth_getBalance", [sender, "latest"]),
            self._rpc("eth_getCode", [sender, "latest"]),
        )
        return classify_authority(
            int(nonce_hex, 16), int(balance_hex, 16),
            str(code).lower() not in ("0x", ""),
        )

    async def auth_gas_for(self, sender: Address) -> int:
        """Authorization gas to add to a 7702 operation's preVerificationGas."""
        try:
            cls = await self.classify(sender)
        except Exception as exc:
            logging.warning(
                "could not classify EIP-7702 authority %s (%r); charging "
                "the empty-account authorization gas", sender, exc,
            )
            cls = AUTHORITY_EMPTY
        return self.costs[cls]
