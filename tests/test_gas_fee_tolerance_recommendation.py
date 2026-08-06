"""
Tests for the debug recommendation emitted when
GasManager.verify_gas_fees_and_get_price rejects a userop for a too-low
maxFeePerGas: the log must name the smallest --enforce_gas_price_tolerance
value that would have accepted the userop, and that value must actually
invert the acceptance formula (recommended passes, recommended - 1 rejects).
"""

import logging

import pytest
from unittest.mock import AsyncMock, patch

from voltaire_bundler.user_operation.user_operation_v7v8v9 import (
    UserOperationV7V8V9,
)
from voltaire_bundler.gas.gas_manager import _min_accepting_tolerance
from voltaire_bundler.gas.gas_manager_v7v8v9 import GasManagerV7V8V9
from voltaire_bundler.gas.gas_price_cache import (
    GasPriceCache,
    GasPriceSnapshot,
)
from voltaire_bundler.bundle.exceptions import ValidationException


BUNDLER_ADDRESS = "0x0000000000000000000000000000000000000001"
BLOCK_GAS_PRICE = 1_000_000_000  # 1 gwei node gas price


def _make_gas_manager(chain_id: int) -> GasManagerV7V8V9:
    return GasManagerV7V8V9(
        ethereum_node_urls=["http://localhost:8545"],
        chain_id=chain_id,
        bundler_address=BUNDLER_ADDRESS,
        is_legacy_mode=False,
        max_verification_gas=1_000_000,
        max_call_data_gas=1_000_000,
        gas_price_cache=GasPriceCache(
            ethereum_node_urls=["http://localhost:8545"],
            chain_id=chain_id,
            is_legacy_mode=False,
            refresh_interval_seconds=1.0,
        ),
    )


def _make_user_operation(
    max_fee_per_gas: int, max_priority_fee_per_gas: int = 0,
) -> UserOperationV7V8V9:
    return UserOperationV7V8V9({
        "sender": "0x7e25461EEE6853f89e5bA2bDf87F47a8965EbE04",
        "nonce": "0x0",
        "callData": "0x",
        "callGasLimit": "0x0",
        "verificationGasLimit": "0x0",
        "preVerificationGas": "0x0",
        "maxFeePerGas": hex(max_fee_per_gas),
        "maxPriorityFeePerGas": hex(max_priority_fee_per_gas),
        "signature": "0x" + "00" * 65,
        "factory": None,
        "factoryData": None,
        "paymaster": None,
        "paymasterVerificationGasLimit": None,
        "paymasterPostOpGasLimit": None,
        "paymasterData": None,
        "eip7702Auth": None,
    })


def _snapshot(priority_fee: int | None) -> GasPriceSnapshot:
    return GasPriceSnapshot(
        max_fee_per_gas=BLOCK_GAS_PRICE,
        max_priority_fee_per_gas=priority_fee,
        fetched_at_monotonic=0.0,
    )


def _patched_snapshot(gm: GasManagerV7V8V9, priority_fee: int | None):
    return patch.object(
        gm.gas_price_cache, "get_snapshot",
        new_callable=AsyncMock, return_value=_snapshot(priority_fee),
    )


# ------------------------------------------------------------------ helper


def test_min_accepting_tolerance_edges():
    # At or above the block price: no tolerance needed.
    assert _min_accepting_tolerance(BLOCK_GAS_PRICE, BLOCK_GAS_PRICE) == 0
    assert _min_accepting_tolerance(BLOCK_GAS_PRICE + 1, BLOCK_GAS_PRICE) == 0
    # Tiny gap: smallest nonzero recommendation.
    assert _min_accepting_tolerance(BLOCK_GAS_PRICE - 1, BLOCK_GAS_PRICE) == 1
    # Huge gap: capped at 100.
    assert _min_accepting_tolerance(1, BLOCK_GAS_PRICE) == 100
    # Degenerate block price.
    assert _min_accepting_tolerance(0, 0) == 0


@pytest.mark.parametrize("fee_ratio_bp", [9999, 9500, 9001, 9000, 8999, 5000, 1])
def test_min_accepting_tolerance_inverts_acceptance(fee_ratio_bp: int):
    """Property: recommended t accepts; t - 1 (when >= 0) rejects."""
    import math
    effective_fee = BLOCK_GAS_PRICE * fee_ratio_bp // 10_000
    t = _min_accepting_tolerance(effective_fee, BLOCK_GAS_PRICE)

    def accepts(tol: int) -> bool:
        return effective_fee >= math.ceil(BLOCK_GAS_PRICE * (1 - tol / 100))

    assert accepts(t), (fee_ratio_bp, t)
    if t > 0:
        assert not accepts(t - 1), (fee_ratio_bp, t)


# ----------------------------------------------------- site A1 (Arbitrum)


@pytest.mark.asyncio
async def test_arbitrum_rejection_logs_recommendation(caplog):
    gm = _make_gas_manager(chain_id=42161)
    # 85% of the node gas price with 10% tolerance -> rejected; needs 15%.
    user_op = _make_user_operation(BLOCK_GAS_PRICE * 85 // 100)

    with _patched_snapshot(gm, None):
        with caplog.at_level(logging.DEBUG):
            with pytest.raises(ValidationException) as excinfo:
                await gm.verify_gas_fees_and_get_price(user_op, 10)

    # Client-facing message unchanged.
    assert excinfo.value.message.startswith(
        "maxFeePerGas is too low. it should be minimum : ")
    # Debug recommendation present and correct.
    assert "a tolerance of at least 15%" in caplog.text
    assert "chain 42161" in caplog.text

    # Property check: recommended tolerance accepts, one less rejects.
    with _patched_snapshot(gm, None):
        await gm.verify_gas_fees_and_get_price(user_op, 15)
        with pytest.raises(ValidationException):
            await gm.verify_gas_fees_and_get_price(user_op, 14)


# ------------------------------------------------- site B2 (EIP-1559 chain)


@pytest.mark.asyncio
async def test_eip1559_combined_rejection_logs_recommendation(caplog):
    gm = _make_gas_manager(chain_id=11155111)
    # Node: 1 gwei total, 0.2 gwei priority -> base 0.8 gwei. Userop:
    # high maxFeePerGas but zero priority -> effective = base = 80% of
    # block price; with 10% tolerance -> rejected; needs 20%.
    user_op = _make_user_operation(
        BLOCK_GAS_PRICE * 2, max_priority_fee_per_gas=0)

    with _patched_snapshot(gm, BLOCK_GAS_PRICE * 20 // 100):
        with caplog.at_level(logging.DEBUG):
            with pytest.raises(ValidationException) as excinfo:
                await gm.verify_gas_fees_and_get_price(user_op, 10)

    assert excinfo.value.message.startswith(
        "maxFeePerGas and (maxPriorityFeePerGas + estimated basefee) ")
    assert "a tolerance of at least 20%" in caplog.text
    assert "chain 11155111" in caplog.text

    # Property check.
    with _patched_snapshot(gm, BLOCK_GAS_PRICE * 20 // 100):
        await gm.verify_gas_fees_and_get_price(user_op, 20)
        with pytest.raises(ValidationException):
            await gm.verify_gas_fees_and_get_price(user_op, 19)


# --------------------------------------------- site B1 (below base fee)


@pytest.mark.asyncio
async def test_below_base_fee_logs_no_tolerance_helps(caplog):
    gm = _make_gas_manager(chain_id=11155111)
    # Base fee is 0.8 gwei; userop maxFeePerGas below it.
    user_op = _make_user_operation(BLOCK_GAS_PRICE * 50 // 100)

    with _patched_snapshot(gm, BLOCK_GAS_PRICE * 20 // 100):
        with caplog.at_level(logging.DEBUG):
            with pytest.raises(ValidationException) as excinfo:
                await gm.verify_gas_fees_and_get_price(user_op, 10)

    assert "estimated base fee" in excinfo.value.message
    assert "no --enforce_gas_price_tolerance value helps" in caplog.text


# ------------------------------------------------------- accepted: silent


@pytest.mark.asyncio
async def test_accepted_userop_logs_nothing(caplog):
    gm = _make_gas_manager(chain_id=42161)
    user_op = _make_user_operation(BLOCK_GAS_PRICE)

    with _patched_snapshot(gm, None):
        with caplog.at_level(logging.DEBUG):
            await gm.verify_gas_fees_and_get_price(user_op, 10)

    assert "gas-fee rejection" not in caplog.text
