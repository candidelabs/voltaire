"""
Tests for enforce_pre_verification_gas_tolerance logic in
GasManager.verify_preverification_gas_and_verification_gas_limit().

Verifies that the tolerance parameter correctly relaxes the strict
preVerificationGas check, allowing user operations within X% of
the expected value.
"""

import pytest
from unittest.mock import AsyncMock, patch

from voltaire_bundler.user_operation.user_operation_v7v8v9 import (
    UserOperationV7V8V9,
)
from voltaire_bundler.gas.gas_manager_v7v8v9 import GasManagerV7V8V9
from voltaire_bundler.gas.gas_price_cache import GasPriceCache
from voltaire_bundler.bundle.exceptions import ValidationException


ENTRYPOINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
BUNDLER_ADDRESS = "0x0000000000000000000000000000000000000001"
EXPECTED_PREVERIFICATION_GAS = 100_000


def _make_gas_manager() -> GasManagerV7V8V9:
    return GasManagerV7V8V9(
        ethereum_node_urls=["http://localhost:8545"],
        chain_id="1337",
        bundler_address=BUNDLER_ADDRESS,
        is_legacy_mode=False,
        max_verification_gas=1_000_000,
        max_call_data_gas=1_000_000,
        gas_price_cache=GasPriceCache(
            ethereum_node_urls=["http://localhost:8545"],
            chain_id=1337,
            is_legacy_mode=False,
            refresh_interval_seconds=1.0,
        ),
    )


def _make_user_operation(
    pre_verification_gas: int,
) -> UserOperationV7V8V9:
    return UserOperationV7V8V9({
        "sender": "0x7e25461EEE6853f89e5bA2bDf87F47a8965EbE04",
        "nonce": "0x0",
        "callData": "0x",
        "callGasLimit": "0x0",
        "verificationGasLimit": "0x0",
        "preVerificationGas": hex(pre_verification_gas),
        "maxFeePerGas": "0x0",
        "maxPriorityFeePerGas": "0x0",
        "signature": "0x" + "00" * 65,
        "factory": None,
        "factoryData": None,
        "paymaster": None,
        "paymasterVerificationGasLimit": None,
        "paymasterPostOpGasLimit": None,
        "paymasterData": None,
        "eip7702Auth": None,
    })


@pytest.mark.asyncio
async def test_tolerance_0_exact_passes():
    """Tolerance 0 (strict): exact expected value should pass."""
    gm = _make_gas_manager()
    user_op = _make_user_operation(EXPECTED_PREVERIFICATION_GAS)

    with patch.object(
        gm, "get_preverification_gas",
        new_callable=AsyncMock,
        return_value=EXPECTED_PREVERIFICATION_GAS,
    ):
        await gm.verify_preverification_gas_and_verification_gas_limit(
            user_op, ENTRYPOINT, 0
        )


@pytest.mark.asyncio
async def test_tolerance_0_below_rejects():
    """Tolerance 0 (strict): 1 below expected should reject."""
    gm = _make_gas_manager()
    user_op = _make_user_operation(EXPECTED_PREVERIFICATION_GAS - 1)

    with patch.object(
        gm, "get_preverification_gas",
        new_callable=AsyncMock,
        return_value=EXPECTED_PREVERIFICATION_GAS,
    ):
        with pytest.raises(ValidationException):
            await gm.verify_preverification_gas_and_verification_gas_limit(
                user_op, ENTRYPOINT, 0
            )


@pytest.mark.asyncio
async def test_tolerance_0_above_passes():
    """Tolerance 0 (strict): above expected value should pass."""
    gm = _make_gas_manager()
    user_op = _make_user_operation(EXPECTED_PREVERIFICATION_GAS * 2)

    with patch.object(
        gm, "get_preverification_gas",
        new_callable=AsyncMock,
        return_value=EXPECTED_PREVERIFICATION_GAS,
    ):
        await gm.verify_preverification_gas_and_verification_gas_limit(
            user_op, ENTRYPOINT, 0
        )


@pytest.mark.asyncio
async def test_tolerance_10_at_90pct_passes():
    """Tolerance 10 (default): exactly 90% of expected should pass."""
    gm = _make_gas_manager()
    user_op = _make_user_operation(90_000)

    with patch.object(
        gm, "get_preverification_gas",
        new_callable=AsyncMock,
        return_value=EXPECTED_PREVERIFICATION_GAS,
    ):
        await gm.verify_preverification_gas_and_verification_gas_limit(
            user_op, ENTRYPOINT, 10
        )


@pytest.mark.asyncio
async def test_tolerance_10_ceil_boundary_passes():
    """Fractional threshold: 100_001 * 0.9 = 90_000.9 -> ceil = 90_001.
    Pins the rounding direction — floor/int would accept 90_000."""
    gm = _make_gas_manager()
    user_op = _make_user_operation(90_001)

    with patch.object(
        gm, "get_preverification_gas",
        new_callable=AsyncMock,
        return_value=100_001,
    ):
        await gm.verify_preverification_gas_and_verification_gas_limit(
            user_op, ENTRYPOINT, 10
        )


@pytest.mark.asyncio
async def test_tolerance_10_ceil_boundary_rejects():
    """Fractional threshold: 90_000 sits below ceil(90_000.9) and must
    reject."""
    gm = _make_gas_manager()
    user_op = _make_user_operation(90_000)

    with patch.object(
        gm, "get_preverification_gas",
        new_callable=AsyncMock,
        return_value=100_001,
    ):
        with pytest.raises(ValidationException):
            await gm.verify_preverification_gas_and_verification_gas_limit(
                user_op, ENTRYPOINT, 10
            )


@pytest.mark.asyncio
async def test_tolerance_10_below_90pct_rejects():
    """Tolerance 10 (default): below 90% of expected should reject."""
    gm = _make_gas_manager()
    user_op = _make_user_operation(89_999)

    with patch.object(
        gm, "get_preverification_gas",
        new_callable=AsyncMock,
        return_value=EXPECTED_PREVERIFICATION_GAS,
    ):
        with pytest.raises(ValidationException):
            await gm.verify_preverification_gas_and_verification_gas_limit(
                user_op, ENTRYPOINT, 10
            )


@pytest.mark.asyncio
async def test_tolerance_100_disables_check():
    """Tolerance 100: check disabled, even very low gas should pass."""
    gm = _make_gas_manager()
    user_op = _make_user_operation(1)

    with patch.object(
        gm, "get_preverification_gas",
        new_callable=AsyncMock,
        return_value=EXPECTED_PREVERIFICATION_GAS,
    ):
        await gm.verify_preverification_gas_and_verification_gas_limit(
            user_op, ENTRYPOINT, 100
        )
