"""Shared test helpers — kept as a plain module (no pytest plugin magic)
so each suite imports what it needs explicitly.

The four ``_make_gas_manager()`` helpers in tests/test_pre_verification_gas_tolerance.py
and tests/v{7,8,9}/test_gas_estimation_iaccount_execute.py were nearly
identical: same constructor shape, only the chain id differed
(1337 for the tolerance suite, 11155111 for the estimation suites).
Without a shared helper, every constructor signature change had to
land in four places at once — and the cherry-picks that landed
gas_price_cache and dropped the fee multipliers proved that pattern
broke down (one of the four was missed for two weeks).
"""
from __future__ import annotations

from voltaire_bundler.gas.gas_manager_v7v8v9 import GasManagerV7V8V9
from voltaire_bundler.gas.gas_price_cache import GasPriceCache


DEFAULT_BUNDLER_ADDRESS = "0x0000000000000000000000000000000000000001"
DEFAULT_NODE_URL = "http://localhost:8545"


def make_gas_manager(
    chain_id: int = 11155111,
    bundler_address: str = DEFAULT_BUNDLER_ADDRESS,
    node_url: str = DEFAULT_NODE_URL,
    is_legacy_mode: bool = False,
    max_verification_gas: int = 1_000_000,
    max_call_data_gas: int = 1_000_000,
    gas_price_refresh_interval_s: float = 10.0,
) -> GasManagerV7V8V9:
    """Construct a GasManagerV7V8V9 for tests.

    The wrapped GasPriceCache is constructed but not started — tests
    don't await background refreshes, and any test that needs to
    observe a specific snapshot patches the cache or the underlying
    send_rpc_request_to_eth_client directly.
    """
    urls = [node_url]
    return GasManagerV7V8V9(
        ethereum_node_urls=urls,
        # Existing callers pass chain_id as a string; preserve that.
        chain_id=str(chain_id),
        bundler_address=bundler_address,
        is_legacy_mode=is_legacy_mode,
        max_verification_gas=max_verification_gas,
        max_call_data_gas=max_call_data_gas,
        gas_price_cache=GasPriceCache(
            ethereum_node_urls=urls,
            chain_id=chain_id,
            is_legacy_mode=is_legacy_mode,
            refresh_interval_seconds=gas_price_refresh_interval_s,
        ),
    )
