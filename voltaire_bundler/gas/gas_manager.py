from abc import ABC, abstractmethod
import asyncio
import logging
import math
from typing import Generic, Any
from functools import cache

from eth_abi import encode, decode
from eth_utils import keccak

from voltaire_bundler.user_operation.models import UserOperationType
from voltaire_bundler.bundle.exceptions import \
    ValidationException, ValidationExceptionCode
from voltaire_bundler.utils.eth_client_utils import \
    encode_handleops_calldata_v6, encode_handleops_calldata_v7v8, send_rpc_request_to_eth_client


class GasManager(ABC, Generic[UserOperationType]):
    ethereum_node_urls: list[str]
    chain_id: str
    is_legacy_mode: bool
    max_fee_per_gas_percentage_multiplier: int
    max_priority_fee_per_gas_percentage_multiplier: int
    estimate_gas_with_override_enabled: bool
    max_verification_gas: int
    max_call_data_gas: int
    entrypoint_code_override: str

    async def verify_gas_fees_and_get_price(
        self, user_operation: UserOperationType,
        enforce_gas_price_tolerance: int
    ) -> str:
        max_fee_per_gas = user_operation.max_fee_per_gas
        max_priority_fee_per_gas = user_operation.max_priority_fee_per_gas

        block_max_fee_per_gas_op = send_rpc_request_to_eth_client(
            self.ethereum_node_urls, "eth_gasPrice", None, None, "result"
        )

        tasks_arr = [block_max_fee_per_gas_op]

        if not self.is_legacy_mode:
            block_max_priority_fee_per_gas_op = send_rpc_request_to_eth_client(
                self.ethereum_node_urls, "eth_maxPriorityFeePerGas", None, None, "result"
            )
            tasks_arr.append(block_max_priority_fee_per_gas_op)

        tasks: Any = await asyncio.gather(*tasks_arr)

        block_max_fee_per_gas_hex = tasks[0]["result"]
        block_max_fee_per_gas = int(block_max_fee_per_gas_hex, 16)
        block_max_fee_per_gas = math.ceil(
            block_max_fee_per_gas * (
                self.max_fee_per_gas_percentage_multiplier / 100)
        )
        block_max_fee_per_gas_with_tolerance = math.ceil(
            block_max_fee_per_gas * (1 - (enforce_gas_price_tolerance / 100))
        )
        block_max_fee_per_gas_with_tolerance_hex = hex(
            block_max_fee_per_gas_with_tolerance
        )

        if enforce_gas_price_tolerance < 100:
            if self.is_legacy_mode:
                block_max_priority_fee_per_gas = block_max_fee_per_gas
                if max_fee_per_gas < block_max_fee_per_gas_with_tolerance:
                    raise ValidationException(
                        ValidationExceptionCode.SimulateValidation,
                        "Max fee per gas is too low. it should be minimum : " +
                        f"{block_max_fee_per_gas_with_tolerance_hex}",
                    )

            else:
                block_max_priority_fee_per_gas = int(tasks[1]["result"], 16)
                block_max_priority_fee_per_gas = math.ceil(
                    block_max_priority_fee_per_gas
                    * (self.max_priority_fee_per_gas_percentage_multiplier
                       / 100)
                )

                # max priority fee per gas can't be higher than max fee per gas
                if block_max_priority_fee_per_gas > block_max_fee_per_gas:
                    block_max_priority_fee_per_gas = block_max_fee_per_gas

                estimated_base_fee = max(
                    block_max_fee_per_gas - block_max_priority_fee_per_gas, 1
                )

                if max_fee_per_gas < estimated_base_fee:
                    raise ValidationException(
                        ValidationExceptionCode.InvalidFields,
                        "Max fee per gas is too low." +
                        "it should be minimum the estimated base fee: " +
                        f"{hex(estimated_base_fee)}",
                    )
                if max_priority_fee_per_gas < 1:
                    raise ValidationException(
                        ValidationExceptionCode.InvalidFields,
                        "Max priority fee per gas is too low. it should be minimum : 1",
                    )
                if (
                    min(
                        max_fee_per_gas,
                        estimated_base_fee + max_priority_fee_per_gas,
                    )
                    < block_max_fee_per_gas_with_tolerance
                ):
                    raise ValidationException(
                        ValidationExceptionCode.InvalidFields,
                        "Max fee per gas and (Max priority fee per gas + estimated basefee) " +
                        f"should be equal or higher than : {block_max_fee_per_gas_with_tolerance_hex}",
                    )

        return block_max_fee_per_gas_hex

    async def verify_preverification_gas_and_verification_gas_limit(
        self,
        user_operation: UserOperationType,
        entrypoint: str,
    ) -> None:
        expected_preverification_gas = await self.get_preverification_gas(
            user_operation,
            entrypoint,
        )

        if user_operation.pre_verification_gas < expected_preverification_gas:
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                "Preverification gas is too low." +
                f"it should be minimum : {hex(expected_preverification_gas)}",
            )

        if user_operation.verification_gas_limit > self.max_verification_gas:
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                "Verification gas is too high." +
                f"it should be maximum : {hex(self.max_verification_gas)}",
            )

    async def get_preverification_gas(
        self,
        user_operation: UserOperationType,
        entrypoint: str,
        latest_block_number_hex: str = "latest",
        preverification_gas_percentage_coefficient: int = 100,
        preverification_gas_addition_constant: int = 0,
    ) -> int:
        base_preverification_gas = self.calc_base_preverification_gas(
            user_operation
        )
        l1_gas = 0

        user_operations_list = [user_operation.to_list()]
        user_op = user_operations_list[0]
        if len(user_op) != 11:  # for now, only estimate l1 gas for ep0.7 and ep0.8
            try:
                ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
                # currently most bundles contains a singler useroperations
                # so l1 fees is calculated for the full handleops transaction
                # set random values for gas limits and gas prices for accurate gas estimation
                if user_op[4] == (0).to_bytes(32):
                    user_op[4] = (0xab8621df9b).to_bytes(16) + (0xa51448df8c).to_bytes(16)
                if user_op[5] == 0:
                    user_op[5] = 0xa8d2755f7a
                if user_op[6] == (0).to_bytes(32):
                    user_op[6] = (0xa4f91cbf5f).to_bytes(16) + (0xa76e216f4b).to_bytes(16)
                handleops_calldata = encode_handleops_calldata_v7v8(
                    user_operations_list, ZERO_ADDRESS
                )

                # op chains (optimism, optimism sepolia, base, world chain)
                if (
                    self.chain_id == 10 or  # op mainnet
                    self.chain_id == 11155420 or  # op sepolia
                    self.chain_id == 8453 or  # base
                    self.chain_id == 84532 or  # base sepolia
                    self.chain_id == 480 or  # world chain
                    self.chain_id == 4801  # world chain sepolia
                ):
                    l1_gas = await self.calc_l1_gas_estimate_optimism(
                        handleops_calldata,
                        latest_block_number_hex
                    )
                # arbitrum One or arbitrum sepolia
                if self.chain_id == 42161 or self.chain_id == 421614:
                    is_init: bool = user_operation.nonce == 0
                    l1_gas = await self.calc_l1_gas_estimate_arbitrum(
                        handleops_calldata,
                        entrypoint,
                        is_init,
                        latest_block_number_hex
                    )
            except Exception as excp:
                logging.error(
                    f"L1 gas estimation failed.error: {str(excp)}."
                    f"useroperation hash: {user_operation.user_operation_hash}"
                )

        calculated_preverification_gas = base_preverification_gas + l1_gas

        adjusted_preverification_gas = math.ceil(
            (
                calculated_preverification_gas
                * preverification_gas_percentage_coefficient
                / 100
            )
            + preverification_gas_addition_constant
        )

        return adjusted_preverification_gas

    async def calc_l1_gas_estimate_optimism(
        self,
        handleops_calldata: str,
        block_number_hex: str,
    ) -> int:
        ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
        optimism_gas_oracle_contract_address = (
            "0x420000000000000000000000000000000000000F"
        )

        function_selector = "0x49948e0e"  # getL1Fee
        params = encode(
            ["bytes"],
            [bytes.fromhex(handleops_calldata[2:])]
        )

        call_data = function_selector + params.hex()

        params = [
            {
                "from": ZERO_ADDRESS,
                "to": optimism_gas_oracle_contract_address,
                "data": call_data,
            },
            block_number_hex,
        ]

        eth_call_op = send_rpc_request_to_eth_client(
            self.ethereum_node_urls, "eth_call", params, None, "result"
        )
        block_max_fee_per_gas_op = send_rpc_request_to_eth_client(
            self.ethereum_node_urls, "eth_gasPrice", None, None, "result"
        )
        tasks_arr = [eth_call_op, block_max_fee_per_gas_op]
        tasks: Any = await asyncio.gather(*tasks_arr)
        result = tasks[0]
        block_max_fee_per_gas_hex = tasks[1]['result']
        block_max_fee_per_gas = int(block_max_fee_per_gas_hex, 16)

        l1_fee = decode(["uint256"], bytes.fromhex(result["result"][2:]))[0]
        gas_estimate_for_l1 = math.ceil(l1_fee / block_max_fee_per_gas)

        return gas_estimate_for_l1

    async def calc_l1_gas_estimate_arbitrum(
        self,
        handleops_calldata: str,
        entrypoint: str,
        is_init: bool,
        block_number_hex: str,
    ) -> int:
        ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
        arbitrum_nodeInterface_address = (
            "0x00000000000000000000000000000000000000C8"
        )
        function_selector = "0x77d488a2"  # gasEstimateL1Component
        encoded_calldata = encode(
            ["address", "bool", "bytes"],  # to  # contractCreation  # data
            [entrypoint, is_init, bytes.fromhex(handleops_calldata[2:])],
        )

        call_data = function_selector + encoded_calldata.hex()

        params = [
            {
                "from": ZERO_ADDRESS,
                "to": arbitrum_nodeInterface_address,
                "data": call_data,
            },
            block_number_hex,
        ]

        result = await send_rpc_request_to_eth_client(
            self.ethereum_node_urls, "eth_call", params, None, "result"
        )

        raw_gas_results = result["result"]
        decoded_results = decode(
            [
                "uint64",  # gasEstimateForL1
                "uint256",  # baseFee
                "uint256",  # l1BaseFeeEstimate
            ],
            bytes.fromhex(raw_gas_results[2:]),
        )

        gas_estimate_for_l1 = decoded_results[0]

        return gas_estimate_for_l1

    @abstractmethod
    def calc_base_preverification_gas(self, user_operation: UserOperationType) -> int:
        pass


@cache
def calculate_deposit_slot_index(address: str) -> str:
    # same deposit value slot for all entrypoints(for ep 0.6 this slot also has
    # the staked and stake values)
    return "0x" + keccak(
        encode(
            ["uint256", "uint256"],
            [int(address, 16), 0]  # slot = 0
        )
    ).hex()


def deep_union(dict1, dict2):
    dict1_copy = dict1.copy()
    for dict2_key, dict2_value in dict2.items():
        if (
            dict2_key in dict1_copy and
            isinstance(dict2_value, dict) and
            isinstance(dict1_copy[dict2_key], dict)
        ):
            dict1_copy[dict2_key] = deep_union(dict1_copy[dict2_key], dict2_value)
        else:
            dict1_copy[dict2_key] = dict2_value
    return dict1_copy
