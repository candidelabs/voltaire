from abc import ABC, abstractmethod
import asyncio
import math
from typing import Generic, Any
from eth_abi import encode, decode

from voltaire_bundler.user_operation.models import UserOperationType
from voltaire_bundler.bundle.exceptions import \
    ValidationException, ValidationExceptionCode
from voltaire_bundler.utils.encode import \
    encode_handleops_calldata_v6, encode_handleops_calldata_v7
from voltaire_bundler.utils.eth_client_utils import \
    get_latest_block_info, send_rpc_request_to_eth_client


ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


class GasManager(ABC, Generic[UserOperationType]):
    ethereum_node_url: str
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
            self.ethereum_node_url, "eth_gasPrice"
        )

        tasks_arr = [block_max_fee_per_gas_op]

        if not self.is_legacy_mode:
            block_max_priority_fee_per_gas_op = send_rpc_request_to_eth_client(
                self.ethereum_node_url, "eth_maxPriorityFeePerGas"
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
        latest_block_number_hex: str,
        latest_block_basefee: int,
    ) -> None:
        expected_preverification_gas = await self.get_preverification_gas(
            user_operation,
            entrypoint,
            latest_block_number_hex,
            latest_block_basefee
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
        latest_block_number_hex: str | None = None,
        latest_block_basefee: int | None = None,
        preverification_gas_percentage_coefficient: int = 100,
        preverification_gas_addition_constant: int = 0,
    ) -> int:
        base_preverification_gas = self.calc_base_preverification_gas(
            user_operation
        )
        l1_gas = 0

        # op chains (optimism, optimism sepolia, base, world chain)
        if (
            self.chain_id == 10 or  # op mainnet
            self.chain_id == 11155420 or  # op sepolia
            self.chain_id == 8453 or  # base
            self.chain_id == 480  # world chain
        ):
            if latest_block_number_hex is None or latest_block_basefee is None:
                (
                    latest_block_number_hex, latest_block_basefee, _, _, _
                ) = await get_latest_block_info(self.ethereum_node_url)
            l1_gas = await self.calc_l1_gas_estimate_optimism(
                user_operation, latest_block_number_hex, latest_block_basefee
            )
        # arbitrum One or arbitrum sepolia
        if self.chain_id == 42161 or self.chain_id == 421614:
            l1_gas = await self.calc_l1_gas_estimate_arbitrum(
                user_operation, entrypoint)

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
        self, user_operation: UserOperationType,
        block_number_hex: str,
        latest_block_base_fee: int
    ) -> int:

        user_operations_list = [user_operation.to_list()]

        # currently most bundles contains a singler useroperations
        # so l1 fees is calculated for the full handleops transaction
        if len(user_operations_list[0]) == 11:
            handleops_calldata = encode_handleops_calldata_v6(
                user_operations_list, ZERO_ADDRESS
            )
        else:
            handleops_calldata = encode_handleops_calldata_v7(
                user_operations_list, ZERO_ADDRESS
            )

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

        result = await send_rpc_request_to_eth_client(
            self.ethereum_node_url, "eth_call", params
        )

        l1_fee = decode(["uint256"], bytes.fromhex(result["result"][2:]))[0]

        l2_gas_price = min(
            user_operation.max_fee_per_gas,
            user_operation.max_priority_fee_per_gas + latest_block_base_fee
        )
        l2_gas_price = max(1, l2_gas_price)  # in case l2_gas_price = 0

        gas_estimate_for_l1 = math.ceil(l1_fee / l2_gas_price)

        return gas_estimate_for_l1

    async def calc_l1_gas_estimate_arbitrum(
        self, user_operation: UserOperationType, entrypoint: str
    ) -> int:
        arbitrum_nodeInterface_address = (
            "0x00000000000000000000000000000000000000C8"
        )

        is_init: bool = user_operation.nonce == 0

        user_operations_list = [user_operation.to_list()]

        user_op = user_operations_list[0]
        if len(user_op) == 11:
            handleops_calldata = encode_handleops_calldata_v6(
                user_operations_list, ZERO_ADDRESS
            )
        else:
            handleops_calldata = encode_handleops_calldata_v7(
                user_operations_list, ZERO_ADDRESS
            )

        call_data = encode_gasEstimateL1Component_calldata(
            entrypoint, is_init, handleops_calldata
        )

        params = [
            {
                "from": ZERO_ADDRESS,
                "to": arbitrum_nodeInterface_address,
                "data": call_data,
            },
            "latest",
        ]

        result = await send_rpc_request_to_eth_client(
            self.ethereum_node_url, "eth_call", params
        )

        raw_gas_results = result["result"]

        gas_estimate_for_l1 = decode_gasEstimateL1Component_result(
            raw_gas_results
        )

        return gas_estimate_for_l1

    @abstractmethod
    def calc_base_preverification_gas(
        self, user_operation: UserOperationType
    ) -> int:
        pass


@staticmethod
def encode_gasEstimateL1Component_calldata(
    entrypoint: str, is_init: bool, handleops_calldata: str
) -> str:
    function_selector = "0x77d488a2"  # gasEstimateL1Component
    params = encode(
        ["address", "bool", "bytes"],  # to  # contractCreation  # data
        [entrypoint, is_init, bytes.fromhex(handleops_calldata[2:])],
    )

    call_data = function_selector + params.hex()
    return call_data


@staticmethod
def decode_gasEstimateL1Component_result(raw_gas_results: str) -> int:
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
