from abc import ABC, abstractmethod
import asyncio
import math
from typing import Generic, Any

from voltaire_bundler.user_operation.models import UserOperationType
from voltaire_bundler.bundle.exceptions import \
    ValidationException, ValidationExceptionCode
from voltaire_bundler.utils.eth_client_utils import \
    send_rpc_request_to_eth_client


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
            self.ethereum_node_url, "eth_gasPrice", None, None, "result"
        )

        tasks_arr = [block_max_fee_per_gas_op]

        if not self.is_legacy_mode:
            block_max_priority_fee_per_gas_op = send_rpc_request_to_eth_client(
                self.ethereum_node_url, "eth_maxPriorityFeePerGas", None, None, "result"
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
        preverification_gas_percentage_coefficient: int = 100,
        preverification_gas_addition_constant: int = 0,
    ) -> int:
        base_preverification_gas = self.calc_base_preverification_gas(
            user_operation
        )
        l1_gas = 0

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

    @abstractmethod
    def calc_base_preverification_gas(self, user_operation: UserOperationType) -> int:
        pass
