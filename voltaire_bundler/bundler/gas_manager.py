import asyncio
import math
from typing import Any

from eth_abi import decode, encode

from voltaire_bundler.bundler.exceptions import (ExecutionException,
                                                 ExecutionExceptionCode,
                                                 ValidationException,
                                                 ValidationExceptionCode)
from voltaire_bundler.user_operation.user_operation import UserOperation
from voltaire_bundler.user_operation.user_operation_handler import \
    UserOperationHandler
from voltaire_bundler.utils.decode import (
    decode_FailedOp_event,
    decode_gasEstimateL1Component_result)
from voltaire_bundler.utils.encode import (
    encode_gasEstimateL1Component_calldata, encode_handleops_calldata)
from voltaire_bundler.utils.eth_client_utils import \
    send_rpc_request_to_eth_client

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
MIN_CALL_GAS_LIMIT = 21_000


class GasManager:
    ethereum_node_url: str
    chain_id: str
    is_legacy_mode: bool
    max_fee_per_gas_percentage_multiplier: int
    max_priority_fee_per_gas_percentage_multiplier: int
    estimate_gas_with_override_enabled: bool
    max_verification_gas: int
    max_call_data_gas: int
    entrypoint_mod_byte_code: str

    def __init__(
        self,
        ethereum_node_url,
        chain_id,
        is_legacy_mode,
        max_fee_per_gas_percentage_multiplier: int,
        max_priority_fee_per_gas_percentage_multiplier: int,
        max_verification_gas,
        max_call_data_gas,
        entrypoint_mod_byte_code,
    ):
        self.ethereum_node_url = ethereum_node_url
        self.chain_id = chain_id
        self.is_legacy_mode = is_legacy_mode
        self.max_fee_per_gas_percentage_multiplier = (
            max_fee_per_gas_percentage_multiplier
        )
        self.max_priority_fee_per_gas_percentage_multiplier = (
            max_priority_fee_per_gas_percentage_multiplier
        )
        self.estimate_gas_with_override_enabled = True
        self.max_verification_gas = max_verification_gas
        self.max_call_data_gas = max_call_data_gas
        self.entrypoint_mod_byte_code = entrypoint_mod_byte_code

    async def estimate_callgaslimit_and_preverificationgas_and_verificationgas(
        self,
        user_operation: UserOperation,
        entrypoint: str,
        state_override_set_dict: dict[str, Any],
    ) -> tuple[str, str, str]:
        input_preverification_gas = user_operation.pre_verification_gas
        input_verification_gas_limit = user_operation.verification_gas_limit
        input_call_gas_limit = user_operation.call_gas_limit

        if user_operation.verification_gas_limit == 0:
            user_operation.verification_gas_limit = self.max_verification_gas

        estimated_verification_gas_limit = 0
        estimated_call_gas_limit = 0
        #is_check_once = not (input_call_gas_limit == 0)
        is_check_once = False

        (estimated_call_gas_limit, estimated_verification_gas_limit) = (
            await self.estimate_call_gas_and_verificationgas_limit(
                user_operation,
                entrypoint,
                state_override_set_dict,
                is_check_once
            )
        )

        if input_verification_gas_limit == 0:
            result_verification_gas_limit = estimated_verification_gas_limit
        else:
            result_verification_gas_limit = input_verification_gas_limit

        if input_call_gas_limit == 0:
            result_call_gas_limit = estimated_call_gas_limit
        else:
            result_call_gas_limit = input_call_gas_limit

        if input_preverification_gas == 0:
            user_operation.call_gas_limit = result_call_gas_limit
            user_operation.verification_gas_limit = result_verification_gas_limit

            result_preverification_gas = await self.get_preverification_gas(
                user_operation,
                entrypoint,
            )
        else:
            result_preverification_gas = user_operation.pre_verification_gas

        return (
            hex(result_call_gas_limit),
            hex(result_preverification_gas),
            hex(result_verification_gas_limit),
        )

    async def estimate_call_gas_and_verificationgas_limit(
        self,
        user_operation: UserOperation,
        entrypoint: str,
        state_override_set_dict: dict[str, Any],
        is_check_once: bool,
    ) -> tuple[int, int]:
        min_gas = 0
        if is_check_once:
            max_gas = user_operation.call_gas_limit
        else:
            max_gas = self.max_call_data_gas
        is_continious = False
        while True:
            (
                solidity_error,
                failed_op_params_res
            ) = await self.simulate_handle_op_mod(
                user_operation,
                entrypoint,
                min_gas,
                max_gas,
                is_continious,
                is_check_once,
                state_override_set_dict,
            )
            if solidity_error[:10] == "0x3a803a81":  # success
                return (int(failed_op_params_res[3]),
                        int(failed_op_params_res[0]))

            elif solidity_error[:10] == "0x22cf94e6":  # continue
                if int(failed_op_params_res[2]) > 30:
                    break
                min_gas = int(failed_op_params_res[0])
                max_gas = int(failed_op_params_res[1])
                is_continious = True
            elif solidity_error[:10] == "0x59f233d2":  # EstimateCallGasRevertAtMax
                errorMessage = failed_op_params_res[0]
                raise ExecutionException(
                    ExecutionExceptionCode.EXECUTION_REVERTED,
                    str(errorMessage)
                )

        raise ValueError(
                "Unexpected error during estimate_call_gas_and_verificationgas_limit")

    async def simulate_handle_op_mod(
        self,
        user_operation: UserOperation,
        entrypoint: str,
        min_gas: int,
        max_gas: int,
        is_continious: bool,
        is_check_once: bool,
        state_override_set_dict: dict[str, Any],
    ) -> tuple[str, list[int | bytes]]:
        # simulateHandleOpMod(entrypoint solidity function) will always revert
        function_selector = "0x85085b6b"
        call_data_params = encode(
            [
                "(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)",  # useroperation
                "(uint256,uint256,uint256,bool,bool)",
            ],
            [
                user_operation.to_list(),
                [min_gas, max_gas, 10_000, is_continious, is_check_once]
            ],
        )

        default_state_overrides: dict[str, Any] = {
            ZERO_ADDRESS: {
                # override the "from" zero address balance with a high value
                "balance": "0x314dc6448d9338c15b0a00000000",
            },
            entrypoint: {
                # override the Entrypoint with EntryPointMod for callGasLimit
                # binary search
                "code": self.entrypoint_mod_byte_code
}
        }


        call_data = function_selector + call_data_params.hex()
        # if there is no paymaster, override the sender's balance for gas estimation
        if len(user_operation.paymaster_and_data) == 0:
            # if the target is zero, simulate_handle_op is called to estimate
            # gas limits override the sender balance with the high value of 10^15 eth
            default_state_overrides[user_operation.sender_address] = {
                "balance": "0x314dc6448d9338c15b0a00000000"
            }

        params: list[Any] = [
            {
                "from": ZERO_ADDRESS,
                "to": entrypoint,
                "data": call_data,
            },
            "latest",
            default_state_overrides | state_override_set_dict
        ]

        result: Any = await send_rpc_request_to_eth_client(
            self.ethereum_node_url, "eth_call", params
        )
        if "error" not in result:
            raise ValueError("simulateHandleOpMod didn't revert!")

        elif (
            "execution reverted" not in result["error"]["message"]
            or "data" not in result["error"]
            or len(result["error"]["data"]) < 10
        ):
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                result["error"]["message"],
            )

        error_data = result["error"]["data"]
        error_selector = str(error_data[:10])
        error_params = error_data[10:]

        error_params_api = []
        if error_selector == "0x3a803a81":  # SimulationResult
            error_params_api = [
                "uint256",  # verificationGasLimit
                "uint48",  # validAfter
                "uint48",  # validUntil
                "uint256",  # callGasLimitMax
                "uint256",  # numRounds
            ]
        elif error_selector == "0x22cf94e6":  # EstimateCallGasContinuation
            error_params_api = [
                "uint256",  # minGas
                "uint256",  # maxGas
                "uint256",  # numRounds
            ]
        elif error_selector[:10] == "0x59f233d2":  # EstimateCallGasRevertAtMax
            error_params_api = ["bytes"]  # revertData
        elif error_selector == "0x220266b6":  # FailedOp
            (
                _,
                reason,
            ) = decode_FailedOp_event(error_params)
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                reason,
            )
        elif error_selector == "0x08c379a0":  # Error(string)
            reason = decode(
                ["string"], bytes.fromhex(error_params)
            )  # decode revert message

            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                reason[0],
            )
        else:
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                error_params,
            )
        error_params_decoded = decode(
                error_params_api, bytes.fromhex(error_params))

        return error_selector, error_params_decoded

    async def verify_gas_fees_and_get_price(
        self, user_operation: UserOperation, enforce_gas_price_tolerance: int
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

                estimated_base_fee = max(
                    block_max_fee_per_gas - block_max_priority_fee_per_gas, 1
                )

                if max_fee_per_gas < estimated_base_fee:
                    raise ValidationException(
                        ValidationExceptionCode.InvalidFields,
                        f"Max fee per gas is too low. it should be minimum the estimated base fee: {hex(estimated_base_fee)}",
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
                        f"Max fee per gas and (Max priority fee per gas + estimated basefee) should be equal or higher than : {block_max_fee_per_gas_with_tolerance_hex}",
                    )

        return block_max_fee_per_gas_hex

    async def verify_preverification_gas_and_verification_gas_limit(
        self,
        user_operation: UserOperation,
        entrypoint: str,
    ) -> None:
        expected_preverification_gas = await self.get_preverification_gas(
            user_operation,
            entrypoint,
        )

        if user_operation.pre_verification_gas < expected_preverification_gas:
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                f"Preverification gas is too low. it should be minimum : {hex(expected_preverification_gas)}",
            )

        if user_operation.verification_gas_limit > self.max_verification_gas:
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                f"Verification gas is too high. it should be maximum : {hex(self.max_verification_gas)}",
            )

    async def calc_l1_gas_estimate_optimism(
        self,
        user_operation: UserOperation,
        block_number_hex: str,
        latest_block_base_fee: int,
    ) -> int:

        user_operations_list = [user_operation.to_list()]

        # currently most bundles contains a singler useroperations
        # so l1 fees is calculated for the full handleops transaction
        handleops_calldata = encode_handleops_calldata(
            user_operations_list, ZERO_ADDRESS
        )

        optimism_gas_oracle_contract_address = (
            "0x420000000000000000000000000000000000000F"
        )

        function_selector = "0x49948e0e"  # getL1Fee
        call_data_params = encode(
                ["bytes"], [bytes.fromhex(handleops_calldata[2:])])

        call_data = function_selector + call_data_params.hex()

        params = [
            {
                "from": ZERO_ADDRESS,
                "to": optimism_gas_oracle_contract_address,
                "data": call_data,
            },
            block_number_hex,
        ]

        result: Any = await send_rpc_request_to_eth_client(
            self.ethereum_node_url, "eth_call", params
        )

        l1_fee = decode(["uint256"], bytes.fromhex(result["result"][2:]))[0]

        l2_gas_price = min(
            user_operation.max_fee_per_gas,
            user_operation.max_priority_fee_per_gas + latest_block_base_fee,
        )
        l2_gas_price = max(1, l2_gas_price)  # in case l2_gas_price = 0

        gas_estimate_for_l1 = math.ceil(l1_fee / l2_gas_price)

        return gas_estimate_for_l1

    async def calc_l1_gas_estimate_arbitrum(
        self, user_operation: UserOperation, entrypoint: str
    ) -> int:
        arbitrum_nodeInterface_address = "0x00000000000000000000000000000000000000C8"

        is_init: bool = user_operation.nonce == 0

        user_operations_list = [user_operation.to_list()]

        handleops_calldata = encode_handleops_calldata(
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

        result: Any = await send_rpc_request_to_eth_client(
            self.ethereum_node_url, "eth_call", params
        )

        raw_gas_results = result["result"]

        gas_estimate_for_l1 = decode_gasEstimateL1Component_result(
                raw_gas_results)

        return gas_estimate_for_l1

    async def get_preverification_gas(
        self,
        user_operation: UserOperation,
        entrypoint: str,
        preverification_gas_percentage_coefficient: int = 100,
        preverification_gas_addition_constant: int = 0,
    ) -> int:
        base_preverification_gas = GasManager.calc_base_preverification_gas(
            user_operation
        )
        l1_gas = 0

        """
        if self.chain_id == 10 or self.chain_id == 420:  # optimism and optimism goerli
            block_number_hex,latest_block_base_fee, _, _,_ = await get_latest_block_info(
                    self.ethereum_node_url)
            l1_gas = await self.calc_l1_gas_estimate_optimism(
                user_operation, block_number_hex, latest_block_base_fee
            )
        elif self.chain_id == 42161:  # arbitrum One
            l1_gas = await self.calc_l1_gas_estimate_arbitrum(user_operation, entrypoint)
        """

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

    @staticmethod
    def calc_base_preverification_gas(user_operation: UserOperation) -> int:
        user_operation_list = user_operation.to_list()

        user_operation_list[6] = 21000

        # set a dummy signature only if the user didn't supply any
        if len(user_operation_list[10]) < 65:
            user_operation_list[10] = (
                b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"  # signature
            )

        fixed = 21000
        per_user_operation = 18300
        per_user_operation_word = 4
        zero_byte = 4
        non_zero_byte = 16
        bundle_size = 1
        # sigSize = 65

        packed = UserOperationHandler.pack_user_operation(
                user_operation_list, False)
        packed_length = len(packed)
        zero_byte_count = packed.count(b"\x00")
        non_zero_byte_count = packed_length - zero_byte_count
        call_data_cost = (
            zero_byte_count * zero_byte + non_zero_byte_count * non_zero_byte
        )

        length_in_words = math.ceil((packed_length + 31) / 32)

        pre_verification_gas = (
            call_data_cost
            + (fixed / bundle_size)
            + per_user_operation
            + per_user_operation_word * length_in_words
        )

        return math.ceil(pre_verification_gas)
