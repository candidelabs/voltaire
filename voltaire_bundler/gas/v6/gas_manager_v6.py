import logging
import math
from typing import Any
from typing import cast

from eth_abi import decode, encode

from voltaire_bundler.bundle.exceptions import ExecutionException, \
        ExecutionExceptionCode, ValidationException, ValidationExceptionCode
from voltaire_bundler.gas.gas_manager import GasManager
from voltaire_bundler.user_operation.models import FailedOp
from voltaire_bundler.user_operation.user_operation_handler import \
        decode_failed_op_event
from voltaire_bundler.utils.load_bytecode import load_bytecode
from ...user_operation.v6.user_operation_v6 import UserOperationV6
from voltaire_bundler.user_operation.v6.user_operation_v6 import \
        pack_user_operation
from voltaire_bundler.utils.eth_client_utils import \
    send_rpc_request_to_eth_client

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
MIN_CALL_GAS_LIMIT = 21_000


class GasManagerV6(GasManager):
    ethereum_node_url: str
    chain_id: str
    is_legacy_mode: bool
    max_fee_per_gas_percentage_multiplier: int
    max_priority_fee_per_gas_percentage_multiplier: int
    estimate_gas_with_override_enabled: bool
    max_verification_gas: int
    max_call_data_gas: int
    entrypoint_code_override: str

    def __init__(
        self,
        ethereum_node_url,
        chain_id,
        is_legacy_mode,
        max_fee_per_gas_percentage_multiplier: int,
        max_priority_fee_per_gas_percentage_multiplier: int,
        max_verification_gas,
        max_call_data_gas,
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
        self.entrypoint_code_override = load_bytecode(
            "EntryPointSimulationsV6WithBinarySearch.json")

    async def estimate_user_operation_gas(
        self,
        user_operation: UserOperationV6,
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
        is_check_once = not (input_call_gas_limit == 0)
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
        user_operation: UserOperationV6,
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

            if solidity_error[:10] == "0xdeb13018":  # SimulationResult
                return (int(failed_op_params_res[1]),
                        int(failed_op_params_res[0]))

            elif solidity_error[:10] == "0x22cf94e6":  # EstimateCallGasContinuation
                if int(failed_op_params_res[2]) > 30:
                    break
                min_gas = int(failed_op_params_res[0])
                max_gas = int(failed_op_params_res[1])
                is_continious = True
            elif solidity_error[:10] == "0x59f233d2":  # EstimateCallGasRevertAtMax
                error_message = failed_op_params_res[0]
                raise ExecutionException(
                    ExecutionExceptionCode.UserOperationReverted,
                    str(bytes([b for b in error_message if b != 0]))  # remove zero bytes from error message
                )
        # this should not be reached
        logging.critical(
                "Unexpected error during estimate_call_gas_and_verificationgas_limit")
        raise ValueError(
                "Unexpected error during estimate_call_gas_and_verificationgas_limit")

    async def simulate_handle_op_mod(
        self,
        user_operation: UserOperationV6,
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
                # override the Entrypoint with EntryPointSimulationsV6 for callGasLimit
                # binary search
                "code": self.entrypoint_code_override
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
            # this should never happen
            logging.critical("simulateHandleOpMod didn't revert!")
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
        if error_selector == "0xdeb13018":  # SimulationResult
            error_params_api = [
                "uint256",  # verificationGasLimit
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
        elif error_selector == FailedOp.SELECTOR:
            (
                _,
                reason,
            ) = decode_failed_op_event(error_params)
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

    def calc_base_preverification_gas(self, user_operation: UserOperationV6) -> int:
        user_operation_list = user_operation.to_list()

        user_operation_list[6] = 21000

        # set a dummy signature only if the user didn't supply any
        if len(cast(bytes, user_operation_list[10])) < 65:
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

        packed = pack_user_operation(
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
