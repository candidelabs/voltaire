import logging
import os
from typing import Any
from eth_abi import decode, encode

import voltaire_bundler
from voltaire_bundler.bundle.exceptions import \
    ValidationException, ValidationExceptionCode
from voltaire_bundler.user_operation.models import \
    AggregatorStakeInfo, FailedOp, ReturnInfo, StakeInfo
from voltaire_bundler.user_operation.user_operation_handler import decode_failed_op_event
from voltaire_bundler.user_operation.user_operation_v6 import UserOperationV6
from voltaire_bundler.user_operation.user_operation_handler_v6 import \
    UserOperationHandlerV6
from voltaire_bundler.utils.eth_client_utils import send_rpc_request_to_eth_client
from voltaire_bundler.utils.load_bytecode import load_bytecode
from .validation_manager import ValidationManager
from voltaire_bundler.user_operation.user_operation_v6 import \
        get_user_operation_hash
from voltaire_bundler.validation.tracer_manager import TracerManager


ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


class ValidationManagerV6(ValidationManager):
    user_operation_handler: UserOperationHandlerV6

    def __init__(
        self,
        user_operation_handler: UserOperationHandlerV6,
        ethereum_node_url: str,
        bundler_address: str,
        chain_id: int,
        is_unsafe: bool,
        is_legacy_mode: bool,
        enforce_gas_price_tolerance: int,
        ethereum_node_debug_trace_call_url: str,
    ):
        self.user_operation_handler = user_operation_handler
        self.tracer_manager = TracerManager(ethereum_node_url, bundler_address)
        self.ethereum_node_url = ethereum_node_url
        self.bundler_address = bundler_address
        self.chain_id = chain_id
        self.is_unsafe = is_unsafe
        self.is_legacy_mode = is_legacy_mode
        self.enforce_gas_price_tolerance = enforce_gas_price_tolerance
        self.ethereum_node_debug_trace_call_url = ethereum_node_debug_trace_call_url

        package_directory = os.path.dirname(
                os.path.abspath(voltaire_bundler.__file__))
        bundler_collector_tracer_file = os.path.join(
            package_directory, "validation", "BundlerCollectorTracer.js"
        )
        with open(bundler_collector_tracer_file) as keyfile:
            self.bundler_collector_tracer = keyfile.read()

        self.entrypoint_code_override = load_bytecode(
            "EntryPointSimulationsV7.json")

    async def validate_user_operation(
        self,
        user_operation: UserOperationV6,
        entrypoint: str,
        block_number: str,
        latest_block_timestamp: int,
        min_stake: int,
        min_unstake_delay: int,
    ) -> tuple[
        StakeInfo,
        StakeInfo | None,
        StakeInfo | None,
        AggregatorStakeInfo | None,
        str,
        list[str] | None,
        dict[str, str | dict[str, str]] | None,
        bytes
    ]:
        debug_data: Any = None
        if self.is_unsafe:
            (
                selector,
                validation_result,
            ) = await self.simulate_validation_without_tracing(
                user_operation, entrypoint
            )
        else:
            debug_data = await self.simulate_validation_with_tracing(
                user_operation, entrypoint, block_number
            )
            selector = debug_data["calls"][-1]["data"][:10]
            validation_result = debug_data["calls"][-1]["data"][10:]

        if selector == FailedOp.SELECTOR:
            _, reason = decode_failed_op_event(validation_result)
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                "revert reason : " + reason,
            )

        (
            return_info,
            sender_stake_info,
            factory_stake_info,
            paymaster_stake_info,
        ) = ValidationManagerV6.decode_validation_result(validation_result)
        ValidationManagerV6.verify_sig_and_timestamp(
            return_info.sigFailed,
            return_info.validUntil,
            return_info.validAfter,
            latest_block_timestamp
        )

        user_operation_hash = get_user_operation_hash(
            user_operation.to_list(), entrypoint, self.chain_id
        )

        if self.is_unsafe:
            associated_addresses = None
            storage_map = None
        else:
            is_sender_staked = (
                sender_stake_info.stake >= min_stake and
                sender_stake_info.unstakeDelaySec >= min_unstake_delay
            )

            if user_operation.factory_address_lowercase is None:
                is_factory_staked = None
            else:
                is_factory_staked = (
                    factory_stake_info.stake >= min_stake and
                    factory_stake_info.unstakeDelaySec >= min_unstake_delay
                )
            if user_operation.paymaster_address_lowercase is None:
                is_paymaster_staked = None
            else:
                is_paymaster_staked = (
                    paymaster_stake_info.stake >= min_stake and
                    paymaster_stake_info.unstakeDelaySec >= min_unstake_delay
                )

            (
                associated_addresses,
                storage_map
            ) = await self.tracer_manager.validate_trace_results(
                user_operation,
                entrypoint,
                is_sender_staked,
                is_factory_staked,
                is_paymaster_staked,
                debug_data,
            )

        verification_cost = return_info.preOpGas - user_operation.pre_verification_gas
        extra_gas = user_operation.verification_gas_limit - verification_cost

        if extra_gas < 2000:
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                f"verificationGas should have extra 2000 gas. has only {extra_gas}",
            )

        return (
            sender_stake_info,
            factory_stake_info,
            paymaster_stake_info,
            None,
            user_operation_hash,
            associated_addresses,
            storage_map,
            return_info.paymasterContext
        )

    async def simulate_validation_without_tracing(
        self, user_operation: UserOperationV6, entrypoint: str
    ) -> tuple[str, str]:
        call_data = ValidationManagerV6.encode_simulate_validation_calldata(
                user_operation)

        params = [
            {
                "from": ZERO_ADDRESS,
                "to": entrypoint,
                "data": call_data,
            },
            "latest",
        ]
        result: Any = await send_rpc_request_to_eth_client(
            self.ethereum_node_url, "eth_call", params
        )
        if ("error" not in result):
            # this should never happen
            logging.critical("simulateValidation didn't revert!")
            raise ValueError("simulateValidation didn't revert!")
        elif (
                "revert" not in result["error"]["message"]
                or
                "data" not in result["error"]
                or
                len(result["error"]["data"]) < 10
        ):
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                result["error"]["message"],
            )

        error_data = result["error"]["data"]
        solidity_error_selector = str(error_data[:10])
        solidity_error_params = error_data[10:]

        return solidity_error_selector, solidity_error_params

    async def simulate_validation_with_tracing(
        self,
        user_operation: UserOperationV6,
        entrypoint: str,
        block_number: str,
    ) -> str:
        call_data = ValidationManagerV6.encode_simulate_validation_calldata(
            user_operation
        )

        params = [
            {
                "from": ZERO_ADDRESS,
                "to": entrypoint,
                "data": call_data,
            },
            block_number,
            {"tracer": self.bundler_collector_tracer},
        ]
        res: Any = await send_rpc_request_to_eth_client(
            self.ethereum_node_debug_trace_call_url, "debug_traceCall", params
        )

        if "result" in res:
            debug_data = res["result"]
            return debug_data

        elif "error" in res and "message" in res["error"]:
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                res["error"]["message"]
            )
        else:
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                "Invalid Validation result from debug_traceCall",
            )

    @staticmethod
    def decode_validation_result(
        solidity_error_params: str,
    ) -> tuple[ReturnInfo, StakeInfo, StakeInfo, StakeInfo]:
        VALIDATION_RESULT_ABI = [
            "(uint256,uint256,bool,uint64,uint64,bytes)",
            "(uint256,uint256)",
            "(uint256,uint256)",
            "(uint256,uint256)",
        ]
        try:
            validation_result_decoded = decode(
                VALIDATION_RESULT_ABI, bytes.fromhex(solidity_error_params)
            )
        except Exception:
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                str(bytes.fromhex(solidity_error_params)),
            )

        return_info_arr = validation_result_decoded[0]
        return_info = ReturnInfo(
            preOpGas=return_info_arr[0],
            prefund=return_info_arr[1],
            sigFailed=return_info_arr[2],
            validAfter=return_info_arr[3],
            validUntil=return_info_arr[4],
            paymasterContext=return_info_arr[5],
        )

        sender_info_arr = validation_result_decoded[1]
        sender_info = StakeInfo(
            stake=sender_info_arr[0], unstakeDelaySec=sender_info_arr[1]
        )

        factory_info_arr = validation_result_decoded[2]
        factory_info = StakeInfo(
            stake=factory_info_arr[0], unstakeDelaySec=factory_info_arr[1]
        )

        paymaster_info_arr = validation_result_decoded[3]
        paymaster_info = StakeInfo(
            stake=paymaster_info_arr[0], unstakeDelaySec=paymaster_info_arr[1]
        )

        return (
            return_info,
            sender_info,
            factory_info,
            paymaster_info,
        )

    @staticmethod
    def encode_simulate_validation_calldata(user_operation: UserOperationV6) -> str:
        # simulateValidation(entrypoint solidity function) will always revert
        function_selector = "0xee219423"
        params = encode(
            [
                "(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)"
            ],
            [user_operation.to_list()],
        )

        return function_selector + params.hex()
