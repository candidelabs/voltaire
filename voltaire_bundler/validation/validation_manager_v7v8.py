import asyncio
import os
import logging
from typing import Any
from eth_abi import decode, encode
from eth_utils import keccak
from eth_utils import ValidationError as EthUtilsValidationError
from eth_keys import KeyAPI
from eth_keys.exceptions import BadSignature
from rlp import encode as rlp_encode
import voltaire_bundler
from voltaire_bundler.bundle.exceptions import \
    ValidationException, ValidationExceptionCode
from voltaire_bundler.user_operation.user_operation_handler import decode_failed_op_event, decode_failed_op_with_revert_event
from voltaire_bundler.user_operation.user_operation_v7v8 import UserOperationV7V8
from voltaire_bundler.user_operation.user_operation_handler_v7v8 import \
    UserOperationHandlerV7V8
from voltaire_bundler.utils.eth_client_utils import send_rpc_request_to_eth_client
from voltaire_bundler.user_operation.user_operation_v7v8 import \
        get_user_operation_hash
from voltaire_bundler.utils.load_bytecode import load_bytecode
from voltaire_bundler.user_operation.models import (
        AggregatorStakeInfo, FailedOp, FailedOpWithRevert, PaymasterValidationData,
        ReturnInfoV7, SenderValidationData, StakeInfo)
from voltaire_bundler.validation.tracer_manager import TracerManager
from .validation_manager import ValidationManager
from voltaire_bundler.typing import Address
from voltaire_bundler.utils.eip7702 import format_hex_array_for_rlp_encode

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


class ValidationManagerV7V8(ValidationManager):
    user_operation_handler: UserOperationHandlerV7V8

    def __init__(
        self,
        user_operation_handler: UserOperationHandlerV7V8,
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

        package_directory = os.path.dirname(os.path.abspath(voltaire_bundler.__file__))
        bundler_collector_tracer_file = os.path.join(
            package_directory, "validation", "BundlerCollectorTracer.js"
        )
        with open(bundler_collector_tracer_file) as keyfile:
            self.bundler_collector_tracer = keyfile.read()

        self.entrypoint_code_override_v7 = load_bytecode(
            "EntryPointSimulationsV7.json")
        self.entrypoint_code_override_v8 = load_bytecode(
            "EntryPointSimulationsV8.json")

    async def validate_user_operation(
        self,
        user_operation: UserOperationV7V8,
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
            validation_result = await self.simulate_validation_without_tracing(
                user_operation, entrypoint
            )
        else:
            validation_result, debug_data = await self.simulate_validation_with_tracing(
                user_operation, entrypoint, block_number
            )
        (
            return_info,
            sender_stake_info,
            factory_stake_info,
            paymaster_stake_info,
            aggregator_stake_info,
        ) = ValidationManagerV7V8.decode_validation_result(validation_result)
        ValidationManagerV7V8.verify_sig_and_timestamp(
            return_info.sender_validation_data.sig_failed,
            return_info.sender_validation_data.valid_until,
            return_info.sender_validation_data.valid_after,
            latest_block_timestamp
        )
        ValidationManagerV7V8.verify_sig_and_timestamp(
            return_info.paymaster_validation_data.sig_failed,
            return_info.paymaster_validation_data.valid_until,
            return_info.paymaster_validation_data.valid_after,
            latest_block_timestamp
        )

        if (
            user_operation.eip7702_auth is not None and
            "address" in user_operation.eip7702_auth
        ):
            user_operation_hash = get_user_operation_hash(
                user_operation.to_list(),
                entrypoint,
                self.chain_id,
                user_operation.eip7702_auth["address"]
            )
        else:
            user_operation_hash = get_user_operation_hash(
                user_operation.to_list(), entrypoint, self.chain_id
            )

        if self.is_unsafe:
            addresses_called = None
            storage_map = None
        else:
            is_sender_staked = (
                sender_stake_info.stake >= min_stake and
                sender_stake_info.unstakeDelaySec >= min_unstake_delay
            )

            if user_operation.factory_address_lowercase is None:
                is_factory_staked = None
            elif user_operation.factory_address_lowercase == "0x7702000000000000000000000000000000000000":
                is_factory_staked = False
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

            addresses_called, storage_map = await self.tracer_manager.validate_trace_results(
                user_operation,
                entrypoint,
                is_sender_staked,
                is_factory_staked,
                is_paymaster_staked,
                debug_data,
            )

        verification_cost = return_info.pre_op_gas - user_operation.pre_verification_gas
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
            aggregator_stake_info,
            user_operation_hash,
            addresses_called,
            storage_map,
            return_info.paymaster_context
        )

    async def simulate_validation_without_tracing(
        self, user_operation: UserOperationV7V8, entrypoint: str
    ) -> str:
        call_data = ValidationManagerV7V8.encode_simulate_validation_calldata(
                user_operation)
        if entrypoint.lower() == "0x4337084d9e255ff0702461cf8895ce9e3b5ff108":
            entrypoint_code_override = self.entrypoint_code_override_v8
        else:
            entrypoint_code_override = self.entrypoint_code_override_v7
        state_overrides = {  # override the Entrypoint with EntryPointSimulationsV7
            entrypoint: {"code": entrypoint_code_override}
        }

        if user_operation.eip7702_auth is not None:
            new_code = await self.verify_authorization_and_get_code(
                user_operation.sender_address,
                user_operation.eip7702_auth
            )
            if new_code is not None:
                state_overrides[user_operation.sender_address] = {"code": new_code}

        params = [
            {
                "from": ZERO_ADDRESS,
                "to": entrypoint,
                "data": call_data,
            },
            "latest",
            state_overrides
        ]

        result: Any = await send_rpc_request_to_eth_client(
            self.ethereum_node_url, "eth_call", params
        )
        if (
            "result" in result
        ):
            return result["result"][2:]
        elif (
                "error" in result and
                "message" in result["error"]
        ):
            if "data" in result["error"]:
                error_data = result["error"]["data"]
                selector = str(error_data[:10])
                error_params = error_data[10:]

                if selector == FailedOp.SELECTOR:
                    _, reason = decode_failed_op_event(error_params)
                    raise ValidationException(
                        ValidationExceptionCode.SimulateValidation,
                        "revert reason : " + reason,
                    )
                elif selector == FailedOpWithRevert.SELECTOR:
                    operation_index, reason, inner = decode_failed_op_with_revert_event(
                        error_params
                    )

                    raise ValidationException(
                        ValidationExceptionCode.SimulateValidation,
                        reason + str(
                            bytes([b for b in inner if b != 0]))
                    )

            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                result["error"]["message"],
            )
        else:
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                "",
            )

    async def simulate_validation_with_tracing(
        self,
        user_operation: UserOperationV7V8,
        entrypoint: str,
        block_number: str,
    ) -> tuple[str, str]:
        call_data = ValidationManagerV7V8.encode_simulate_validation_calldata(
            user_operation)
        if entrypoint.lower() == "0x4337084d9e255ff0702461cf8895ce9e3b5ff108":
            entrypoint_code_override = self.entrypoint_code_override_v8
        else:
            entrypoint_code_override = self.entrypoint_code_override_v7
        state_overrides = {  # override the Entrypoint with EntryPointSimulationsV7
            entrypoint: {"code": entrypoint_code_override}
        }

        if user_operation.eip7702_auth is not None:
            new_code = await self.verify_authorization_and_get_code(
                user_operation.sender_address,
                user_operation.eip7702_auth
            )
            if new_code is not None:
                state_overrides[user_operation.sender_address] = {"code": new_code}
        params = [
            {
                "from": ZERO_ADDRESS,
                "to": entrypoint,
                "data": call_data,
            },
            block_number,
            {
                "tracer": self.bundler_collector_tracer,
                "stateOverrides": state_overrides
            }
        ]
        res: Any = await send_rpc_request_to_eth_client(
            self.ethereum_node_debug_trace_call_url, "debug_traceCall", params
        )
        if "result" in res:
            debug_data = res["result"]
            selector = debug_data["calls"][-1]["data"][:10]
            remaining_result = debug_data["calls"][-1]["data"][10:]
            if selector == FailedOp.SELECTOR:
                _, reason = decode_failed_op_event(remaining_result)
                raise ValidationException(
                    ValidationExceptionCode.SimulateValidation,
                    "revert reason : " + reason,
                )
            elif selector == FailedOpWithRevert.SELECTOR:
                operation_index, reason, inner = decode_failed_op_with_revert_event(
                    remaining_result
                )

                raise ValidationException(
                    ValidationExceptionCode.SimulateValidation,
                    reason + str(
                        bytes([b for b in inner if b != 0]))
                )
            elif selector == "0x08c379a0":  # Error(string)
                reason = decode(
                    ["string"], bytes.fromhex(remaining_result)
                )  # decode revert message

                raise ValidationException(
                    ValidationExceptionCode.SimulateValidation,
                    reason[0],
                )

            validation_result = debug_data["calls"][-1]["data"][2:]
            return validation_result, debug_data

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
    
    async def verify_authorization_and_get_code(
        self,
        sender_address: Address,
        authorization: dict[str, str],
    ) -> str | None:
        chain_id_hex = authorization["chainId"][2:]
        chain_id = int(chain_id_hex, 16)
        if chain_id != self.chain_id and chain_id != 0:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Invalid eip7702Auth chainId.",
            )

        auth_hash = keccak(
            bytes.fromhex(
                "05" +  # magic value
                rlp_encode(
                    format_hex_array_for_rlp_encode(
                        [
                            authorization["chainId"],
                            authorization["address"],
                            authorization["nonce"],
                        ]
                    )
                ).hex()
            )
        )
        try:
            y_parity = authorization["yParity"]
            r = authorization["r"]
            s = authorization["s"]
            signature = KeyAPI.Signature(
                vrs=(
                    int(y_parity, 16),
                    int(r, 16),
                    int(s, 16)
                )
            )
            auth_signer_address = signature.recover_public_key_from_msg_hash(
                auth_hash
            ).to_address()
        except EthUtilsValidationError or BadSignature as excp:
            logging.error(
                f"Failed to recover authorization for address: {authorization["address"]}."
                f"error:{str(excp)}"
            )
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                f"Failed to recover authorization for address: {authorization["address"]}."
            )
        if sender_address.lower() != auth_signer_address.lower():
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                f"Userop sender: {sender_address} is not equal to auth signer "
                f"recovered address {auth_signer_address}"
            )

        existing_code_op = send_rpc_request_to_eth_client(
            self.ethereum_node_url,
            "eth_getCode",
            [sender_address, "latest"],
            None, "result"
        )
        nonce_op = send_rpc_request_to_eth_client(
            self.ethereum_node_url,
            "eth_getTransactionCount",
            [sender_address, "latest"], None, "result"
        )
        tasks_arr = [existing_code_op, nonce_op]
        tasks = await asyncio.gather(*tasks_arr)
        existing_code = tasks[0]["result"]
        current_nonce = tasks[1]["result"]

        new_code = "0xef0100" + authorization["address"][2:]
        if (
                existing_code == new_code or
                int(authorization["nonce"], 16) != int(current_nonce, 16)
        ):
            return None
        return new_code

    @staticmethod
    def decode_validation_result(
        solidity_error_params: str,
    ) -> tuple[ReturnInfoV7, StakeInfo, StakeInfo,
               StakeInfo, AggregatorStakeInfo]:
        VALIDATION_RESULT_ABI = [
            "((uint256,uint256,uint256,uint256,bytes),(uint256,uint256),(uint256,uint256),(uint256,uint256),(address,(uint256,uint256)))"
        ]
        try:
            validation_result_decoded = decode(
                    VALIDATION_RESULT_ABI, bytes.fromhex(solidity_error_params)
            )[0]
        except Exception:
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                str(bytes.fromhex(solidity_error_params)),
            )

        return_info_arr = validation_result_decoded[0]

        sender_validation_data_bytes = encode(["uint256"], [return_info_arr[2]])
        sender_validation_data_int = int(sender_validation_data_bytes.hex() ,16)
        if sender_validation_data_int > 1:
            sig_failed_or_aggregator = sender_validation_data_bytes[12:].hex()
            if int(sig_failed_or_aggregator, 16) > 1:
                sender_sig_failed = None
                aggregator = '0x' + sig_failed_or_aggregator
            else:
                sender_sig_failed = (int(sig_failed_or_aggregator, 16) == 1)
                aggregator = None
            sender_valid_until_int = int(sender_validation_data_bytes[6:12].hex(), 16)
            if sender_valid_until_int == 0:
                sender_valid_until = 18446744073709551615  # type(uint64).max
            else:
                sender_valid_until = sender_valid_until_int
            sender_valid_after = int(sender_validation_data_bytes[:6].hex() ,16)
        else:
            # the most likely validation_data_int is either 0 or 1
            # this is why a separate branch is created
            sender_sig_failed = (sender_validation_data_int == 1)
            aggregator = None
            sender_valid_until = 18446744073709551615  # type(uint64).max
            sender_valid_after = 0
        sender_validation_data = SenderValidationData(
            sig_failed=sender_sig_failed,
            aggregator=aggregator,
            valid_until=sender_valid_until,
            valid_after=sender_valid_after
        )

        paymaster_validation_data_bytes = encode(["uint256"], [return_info_arr[3]])
        paymaster_validation_data_int = int(paymaster_validation_data_bytes.hex() ,16)
        if paymaster_validation_data_int > 1:
            paymaster_sig_failed = (
                int(paymaster_validation_data_bytes[12:].hex(), 16) == 1
            )
            paymaster_valid_until_int = int(paymaster_validation_data_bytes[6:12].hex(), 16)
            if paymaster_valid_until_int == 0:
                paymaster_valid_until = 18446744073709551615  # type(uint64).max
            else:
                paymaster_valid_until = paymaster_valid_until_int
            paymaster_valid_after = int(paymaster_validation_data_bytes[:6].hex() ,16)
        else:
            # the most likely validation_data_int is either 0 or 1
            # this is why a separate branch is created
            paymaster_sig_failed = (paymaster_validation_data_int == 1)
            paymaster_valid_until = 18446744073709551615  # type(uint64).max
            paymaster_valid_after = 0

        paymaster_validation_data = PaymasterValidationData(
            sig_failed=paymaster_sig_failed,
            valid_until=paymaster_valid_until,
            valid_after=paymaster_valid_after
        )

        return_info = ReturnInfoV7(
            pre_op_gas=return_info_arr[0],
            prefund=return_info_arr[1],
            sender_validation_data=sender_validation_data,
            paymaster_validation_data=paymaster_validation_data,
            paymaster_context=return_info_arr[4],
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

        aggregator_staked_arr = validation_result_decoded[4]
        aggregator_staked_info = AggregatorStakeInfo(
            aggregator=aggregator_staked_arr[0],
            stake_info=StakeInfo(
                aggregator_staked_arr[1][0], aggregator_staked_arr[1][1]
            )
        )

        return (
            return_info,
            sender_info,
            factory_info,
            paymaster_info,
            aggregator_staked_info,
        )

    @staticmethod
    def encode_simulate_validation_calldata(user_operation: UserOperationV7V8) -> str:
        # simulateValidation(entrypoint solidity function) will always revert
        function_selector = "0xc3bce009"
        params = encode(
            [
                "(address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)"
            ],
            [user_operation.to_list()],
        )

        return function_selector + params.hex()
