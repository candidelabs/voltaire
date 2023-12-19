import asyncio
from functools import reduce
import math
from eth_abi import encode, decode

from voltaire_bundler.user_operation.user_operation import UserOperation
from voltaire_bundler.user_operation.user_operation_handler import (
    UserOperationHandler,
)

from voltaire_bundler.bundler.exceptions import (
    ExecutionException,
    ExecutionExceptionCode,
    ValidationException,
    ValidationExceptionCode,
)
from voltaire_bundler.utils.eth_client_utils import (
    send_rpc_request_to_eth_client,
    get_latest_block_info
)
from voltaire_bundler.utils.decode import (
    decode_ExecutionResult,
    decode_FailedOp_event,
    decode_gasEstimateL1Component_result,
)

from voltaire_bundler.utils.encode import (
    encode_handleops_calldata,
    encode_gasEstimateL1Component_calldata,
)

MAX_VERIFICATION_GAS_LIMIT = 10000000
MIN_CALL_GAS_LIMIT = 21000

class GasManager:
    ethereum_node_url: str
    chain_id: str
    is_legacy_mode: bool
    max_fee_per_gas_percentage_multiplier: int
    max_priority_fee_per_gas_percentage_multiplier: int

    def __init__(
        self, 
        ethereum_node_url, 
        chain_id, 
        is_legacy_mode,
        max_fee_per_gas_percentage_multiplier: int,
        max_priority_fee_per_gas_percentage_multiplier: int,
    ):
        self.ethereum_node_url = ethereum_node_url
        self.chain_id = chain_id
        self.is_legacy_mode = is_legacy_mode
        self.max_fee_per_gas_percentage_multiplier = max_fee_per_gas_percentage_multiplier
        self.max_priority_fee_per_gas_percentage_multiplier = max_priority_fee_per_gas_percentage_multiplier

    async def estimate_callgaslimit_and_preverificationgas_and_verificationgas(
        self, 
        user_operation: UserOperation,
        entrypoint:str, 
    ) -> [str, str, str]:
        latest_block_number, latest_block_basefee, latest_block_gas_limit_hex = await get_latest_block_info(self.ethereum_node_url)

        preverification_gas = await self.get_preverification_gas(
            user_operation, entrypoint, latest_block_number, latest_block_basefee
        )
        preverification_gas_hex = hex(preverification_gas)

        user_operation.pre_verification_gas = preverification_gas
        user_operation.verification_gas_limit = MAX_VERIFICATION_GAS_LIMIT

        call_data = user_operation.call_data
        user_operation.call_data = bytes(0)
        user_operation.call_gas_limit = 0 #

        # Call simulateHandleOp with empty callData and pass callData to simulateHandleOp target param
        # to be able to get determine if callData was reverted and retrieve the revert error
        (
            preOpGas,
            _,
            targetSuccess,
            targetResult,
        ) = await self.simulate_handle_op(
            user_operation,
            entrypoint,
            latest_block_number,
            latest_block_gas_limit_hex,
            user_operation.sender_address,
            call_data,
        )

        if not targetSuccess:
            raise ExecutionException(
                ExecutionExceptionCode.EXECUTION_REVERTED, targetResult,
            )
        user_operation.call_data = call_data
        verification_gas_limit = math.ceil(
            (preOpGas - user_operation.pre_verification_gas) * 1.1
        )
        verification_gas_hex = hex(verification_gas_limit)

        call_gas_limit_hex = await self.estimate_call_gas_limit(
                call_data="0x" + user_operation.call_data.hex(),
                _from=entrypoint,
                to=user_operation.sender_address,
            )
        if call_gas_limit_hex == "0x":
            call_gas_limit = 0
        else:
            call_gas_limit = int(call_gas_limit_hex, 16)

        call_gas_limit = max(MIN_CALL_GAS_LIMIT, call_gas_limit)
        call_gas_limit_hex = hex(call_gas_limit)

        return (
            call_gas_limit_hex,
            preverification_gas_hex,
            verification_gas_hex,
        )

    async def estimate_call_gas_limit(self, call_data, _from, to):
        if call_data == "0x":
            return "0x"

        params = [{"from": _from, "to": to, "data": call_data}]

        result = await send_rpc_request_to_eth_client(
            self.ethereum_node_url, "eth_estimateGas", params
        )
        if "error" in result:
            errorMessage = result["error"]["message"]
            errorParams = ""
            if "data" in result["error"]:
                errorData = result["error"]["data"]
                errorParams = errorData[10:]
            raise ExecutionException(
                ExecutionExceptionCode.EXECUTION_REVERTED,
                errorMessage + " " + bytes.fromhex(errorParams[-64:]).decode("ascii"),
            )
        call_gas_limit = result["result"]

        return call_gas_limit

    async def simulate_handle_op(
        self,
        user_operation: UserOperation,
        entrypoint:str,
        bloch_number_hex: str,
        gasLimit,
        target: str = "0x0000000000000000000000000000000000000000",
        target_call_data: bytes = bytes(0),
    ):
        # simulateHandleOp(entrypoint solidity function) will always revert
        function_selector = "0xd6383f94"
        params = encode(
            [
                "(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)",  # useroperation
                "address",  # target (Optional - to check the )
                "bytes",  # targetCallData
            ],
            [user_operation.to_list(), target, target_call_data],
        )

        call_data = function_selector + params.hex()

        params = [
            {
                "from": "0x0000000000000000000000000000000000000000",
                "to": entrypoint,
                "data": call_data,
                "gas": gasLimit,
                # "gasPrice": "0x0",
            },
            bloch_number_hex,
            {
                "0x0000000000000000000000000000000000000000": {
                    "balance": "0x21E19E0C9BAB2400000"  # to make sure that the zero address is wel funded for gas estimation
                },
                user_operation.sender_address: {  # to make sure that the sender address is wel funded for gas estimation
                    "balance": "0x21E19E0C9BAB2400000"
                },
            },
        ]

        result = await send_rpc_request_to_eth_client(
            self.ethereum_node_url, "eth_call", params
        )
        if (
            "error" not in result
            or "execution reverted" not in result["error"]["message"]
        ):
            raise ValueError("simulateHandleOp didn't revert!")

        elif (
            "data" not in result["error"] or len(result["error"]["data"]) < 10
        ):
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                result["error"]["message"],
            )

        error_data = result["error"]["data"]
        solidity_error_selector = str(error_data[:10])
        solidity_error_params = error_data[10:]

        if solidity_error_selector == "0x8b7ac980":
            (
                preOpGas,
                paid,
                targetSuccess,
                targetResult,
            ) = decode_ExecutionResult(solidity_error_params)
        elif solidity_error_selector == "0x220266b6":
            (
                _,
                reason,
            ) = decode_FailedOp_event(solidity_error_params)
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                reason,
            )
        elif solidity_error_selector == "0x08c379a0":  # Error(string)
            reason = decode(
                ["string"], bytes.fromhex(solidity_error_params)
            )  # decode revert message

            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                reason[0],
            )
        else:
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                solidity_error_params,
            )

        return preOpGas, paid, targetSuccess, targetResult

    async def verify_gas_fees_and_get_price(
        self, user_operation: UserOperation, enforce_gas_price_tolerance:int
    ) -> int:
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

        tasks = await asyncio.gather(*tasks_arr)

        block_max_fee_per_gas_hex = tasks[0]["result"]
        block_max_fee_per_gas = int(tasks[0]["result"], 16)
        block_max_fee_per_gas = math.ceil(block_max_fee_per_gas * (self.max_fee_per_gas_percentage_multiplier/100))
        block_max_fee_per_gas_with_tolerance = math.ceil(block_max_fee_per_gas * (1 - (enforce_gas_price_tolerance/100)))
        block_max_fee_per_gas_with_tolerance_hex = hex(block_max_fee_per_gas_with_tolerance)

        if enforce_gas_price_tolerance < 100:
            if self.is_legacy_mode:
                block_max_priority_fee_per_gas = block_max_fee_per_gas
                if max_fee_per_gas < block_max_fee_per_gas_with_tolerance:
                    raise ValidationException(
                        ValidationExceptionCode.SimulateValidation,
                        f"Max fee per gas is too low. it should be minimum : {block_max_fee_per_gas_with_tolerance_hex}",
                    )

            else:
                block_max_priority_fee_per_gas = int(tasks[1]["result"], 16)
                block_max_priority_fee_per_gas = math.ceil(block_max_priority_fee_per_gas * (self.max_priority_fee_per_gas_percentage_multiplier/100))

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
                        f"Max priority fee per gas is too low. it should be minimum : 1",
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
        latest_block_number:str,
        latest_block_basefee:int,
    ) -> None:
        expected_preverification_gas = await self.get_preverification_gas(
            user_operation, entrypoint, latest_block_number, latest_block_basefee
        )

        if user_operation.pre_verification_gas < expected_preverification_gas:
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                f"Preverification gas is too low. it should be minimum : {hex(expected_preverification_gas)}",
            )

        if user_operation.verification_gas_limit > MAX_VERIFICATION_GAS_LIMIT:
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                f"Verification gas is too high. it should be maximum : {hex(MAX_VERIFICATION_GAS_LIMIT)}",
            )

    async def calc_l1_gas_estimate_optimism(
        self, user_operation: UserOperation, 
        block_number_hex: str,
        latest_block_base_fee: int
    ) -> int:

        user_operations_list = [user_operation.to_list()]

        # currently most bundles contains a singler useroperations
        # so l1 fees is calculated for the full handleops transaction 
        handleops_calldata = encode_handleops_calldata(
            user_operations_list, "0x0000000000000000000000000000000000000000"
        )

        optimism_gas_oracle_contract_address = (
            "0x420000000000000000000000000000000000000F"
        )

        function_selector = "0x49948e0e" # getL1Fee
        params = encode(
            ["bytes"], 
            [bytes.fromhex(handleops_calldata[2:])]
        )

        call_data = function_selector + params.hex()

        params = [
            {
                "from": "0x0000000000000000000000000000000000000000",
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
        l2_gas_price = max(1, l2_gas_price) #in case l2_gas_price = 0

        gas_estimate_for_l1 = math.ceil(l1_fee / l2_gas_price)

        return gas_estimate_for_l1

    async def calc_l1_gas_estimate_arbitrum(
        self, user_operation: UserOperation, entrypoint:str
    ) -> int:
        arbitrum_nodeInterface_address = (
            "0x00000000000000000000000000000000000000C8"
        )

        is_init: bool = user_operation.nonce == 0

        user_operations_list = [user_operation.to_list()]

        handleops_calldata = encode_handleops_calldata(
            user_operations_list, "0x0000000000000000000000000000000000000000"
        )

        call_data = encode_gasEstimateL1Component_calldata(
            entrypoint, is_init, handleops_calldata
        )

        params = [
            {
                "from": "0x0000000000000000000000000000000000000000",
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

    async def get_preverification_gas(
        self,
        user_operation: UserOperation,
        entrypoint: str,
        block_number_hex: str,
        latest_block_base_fee: int,
        preverification_gas_percentage_coefficient: int = 100,
        preverification_gas_addition_constant: int = 0,
    ) -> int:
        base_preverification_gas = GasManager.calc_base_preverification_gas(
            user_operation
        )
        l1_gas = 0

        if self.chain_id == 10 or self.chain_id == 420:  # optimism and optimism goerli
            l1_gas = await self.calc_l1_gas_estimate_optimism(
                user_operation, block_number_hex, latest_block_base_fee
            )
        elif self.chain_id == 42161:  # arbitrum One
            l1_gas = await self.calc_l1_gas_estimate_arbitrum(user_operation, entrypoint)

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

        #set a dummy signature only if the user didn't supply any
        if(len(user_operation_list[10]) < 65):
            user_operation_list[
                10
            ] = b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"  # signature

        fixed = 21000
        per_user_operation = 18300
        per_user_operation_word = 4
        zero_byte = 4
        non_zero_byte = 16
        bundle_size = 1
        # sigSize = 65

        packed = UserOperationHandler.pack_user_operation(
            user_operation_list, False
        )
        packed_length = len(packed)
        zero_byte_count = packed.count(b"\x00")
        non_zero_byte_count = packed_length - zero_byte_count
        call_data_cost = zero_byte_count * zero_byte + non_zero_byte_count * non_zero_byte

        length_in_words = math.ceil((packed_length + 31) /32)
        # cost_list = list(
        #     map(lambda x: zero_byte if x == b"\x00" else non_zero_byte, packed)
        # )
        # call_data_cost = reduce(lambda x, y: x + y, cost_list)

        pre_verification_gas = (
            call_data_cost
            + (fixed / bundle_size)
            + per_user_operation
            + per_user_operation_word * length_in_words
        )

        return math.ceil(pre_verification_gas)
