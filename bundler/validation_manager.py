import asyncio
from functools import reduce
import math

from web3 import Web3
from eth_abi import decode

from user_operation.user_operation import UserOperation
from user_operation.models import ReturnInfo, StakeInfo, FailedOpRevertData
from bundler.exceptions import (
    BundlerException,
    BundlerExceptionCode,
    ValidationException,
    ValidationExceptionCode,
)
from utils.eth_client_utils import (
    send_rpc_request_to_eth_client,
    DebugTraceCallData,
    DebugEntityData,
)


class ValidationManager:
    geth_rpc_url: str
    bundler_private_key: str
    bundler_address: str
    entrypoint: str
    entrypoint_abi: str
    bundler_collector_tracer: str
    banned_opcodes: list()

    def __init__(
        self,
        geth_rpc_url,
        bundler_private_key,
        bundler_address,
        entrypoint,
        entrypoint_abi,
    ):
        self.geth_rpc_url = geth_rpc_url
        self.bundler_private_key = bundler_private_key
        self.bundler_address = bundler_address
        self.entrypoint = entrypoint
        self.entrypoint_abi = entrypoint_abi

        path = "utils/BundlerCollectorTracer.min.js"
        with open(path) as keyfile:
            self.bundler_collector_tracer = keyfile.read()

        self.banned_opcodes = [
            "GAS",
            "NUMBER",
            "TIMESTAMP",
            "COINBASE",
            "DIFFICULTY",
            "BASEFEE",
            "GASLIMIT",
            "GASPRICE",
            "SELFBALANCE",
            "BALANCE",
            "ORIGIN",
            "BLOCKHASH",
            "CREATE",
            "CREATE2",
            "SELFDESTRUCT",
        ]

    async def simulate_validation_and_decode_result(
        self, user_operation: UserOperation
    ) -> ReturnInfo:
        # simulateValidation(entrypoint solidity function) will always revert
        (
            solidity_error_selector,
            solidity_error_params,
        ) = await self.simulate_validation(user_operation)

        if ValidationManager.check_if_failed_op_error(solidity_error_selector):
            _, _, reason = ValidationManager.decode_FailedOp_event(
                solidity_error_params
            )
            raise BundlerException(
                BundlerExceptionCode.REJECTED_BY_EP_OR_ACCOUNT,
                "revert reason : " + reason,
                solidity_error_params,
            )

        (
            return_info,
            sender_info,
            factory_info,
            paymaster_info,
        ) = ValidationManager.decode_validation_result_event(
            solidity_error_params
        )

        return return_info, sender_info, factory_info, paymaster_info

    @staticmethod
    def check_if_failed_op_error(solidity_error_selector) -> bool:
        return solidity_error_selector == FailedOpRevertData.SELECTOR

    @staticmethod
    def decode_validation_result_event(solidity_error_params) -> ReturnInfo:
        VALIDATION_RESULT_ABI = [
            "(uint256,uint256,bool,uint64,uint64,bytes)",
            "(uint256,uint256)",
            "(uint256,uint256)",
            "(uint256,uint256)",
        ]
        validation_result_decoded = decode(
            VALIDATION_RESULT_ABI, bytes.fromhex(solidity_error_params)
        )
        return_info_arr = validation_result_decoded[0]
        return_info = ReturnInfo(
            preOpGas=return_info_arr[0],
            prefund=return_info_arr[1],
            sigFailed=return_info_arr[2],
            validAfter=return_info_arr[3],
            validUntil=return_info_arr[4],
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

        return return_info, sender_info, factory_info, paymaster_info

    @staticmethod
    def decode_FailedOp_event(solidity_error_params):
        FAILED_OP_PARAMS_API = ["uint256", "address", "string"]
        failed_op_params_res = decode(
            FAILED_OP_PARAMS_API, bytes.fromhex(solidity_error_params)
        )
        operation_index = failed_op_params_res[0]
        paymaster_address = failed_op_params_res[1]
        reason = failed_op_params_res[2]

        return operation_index, paymaster_address, reason

    async def simulate_validation(self, user_operation: UserOperation):
        w3_provider = Web3()
        entrypoint_contract = w3_provider.eth.contract(
            address=self.entrypoint, abi=self.entrypoint_abi
        )
        call_data = entrypoint_contract.encodeABI(
            "simulateValidation", [user_operation.get_user_operation_dict()]
        )

        params = [
            {
                "from": self.bundler_address,
                "to": self.entrypoint,
                "data": call_data,
            },
            "latest",
        ]

        result = await send_rpc_request_to_eth_client(
            self.geth_rpc_url, "eth_call", params
        )
        if (
            "error" not in result
            or result["error"]["message"] != "execution reverted"
        ):
            raise ValueError("simulateValidation didn't revert!")

        error_data = result["error"]["data"]

        solidity_error_selector = str(error_data[:10])
        solidity_error_params = error_data[10:]

        return solidity_error_selector, solidity_error_params

    async def check_banned_op_codes(self, user_operation: UserOperation):
        (
            factory_opcodes,
            account_opcodes,
            paymaster_opcodes,
        ) = await self.get_user_operation_banned_opcodes(user_operation)

        await asyncio.gather(
            self.verify_banned_opcodes(factory_opcodes, "factory"),
            self.verify_banned_opcodes(account_opcodes, "account"),
            self.verify_banned_opcodes(paymaster_opcodes, "paymaster"),
        )

    async def get_user_operation_banned_opcodes(
        self, user_operation: UserOperation
    ):
        debug_data = await self.get_debug_traceCall_data(user_operation)

        factory_opcodes = debug_data["numberLevels"][0]["opcodes"]
        account_opcodes = debug_data["numberLevels"][1]["opcodes"]
        paymaster_opcodes = debug_data["numberLevels"][2]["opcodes"]

        return factory_opcodes, account_opcodes, paymaster_opcodes

    async def get_debug_traceCall_data(self, user_operation: UserOperation):
        simultion_gas = (
            user_operation.pre_verification_gas
            + user_operation.verification_gas_limit
        )

        w3_provider = Web3()
        entrypoint_contract = w3_provider.eth.contract(
            address=self.entrypoint, abi=self.entrypoint_abi
        )
        call_data = entrypoint_contract.encodeABI(
            "simulateValidation", [user_operation.get_user_operation_dict()]
        )

        params = [
            {
                "from": self.bundler_address,
                "to": self.entrypoint,
                "data": call_data,
                "gasLimit": simultion_gas,
            },
            "latest",
            {"tracer": self.bundler_collector_tracer},
        ]

        res = await send_rpc_request_to_eth_client(
            self.geth_rpc_url, "debug_traceCall", params
        )
        return res["result"]

    async def verify_banned_opcodes(self, opcodes, opcode_source):
        opcodes = {k for k in opcodes.keys() if k in self.banned_opcodes}
        number_of_opcodes = len(opcodes)
        if number_of_opcodes > 0:
            opcodes_str = " ".join([opcode for opcode in opcodes])
            raise BundlerException(
                BundlerExceptionCode.BANNED_OPCODE,
                opcode_source + " uses banned opcode: " + opcodes_str,
                "",
            )
