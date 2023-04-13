import asyncio
import time

from eth_utils import to_checksum_address, keccak
from eth_abi import decode, encode

from user_operation.user_operation_handler import UserOperationHandler
from user_operation.user_operation import UserOperation
from user_operation.models import ReturnInfo, StakeInfo, FailedOpRevertData
from bundler.exceptions import (
    ValidationException,
    ValidationExceptionCode,
)
from utils.eth_client_utils import (
    send_rpc_request_to_eth_client,
    DebugTraceCallData,
    DebugEntityData,
    Call,
)


class ValidationManager:
    user_operation_handler: UserOperationHandler
    geth_rpc_url: str
    bundler_private_key: str
    bundler_address: str
    entrypoint: str
    bundler_collector_tracer: str
    banned_opcodes: list()
    bundler_helper_byte_code: str

    def __init__(
        self,
        user_operation_handler: UserOperationHandler,
        geth_rpc_url: str,
        bundler_private_key: str,
        bundler_address: str,
        entrypoint: str,
        bundler_helper_byte_code: str,
    ):
        self.user_operation_handler = user_operation_handler
        self.geth_rpc_url = geth_rpc_url
        self.bundler_private_key = bundler_private_key
        self.bundler_address = bundler_address
        self.entrypoint = entrypoint
        self.bundler_helper_byte_code = bundler_helper_byte_code

        path = "utils/BundlerCollectorTracer.js"
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
            # "CREATE2",
            "SELFDESTRUCT",
            "RANDOM",
            "PREVRANDAO"
        ]

    async def validate_user_operation(
        self,
        user_operation: UserOperation,
        sender_stake_info: StakeInfo,
        factory_stake_info: StakeInfo,
        paymaster_stake_info: StakeInfo,
    ) -> None:
        debug_data: DebugTraceCallData = await self.get_debug_traceCall_data(
            user_operation
        )

        factory_opcodes = debug_data.factory_data.opcodes
        account_opcodes = debug_data.account_data.opcodes
        paymaster_opcodes = debug_data.paymaster_data.opcodes
        await self.check_banned_op_codes(
            factory_opcodes, account_opcodes, paymaster_opcodes
        )

        sender = user_operation.sender
        factory_address = user_operation.factory_address
        paymaster_address = user_operation.paymaster_address

        is_init_code = len(user_operation.init_code) > 2

        entities_addreses = []
        if factory_address is not None:
            entities_addreses.append(factory_address)

        entities_addreses.append(sender)

        if paymaster_address is not None:
            entities_addreses.append(paymaster_address)

        associated_slots_per_entity = ValidationManager.parse_entity_slots(
            entities_addreses, debug_data.keccak
        )

        self.validate_entity_storage_access(
            sender,
            "sender",
            associated_slots_per_entity,
            sender_stake_info,
            sender,
            debug_data.account_data.access,
            is_init_code,
        )
        associated_addresses_lowercase = list(
            debug_data.account_data.contract_size.keys()
        )

        if factory_address is not None:
            self.validate_entity_storage_access(
                factory_address,
                "factory",
                associated_slots_per_entity,
                factory_stake_info,
                sender,
                debug_data.factory_data.access,
                is_init_code,
            )
            associated_addresses_lowercase = (
                associated_addresses_lowercase
                + list(debug_data.factory_data.contract_size.keys())
            )

        _, paymaster_call = ValidationManager.parse_call_stack(
            debug_data.calls, paymaster_address
        )

        if paymaster_address is not None:
            self.validate_entity_storage_access(
                paymaster_address,
                "paymaster",
                associated_slots_per_entity,
                paymaster_stake_info,
                sender,
                debug_data.paymaster_data.access,
                is_init_code,
            )
            associated_addresses_lowercase = (
                associated_addresses_lowercase
                + list(debug_data.paymaster_data.contract_size.keys())
            )
            is_paymaster_staked = ValidationManager.is_staked(
                paymaster_stake_info
            )
            if len(paymaster_call._data) > 194 and not is_paymaster_staked:
                raise ValidationException(
                    ValidationExceptionCode.OpcodeValidation,
                    "unstaked paymaster must not return context",
                    "",
                )

        if len(associated_addresses_lowercase) > 0:
            associated_addresses = [
                to_checksum_address(lower_case_address)
                for lower_case_address in associated_addresses_lowercase
            ]

        if user_operation.code_hash is None:
            if len(associated_addresses) > 0:
                user_operation.code_hash = await self.get_addresses_code_hash(
                    associated_addresses
                )
        else:
            new_code_hash = None
            if len(associated_addresses) > 0:
                new_code_hash = await self.get_addresses_code_hash(
                    associated_addresses
                )
            if new_code_hash != user_operation.code_hash:
                raise ValidationException(
                    ValidationExceptionCode.OpcodeValidation,
                    "modified code after first validation",
                    "",
                )

    @staticmethod
    def is_slot_associated_with_address(
        slot, address: str, associated_slots: list[str]
    ) -> bool:
        address_lowercase = address[2:].lower()
        address_padded = "0x000000000000000000000000" + address_lowercase
        address_lowercase = "0x" + address_lowercase

        if slot == address_padded:
            return True

        slot_int = int(slot, 16)

        for associated_slot in associated_slots:
            associated_slot_int = int(associated_slot, 16)
            if (
                slot_int >= associated_slot_int
                and slot_int < associated_slot_int + 18
            ):
                return True

        return False

    @staticmethod
    def is_staked(entity_stake: StakeInfo) -> bool:
        return entity_stake.stake > 1 and entity_stake.unstakeDelaySec > 1

    def validate_entity_storage_access(
        self,
        entity_address: str,
        entity_title: str,
        associated_slots_per_entity: list[str],
        stake_info: StakeInfo,
        sender_address: str,
        access: dict[str, dict[str : list[str]]],
        is_init_code: bool,
    ) -> None:
        is_staked = ValidationManager.is_staked(stake_info)

        for contract_address in access.keys():
            if contract_address == sender_address.lower():
                continue  # allowed to access sender's storage
            elif contract_address == self.entrypoint.lower():
                continue

            storage_slots = access[contract_address]
            slots = storage_slots["reads"] | storage_slots["writes"]

            for slot in slots:
                require_stake_slot = None

                if (
                    sender_address in associated_slots_per_entity
                    and ValidationManager.is_slot_associated_with_address(
                        slot,
                        sender_address,
                        associated_slots_per_entity[sender_address],
                    )
                ):
                    if is_init_code:
                        require_stake_slot = slot
                elif (
                    entity_address in associated_slots_per_entity
                    and ValidationManager.is_slot_associated_with_address(
                        slot,
                        entity_address,
                        associated_slots_per_entity[entity_address],
                    )
                ):
                    require_stake_slot = slot
                elif contract_address == entity_address:
                    require_stake_slot = slot
                else:
                    raise ValidationException(
                        ValidationExceptionCode.OpcodeValidation,
                        " ".join(
                            (
                                entity_title,
                                ":",
                                entity_address,
                                "banned access to slot",
                                slot,
                                "at contract :",
                                contract_address,
                            )
                        ),
                        "",
                    )
                if not is_staked and require_stake_slot is not None:
                    raise ValidationException(
                        ValidationExceptionCode.OpcodeValidation,
                        " ".join(
                            (
                                entity_title,
                                ":",
                                entity_address,
                                "insuffient stake to access",
                                slot,
                                "at contract :",
                                contract_address,
                            )
                        ),
                        "",
                    )

    async def simulate_validation_and_decode_result(
        self, user_operation: UserOperation
    ) -> ReturnInfo:
        # simulateValidation(entrypoint solidity function) will always revert
        (
            solidity_error_selector,
            solidity_error_params,
        ) = await self.simulate_validation(user_operation)

        if ValidationManager.check_if_failed_op_error(solidity_error_selector):
            _, reason = ValidationManager.decode_FailedOp_event(
                solidity_error_params
            )
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
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
    def check_if_failed_op_error(solidity_error_selector: str) -> bool:
        return solidity_error_selector == FailedOpRevertData.SELECTOR

    @staticmethod
    def decode_validation_result_event(
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
        except Exception as err:
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                bytearray.fromhex(solidity_error_params).decode(),
                "",
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
    def decode_FailedOp_event(solidity_error_params: str) -> tuple[str, str]:
        FAILED_OP_PARAMS_API = ["uint256", "string"]
        failed_op_params_res = decode(
            FAILED_OP_PARAMS_API, bytes.fromhex(solidity_error_params)
        )
        operation_index = failed_op_params_res[0]
        reason = failed_op_params_res[1]

        return operation_index, reason

    async def simulate_validation(
        self, user_operation: UserOperation
    ) -> tuple[str, str]:
        function_selector = "0xee219423"  # simulateValidation
        params = encode(
            [
                "(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)"
            ],
            [user_operation.to_list()],
        )

        call_data = function_selector + params.hex()

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

        elif("data" not in result["error"] or len(result["error"]["data"]) < 10):
            raise ValidationException(
                        ValidationExceptionCode.SimulateValidation,
                        result["error"]["message"],
                        "",
                    )
    
        error_data = result["error"]["data"]

        solidity_error_selector = str(error_data[:10])
        solidity_error_params = error_data[10:]

        return solidity_error_selector, solidity_error_params

    async def check_banned_op_codes(
        self,
        factory_opcodes: dict[str:int],
        account_opcodes: dict[str:int],
        paymaster_opcodes: dict[str:int],
    ) -> None:
        await asyncio.gather(
            self.verify_banned_opcodes(factory_opcodes, "factory", True),
            self.verify_banned_opcodes(account_opcodes, "account"),
            self.verify_banned_opcodes(paymaster_opcodes, "paymaster"),
        )

    async def get_debug_traceCall_data(
        self, user_operation: UserOperation
    ) -> DebugTraceCallData:
        simultion_gas = (
            user_operation.pre_verification_gas
            + user_operation.verification_gas_limit
        )

        function_selector = "0xee219423"  # simulateValidation
        params = encode(
            [
                "(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes,bytes)"
            ],
            [user_operation.to_list()],
        )

        call_data = function_selector + params.hex()

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
        debug_data = res["result"]
        factory_data = DebugEntityData(
            debug_data["numberLevels"][0]["access"],
            debug_data["numberLevels"][0]["opcodes"],
            debug_data["numberLevels"][0]["contractSize"],
        )
        account_data = DebugEntityData(
            debug_data["numberLevels"][1]["access"],
            debug_data["numberLevels"][1]["opcodes"],
            debug_data["numberLevels"][1]["contractSize"],
        )
        paymaster_data = DebugEntityData(
            debug_data["numberLevels"][2]["access"],
            debug_data["numberLevels"][2]["opcodes"],
            debug_data["numberLevels"][2]["contractSize"],
        )

        debug_trace_call_data = DebugTraceCallData(
            factory_data,
            account_data,
            paymaster_data,
            debug_data["keccak"],
            debug_data["logs"],
            debug_data["calls"],
            debug_data["debug"],
        )

        return debug_trace_call_data

    async def verify_banned_opcodes(
        self,
        opcodes: dict[str:int],
        opcode_source: str,
        is_factory: bool = False,
    ) -> None:
        found_opcodes = {
            opcode
            for opcode in opcodes.keys()
            if opcode in self.banned_opcodes
        }
        number_of_opcodes = len(found_opcodes)
        if number_of_opcodes > 0:
            opcodes_str = " ".join([opcode for opcode in found_opcodes])
            raise ValidationException(
                ValidationExceptionCode.OpcodeValidation,
                opcode_source + " uses banned opcode: " + opcodes_str,
                "",
            )

        if "CREATE2" in opcodes:
            if (opcodes["CREATE2"] > 1) or (
                opcodes["CREATE2"] == 1 and not is_factory
            ):
                raise ValidationException(
                    ValidationExceptionCode.OpcodeValidation,
                    opcode_source + " uses banned opcode: " + "CREATE2",
                    "",
                )

    async def get_addresses_code_hash(self, addresses: list[str]) -> str:
        call_data = encode(["address[]"], [addresses])
        params = [
            {
                "from": self.bundler_address,
                "data": "0x" + self.bundler_helper_byte_code + call_data.hex(),
            },
            "latest",
        ]
        result = await send_rpc_request_to_eth_client(
            self.geth_rpc_url, "eth_call", params
        )
        if "error" not in result:
            raise ValueError("BundlerHelper should revert")

        return result["error"]["data"]

    @staticmethod
    def parse_entity_slots(entities: list[str], keccak_list: list[str]):
        entity_slots = dict()
        for slot_keccak in keccak_list:
            for address in entities:
                address_lowercase = address[2:].lower()
                address_padded = (
                    "0x000000000000000000000000" + address_lowercase
                )
                address_lowercase = "0x" + address_lowercase
                if address not in entity_slots:
                    entity_slots[address] = []

                current_entity_slot = entity_slots[address]
                if address_padded in slot_keccak:
                    keccak_hash = keccak(bytes.fromhex(slot_keccak[2:]))
                    slot = keccak_hash.hex()
                    if slot not in current_entity_slot:
                        current_entity_slot.append(slot)
        return entity_slots

    @staticmethod
    def parse_call_stack(
        calls: list[dict[str, str]], paymaster_address: str
    ) -> tuple[list[Call], Call | None]:
        stack = []
        top = Call()
        results = []
        paymaster_call = None
        VALIDATE_PAYMASTER_USER_OP_METHOD_SELECTOR = "0xf465c77e"
        for call in calls:
            if call.get("type") == "RETURN" or call.get("type") == "REVERT":
                if len(stack) == 0:
                    top = Call()
                    top._type = "top"
                    top._method = "validateUserOp"
                else:
                    top = stack.pop()

                return_data = call["data"]

                result = Call()
                result._to = top._to
                result._from = top._from
                result._type = top._type
                result._gas = top._gas
                result._gas_used = call.get("gasUsed")
                if top._type == "CREATE":
                    result._data = "len=" + str(len(return_data))
                elif top._type == "REVERT":
                    result._method = top._method
                    result._data = call.get("data")
                    result._return_type = "REVERT"
                else:
                    result._method = top._method
                    result._data = call.get("data")
                    result._return_type = "RETURN"

                if (
                    paymaster_address is not None
                    and paymaster_address == result._to
                    and VALIDATE_PAYMASTER_USER_OP_METHOD_SELECTOR
                    == result._method
                ):
                    paymaster_call = result

                results.append(result)
            else:
                call_to_stack = Call(
                    _to=call.get("to"),
                    _from=call.get("from"),
                    _type=call.get("type"),
                    _method=call.get("method"),
                    _value=call.get("value"),
                    _gas=call.get("gas"),
                    _data=call.get("data"),
                )

                stack.append(call_to_stack)

        return results, paymaster_call

    async def verify_gas_and_return_info(
        self, user_operation: UserOperation, return_info: ReturnInfo
    ) -> None:
        pre_operation_gas = return_info.preOpGas
        # prefund=return_info.prefund
        sigFailed = return_info.sigFailed
        validAfter = return_info.validAfter
        deadline = return_info.validUntil

        (
            call_gas_limit,
            preverification_gas,
        ) = await self.user_operation_handler.estimate_user_operation_gas(
            user_operation
        )

        if sigFailed:
            raise ValidationException(
                ValidationExceptionCode.InvalidSignature,
                "Invalide Signature",
                "",
            )

        if call_gas_limit != "0x" and user_operation.call_gas_limit < int(
            call_gas_limit, 16
        ):
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                "Call gas limit is too low. it should be minimum :"
                + call_gas_limit,
                "",
            )
        if user_operation.pre_verification_gas < preverification_gas:
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                f"Preverification gas is too low. it should be minimum : {preverification_gas}",
                "",
            )
        if (
            user_operation.verification_gas_limit
            + user_operation.pre_verification_gas
            < pre_operation_gas
        ):
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                f"verification gas + preverification gas is too low. it should be minimum : {pre_operation_gas}",
                "",
            )

        if validAfter is None or validAfter > (time.time() / 1000) - 30:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Transaction is not valid yet",
                "",
            )

        if deadline is None or deadline + 30 < (time.time() / 1000):
            raise ValidationException(
                ValidationExceptionCode.ExpiresShortly,
                "Transaction will expire shortly or has expired.",
                "",
            )
