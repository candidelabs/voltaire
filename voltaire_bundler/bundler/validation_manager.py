import asyncio
import time
import os

from eth_utils import to_checksum_address, keccak
from eth_abi import decode, encode

from voltaire_bundler.user_operation.user_operation_handler import (
    UserOperationHandler,
)
from voltaire_bundler.user_operation.user_operation import UserOperation
from voltaire_bundler.user_operation.models import (
    ReturnInfo,
    StakeInfo,
    FailedOpRevertData,
)
from voltaire_bundler.bundler.exceptions import (
    ValidationException,
    ValidationExceptionCode,
)
from voltaire_bundler.utils.eth_client_utils import (
    send_rpc_request_to_eth_client,
    DebugTraceCallData,
    DebugEntityData,
    Call,
)
from voltaire_bundler.utils.decode import decode_FailedOp_event
from voltaire_bundler.utils.encode import encode_simulate_validation_calldata
from voltaire_bundler.bundler.gas_manager import GasManager


class ValidationManager:
    user_operation_handler: UserOperationHandler
    ethereum_node_url: str
    gas_manager: GasManager
    bundler_private_key: str
    bundler_address: str
    entrypoint: str
    chain_id: int
    bundler_collector_tracer: str
    banned_opcodes: list()
    bundler_helper_byte_code: str
    is_unsafe: bool
    is_legacy_mode: bool
    whitelist_entity_storage_access: list()
    enforce_gas_price_tolerance: int

    def __init__(
        self,
        user_operation_handler: UserOperationHandler,
        ethereum_node_url: str,
        gas_manager: GasManager,
        bundler_private_key: str,
        bundler_address: str,
        entrypoint: str,
        chain_id: int,
        bundler_helper_byte_code: str,
        is_unsafe: bool,
        is_legacy_mode: bool,
        whitelist_entity_storage_access: list(),
        enforce_gas_price_tolerance: int,
    ):
        self.user_operation_handler = user_operation_handler
        self.ethereum_node_url = ethereum_node_url
        self.gas_manager = gas_manager
        self.bundler_private_key = bundler_private_key
        self.bundler_address = bundler_address
        self.entrypoint = entrypoint
        self.chain_id = chain_id
        self.bundler_helper_byte_code = bundler_helper_byte_code
        self.is_unsafe = is_unsafe
        self.is_legacy_mode = is_legacy_mode
        self.whitelist_entity_storage_access = whitelist_entity_storage_access
        self.enforce_gas_price_tolerance = enforce_gas_price_tolerance

        package_directory = os.path.dirname(os.path.abspath(__file__))
        BundlerCollectorTracer_file = os.path.join(
            package_directory, "..", "utils", "BundlerCollectorTracer.js"
        )
        with open(BundlerCollectorTracer_file) as keyfile:
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
            "PREVRANDAO",
        ]

    async def validate_user_operation(
        self,
        user_operation: UserOperation,
        latest_block_number:str,
        latest_block_basefee: int,
    ) -> bool:
        await self.gas_manager.verify_preverification_gas_and_verification_gas_limit(
            user_operation, latest_block_number, latest_block_basefee
        )
        gas_price_hex = await self.gas_manager.verify_gas_fees_and_get_price(
            user_operation, self.enforce_gas_price_tolerance
        )

        if self.is_unsafe:
            (
                selector,
                validation_result,
            ) = await self.simulate_validation_without_tracing(user_operation)
        else:
            debug_data: str = await self.simulate_validation_with_tracing(
                user_operation,
                gas_price_hex,
            )
            selector = debug_data["debug"][-2]["REVERT"][:10]
            validation_result = debug_data["debug"][-2]["REVERT"][10:]

        if ValidationManager.check_if_failed_op_error(selector):
            _, reason = ValidationManager.decode_FailedOp_event(
                validation_result
            )
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                "revert reason : " + reason,
                validation_result,
            )

        (
            return_info,
            sender_stake_info,
            factory_stake_info,
            paymaster_stake_info,
            is_sender_staked,
        ) = ValidationManager.decode_validation_result(validation_result)

        self.verify_sig_and_timestamp(user_operation, return_info)

        if self.is_unsafe:
            user_operation_hash = UserOperationHandler.get_user_operation_hash(
                user_operation.to_list(), self.entrypoint, self.chain_id
            )
        else:
            debug_data_formated = (
                ValidationManager.format_debug_traceCall_data(debug_data)
            )
            await self.validate_trace_results(
                user_operation,
                sender_stake_info,
                factory_stake_info,
                paymaster_stake_info,
                debug_data_formated,
            )
            user_operation_hash = (
                ValidationManager.get_user_operation_hash_from_debug_data(
                    debug_data
                )
            )

        return is_sender_staked, user_operation_hash

    async def simulate_validation_without_tracing(
        self, user_operation: UserOperation
    ) -> tuple[str, str]:
        call_data = encode_simulate_validation_calldata(user_operation)

        params = [
            {
                "from": self.bundler_address,
                "to": self.entrypoint,
                "data": call_data,
            },
            "latest",
        ]

        result = await send_rpc_request_to_eth_client(
            self.ethereum_node_url, "eth_call", params
        )
        if (
            "error" not in result
            or "execution reverted" not in result["error"]["message"]
        ):
            raise ValueError("simulateValidation didn't revert!")

        elif (
            "data" not in result["error"] or len(result["error"]["data"]) < 10
        ):
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                result["error"]["message"],
                "",
            )

        error_data = result["error"]["data"]
        solidity_error_selector = str(error_data[:10])
        solidity_error_params = error_data[10:]

        return solidity_error_selector, solidity_error_params

    async def simulate_validation_with_tracing(
        self, user_operation: UserOperation, gas_price_hex: int
    ) -> str:
        call_data = encode_simulate_validation_calldata(user_operation)

        params = [
            {
                "from": self.bundler_address,
                "to": self.entrypoint,
                "data": call_data,
                "gasLimit": 0,
                "gasPrice": gas_price_hex,
            },
            "latest",
            {"tracer": self.bundler_collector_tracer},
        ]

        res = await send_rpc_request_to_eth_client(
            self.ethereum_node_url, "debug_traceCall", params
        )

        if "result" in res:
            debug_data = res["result"]
            return debug_data

        elif "error" in res and "message" in res["error"]:
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                res["error"]["message"]
                + " - Try reducing maxFeePerGas or contact the bundler maintainer if the bundler account is not sufficiently funded",
                "",
            )
        else:
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                "Invalide Validation result from debug_traceCall",
                "",
            )

    async def validate_trace_results(
        self,
        user_operation: UserOperation,
        sender_stake_info: StakeInfo,
        factory_stake_info: StakeInfo,
        paymaster_stake_info: StakeInfo,
        debug_data: DebugTraceCallData,
    ) -> None:
        factory_opcodes = debug_data.factory_data.opcodes
        account_opcodes = debug_data.account_data.opcodes
        paymaster_opcodes = debug_data.paymaster_data.opcodes
        await self.check_banned_op_codes(
            factory_opcodes, account_opcodes, paymaster_opcodes
        )

        sender_address_lowercase = user_operation.sender_address.lower()
        factory_address_lowercase = user_operation.factory_address_lowercase
        paymaster_address_lowercase = (
            user_operation.paymaster_address_lowercase
        )

        is_init_code = len(user_operation.init_code) > 2

        entities_addreses = []
        if factory_address_lowercase is not None:
            entities_addreses.append(factory_address_lowercase)

        entities_addreses.append(sender_address_lowercase)

        if paymaster_address_lowercase is not None:
            entities_addreses.append(paymaster_address_lowercase)

        associated_slots_per_entity = ValidationManager.parse_entity_slots(
            entities_addreses, debug_data.keccak
        )

        self.validate_entity_storage_access(
            sender_address_lowercase,
            "sender",
            associated_slots_per_entity,
            sender_stake_info,
            sender_address_lowercase,
            debug_data.account_data.access,
            is_init_code,
        )
        associated_addresses_lowercase = list(
            debug_data.account_data.contract_size.keys()
        )

        if factory_address_lowercase is not None:
            self.validate_entity_storage_access(
                factory_address_lowercase,
                "factory",
                associated_slots_per_entity,
                factory_stake_info,
                sender_address_lowercase,
                debug_data.factory_data.access,
                is_init_code,
            )
            associated_addresses_lowercase = (
                associated_addresses_lowercase
                + list(debug_data.factory_data.contract_size.keys())
            )

        _, paymaster_call = ValidationManager.parse_call_stack(
            debug_data.calls, paymaster_address_lowercase
        )

        if paymaster_address_lowercase is not None:
            self.validate_entity_storage_access(
                paymaster_address_lowercase,
                "paymaster",
                associated_slots_per_entity,
                paymaster_stake_info,
                sender_address_lowercase,
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

        if len(associated_addresses) > 0:
            user_operation.code_hash = await self.get_addresses_code_hash(
                associated_addresses
            )
            user_operation.associated_addresses = associated_addresses

    def validate_entity_storage_access(
        self,
        entity_address: str,
        entity_title: str,
        associated_slots_per_entity: list[str],
        stake_info: StakeInfo,
        sender_address_lowercase: str,
        access: dict[str, dict[str : list[str]]],
        is_init_code: bool,
    ) -> None:
        if entity_address in self.whitelist_entity_storage_access:
            return

        is_staked = ValidationManager.is_staked(stake_info)

        for contract_address in access.keys():
            if contract_address == sender_address_lowercase:
                continue  # allowed to access sender's storage
            elif contract_address == self.entrypoint.lower():
                continue

            storage_slots = access[contract_address]
            slots = storage_slots["reads"] | storage_slots["writes"]

            for slot in slots:
                require_stake_slot = None

                if (
                    sender_address_lowercase in associated_slots_per_entity
                    and ValidationManager.is_slot_associated_with_address(
                        slot,
                        sender_address_lowercase,
                        associated_slots_per_entity[sender_address_lowercase],
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

    def format_debug_traceCall_data(debug_data: str) -> DebugEntityData:
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
            self.ethereum_node_url, "eth_call", params
        )
        if "error" not in result:
            raise ValueError("BundlerHelper should revert")

        return result["error"]["data"]

    def verify_sig_and_timestamp(
        self, user_operation: UserOperation, return_info: ReturnInfo
    ) -> None:
        pre_operation_gas = return_info.preOpGas
        sigFailed = return_info.sigFailed
        validAfter = return_info.validAfter
        deadline = return_info.validUntil

        if sigFailed:
            raise ValidationException(
                ValidationExceptionCode.InvalidSignature,
                "Invalid UserOp signature or paymaster signature",
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

    @staticmethod
    def check_if_failed_op_error(solidity_error_selector: str) -> bool:
        return solidity_error_selector == FailedOpRevertData.SELECTOR

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
        except Exception as err:
            operation_index, reason = decode_FailedOp_event(
                solidity_error_params
            )
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                reason,
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

        is_sender_staked = ValidationManager.is_staked(sender_info)

        return (
            return_info,
            sender_info,
            factory_info,
            paymaster_info,
            is_sender_staked,
        )

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

    @staticmethod
    def get_user_operation_hash_from_debug_data(debug_data):
        encodedInfo = next(
            (
                inp["enter"]["in"]
                for inp in reversed(debug_data["debug"][:-2])
                if "enter" in inp
                and "in" in inp["enter"]
                and "0x3a871cdd" in inp["enter"]["in"]
            ),
            None,
        )
        decoded_result = decode(
            ["bytes32", "bytes32", "uint256"],
            bytes.fromhex(encodedInfo[10:]),
        )
        user_operation_hash = "0x" + decoded_result[1].hex()
        return user_operation_hash
