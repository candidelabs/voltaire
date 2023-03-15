import asyncio
from typing import Dict
import json

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
    bundler_helper_abi: str
    bundler_helper_address: str

    def __init__(
        self,
        geth_rpc_url,
        bundler_private_key,
        bundler_address,
        entrypoint,
        entrypoint_abi,
        bundler_helper_address,
        bundler_helper_abi,
    ):
        self.geth_rpc_url = geth_rpc_url
        self.bundler_private_key = bundler_private_key
        self.bundler_address = bundler_address
        self.entrypoint = entrypoint
        self.entrypoint_abi = entrypoint_abi
        self.bundler_helper_address = bundler_helper_address
        self.bundler_helper_abi = bundler_helper_abi

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
        ]

    async def validate_user_operation(self, user_operation: UserOperation):
        (
            _,
            sender_stake_info,
            factory_stake_info,
            paymaster_stake_info,
        ) = await self.simulate_validation_and_decode_result(user_operation)

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
        (
            factory_address,
            paymaster_address,
        ) = ValidationManager.get_factory_and_paymaster_address(
            user_operation.init_code, user_operation.paymaster_and_data
        )
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

        if len(associated_addresses_lowercase) > 0:
            associated_addresses = [
                Web3.to_checksum_address(lower_case_address)
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
                raise BundlerException(
                    ValidationExceptionCode.OpcodeValidation,
                    "modified code after first validation",
                    "",
                )

    @staticmethod
    def is_slot_associated_with_address(slot, address, associated_slots):
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
    def is_staked(entity_stake: StakeInfo):
        return entity_stake.stake > 1 and entity_stake.unstakeDelaySec > 1

    @staticmethod
    def get_factory_and_paymaster_address(intit_data, paymaster_data):
        factory_address = None
        paymaster_address = None

        if len(intit_data) > 20:
            factory_address = "0x" + intit_data[:20].hex()

        if len(paymaster_data) > 20:
            paymaster_address = "0x" + paymaster_data[:20].hex()

        return factory_address, paymaster_address

    def validate_entity_storage_access(
        self,
        entity_address,
        entity_title,
        associated_slots_per_entity,
        stake_info: StakeInfo,
        sender,
        access,
        is_init_code,
    ):
        is_staked = ValidationManager.is_staked(stake_info)

        for contract_address in access.keys():
            if contract_address == sender.lower():
                continue  # allowed to access sender's storage
            elif contract_address == self.entrypoint.lower():
                continue

            storage_slots = access[contract_address]
            slots = storage_slots["reads"] | storage_slots["writes"]

            for slot in slots:
                require_stake_slot = None

                if (
                    sender in associated_slots_per_entity
                    and ValidationManager.is_slot_associated_with_address(
                        slot, sender, associated_slots_per_entity[sender]
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
        try:
            validation_result_decoded = decode(
                VALIDATION_RESULT_ABI, bytes.fromhex(solidity_error_params)
            )
        except Exception as err:
            raise BundlerException(
                BundlerExceptionCode.REJECTED_BY_EP_OR_ACCOUNT,
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

    async def check_banned_op_codes(
        self, factory_opcodes, account_opcodes, paymaster_opcodes
    ):
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
        self, opcodes, opcode_source, is_factory=False
    ):
        found_opcodes = {
            opcode
            for opcode in opcodes.keys()
            if opcode in self.banned_opcodes
        }
        number_of_opcodes = len(found_opcodes)
        if number_of_opcodes > 0:
            opcodes_str = " ".join([opcode for opcode in found_opcodes])
            raise BundlerException(
                BundlerExceptionCode.BANNED_OPCODE,
                opcode_source + " uses banned opcode: " + opcodes_str,
                "",
            )

        if "CREATE2" in opcodes:
            if (opcodes["CREATE2"] > 1) or (
                opcodes["CREATE2"] == 1 and not is_factory
            ):
                raise BundlerException(
                    BundlerExceptionCode.BANNED_OPCODE,
                    opcode_source + " uses banned opcode: " + "CREATE2",
                    "",
                )

    async def get_addresses_code_hash(self, addresses):
        w3_provider = Web3()
        entrypoint_contract = w3_provider.eth.contract(
            address=self.bundler_helper_address, abi=self.bundler_helper_abi
        )
        call_data = entrypoint_contract.encodeABI("getCodeHashes", [addresses])

        params = [
            {
                "from": self.bundler_address,
                "to": self.bundler_helper_address,
                "data": call_data,
            },
            "latest",
        ]

        result = await send_rpc_request_to_eth_client(
            self.geth_rpc_url, "eth_call", params
        )
        return result["result"]

    @staticmethod
    def parse_entity_slots(entities: str, keccak_list):
        entity_slots = dict()
        for keccak in keccak_list:
            for address in entities:
                address_lowercase = address[2:].lower()
                address_padded = (
                    "0x000000000000000000000000" + address_lowercase
                )
                address_lowercase = "0x" + address_lowercase
                if address not in entity_slots:
                    entity_slots[address] = []

                current_entity_slot = entity_slots[address]
                if address_padded in keccak:
                    keccak_hash = Web3.solidity_keccak(["bytes"], [keccak])
                    slot = keccak_hash.hex()[2:]
                    if slot not in current_entity_slot:
                        current_entity_slot.append(slot)
        return entity_slots
