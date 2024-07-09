import logging
from typing import Any

from eth_abi import encode
from eth_utils import keccak, to_checksum_address

from voltaire_bundler.bundle.exceptions import (ValidationException,
                                                 ValidationExceptionCode)
from voltaire_bundler.user_operation.v7.user_operation_v7 import UserOperationV7
from voltaire_bundler.user_operation.v6.user_operation_v6 import UserOperationV6
from voltaire_bundler.utils.eth_client_utils import send_rpc_request_to_eth_client
from voltaire_bundler.typing import Address
from voltaire_bundler.utils.load_bytecode import load_bytecode


class TracerManager():
    ethereum_node_url: str
    bundler_address: str
    bundler_helper_byte_code: str

    def __init__(
        self,
        ethereum_node_url: str,
        bundler_address: str,
    ):
        self.ethereum_node_url = ethereum_node_url
        self.bundler_address = bundler_address
        self.bundler_helper_byte_code = load_bytecode(
            "BundlerHelper.json")

    async def validate_trace_results(
        self,
        user_operation: UserOperationV7 | UserOperationV6,
        entrypoint: str,
        is_sender_staked: bool,
        is_factory_staked: bool | None,
        is_paymaster_staked: bool | None,
        raw_tracer_result: Any,
    ) -> tuple[list[str], dict[str, dict[str, str]]]:
        entrypoint_lowercase = Address(entrypoint.lower())

        # [OP-052], [OP-053], [OP-054], [OP-061]
        validate_call_stack(raw_tracer_result["calls"], entrypoint_lowercase)

        sender_lowercase = Address(user_operation.sender_address.lower())
        factory_lowercase = None
        paymaster_lowercase = None

        if isinstance(user_operation, UserOperationV6):
            factory_lowercase = user_operation.factory_address_lowercase
            paymaster_lowercase = user_operation.paymaster_address_lowercase
            sender_creator_lowercase = "0x7fc98430eaedbb6070b35b39d798725049088348"
            is_init_code = len(user_operation.init_code) > 2
        else:
            if user_operation.factory is not None:
                factory_lowercase = Address(user_operation.factory.lower())
            if user_operation.paymaster is not None:
                paymaster_lowercase = Address(user_operation.paymaster.lower())
            sender_creator_lowercase = "0xefc2c1444ebcc4db75e7613d20c6a62ff67a167c"
            is_init_code = user_operation.factory is not None

        (
            sender_data,
            factory_data,
            paymaster_data,
            sender_opcodes,
            factory_opcodes,
            paymaster_opcodes,
            associated_addresses_lowercase
        ) = filter_entites_data(
            raw_tracer_result,
            sender_lowercase,
            factory_lowercase,
            paymaster_lowercase,
            sender_creator_lowercase
        )

        # [OP-011], [OP-080], [OP-031]
        validate_banned_opcodes(
            sender_opcodes,
            factory_opcodes,
            paymaster_opcodes,
            is_sender_staked,
            is_factory_staked,
            is_paymaster_staked
        )

        storage_map = validate_storage_access(
            entrypoint_lowercase,
            raw_tracer_result["keccak"],
            sender_lowercase,
            is_sender_staked,
            sender_data,
            factory_lowercase,
            is_factory_staked,
            factory_data,
            paymaster_lowercase,
            is_paymaster_staked,
            paymaster_data,
            is_init_code,
        )

        if len(associated_addresses_lowercase) > 0:
            associated_addresses = [
                to_checksum_address(lower_case_address)
                for lower_case_address in associated_addresses_lowercase
            ]
        else:
            associated_addresses = []

        return associated_addresses, storage_map

    async def get_code_hash_and_associated_addresses(
        self,
        sender_data: Any,
        factory_data: Any | None,
        paymaster_data: Any | None,
    ) -> tuple[str | None, list[str]]:
        associated_addresses_lowercase: list[str] = list(
            sender_data["contractSize"].keys()
        )
        if factory_data is not None:
            associated_addresses_lowercase = (
                associated_addresses_lowercase +
                list(factory_data["contractSize"].keys())
            )

        if paymaster_data is not None:
            associated_addresses_lowercase = (
                associated_addresses_lowercase +
                list(paymaster_data["contractSize"].keys())
            )
        code_hash = None
        associated_addresses = []
        if len(associated_addresses_lowercase) > 0:
            associated_addresses = [
                to_checksum_address(lower_case_address)
                for lower_case_address in associated_addresses_lowercase
            ]
            if len(associated_addresses) > 0:
                code_hash = await self.get_addresses_code_hash(
                    associated_addresses
                )
        return code_hash, associated_addresses

    async def get_addresses_code_hash(self, addresses: list[str]) -> str:
        call_data = encode(["address[]"], [addresses])
        params = [
            {
                "from": self.bundler_address,
                "data": self.bundler_helper_byte_code + call_data.hex(),
            },
            "latest",
        ]
        result: Any = await send_rpc_request_to_eth_client(
            self.ethereum_node_url, "eth_call", params
        )
        if "error" not in result:
            # this should never happen
            logging.critical("BundlerHelper should revert")
            raise ValueError("BundlerHelper should revert")

        return result["error"]["data"]


def validate_call_stack(calls: Any, entrypoint_lowecase: Address) -> None:
    for call in calls:
        to = call.get("to")
        From = call.get("from")
        method = call.get("method")
        value = call.get("value")

        # [OP-052], [OP-053], [OP-054]
        if (
            to == entrypoint_lowecase and
            From != entrypoint_lowecase and
            (
                method != "0x" and
                method != "0xb760faf9"  # depositTo
            )
        ):
            raise ValidationException(
                ValidationExceptionCode.OpcodeValidation,
                f"illegal call into EntryPoint during validation to method: {method}"
            )

        # [OP-061]
        if (
            value is not None and
            int(value) > 0 and
            to != entrypoint_lowecase
        ):
            raise ValidationException(
                ValidationExceptionCode.OpcodeValidation,
                "May not may CALL with value"
            )


def validate_entity_banned_opcodes(
    opcodes: dict[str, int],
    opcode_source: str,
    is_entity_staked: bool | None,
    is_factory: bool = False,
) -> None:
    # opcodes from [OP-011]
    BANNED_OPCODES = [
        "ORIGIN",
        "GASPRICE",
        "BLOCKHASH",
        "COINBASE",
        "TIMESTAMP",
        "NUMBER",
        "PREVRANDAO",
        "DIFFICULTY",
        "GASLIMIT",
        "BASEFEE",
        "CREATE",
        "INVALID",
        "SELFDESTRUCT",
        "GAS",
    ]

    found_opcodes = opcodes.keys() & BANNED_OPCODES
    number_of_opcodes = len(found_opcodes)
    if number_of_opcodes > 0:
        opcodes_str = " ".join([opcode for opcode in found_opcodes])
        raise ValidationException(
            ValidationExceptionCode.OpcodeValidation,
            opcode_source + " uses banned opcode: " + opcodes_str,
        )
    # [OP-031]
    if "CREATE2" in opcodes:
        if ((opcodes["CREATE2"] > 1) or
                (opcodes["CREATE2"] == 1 and not is_factory)):
            raise ValidationException(
                ValidationExceptionCode.OpcodeValidation,
                opcode_source + " uses banned opcode: " + "CREATE2",
            )

    # opcodes allowed in staked entities [OP-080]
    if "BALANCE" in opcodes and not is_entity_staked:
        raise ValidationException(
            ValidationExceptionCode.OpcodeValidation,
            opcode_source + " uses banned opcode: " + "BALANCE",
        )

    if "SELFBALANCE" in opcodes and not is_entity_staked:
        raise ValidationException(
            ValidationExceptionCode.OpcodeValidation,
            opcode_source + " uses banned opcode: " + "SELFBALANCE",
        )


def validate_banned_opcodes(
    sender_opcodes: dict[str, int],
    factory_opcodes: dict[str, int] | None,
    paymaster_opcodes: dict[str, int] | None,
    is_sender_staked: bool,
    is_factory_staked: bool | None,
    is_paymaster_staked: bool | None,
) -> None:
    validate_entity_banned_opcodes(sender_opcodes, "account", is_sender_staked)
    if factory_opcodes is not None:
        validate_entity_banned_opcodes(
                factory_opcodes, "factory", is_factory_staked, True)
    if paymaster_opcodes is not None:
        validate_entity_banned_opcodes(
            paymaster_opcodes, "paymaster", is_paymaster_staked)


def filter_entites_data(
    raw_tracer_result: Any,
    sender_lowercase: Address,
    factory_lowercase: Address | None,
    paymaster_lowercase: Address | None,
    sender_creator: str
) -> tuple[
        Any,
        Any | None,
        Any | None,
        dict[str, int],
        dict[str, int] | None,
        dict[str, int] | None,
        list[str]]:
    calls_from_entrypoint = raw_tracer_result["callsFromEntryPoint"]
    sender_data = None
    factory_data = None
    paymaster_data = None

    sender_opcodes = None
    factory_opcodes = None
    paymaster_opcodes = None
    associated_addresses_lowercase = []
    for target in calls_from_entrypoint:
        associated_addresses_lowercase += list(target["contractSize"].keys())
        if target["topLevelTargetAddress"] == sender_lowercase:
            sender_data = target
            sender_opcodes = sender_data["opcodes"]
        elif (
                factory_lowercase is not None and
                target["topLevelTargetAddress"] == sender_creator):
            factory_data = target
            factory_opcodes = factory_data["opcodes"]
        elif (
                paymaster_lowercase is not None and
                target["topLevelTargetAddress"] == paymaster_lowercase):
            paymaster_data = target
            paymaster_opcodes = paymaster_data["opcodes"]
    assert sender_opcodes is not None
    return (
            sender_data, factory_data, paymaster_data,
            sender_opcodes, factory_opcodes, paymaster_opcodes,
            associated_addresses_lowercase)


def is_slot_associated_with_address(
    slot: str, address: str, associated_slots: list[str]
) -> bool:
    address_lowercase = address[2:]  # .lower()
    address_padded = "0x000000000000000000000000" + address_lowercase
    address_lowercase = "0x" + address_lowercase

    if slot == address_padded:
        return True

    slot_int = int(slot, 16)

    for associated_slot in associated_slots:
        associated_slot_int = int(associated_slot, 16)
        if (
            slot_int >= associated_slot_int and
            slot_int < associated_slot_int + 18
        ):
            return True

    return False


def parse_entity_slots(
        entities: list[str],
        keccak_list_unique: set[str]
) -> dict[str, list[str]]:
    entity_slots: dict[str, list[str]] = dict()
    entities_addresses_padded_pair_list = map(
        lambda address: (address, "0x000000000000000000000000" + address[2:]),
        entities,
    )

    [
        update_current_entity_slot(
            slot_keccak, address, address_padded, entity_slots
        )
        for address, address_padded in entities_addresses_padded_pair_list
        for slot_keccak in keccak_list_unique
    ]
    return entity_slots


def update_current_entity_slot(
        slot_keccak: str,
        address: str,
        address_padded: str,
        entity_slots: dict[str, list[str]]) -> None:
    if address not in entity_slots:
        entity_slots[address] = []

    current_entity_slot = entity_slots[address]
    if address_padded in slot_keccak:
        slot = keccak(bytes.fromhex(slot_keccak[2:])).hex()
        if slot not in current_entity_slot:
            current_entity_slot.append(slot)


def validate_storage_access(
    entrypoint_lowercase: Address,
    tracer_result_keccak: Any,
    sender_lowercase: Address,
    is_sender_staked: bool,
    sender_data: Any,
    factory_lowercase: Address | None,
    is_factory_staked: bool | None,
    factory_data: Any | None,
    paymaster_lowercase: Address | None,
    is_paymaster_staked: bool | None,
    paymaster_data: Any | None,
    is_init_code: bool,
) -> dict[str, dict[str, str]]:
    entities_addreses = []

    entities_addreses.append(sender_lowercase)
    if factory_lowercase is not None:
        entities_addreses.append(factory_lowercase)
    if paymaster_lowercase is not None:
        entities_addreses.append(paymaster_lowercase)

    associated_slots_per_entity = parse_entity_slots(
        entities_addreses, set(tracer_result_keccak)
    )

    storage_map = validate_entity_storage_access(
        entrypoint_lowercase,
        sender_lowercase,
        "sender",
        associated_slots_per_entity,
        is_sender_staked,
        sender_lowercase,
        sender_data,
        is_init_code,
        is_factory_staked
    )

    if factory_lowercase is not None:
        assert is_factory_staked is not None
        sender_storage_map = validate_entity_storage_access(
            entrypoint_lowercase,
            factory_lowercase,
            "factory",
            associated_slots_per_entity,
            is_factory_staked,
            sender_lowercase,
            factory_data,
            is_init_code,
            is_factory_staked
        )
        storage_map |= sender_storage_map

    if paymaster_lowercase is not None:
        assert is_paymaster_staked is not None
        paymaster_storage_map = validate_entity_storage_access(
            entrypoint_lowercase,
            paymaster_lowercase,
            "paymaster",
            associated_slots_per_entity,
            is_paymaster_staked,
            sender_lowercase,
            paymaster_data,
            is_init_code,
            is_factory_staked
        )
        storage_map |= paymaster_storage_map

    return storage_map


def validate_entity_storage_access(
    entrypoint_lowercase: Address,
    entity_address: Address,
    entity_title: str,
    associated_slots_per_entity: dict[str, list[str]],
    is_staked: bool,
    sender_lowercase: Address,
    entity_data: Any,
    is_init_code: bool,
    is_factory_staked: bool | None,
) -> dict[str, dict[str, str]]:
    validate_extcode_and_call_to_undeployed_contracts(
        entrypoint_lowercase, entity_title, entity_data, sender_lowercase)

    storage_map: dict[str, dict[str, str]] = dict()
    access = entity_data["access"]
    for contract_address in access.keys():
        storage_slots = access[contract_address]
        if len(storage_slots["reads"]) > 0:
            storage_map[contract_address] = storage_slots["reads"]

        # [STO-010]
        if contract_address == sender_lowercase:
            continue  # allowed to access sender's storage
        elif contract_address == entrypoint_lowercase:
            # ignore storage access on entryPoint (balance/deposit of entities.
            # we block them on method calls: only allowed to deposit, never to read
            continue

        slots = (
            set(storage_slots["reads"]) |
            set(storage_slots["writes"]) |
            set(storage_slots["transientReads"]) |
            set(storage_slots["transientWrites"])
        )

        for slot in slots:
            require_stake_slot = None

            # slot associated with sender is allowed (e.g. token.balanceOf(sender)
            # but during initial UserOp (where there is an initCode),
            # it is allowed only for staked entity
            if (
                sender_lowercase in associated_slots_per_entity
                and is_slot_associated_with_address(
                    slot,
                    sender_lowercase,
                    associated_slots_per_entity[sender_lowercase],
                )
            ):
                # special case: account.validateUserOp is allowed to use assoc
                # storage if factory is staked.
                # [STO-022], [STO-021]
                if is_init_code:
                    if not (entity_title == "sender" and is_factory_staked):
                        require_stake_slot = slot
            elif (
                entity_address in associated_slots_per_entity
                and is_slot_associated_with_address(
                    slot,
                    entity_address,
                    associated_slots_per_entity[entity_address],
                )
            ):
                # [STO-032]
                # accessing a slot associated with entityAddr
                # (e.g. token.balanceOf(paymaster)
                require_stake_slot = slot
            elif contract_address == entity_address:
                # [STO-031]
                # accessing storage member of entity itself requires stake.
                require_stake_slot = slot
            elif (
                    slot not in storage_slots["writes"] and
                    slot not in storage_slots["transientWrites"]):
                # [STO-033]: staked entity have read-only access
                # to any storage in non-entity contract.
                require_stake_slot = slot
            else:
                # accessing arbitrary storage of another contract is not allowed
                if slot in storage_slots["transientWrites"]:
                    read_write = "write to"
                    transient_str = "transient"
                elif slot in storage_slots["writes"]:
                    read_write = "write to"
                    transient_str = ""
                elif slot in storage_slots["transientReads"]:
                    read_write = "read from"
                    transient_str = "transient"
                else:  # slot in storage_slots["reads"]:
                    read_write = "read from"
                    transient_str = ""
                raise ValidationException(
                    ValidationExceptionCode.OpcodeValidation,
                    f"{entity_title}:{entity_address} has forbidden ${read_write} " +
                    f"{transient_str} {contract_address} slot {slot}",
                )
            if not is_staked and require_stake_slot is not None:
                raise ValidationException(
                    ValidationExceptionCode.OpcodeValidation,
                    f"{entity_title}:{entity_address} " +
                    f"insuffient stake to access slot {slot} at {contract_address}"
                )
    return storage_map


def validate_extcode_and_call_to_undeployed_contracts(
    entrypoint_lowercase: Address,
    entity_title: str,
    entity_data,
    sender_lowercase: Address
) -> None:
    if len(entity_data["extCodeAccessInfo"]) > 0:
        for contract_address in entity_data["extCodeAccessInfo"].keys():
            if contract_address == entrypoint_lowercase:
                raise ValidationException(
                    ValidationExceptionCode.OpcodeValidation,
                    "illegal EXTCODE*",
                )
    # [OP-020]
    if "oog" in entity_data and entity_data["oog"]:
        raise ValidationException(
            ValidationExceptionCode.OpcodeValidation,
            f"{entity_title} internally reverts on oog",
        )
    # the only contract we allow to access before its deployment is the
    # "sender" itself, which gets created.
    for contract_address, size in entity_data["contractSize"].items():
        # [OP-042]
        if contract_address != sender_lowercase and size["contractSize"] < 2:
            raise ValidationException(
                ValidationExceptionCode.OpcodeValidation,
                "illegal call to undeployed contract",
            )
