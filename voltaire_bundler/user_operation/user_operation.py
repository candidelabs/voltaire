from abc import ABC, abstractmethod
from datetime import datetime
import re
from voltaire_bundler.bundle.exceptions import \
        ValidationException, ValidationExceptionCode
from voltaire_bundler.typing import Address, MempoolId


class UserOperation(ABC):
    sender_address: Address
    nonce: int
    max_fee_per_gas: int
    max_priority_fee_per_gas: int
    factory_address_lowercase: Address | None
    paymaster_address_lowercase: Address | None
    valid_mempools_ids: list[MempoolId]
    user_operation_hash: str
    code_hash: str | None
    storage_map: dict[str, str | dict[str, str]] | None
    validated_at_block_hex: str | None
    attempted_bundle_transaction_hash: str | None
    last_add_to_mempool_date: datetime | None
    number_of_add_to_mempool_attempts: int
    eip7702_auth: dict[str, str] | None

    @abstractmethod
    def get_user_operation_json(
            self
    ) -> dict[str, Address | str] | dict[str, Address | str | None]:
        pass

    @abstractmethod
    def get_max_validation_cost(self) -> int:
        pass

    @abstractmethod
    def get_max_gas_without_pre_verification_gas(self) -> int:
        pass

    @abstractmethod
    def get_max_gas_with_pre_verification_gas(self) -> int:
        pass

    def get_max_cost(self) -> int:
        return self.get_max_gas_with_pre_verification_gas() * self.max_fee_per_gas


def verify_and_get_address(field_name: str, value: Address | None) -> Address:
    address_pattern = "^0x[0-9,a-f,A-F]{40}$"
    if isinstance(value, str) and re.match(address_pattern, value) is not None:
        return value
    else:
        raise ValidationException(
            ValidationExceptionCode.InvalidFields,
            f"Invalid address value : {value} in field {field_name}",
        )


def verify_and_get_uint(field_name: str, value: str | None) -> int:
    if value is None:
        raise ValidationException(
            ValidationExceptionCode.InvalidFields,
            f"Invalid uint hex value in field {field_name}",
        )

    if value == "0x":
        return 0
    elif isinstance(value, str) and value[:2] == "0x":
        try:
            return int(value, 16)
        except ValueError:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                f"Invalid uint hex value : {value} in field {field_name}",
            )
    else:
        raise ValidationException(
            ValidationExceptionCode.InvalidFields,
            f"Invalid uint hex value : {value} in field {field_name}",
        )


def verify_and_get_bytes(field_name: str, value: str | None) -> bytes:
    if value is None:
        raise ValidationException(
            ValidationExceptionCode.InvalidFields,
            f"Invalid bytes hex value in field {field_name}",
        )

    if isinstance(value, str) and value[:2] == "0x":
        try:
            return bytes.fromhex(value[2:])
        except ValueError:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                f"Invalid bytes hex value : {value} in field {field_name}",
            )
    else:
        raise ValidationException(
            ValidationExceptionCode.InvalidFields,
            f"Invalid bytes hex value : {value} in field {field_name}",
        )


def verify_and_get_eip7702_auth(value: dict) -> dict[str, str]:
    if (
        "chainId" not in value or
        "address" not in value or
        "nonce" not in value or
        "yParity" not in value or
        "r" not in value or
        "s" not in value
    ):
        raise ValidationException(
            ValidationExceptionCode.InvalidFields,
            "Invalid eip7702Auth field.",
        )
    return {
        "chainId": hex(verify_and_get_uint("eip7702Auth.chainId", value["chainId"])),
        "address": verify_and_get_address("eip7702Auth.address", value["address"]),
        "nonce": hex(verify_and_get_uint("eip7702Auth.nonce", value["nonce"])),
        "yParity": hex(verify_and_get_uint("eip7702Auth.yParity", value["yParity"])),
        "r": hex(verify_and_get_uint("eip7702Auth.r", value["r"])),
        "s": hex(verify_and_get_uint("eip7702Auth.s", value["s"]))
    }


def is_user_operation_hash(user_operation_hash: str) -> bool:
    hash_pattern = "^0x[0-9,a-f,A-F]{64}$"
    return (
        isinstance(user_operation_hash, str)
        and re.match(hash_pattern, user_operation_hash) is not None
    )
