from abc import ABC, abstractmethod
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

    @abstractmethod
    def get_user_operation_json(
            self
    ) -> dict[str, Address | str] | dict[str, Address | str | None]:
        pass

    @abstractmethod
    def get_max_validation_cost(self) -> int:
        pass

    @abstractmethod
    def get_max_cost(self) -> int:
        pass


def verify_and_get_address(value: Address) -> Address:
    address_pattern = "^0x[0-9,a-f,A-F]{40}$"
    if isinstance(value, str) and re.match(address_pattern, value) is not None:
        return value
    else:
        raise ValidationException(
            ValidationExceptionCode.InvalidFields,
            f"Invalide address value : {value}",
        )


def verify_and_get_uint(value: str) -> int:
    if value is None:
        raise ValidationException(
            ValidationExceptionCode.InvalidFields,
            "Invalide bytes hex value",
        )

    if value == "0x":
        return 0
    elif isinstance(value, str) and value[:2] == "0x":
        try:
            return int(value, 16)
        except ValueError:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                f"Invalide uint hex value : {value}",
            )
    else:
        raise ValidationException(
            ValidationExceptionCode.InvalidFields,
            f"Invalide uint hex value : {value}",
        )


def verify_and_get_bytes(value: str) -> bytes:
    if value is None:
        raise ValidationException(
            ValidationExceptionCode.InvalidFields,
            "Invalide bytes hex value",
        )

    if isinstance(value, str) and value[:2] == "0x":
        try:
            return bytes.fromhex(value[2:])
        except ValueError:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                f"Invalide bytes hex value : {value}",
            )
    else:
        raise ValidationException(
            ValidationExceptionCode.InvalidFields,
            f"Invalide bytes hex value : {value}",
        )


def is_user_operation_hash(user_operation_hash: str) -> bool:
    hash_pattern = "^0x[0-9,a-f,A-F]{64}$"
    return (
        isinstance(user_operation_hash, str)
        and re.match(hash_pattern, user_operation_hash) is not None
    )
