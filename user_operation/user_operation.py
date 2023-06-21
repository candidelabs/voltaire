from dataclasses import dataclass, InitVar
from bundler.exceptions import ValidationException, ValidationExceptionCode
import re


@dataclass()
class UserOperation:
    sender: str
    nonce: int
    init_code: bytes
    call_data: bytes
    call_gas_limit: int
    verification_gas_limit: int
    pre_verification_gas: int
    max_fee_per_gas: int
    max_priority_fee_per_gas: int
    paymaster_and_data: bytes
    signature: bytes
    code_hash: str | None
    associated_addresses: list()
    factory_address: str | None
    paymaster_address: str | None
    jsonRequestDict: InitVar[dict]

    def __init__(self, jsonRequestDict):
        if len(jsonRequestDict) != 11:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Invalide UserOperation",
                "",
            )
        self.verify_fields_exist(jsonRequestDict)

        self.sender = verify_and_get_address(jsonRequestDict["sender"])
        self.nonce = verify_and_get_uint(jsonRequestDict["nonce"])
        self.init_code = verify_and_get_bytes(jsonRequestDict["initCode"])
        self.call_data = verify_and_get_bytes(jsonRequestDict["callData"])
        self.call_gas_limit = verify_and_get_uint(
            jsonRequestDict["callGasLimit"]
        )
        self.verification_gas_limit = verify_and_get_uint(
            jsonRequestDict["verificationGasLimit"]
        )
        self.pre_verification_gas = verify_and_get_uint(
            jsonRequestDict["preVerificationGas"]
        )
        self.max_fee_per_gas = verify_and_get_uint(
            jsonRequestDict["maxFeePerGas"]
        )
        self.max_priority_fee_per_gas = verify_and_get_uint(
            jsonRequestDict["maxPriorityFeePerGas"]
        )
        self.paymaster_and_data = verify_and_get_bytes(
            jsonRequestDict["paymasterAndData"]
        )
        self.signature = verify_and_get_bytes(jsonRequestDict["signature"])

        self.code_hash = None

        self.associated_addresses = []

        self._set_factory_and_paymaster_address()

    @staticmethod
    def verify_fields_exist(jsonRequestDict) -> None:
        field_list = [
            "sender",
            "nonce",
            "initCode",
            "callData",
            "callGasLimit",
            "verificationGasLimit",
            "preVerificationGas",
            "maxFeePerGas",
            "maxPriorityFeePerGas",
            "paymasterAndData",
            "signature",
        ]

        for field in field_list:
            if field not in jsonRequestDict:
                raise ValidationException(
                    ValidationExceptionCode.InvalidFields,
                    f"UserOperation missing {field} field",
                    "",
                )

    def get_user_operation_dict(self) -> tuple:
        return {
            "sender": self.sender,
            "nonce": self.nonce,
            "initCode": self.init_code,
            "callData": self.call_data,
            "callGasLimit": self.call_gas_limit,
            "verificationGasLimit": self.verification_gas_limit,
            "preVerificationGas": self.pre_verification_gas,
            "maxFeePerGas": self.max_fee_per_gas,
            "maxPriorityFeePerGas": self.max_priority_fee_per_gas,
            "paymasterAndData": self.paymaster_and_data,
            "signature": self.signature,
        }

    def get_user_operation_json(self):
        return {
            "sender": self.sender,
            "nonce": hex(self.nonce),
            "initCode": "0x" + self.init_code.hex(),
            "callData": "0x" + self.call_data.hex(),
            "callGasLimit": hex(self.call_gas_limit),
            "verificationGasLimit": hex(self.verification_gas_limit),
            "preVerificationGas": hex(self.pre_verification_gas),
            "maxFeePerGas": hex(self.max_fee_per_gas),
            "maxPriorityFeePerGas": hex(self.max_priority_fee_per_gas),
            "paymasterAndData": "0x" + self.paymaster_and_data.hex(),
            "signature": "0x" + self.signature.hex(),
        }

    def to_list(self) -> list:
        return [
            self.sender,
            self.nonce,
            self.init_code,
            self.call_data,
            self.call_gas_limit,
            self.verification_gas_limit,
            self.pre_verification_gas,
            self.max_fee_per_gas,
            self.max_priority_fee_per_gas,
            self.paymaster_and_data,
            self.signature,
        ]

    def _set_factory_and_paymaster_address(self):
        if len(self.init_code) > 20:
            self.factory_address = "0x" + self.init_code[:20].hex()
        else:
            self.factory_address = None

        if len(self.paymaster_and_data) > 20:
            self.paymaster_address = "0x" + self.paymaster_and_data[:20].hex()
        else:
            self.paymaster_address = None


def verify_and_get_address(value) -> str:
    if value is None:
        return 0

    address_pattern = "^0x[0-9,a-f,A-F]{40}$"
    if isinstance(value, str) and re.match(address_pattern, value) is not None:
        return value
    else:
        raise ValidationException(
            ValidationExceptionCode.InvalidFields,
            f"Invalide address value : {value}",
            "",
        )


def verify_and_get_uint(value) -> int:
    if value is None or value == "0x":
        return 0

    if isinstance(value, int):
        return value
    elif isinstance(value, str) and value.isdigit():
        return int(value)
    elif isinstance(value, str):
        try:
            return int(value, 16)
        except ValueError as exp:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                f"Invalide uint value : {value}",
                "",
            )
    else:
        raise ValidationException(
            ValidationExceptionCode.InvalidFields,
            f"Invalide uint value : {value}",
            "",
        )


def verify_and_get_bytes(value) -> bytes:
    if value is None:
        return bytes(0)

    bytes_pattern = "(^$|^0x|0x([1-9a-f]+[0-9a-f]*|0)$)"
    if isinstance(value, str) and re.match(bytes_pattern, value) is not None:
        try:
            return bytes.fromhex(value[2:])
        except ValueError as exp:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                f"Invalide bytes value : {value}",
                "",
            )
    else:
        raise ValidationException(
            ValidationExceptionCode.InvalidFields,
            f"Invalide bytes value : {value}",
            "",
        )


def is_user_operation_hash(user_operation_hash) -> bool:
    hash_pattern = "^0x[0-9,a-f,A-F]{64}$"
    return (
        isinstance(user_operation_hash, str)
        and re.match(hash_pattern, user_operation_hash) is not None
    )
