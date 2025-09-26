from dataclasses import InitVar, dataclass

from eth_abi import encode
from eth_utils import keccak
from voltaire_bundler.bundle.exceptions import \
    ValidationException, ValidationExceptionCode
from voltaire_bundler.typing import Address, MempoolId
from .user_operation import \
    verify_and_get_uint, verify_and_get_bytes, verify_and_get_address
from .user_operation import UserOperation


@dataclass()
class UserOperationV6(UserOperation):
    sender_address: Address
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
    factory_address_lowercase: Address | None
    paymaster_address_lowercase: Address | None
    valid_mempools_ids: list[MempoolId]
    user_operation_hash: str
    jsonRequestDict: InitVar[dict[str, Address | int | bytes]]

    def __init__(self, jsonRequestDict) -> None:
        if len(jsonRequestDict) != 11:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Invalid UserOperation",
            )
        self.verify_fields_exist(jsonRequestDict)

        self.sender_address = verify_and_get_address(
            "sender", jsonRequestDict["sender"])
        self.nonce = verify_and_get_uint(
            "nonce", jsonRequestDict["nonce"])
        self.init_code = verify_and_get_bytes(
            "initCode", jsonRequestDict["initCode"])
        self.call_data = verify_and_get_bytes(
            "callData", jsonRequestDict["callData"])
        self.call_gas_limit = verify_and_get_uint(
            "callGasLimit", jsonRequestDict["callGasLimit"])
        self.verification_gas_limit = verify_and_get_uint(
            "verificationGasLimit", jsonRequestDict["verificationGasLimit"]
        )
        self.pre_verification_gas = verify_and_get_uint(
            "preVerificationGas", jsonRequestDict["preVerificationGas"]
        )
        self.max_fee_per_gas = verify_and_get_uint(
            "maxFeePerGas", jsonRequestDict["maxFeePerGas"])
        self.max_priority_fee_per_gas = verify_and_get_uint(
            "maxPriorityFeePerGas", jsonRequestDict["maxPriorityFeePerGas"]
        )
        self.paymaster_and_data = verify_and_get_bytes(
            "paymasterAndData", jsonRequestDict["paymasterAndData"]
        )
        self.signature = verify_and_get_bytes(
            "signature", jsonRequestDict["signature"])

        self.code_hash = None
        self.storage_map = None
        self.valid_mempools_ids = []
        self.user_operation_hash = ""
        self.validated_at_block_hex = None
        self._set_factory_and_paymaster_address()
        self.attempted_bundle_transaction_hash = None
        self.last_add_to_mempool_date = None
        self.number_of_add_to_mempool_attempts = 0

    @staticmethod
    def verify_fields_exist(
            jsonRequestDict: dict[str, Address | int | bytes]
    ) -> None:
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
                )

    def get_user_operation_dict(self) -> dict[str, Address | int | bytes]:
        return {
            "sender": self.sender_address,
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

    def get_user_operation_json(self) -> dict[str, Address | str]:
        return {
            "sender": self.sender_address,
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

    def to_list(self) -> list[Address | str | int | bytes]:
        return [
            self.sender_address,
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

    def get_max_validation_cost(self) -> int:
        max_cost = self.pre_verification_gas + self.verification_gas_limit
        if self.paymaster_address_lowercase is not None:
            max_cost += 2 * self.verification_gas_limit
        return max_cost * self.max_fee_per_gas

    def get_max_gas_without_pre_verification_gas(self) -> int:
        max_cost = (
            self.verification_gas_limit +
            self.call_gas_limit
        )
        if self.paymaster_address_lowercase is not None:
            max_cost += 2 * self.verification_gas_limit

        return max_cost

    def get_max_gas_with_pre_verification_gas(self) -> int:
        max_cost = (
            self.pre_verification_gas +
            self.verification_gas_limit +
            self.call_gas_limit
        )
        if self.paymaster_address_lowercase is not None:
            max_cost += 2 * self.verification_gas_limit

        return max_cost

    def _set_factory_and_paymaster_address(self) -> None:
        if len(self.init_code) > 20:
            self.factory_address_lowercase = Address(
                "0x" + self.init_code[:20].hex())
        else:
            self.factory_address_lowercase = None

        if len(self.paymaster_and_data) >= 20:
            self.paymaster_address_lowercase = Address(
                "0x" + self.paymaster_and_data[:20].hex())
        else:
            self.paymaster_address_lowercase = None


def get_user_operation_hash(
    user_operation_list: list, entrypoint_addr: str, chain_id: int
):
    packed_user_operation = keccak(
        pack_user_operation(user_operation_list)
    )

    encoded_user_operation_hash = encode(
        ["(bytes32,address,uint256)"],
        [[packed_user_operation, entrypoint_addr, chain_id]],
    )
    user_operation_hash = "0x" + keccak(encoded_user_operation_hash).hex()
    return user_operation_hash


def pack_user_operation(
    user_operation_list: list, for_signature: bool = True
) -> bytes:
    if for_signature:
        user_operation_list[2] = keccak(user_operation_list[2])
        user_operation_list[3] = keccak(user_operation_list[3])
        user_operation_list[9] = keccak(user_operation_list[9])
        user_operation_list_without_signature = user_operation_list[:-1]

        packed_user_operation = encode(
            [
                "address",
                "uint256",
                "bytes32",
                "bytes32",
                "uint256",
                "uint256",
                "uint256",
                "uint256",
                "uint256",
                "bytes32",
            ],
            user_operation_list_without_signature,
        )
    else:
        packed_user_operation = encode(
            [
                "address",
                "uint256",
                "bytes",
                "bytes",
                "uint256",
                "uint256",
                "uint256",
                "uint256",
                "uint256",
                "bytes",
                "bytes",
            ],
            user_operation_list,
        )
    return packed_user_operation
