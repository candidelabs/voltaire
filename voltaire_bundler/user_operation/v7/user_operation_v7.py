from dataclasses import InitVar, dataclass

from eth_abi import encode
from eth_utils import keccak
from voltaire_bundler.bundle.exceptions import \
    ValidationException, ValidationExceptionCode
from voltaire_bundler.typing import Address, MempoolId
from ..user_operation import \
    verify_and_get_uint, verify_and_get_bytes, verify_and_get_address
from ..user_operation import UserOperation


@dataclass()
class UserOperationV7(UserOperation):
    sender_address: Address
    nonce: int
    factory: Address | None
    factory_data: bytes | None
    call_data: bytes
    call_gas_limit: int
    verification_gas_limit: int
    pre_verification_gas: int
    max_fee_per_gas: int
    max_priority_fee_per_gas: int
    paymaster: Address | None
    paymaster_verification_gas_limit: int | None
    paymaster_post_op_gas_limit: int | None
    paymaster_data: bytes | None
    signature: bytes
    code_hash: str | None
    factory_address_lowercase: Address | None
    paymaster_address_lowercase: Address | None
    valid_mempools_ids: list[MempoolId]
    user_operation_hash: str
    jsonRequestDict: InitVar[dict[str, Address | int | bytes]]

    def __init__(self, jsonRequestDict) -> None:
        if len(jsonRequestDict) != 15:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Invalide UserOperation",
            )
        self.verify_fields_exist(jsonRequestDict)

        self.sender_address = verify_and_get_address(jsonRequestDict["sender"])
        self.nonce = verify_and_get_uint(jsonRequestDict["nonce"])

        factory = jsonRequestDict["factory"]
        factory_data = jsonRequestDict["factoryData"]
        if factory is not None:
            self.factory = verify_and_get_address(factory)
            self.factory_data = verify_and_get_bytes(factory_data)
        elif factory_data is None:
            self.factory = None
            self.factory_data = None
        else:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Invalide UserOperation",
            )

        self.call_data = verify_and_get_bytes(jsonRequestDict["callData"])
        self.call_gas_limit = verify_and_get_uint(
                jsonRequestDict["callGasLimit"])
        self.verification_gas_limit = verify_and_get_uint(
            jsonRequestDict["verificationGasLimit"]
        )

        self.pre_verification_gas = verify_and_get_uint(
            jsonRequestDict["preVerificationGas"]
        )
        self.max_fee_per_gas = verify_and_get_uint(
                jsonRequestDict["maxFeePerGas"])
        self.max_priority_fee_per_gas = verify_and_get_uint(
            jsonRequestDict["maxPriorityFeePerGas"]
        )

        paymaster = jsonRequestDict["paymaster"]
        paymaster_verification_gas_limit = jsonRequestDict[
                "paymasterVerificationGasLimit"]
        paymaster_post_op_gas_limit = jsonRequestDict["paymasterPostOpGasLimit"]
        paymaster_data = jsonRequestDict["paymasterData"]
        if paymaster is not None:
            self.paymaster = verify_and_get_address(paymaster)
            self.paymaster_verification_gas_limit = verify_and_get_uint(
                paymaster_verification_gas_limit
            )
            self.paymaster_post_op_gas_limit = verify_and_get_uint(
               paymaster_post_op_gas_limit
            )
            self.paymaster_data = verify_and_get_bytes(
               paymaster_data
            )

        elif (
            paymaster_verification_gas_limit is None and
            paymaster_post_op_gas_limit is None and
            paymaster_data is None
        ):
            self.paymaster = None
            self.paymaster_verification_gas_limit = None
            self.paymaster_post_op_gas_limit = None
            self.paymaster_data = None
        else:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Invalide UserOperation",
            )

        self.signature = verify_and_get_bytes(jsonRequestDict["signature"])

        self.code_hash = None

        self.storage_map = None

        self.valid_mempools_ids = []

        self.user_operation_hash = ""

        self.validated_at_block_hex = None

        self._set_factory_and_paymaster_address()

    @staticmethod
    def verify_fields_exist(
        jsonRequestDict: dict[str, Address | int | bytes]
    ) -> None:
        field_list = [
            "sender",
            "nonce",
            "factory",
            "factoryData",
            "callData",
            "callGasLimit",
            "verificationGasLimit",
            "preVerificationGas",
            "maxFeePerGas",
            "maxPriorityFeePerGas",
            "paymaster",
            "paymasterVerificationGasLimit",
            "paymasterPostOpGasLimit",
            "paymasterData",
            "signature",
        ]

        for field in field_list:
            if field not in jsonRequestDict:
                raise ValidationException(
                    ValidationExceptionCode.InvalidFields,
                    f"UserOperation missing {field} field",
                )

    def get_user_operation_dict(self) -> dict[str, Address | int | bytes | None]:
        return {
            "sender": self.sender_address,
            "nonce": self.nonce,
            "factory": self.factory,
            "factoryData": self.factory_data,
            "callData": self.call_data,
            "callGasLimit": self.call_gas_limit,
            "verificationGasLimit": self.verification_gas_limit,
            "preVerificationGas": self.pre_verification_gas,
            "maxFeePerGas": self.max_fee_per_gas,
            "maxPriorityFeePerGas": self.max_priority_fee_per_gas,
            "paymaster": self.paymaster,
            "paymasterVerificationGasLimit": self.paymaster_verification_gas_limit,
            "paymasterPostOpGasLimit": self.paymaster_post_op_gas_limit,
            "paymasterData": self.paymaster_data,
            "signature": self.signature,
        }

    def get_user_operation_json(self) -> dict[str, Address | str | None]:
        return {
            "sender": self.sender_address,
            "nonce": hex(self.nonce),
            "factory": self.factory,
            "factoryData":
            None if self.factory_data is None
            else "0x" + self.factory_data.hex(),
            "callData": "0x" + self.call_data.hex(),
            "callGasLimit": hex(self.call_gas_limit),
            "verificationGasLimit": hex(self.verification_gas_limit),
            "preVerificationGas": hex(self.pre_verification_gas),
            "maxFeePerGas": hex(self.max_fee_per_gas),
            "maxPriorityFeePerGas": hex(self.max_priority_fee_per_gas),
            "paymaster": self.paymaster,
            "paymasterVerificationGasLimit":
            None if self.paymaster_verification_gas_limit is None
            else hex(self.paymaster_verification_gas_limit),
            "paymasterPostOpGasLimit":
            None if self.paymaster_post_op_gas_limit is None
            else hex(self.paymaster_post_op_gas_limit),
            "paymasterData":
            None if self.paymaster_data is None
            else "0x" + self.paymaster_data.hex(),
            "signature": "0x" + self.signature.hex(),
        }

    def to_list(self) -> list[Address | str | int | bytes | None]:
        if self.factory is None:
            init_code = bytes(0)
        else:
            init_code = (
                bytes.fromhex(self.factory[2:]) +
                self.factory_data  # type: ignore
            )
        account_gas_limits = (
            self.verification_gas_limit.to_bytes(16) +
            self.call_gas_limit.to_bytes(16)
        )

        gas_fees = (
            self.max_priority_fee_per_gas.to_bytes(16) +
            self.max_fee_per_gas.to_bytes(16)
        )

        if self.paymaster is None:
            paymaster_and_data = bytes(0)
        else:
            paymaster_and_data = (
                bytes.fromhex(self.paymaster[2:]) +  # type: ignore
                self.paymaster_verification_gas_limit.to_bytes(16) +  # type: ignore
                self.paymaster_post_op_gas_limit.to_bytes(16) +  # type: ignore
                self.paymaster_data
            )

        return [
            self.sender_address,
            self.nonce,
            init_code,
            self.call_data,
            account_gas_limits,
            self.pre_verification_gas,
            gas_fees,
            paymaster_and_data,
            self.signature
        ]

    def get_max_validation_cost(self) -> int:
        max_cost = self.pre_verification_gas + self.verification_gas_limit
        if self.paymaster_verification_gas_limit is not None:
            max_cost += self.paymaster_verification_gas_limit
        return max_cost * self.max_fee_per_gas

    def get_max_cost(self) -> int:
        max_cost = (
            self.pre_verification_gas +
            self.verification_gas_limit +
            self.call_gas_limit
        )
        if self.paymaster_verification_gas_limit is not None:
            max_cost += self.paymaster_verification_gas_limit
        if self.paymaster_post_op_gas_limit is not None:
            max_cost += self.paymaster_post_op_gas_limit

        return max_cost * self.max_fee_per_gas

    def _set_factory_and_paymaster_address(self) -> None:
        if self.factory is not None and len(self.factory) >= 20:
            self.factory_address_lowercase = Address(self.factory.lower())
        else:
            self.factory_address_lowercase = None

        if self.paymaster is not None and len(self.paymaster) >= 20:
            self.paymaster_address_lowercase = Address(self.paymaster.lower())
        else:
            self.paymaster_address_lowercase = None


def get_user_operation_hash(
    user_operation_list: list, entrypoint_addr: str, chain_id: int
) -> str:
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
        user_operation_list[2] = keccak(user_operation_list[2])  # initCode
        user_operation_list[3] = keccak(user_operation_list[3])  # callData
        user_operation_list[7] = keccak(user_operation_list[7])  # paymasterAndData

        user_operation_list_without_signature = user_operation_list[:-1]

        packed_user_operation = encode(
            [
                "address",
                "uint256",
                "bytes32",
                "bytes32",
                "bytes32",
                "uint256",
                "bytes32",
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
                "bytes32",
                "uint256",
                "bytes32",
                "bytes",
                "bytes",
            ],
            user_operation_list,
        )
    return packed_user_operation
