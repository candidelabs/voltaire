from dataclasses import InitVar, dataclass

from eth_abi import encode
from eth_utils import keccak
from voltaire_bundler.bundle.exceptions import \
    ValidationException, ValidationExceptionCode
from voltaire_bundler.typing import Address, MempoolId
from .user_operation import \
    verify_and_get_eip7702_auth, verify_and_get_uint, verify_and_get_bytes, verify_and_get_address
from .user_operation import UserOperation


@dataclass()
class UserOperationV7V8(UserOperation):
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
    eip7702_auth: dict[str, str] | None
    jsonRequestDict: InitVar[dict[str, Address | int | bytes]]

    def __init__(self, jsonRequestDict) -> None:
        self.verify_fields_exist_and_fill_optional(jsonRequestDict)
        if len(jsonRequestDict) != 16:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Invalid UserOperation",
            )
        if jsonRequestDict["eip7702Auth"] is not None:
            self.eip7702_auth = verify_and_get_eip7702_auth(
                jsonRequestDict["eip7702Auth"]
            )
        else:
            self.eip7702_auth = None

        self.sender_address = verify_and_get_address(
            "sender", jsonRequestDict["sender"])
        self.nonce = verify_and_get_uint(
            "nonce", jsonRequestDict["nonce"])

        factory = jsonRequestDict["factory"]
        factory_data = jsonRequestDict["factoryData"]
        if factory is not None:
            if factory == "0x7702":
                self.factory = Address("0x7702000000000000000000000000000000000000")
            else:
                self.factory = verify_and_get_address("factory", factory)
            if factory_data is None:
                self.factory_data = None
            else:
                self.factory_data = verify_and_get_bytes("factoryData", factory_data)
        elif factory_data is None:
            self.factory = None
            self.factory_data = None
        else:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                'Invalid UserOperation, '
                '"factoryData" has to be null if "factory" is null',
            )

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

        paymaster = jsonRequestDict["paymaster"]
        paymaster_verification_gas_limit = jsonRequestDict[
                "paymasterVerificationGasLimit"]
        paymaster_post_op_gas_limit = jsonRequestDict["paymasterPostOpGasLimit"]
        paymaster_data = jsonRequestDict["paymasterData"]
        if paymaster is not None:
            self.paymaster = verify_and_get_address("paymaster", paymaster)
            self.paymaster_verification_gas_limit = verify_and_get_uint(
                "paymasterVerificationGasLimit", paymaster_verification_gas_limit
            )
            self.paymaster_post_op_gas_limit = verify_and_get_uint(
               "paymasterPostOpGasLimit", paymaster_post_op_gas_limit
            )
            self.paymaster_data = verify_and_get_bytes(
               "paymasterData", paymaster_data
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
                "Invalid UserOperation, "
                '"paymasterVerificationGasLimit", "paymasterPostOpGasLimit" '
                'and "paymasterData" have to be null if "paymaster" is null',
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
    def verify_fields_exist_and_fill_optional(
        jsonRequestDict: dict[str, Address | int | bytes | None]
    ) -> None:
        required_fields_list = [
            "sender",
            "nonce",
            "callData",
            "callGasLimit",
            "verificationGasLimit",
            "preVerificationGas",
            "maxFeePerGas",
            "maxPriorityFeePerGas",
            "signature",
        ]

        for field in required_fields_list:
            if field not in jsonRequestDict:
                raise ValidationException(
                    ValidationExceptionCode.InvalidFields,
                    f"UserOperation missing {field} field",
                )

        optional_fields_list = [
            "factory",
            "factoryData",
            "paymaster",
            "paymasterVerificationGasLimit",
            "paymasterPostOpGasLimit",
            "paymasterData",
            "eip7702Auth"
        ]

        for field in optional_fields_list:
            if field not in jsonRequestDict:
                jsonRequestDict[field] = None

    def get_use_operation_dict(self) -> dict[str, Address | int | bytes | None]:
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
        elif self.factory_data is None:
            init_code = bytes.fromhex(self.factory[2:])
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

    def get_max_gas(self) -> int:
        max_cost = (
            self.verification_gas_limit +
            self.call_gas_limit
        )
        if self.paymaster_verification_gas_limit is not None:
            max_cost += self.paymaster_verification_gas_limit
        if self.paymaster_post_op_gas_limit is not None:
            max_cost += self.paymaster_post_op_gas_limit

        return max_cost

    def get_max_gas_with_pre_verification_gas(self) -> int:
        max_cost = (
            self.pre_verification_gas +
            self.verification_gas_limit +
            self.call_gas_limit
        )
        if self.paymaster_verification_gas_limit is not None:
            max_cost += self.paymaster_verification_gas_limit
        if self.paymaster_post_op_gas_limit is not None:
            max_cost += self.paymaster_post_op_gas_limit

        return max_cost

    def _set_factory_and_paymaster_address(self) -> None:
        if (self.factory is not None and len(self.factory) >= 20):
            self.factory_address_lowercase = Address(self.factory.lower())
        else:
            self.factory_address_lowercase = None

        if self.paymaster is not None and len(self.paymaster) >= 20:
            self.paymaster_address_lowercase = Address(self.paymaster.lower())
        else:
            self.paymaster_address_lowercase = None


DOMAIN_SEPARATOR: bytes | None = None


def get_user_operation_hash(
    user_operation_list: list,
    entrypoint_addr: str,
    chain_id: int,
    delegate: str | None = None
) -> str:
    if entrypoint_addr.startswith("0x4337"):  # ep v0.8.0
        packed_user_operation_hash = keccak(
            pack_user_operation_for_hashing_v8(user_operation_list, delegate)
        )

        domain_separator = build_domain_separator(chain_id)
        user_operation_hash = "0x" + keccak(
            b'\x19\x01' + domain_separator + packed_user_operation_hash,
        ).hex()
        return user_operation_hash
    else:  # ep v0.7.0
        packed_user_operation_hash = keccak(
            pack_user_operation_for_hashing_v7(user_operation_list)
        )
        encoded_user_operation_hash = encode(
            ["(bytes32,address,uint256)"],
            [[packed_user_operation_hash, entrypoint_addr, chain_id]],
        )

        user_operation_hash = "0x" + keccak(encoded_user_operation_hash).hex()
        return user_operation_hash


def build_domain_separator(chain_id: int) -> bytes:
    global DOMAIN_SEPARATOR

    if DOMAIN_SEPARATOR is None:
        # DOMAIN_NAME = "ERC4337"
        HASHED_NAME = b'6M\xa2\x8a\\\x92\xbc\xc8\x7f\xe9|\x88\x13\xa6\xc6\xb8\xa3\xa0I\xb0\xea\n2\x8f\xcb\x0bO\x0e\x003u\x86'
        # DOMAIN_VERSION = "1"
        HASHED_VERSION = b'\xc8\x9e\xfd\xaaT\xc0\xf2\x0cz\xdfa(\x82\xdf\tP\xf5\xa9Qc~\x03\x07\xcd\xcbLg/)\x8b\x8b\xc6'
        # TYPE_HASH = keccak("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        TYPE_HASH = b'\x8bs\xc3\xc6\x9b\xb8\xfe=Q.\xccL\xf7Y\xccy#\x9f{\x17\x9b\x0f\xfa\xca\xa9\xa7]R+9@\x0f'
        encoded_user_operation_hash = encode(
            ["(bytes32,bytes32,bytes32,uint256,address)"],
            [[TYPE_HASH, HASHED_NAME, HASHED_VERSION, chain_id, "0x4337084d9e255ff0702461cf8895ce9e3b5ff108"]],
        )

        DOMAIN_SEPARATOR = keccak(encoded_user_operation_hash)

    assert DOMAIN_SEPARATOR is not None
    return DOMAIN_SEPARATOR


def pack_user_operation_for_hashing_v8(
    user_operation_list: list, delegate: str | None = None
) -> bytes:
    if user_operation_list[2] == bytes(0):
        user_operation_list[2] = keccak(user_operation_list[2])  # initCode
    elif delegate is not None:
        if len(user_operation_list[2]) > 20:
            user_operation_list[2] = keccak(
                bytes.fromhex(delegate[2:]) + user_operation_list[2][20:])
        else:
            user_operation_list[2] = keccak(bytes.fromhex(delegate[2:]))
    else:
        user_operation_list[2] = keccak(user_operation_list[2])  # initCode
    user_operation_list[3] = keccak(user_operation_list[3])  # callData
    user_operation_list[7] = keccak(user_operation_list[7])  # paymasterAndData

    user_operation_list_without_signature = user_operation_list[:-1]
    # PACKED_USEROP_TYPEHASH = keccak("PackedUserOperation(address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData)")
    PACKED_USEROP_TYPEHASH = b')\xa0\xbc\xa4\xafK\xe3B\x13\x98\xda\x00)^X\xe6\xd7\xde8\xcbI"\x14uL\xb6\xa4u\x07\xddo\x8e'
    user_operation_list_without_signature.insert(0, PACKED_USEROP_TYPEHASH)
    res = encode(
        [
            "bytes32",
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
    return res


def pack_user_operation_for_hashing_v7(
    user_operation_list: list, for_signature: bool = True
) -> bytes:
    user_operation_list[2] = keccak(user_operation_list[2])  # initCode
    user_operation_list[3] = keccak(user_operation_list[3])  # callData
    user_operation_list[7] = keccak(user_operation_list[7])  # paymasterAndData

    user_operation_list_without_signature = user_operation_list[:-1]

    return encode(
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


def pack_user_operation_with_signature(user_operation_list: list) -> bytes:
    return encode(
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
