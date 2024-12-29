from dataclasses import dataclass
from enum import Enum


class ValidationExceptionCode(Enum):
    InvalidFields = -32602
    SimulateValidation = -32500
    SimulatePaymasterValidation = -32501
    OpcodeValidation = -32502
    ExpiresShortly = -32503
    Reputation = -32504
    InsufficientStake = -32505
    UnsupportedSignatureAggregator = -32506
    InvalidSignature = -32507
    PaymasterDepositTooLow = -32508


@dataclass
class ValidationException(Exception):
    exception_code: ValidationExceptionCode
    message: str


class ExecutionExceptionCode(Enum):
    UserOperationReverted = -32521


@dataclass
class ExecutionException(Exception):
    exception_code: ExecutionExceptionCode
    message: str


class OtherJsonRpcErrorCode(Enum):
    InternalError = -32603


@dataclass
class OtherJsonRpcErrorException(Exception):
    exception_code: OtherJsonRpcErrorCode
    message: str


@dataclass
class MethodNotFoundException(Exception):
    exception_code: ExecutionExceptionCode


@dataclass
class UserOpFoundException(Exception):
    user_op_by_hash_result: dict
