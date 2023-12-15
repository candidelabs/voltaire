from enum import Enum
from dataclasses import dataclass


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
    INVALID_USEROPHASH = -32601


@dataclass
class ValidationException(Exception):
    exception_code: ValidationExceptionCode
    message: str

class ExecutionExceptionCode(Enum):
    EXECUTION_REVERTED = -32521


@dataclass
class ExecutionException(Exception):
    exception_code: ExecutionExceptionCode
    message: str