from typing import Dict, Type
from enum import Enum
from dataclasses import dataclass, field


class BundlerExceptionCode(Enum):
    REJECTED_BY_EP_OR_ACCOUNT = -32500
    REJECTED_BY_PAYMASTER = -32501
    BANNED_OPCODE = -32502
    SHORT_DEADLINE = -32503
    BANNED_OR_THROTTLED_PAYMASTER = -32504
    INAVLID_PAYMASTER_STAKE = -32505
    INVALID_AGGREGATOR = -32506

    EXECUTION_REVERTED = -32521
    INVALID_FIELDS = -32602

    INVALID_USEROPHASH = -32601


@dataclass
class BundlerException(Exception):
    exception_code: BundlerExceptionCode
    message: str
    data: bytes


class ValidationExceptionCode(Enum):
    InvalidFields = (-32602,)
    SimulateValidation = -32500
    SimulatePaymasterValidation = -32501
    OpcodeValidation = -32502
    ExpiresShortly = -32503
    Reputation = -32504
    InsufficientStake = -32505
    UnsupportedSignatureAggregator = -32506
    InvalidSignature = -32507


@dataclass
class ValidationException(Exception):
    exception_code: BundlerExceptionCode
    message: str
    data: bytes
