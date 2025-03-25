from dataclasses import dataclass
from voltaire_bundler.typing import Address
from voltaire_bundler.user_operation.user_operation_v6 import UserOperationV6
from voltaire_bundler.user_operation.user_operation_v7v8 import UserOperationV7V8
from typing import TypeVar

UserOperationType = TypeVar('UserOperationType', UserOperationV6, UserOperationV7V8)


@dataclass
class ReturnInfo:
    # SELECTOR = "0xf04297e9"
    preOpGas: int
    prefund: int
    sigFailed: bool
    validAfter: int
    validUntil: int
    paymasterContext: bytes


@dataclass
class StakeInfo:
    stake: int
    unstakeDelaySec: int


@dataclass
class SenderValidationData:
    sig_failed: bool | None
    aggregator: Address | None
    valid_until: int
    valid_after: int


@dataclass
class PaymasterValidationData:
    sig_failed: bool
    valid_until: int
    valid_after: int


@dataclass
class AggregatorStakeInfo:
    aggregator: str
    stake_info: StakeInfo


@dataclass
class ReturnInfoV7:
    pre_op_gas: int
    prefund: int
    sender_validation_data: SenderValidationData
    paymaster_validation_data: PaymasterValidationData
    paymaster_context: bytes


@dataclass
class FailedOp:
    SELECTOR = "0x220266b6"
    opIndex: int
    reason: str


@dataclass
class FailedOpWithRevert:
    SELECTOR = "0x65c8fd4d"
    opIndex: int
    reason: str
    inner: bytes


@dataclass
class DepositInfo:
    deposit: int
    staked: bool
    stake: int
    unstake_delay_sec: int
    withdraw_time: int


@dataclass
class Log:
    removed: bool
    logIndex: str
    transactionIndex: str
    transactionHash: str
    blockHash: str
    blockNumber: str
    address: str
    data: str
    topics: str


@dataclass
class ReceiptInfo:
    transactionHash: str
    transactionIndex: str
    blockHash: str
    blockNumber: str
    _from: str
    to: str
    cumulativeGasUsed: str
    gasUsed: str
    contractAddress: str
    logsBloom: str
    # root:str
    status: str
    effectiveGasPrice: str
    logs: list[str]


@dataclass
class UserOperationReceiptInfo:
    userOpHash: str
    sender: str
    paymaster: str
    nonce: int
    success: bool
    actualGasCost: str
    actualGasUsed: str
    logs: Log
    receipt: ReceiptInfo
