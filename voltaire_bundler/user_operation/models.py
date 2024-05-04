from dataclasses import dataclass


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
class FailedOpRevertData:
    SELECTOR = "0x00fa072b"
    opIndex: int
    paymaster: str
    reason: str


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
    actualGasCost: int
    actualGasUsed: int
    logs: Log
    receipt: ReceiptInfo
