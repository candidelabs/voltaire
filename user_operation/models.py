from dataclasses import field, dataclass


@dataclass
class ReturnInfo:
    # SELECTOR = "0xf04297e9"
    preOpGas: int | str
    prefund: int | str
    sigFailed: bool
    validAfter: int | str
    validUntil: int | str


@dataclass
class StakeInfo:
    stake: int | str
    unstakeDelaySec: int | str


@dataclass
class FailedOpRevertData:
    SELECTOR = "0x00fa072b"
    opIndex: int | str
    paymaster: str
    reason: str


@dataclass
class DepositInfo:
    deposit: int | str
    staked: bool
    stake: int | str
    unstake_delay_sec: int | str
    withdraw_time: int | str


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
    logs: list = field(default_factory=list)


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
