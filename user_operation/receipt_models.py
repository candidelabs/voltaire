from dataclasses import field, dataclass


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
