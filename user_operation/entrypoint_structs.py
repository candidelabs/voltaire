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
