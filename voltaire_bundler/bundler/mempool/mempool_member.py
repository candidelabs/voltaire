from voltaire_bundler.user_operation.user_operation import UserOperation
from enum import Enum


class MempoolMemberStatus(Enum):
    RECEVIED = 1  # received on the mempool
    SUBMITED = 2  # submitted and bundled onchian
    CONFIRMED = 3  # verified that it was included onchain


class MempoolMember:
    user_operation: UserOperation
    mempool_member_status: MempoolMemberStatus

    def __init__(
        self,
        user_operation: UserOperation,
        mempool_member_status: MempoolMemberStatus,
    ):
        self.user_operation = user_operation
        self.mempool_member_status = mempool_member_status