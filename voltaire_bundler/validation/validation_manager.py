from abc import ABC, abstractmethod
from typing import Generic
from voltaire_bundler.user_operation.models import \
    AggregatorStakeInfo, StakeInfo, UserOperationType
from voltaire_bundler.validation.tracer_manager import TracerManager


class ValidationManager(ABC, Generic[UserOperationType]):
    tracer_manager: TracerManager

    @abstractmethod
    async def validate_user_operation(
        self,
        user_operation: UserOperationType,
        entrypoint: str,
        block_number: str,
        latest_block_timestamp: int,
        min_stake: int,
        min_unstake_delay: int,
    ) -> tuple[
        StakeInfo,
        StakeInfo | None,
        StakeInfo | None,
        AggregatorStakeInfo | None,
        str,
        list[str] | None,
        dict[str, str | dict[str, str]] | None
    ]:
        pass
