from abc import ABC, abstractmethod
from typing import Generic
from voltaire_bundler.bundle.exceptions import \
    ValidationException, ValidationExceptionCode
from voltaire_bundler.user_operation.models import \
    AggregatorStakeInfo, StakeInfo, UserOperationType
from voltaire_bundler.validation.tracer_manager import TracerManager


class ValidationManager(ABC, Generic[UserOperationType]):
    tracer_manager: TracerManager
    chain_id: int
    ethereum_node_url: str
    bundler_address: str
    bundler_collector_tracer: str
    is_unsafe: bool
    is_legacy_mode: bool
    enforce_gas_price_tolerance: int
    ethereum_node_debug_trace_call_url: str

    @abstractmethod
    async def validate_user_operation(
        self,
        user_operation: UserOperationType,
        entrypoint: str,
        block_number: str | None,
        min_block_number: str | None,
        min_stake: int,
        min_unstake_delay: int,
    ) -> tuple[
        StakeInfo,
        StakeInfo | None,
        StakeInfo | None,
        AggregatorStakeInfo | None,
        str,
        list[str] | None,
        dict[str, str | dict[str, str]] | None,
        bytes,
        str,
        str
    ]:
        pass

    @staticmethod
    def verify_sig_and_timestamp(
        sig_failed: bool | None,
        valid_until: int,
        valid_after: int,
        latest_block_timestamp: int
    ) -> None:
        if sig_failed:
            raise ValidationException(
                ValidationExceptionCode.InvalidSignature,
                "Invalid UserOp signature or paymaster signature",
            )

        if valid_after is None or latest_block_timestamp < valid_after:
            raise ValidationException(
                ValidationExceptionCode.ExpiresShortly,
                f"time-range in the future time {valid_after}, now {latest_block_timestamp}",
            )

        if valid_until is None or latest_block_timestamp >= valid_until:
            raise ValidationException(
                ValidationExceptionCode.ExpiresShortly,
                "already expired.",
            )

        if valid_until is None or latest_block_timestamp + 30 >= valid_until:
            raise ValidationException(
                ValidationExceptionCode.ExpiresShortly,
                "expires too soon.",
            )
