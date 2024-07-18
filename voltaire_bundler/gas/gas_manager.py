from abc import ABC, abstractmethod
from typing import Generic
from voltaire_bundler.user_operation.models import UserOperationType


class GasManager(ABC, Generic[UserOperationType]):
    @abstractmethod
    async def verify_gas_fees_and_get_price(
        self, user_operation: UserOperationType,
        enforce_gas_price_tolerance: int
    ) -> str:
        pass

    @abstractmethod
    async def verify_preverification_gas_and_verification_gas_limit(
        self,
        user_operation: UserOperationType,
        entrypoint: str,
    ) -> None:
        pass
