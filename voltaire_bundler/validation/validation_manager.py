from abc import ABC, abstractmethod
import asyncio
import logging
from eth_utils import keccak
from eth_utils import ValidationError as EthUtilsValidationError
from eth_keys import KeyAPI
from eth_keys.exceptions import BadSignature
from rlp import encode as rlp_encode

from typing import Generic
from voltaire_bundler.bundle.exceptions import \
    ValidationException, ValidationExceptionCode
from voltaire_bundler.typing import Address
from voltaire_bundler.user_operation.models import \
    AggregatorStakeInfo, StakeInfo, UserOperationType
from voltaire_bundler.utils.eth_client_utils import send_rpc_request_to_eth_client
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

    async def verify_authorization_and_get_code(
        self,
        sender_address: Address,
        authorization: dict[str, str | int],
    ) -> str | None:
        chain_id = authorization["chainId"]
        if chain_id != self.chain_id and chain_id != 0:
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                "Invalid eip7702auth chainId.",
            )

        address = str(authorization["address"])
        nonce = authorization["nonce"]
        auth_hash = keccak(
            "0x05" +  # magic value
            rlp_encode([chain_id, address, nonce])[2:]
        )
        try:
            y_parity = authorization["yParity"]
            r = authorization["r"]
            s = authorization["s"]
            signature = KeyAPI.Signature((y_parity, r, s))
            auth_signer_address = signature.recover_public_key_from_msg_hash(
                auth_hash
            )
        except EthUtilsValidationError or BadSignature as excp:
            logging.error(
                f"Failed to recover authorization for address: {address}."
                f"error:{str(excp)}"
            )
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                f"Failed to recover authorization for address: {address}."
            )
        if sender_address.lower() != auth_signer_address.lower():
            raise ValidationException(
                ValidationExceptionCode.SimulateValidation,
                f"Userop sender: {sender_address} is not equal to auth signer "
                f"recovered address {auth_signer_address}"
            )

        existing_code_op = send_rpc_request_to_eth_client(
            self.ethereum_node_url,
            "eth_getCode",
            [sender_address, "latest"],
            None, "result"
        )
        nonce_op = send_rpc_request_to_eth_client(
            self.ethereum_node_url,
            "eth_getTransactionCount",
            [sender_address, "latest"], None, "result"
        )
        tasks_arr = [existing_code_op, nonce_op]
        tasks = await asyncio.gather(*tasks_arr)
        existing_code = tasks[0]["result"]
        current_nonce = tasks[1]["result"]

        new_code = "0xef0100" + address[2:]

        if existing_code == new_code or nonce != current_nonce:
            return None
        return new_code

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
