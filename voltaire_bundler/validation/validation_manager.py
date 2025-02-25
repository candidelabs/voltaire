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
from voltaire_bundler.utils.eip7702 import format_hex_array_for_rlp_encode
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
        authorization: dict[str, str],
    ) -> str | None:
        chain_id_hex = authorization["chainId"][2:]
        chain_id = int(chain_id_hex, 16)
        if chain_id != self.chain_id and chain_id != 0:
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                "Invalid eip7702auth chainId.",
            )

        auth_hash = keccak(
            bytes.fromhex(
                "05" +  # magic value
                rlp_encode(
                    format_hex_array_for_rlp_encode(
                        [
                            authorization["chainId"],
                            authorization["address"],
                            authorization["nonce"],
                        ]
                    )
                ).hex()
            )
        )
        try:
            y_parity = authorization["yParity"]
            r = authorization["r"]
            s = authorization["s"]
            signature = KeyAPI.Signature(
                vrs=(
                    int(y_parity, 16),
                    int(r, 16),
                    int(s, 16)
                )
            )
            auth_signer_address = signature.recover_public_key_from_msg_hash(
                auth_hash
            ).to_address()
        except EthUtilsValidationError or BadSignature as excp:
            logging.error(
                f"Failed to recover authorization for address: {authorization["address"]}."
                f"error:{str(excp)}"
            )
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
                f"Failed to recover authorization for address: {authorization["address"]}."
            )
        if sender_address.lower() != auth_signer_address.lower():
            raise ValidationException(
                ValidationExceptionCode.InvalidFields,
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

        new_code = "0xef0100" + authorization["address"][2:]
        if (
                existing_code == new_code or
                int(authorization["nonce"], 16) != int(current_nonce, 16)
        ):
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
