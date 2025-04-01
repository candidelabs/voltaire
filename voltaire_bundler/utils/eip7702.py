# https://github.com/ethereum/EIPs/blob/master/EIPS/eip-7702.md
# rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
#   gas_limit, destination, value, data, access_list, authorization_list,
#   signature_y_parity, signature_r, signature_s]
# )
# authorization_list = [[chain_id, address, nonce, y_parity, r, s], ...]

from rlp import encode as rlp_encode
from eth_utils import keccak
from eth_account import Account


def create_and_sign_eip7702_raw_transaction(
    chain_id_hex: str,
    nonce_hex: str,
    max_priority_fee_per_gas_hex: str,
    max_fee_per_gas_hex: str,
    gas_limit_hex: str,
    destination: str,
    value_hex: str,
    data: str,
    authorization_list: list[dict[str, str]],
    eoa_private_key: str
) -> str:
    tx_hash = create_eip7702_transaction_hash(
        chain_id_hex,
        nonce_hex,
        max_priority_fee_per_gas_hex,
        max_fee_per_gas_hex,
        gas_limit_hex,
        destination,
        value_hex,
        data,
        authorization_list,
    )

    account = Account.from_key(eoa_private_key)
    signature = account.unsafe_sign_hash(tx_hash)
    # not sure how to calculate y parity if v is not equal to 27 or 28
    assert (signature.v == 27 or signature.v == 28)

    rlp_encoded_signed_eip7702_transaction_base = rlp_encode(
        format_hex_array_for_rlp_encode(
            [
                chain_id_hex,
                nonce_hex,
                max_priority_fee_per_gas_hex,
                max_fee_per_gas_hex,
                gas_limit_hex,
                destination,
                value_hex,
                data,
                [],
                format_auth_list(authorization_list),
                "0x0" if signature.v == 27 else "0x1",  # y parity
                hex(signature.r),
                hex(signature.s)
            ]
        )
    ).hex()
    return (
        "0x04" +  # SET_CODE_TX_TYPE
        rlp_encoded_signed_eip7702_transaction_base
    )


def create_eip7702_transaction_hash(
    chain_id_hex: str,
    nonce_hex: str,
    max_priority_fee_per_gas_hex: str,
    max_fee_per_gas_hex: str,
    gas_limit_hex: str,
    destination: str,
    value_hex: str,
    data: str,
    authorization_list: list[dict[str, str]],
) -> str:
    rlp_encoded_eip7702_transaction_base = rlp_encode(
        format_hex_array_for_rlp_encode(
            [
                chain_id_hex,
                nonce_hex,
                max_priority_fee_per_gas_hex,
                max_fee_per_gas_hex,
                gas_limit_hex,
                destination,
                value_hex,
                data,
                [],
                format_auth_list(authorization_list)
            ]
        )
    ).hex()

    return keccak(
        bytes.fromhex(
            "04" +  # SET_CODE_TX_TYPE
            rlp_encoded_eip7702_transaction_base
        )
    )


def format_auth_list(authorization_list: list[dict[str, str]]) -> list[bytes]:
    formated_auth_list = []
    for authorization in authorization_list:
        formated_auth_list.append(
            format_hex_array_for_rlp_encode(
                [
                    authorization["chainId"],
                    authorization["address"],
                    authorization["nonce"],
                    authorization["yParity"],
                    authorization["r"],
                    authorization["s"],
                ]
            )
        )
    return formated_auth_list


def format_hex_array_for_rlp_encode(
    values: list[str | list[bytes]]
) -> list[bytes | list[bytes]]:
    bytes_array = []
    for value in values:
        if isinstance(value, str):
            hex_value = value[2:]
            if hex_value == "0":
                hex_value = ""
            hex_value = hex_value if len(hex_value) % 2 == 0 else "0" + hex_value
            bytes_array.append(bytes.fromhex(hex_value))
        else:  # previously formated list
            bytes_array.append(value)
    return bytes_array
