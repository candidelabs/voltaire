from web3 import Web3
from web3.auto import w3
import os
import glob
import json
from eth_account import Account


def get_account():
    path = "keystore/*"

    keystore = glob.glob(path)[0]
    with open(keystore) as keyfile:
        encrypted_key = keyfile.read()
        private_key = w3.eth.account.decrypt(encrypted_key, "")
        acct = Account.from_key(private_key)
        return acct.address, private_key.hex()


def deploy(abi, bytecode, public_key, private_key):
    entrypoint = provider.eth.contract(abi=abi, bytecode=bytecode)
    chain_id = 1337
    nonce = 0

    # Submit the transaction that deploys the contract
    transaction = entrypoint.constructor().build_transaction(
        {
            "chainId": chain_id,
            "gasPrice": w3.eth.gas_price,
            "from": public_key,
            "nonce": nonce,
        }
    )

    sign_transaction = w3.eth.account.sign_transaction(
        transaction, private_key=private_key
    )

    transaction_hash = w3.eth.send_raw_transaction(
        sign_transaction.rawTransaction
    )

    transaction_receipt = w3.eth.wait_for_transaction_receipt(transaction_hash)
    print(transaction_receipt.contractAddress)


if __name__ == "__main__":
    public_key, private_key = get_account()
    path = "http://0.0.0.0:8545"
    provider = Web3(Web3.HTTPProvider(path))
    f = open("utils/EntryPoint.json")
    data = json.load(f)

    abi = data["abi"]
    bytecode = data["bytecode"]

    deploy(abi, bytecode, public_key, private_key)
