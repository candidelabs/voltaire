from dataclasses import dataclass
import glob
from web3.auto import w3
from eth_account import Account

def import_bundler_account(keystore_file_password, keystore_file_path="keystore/*"):
    if keystore_file_path != "keystore/*":
        keystore = keystore_file_path
    else:
        keystore = glob.glob(keystore_file_path)[0]

    with open(keystore) as keyfile:
        encrypted_key = keyfile.read()
        private_key = w3.eth.account.decrypt(
            encrypted_key, keystore_file_password
        )
        acct = Account.from_key(private_key)
        return acct.address, private_key.hex()
