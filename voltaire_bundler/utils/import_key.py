import glob
from eth_account import Account


def import_bundler_account(
    keystore_file_password, keystore_file_path="keystore/*"
):
    if keystore_file_path != "keystore/*":
        keystore = keystore_file_path
    else:
        keystore = glob.glob(keystore_file_path)[0]

    with open(keystore) as keyfile:
        encrypted_key = keyfile.read()
        private_key = Account.decrypt(encrypted_key, keystore_file_password)
        acct = Account.from_key(private_key)
        return acct.address, private_key.hex()


def public_address_from_private_key(private_key):
    public_address = Account.from_key(bytes.fromhex(private_key[2:]))
    return public_address.address
