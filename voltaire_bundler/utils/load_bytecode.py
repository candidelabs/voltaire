import os
import json
import voltaire_bundler


def load_bytecode(file_name: str):
    package_directory = os.path.dirname(
            os.path.abspath(voltaire_bundler.__file__))
    bytecode_file = os.path.join(
            package_directory, "contracts", file_name)

    byte_code_file = open(bytecode_file)
    data = json.load(byte_code_file)
    byte_code = data["bytecode"]

    return byte_code
