"""
Guard: every bundled EntryPointSimulations*.json must hold RUNTIME bytecode.

The simulation bytecode is injected at the EntryPoint address through
eth_call / debug_traceCall state overrides. If a JSON file holds the init
(creation) bytecode instead, the EVM runs the constructor and the call
"returns" the runtime code, so validation fails with a bytecode blob as the
error message instead of a decodable ValidationResult. See CLAUDE.md
"Simulation Contracts & Bytecode".

EntryPointSimulationsV8Arb.json shipped init code from 2025-12-10 until this
test was added, which broke EntryPoint v0.8 validation on Arbitrum One and
Arbitrum Sepolia.
"""

import glob
import os

import pytest

import voltaire_bundler
from voltaire_bundler.utils.load_bytecode import load_bytecode

CONTRACTS_DIR = os.path.join(
    os.path.dirname(os.path.abspath(voltaire_bundler.__file__)), "contracts"
)
SIMULATION_JSONS = sorted(
    os.path.basename(p)
    for p in glob.glob(os.path.join(CONTRACTS_DIR, "EntryPointSimulations*.json"))
)

# solc constructor epilogue: CODECOPY ... RETURN, then INVALID, then the
# runtime's own "PUSH1 0x80 PUSH1 0x40 MSTORE" prologue.
CREATION_TO_RUNTIME_BOUNDARY = bytes.fromhex("f3fe6080604052")
# A constructor is small; the boundary sits well within the first few KB.
MAX_CONSTRUCTOR_SIZE = 4096


def _looks_like_init_code(code: bytes) -> bool:
    idx = code.find(CREATION_TO_RUNTIME_BOUNDARY)
    return 0 < idx < MAX_CONSTRUCTOR_SIZE


@pytest.mark.parametrize("file_name", SIMULATION_JSONS)
def test_simulation_bytecode_is_runtime_not_init(file_name: str) -> None:
    hex_code = load_bytecode(file_name)
    assert hex_code.startswith("0x60"), f"{file_name}: unexpected bytecode prefix"
    code = bytes.fromhex(hex_code[2:])
    assert not _looks_like_init_code(code), (
        f"{file_name} holds init (creation) bytecode. Export "
        "deployedBytecode.object (runtime) instead - see CLAUDE.md "
        "'Simulation Contracts & Bytecode'."
    )


def test_all_simulation_files_are_covered() -> None:
    assert len(SIMULATION_JSONS) >= 12, SIMULATION_JSONS
