"""ERC-7562 [OP-011] banned opcodes
(validation.tracer_manager.validate_entity_banned_opcodes), pure unit tests."""
import pytest

from voltaire_bundler.bundle.exceptions import ValidationException
from voltaire_bundler.validation.tracer_manager import \
    validate_entity_banned_opcodes


@pytest.mark.parametrize("opcode", [
    "ORIGIN", "GASPRICE", "BLOCKHASH", "COINBASE", "TIMESTAMP", "NUMBER",
    "PREVRANDAO", "DIFFICULTY", "GASLIMIT", "BASEFEE", "INVALID",
    "SELFDESTRUCT", "GAS", "BLOBHASH", "BLOBBASEFEE",
    "SLOTNUM",  # EIP-7843, Glamsterdam
])
def test_environment_opcodes_are_banned_for_every_entity(opcode):
    """Each opcode fails validation for a staked and an unstaked entity,
    named in the message."""
    for staked in (True, False):
        with pytest.raises(ValidationException) as excinfo:
            validate_entity_banned_opcodes(
                {opcode: 1, "PUSH1": 7}, "account", staked, None)
        assert opcode in excinfo.value.message


@pytest.mark.parametrize("opcode", ["CLZ", "DUPN", "SWAPN", "EXCHANGE"])
def test_new_glamsterdam_opcodes_without_environment_access_are_allowed(opcode):
    """EIP-7939 CLZ and EIP-663 DUPN/SWAPN/EXCHANGE read no block
    environment and pass."""
    validate_entity_banned_opcodes({opcode: 1}, "account", False, None)
