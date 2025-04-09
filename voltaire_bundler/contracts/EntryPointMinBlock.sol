// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

contract EntryPointMinBlock {
    uint256 internal immutable minBlock = 0x123fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    /// @dev Fallback function forwards all transactions and returns all received return data.
    fallback() external payable {
        require(block.number > minBlock, "current block number is not higher than minBlock");

        /* solhint-disable no-inline-assembly */
        assembly {
            let _singleton := sload(0)
            calldatacopy(0, 0, calldatasize())
            let success := call(gas(), 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108, 0, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(success) {
                revert(0, returndatasize())
            }
            return(0, returndatasize())
        }
        /* solhint-enable no-inline-assembly */
    }
}
