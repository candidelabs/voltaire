// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

interface ArbSys {
     /**
     * @notice Get Arbitrum block number (distinct from L1 block number; Arbitrum genesis block has block number 0)
     * @return block number as int
     */
    function arbBlockNumber() external view returns (uint256);

    /**
     * @notice Get Arbitrum block hash (reverts unless currentBlockNum-256 <= arbBlockNum < currentBlockNum)
     * @return block hash
     */
    function arbBlockHash(
        uint256 arbBlockNum
    ) external view returns (bytes32);
}

contract EntryPointMinBlockArb {
    uint256 internal immutable minBlock = 0x123fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    /// @dev Fallback function forwards all transactions and returns all received return data.
    fallback() external payable {
         ArbSys arbSys = ArbSys(0x0000000000000000000000000000000000000064);
        uint256 arbBlockNumber = arbSys.arbBlockNumber();
        require(arbBlockNumber > minBlock, "current block number is not higher than minBlock");

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
