// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;
/**
 * This contract bytecode will be deployed at the entrypoint address using eth_call state override during gas estimation.
 */
contract GasHelper {
    /**
     * call the "initCode" factory to create and return the sender account address
     * @param initCode the initCode value from a UserOp. contains 20 bytes of factory address, followed by calldata
     * @return sender the returned address of the created account, or zero address on failure.
     */
    function createSender(bytes calldata initCode) external returns (address sender) {
        address factory = address(bytes20(initCode[0 : 20]));
        bytes memory initCallData = initCode[20 :];
        bool success;
        /* solhint-disable no-inline-assembly */
        assembly {
            success := call(gas(), factory, 0, add(initCallData, 0x20), mload(initCallData), 0, 32)
            sender := mload(0)
        }
        if (!success) {
            sender = address(0);
        }
    }

    /**
     * call the "initCode" factory to create and return the sender account address if initCode exists
     * and call the sender constract with the callData to check the gas used and if the transaction was
     * successful with the provided callGasLimit
     * @param sender the initCode value from a UserOp. contains 20 bytes of factory address, followed by calldata
     * @param initCode if set, the account contract will be created before calling the sender contract
     * @param callData the method call to execute on this account.
     * @param callGasLimit the gas limit passed to the callData method call.
     * @return success true if the callData execution successful.
     * @return gasUsed aproximate gas used during callData execution, used by the bundler to estimate the maximum and minimum callGasLimit values.
     * @return data the returned data from callData execution.
     */
    function callGasLimitCheck(address sender, bytes calldata initCode, bytes calldata callData, uint256 callGasLimit)public returns (bool success, uint256 gasUsed, bytes memory data){
        if(initCode.length > 0){
            this.createSender(initCode);
        }

        uint256 preGas = gasleft();

        (success, data) = sender.call{gas: callGasLimit}(callData);

        gasUsed = preGas - gasleft();
    }
}