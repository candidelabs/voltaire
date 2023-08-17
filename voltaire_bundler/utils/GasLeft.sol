// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

contract GasLeft {
    function getGasLeft() public view returns(uint256){
        return gasleft();
    }
}