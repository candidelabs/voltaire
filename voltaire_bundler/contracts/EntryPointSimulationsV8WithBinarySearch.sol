// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.28;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */

import "https://github.com/eth-infinitism/account-abstraction/blob/releases/v0.8/contracts/core/EntryPoint.sol";
import "https://github.com/eth-infinitism/account-abstraction/blob/releases/v0.8/contracts/interfaces/IEntryPointSimulations.sol";

/*
 * This contract inherits the EntryPoint and extends it with the view-only methods that are executed by
 * the bundler in order to check UserOperation validity and estimate its gas consumption.
 * This contract should never be deployed on-chain and is only used as a parameter for the "eth_call" request.
 */
contract EntryPointSimulationsV8WithBinarySearch is EntryPoint, IEntryPointSimulations {
    
    SenderCreator private _senderCreator;

    bytes32 private __domainSeparatorV4;

    function initSenderCreator() internal virtual {
        // This is the address of the first contract created with CREATE by this address.
        address createdObj = address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", address(this), hex"01")))));
        _senderCreator = SenderCreator(createdObj);

        _initDomainSeparator();
    }

    function senderCreator() public view virtual override(EntryPoint, IEntryPoint) returns (ISenderCreator) {
        // return the same senderCreator as real EntryPoint.
        // this call is slightly (100) more expensive than EntryPoint's access to immutable member
        return _senderCreator;
    }

    /// @inheritdoc IEntryPointSimulations
    function simulateValidation(
        PackedUserOperation calldata userOp
    )
    external
    returns (
        ValidationResult memory
    ){
        UserOpInfo memory outOpInfo;

        _simulationOnlyValidations(userOp);
        (
            uint256 validationData,
            uint256 paymasterValidationData
        ) = _validatePrepayment(0, userOp, outOpInfo);
        StakeInfo memory paymasterInfo = _getStakeInfo(
            outOpInfo.mUserOp.paymaster
        );
        StakeInfo memory senderInfo = _getStakeInfo(outOpInfo.mUserOp.sender);
        StakeInfo memory factoryInfo;
        {
            bytes calldata initCode = userOp.initCode;
            address factory = initCode.length >= 20
                ? address(bytes20(initCode[0 : 20]))
                : address(0);
            factoryInfo = _getStakeInfo(factory);
        }

        address aggregator = address(uint160(validationData));
        ReturnInfo memory returnInfo = ReturnInfo(
            outOpInfo.preOpGas,
            outOpInfo.prefund,
            validationData,
            paymasterValidationData,
            _getMemoryBytesFromOffset(outOpInfo.contextOffset)
        );

        AggregatorStakeInfo memory aggregatorInfo; // = NOT_AGGREGATED;
        if (uint160(aggregator) != SIG_VALIDATION_SUCCESS && uint160(aggregator) != SIG_VALIDATION_FAILED) {
            aggregatorInfo = AggregatorStakeInfo(
                aggregator,
                _getStakeInfo(aggregator)
            );
        }
        return ValidationResult(
            returnInfo,
            senderInfo,
            factoryInfo,
            paymasterInfo,
            aggregatorInfo
        );
    }

    /// @inheritdoc IEntryPointSimulations
    function simulateHandleOp(
        PackedUserOperation calldata op,
        address target,
        bytes calldata targetCallData
    )
    external nonReentrant
    returns (
        ExecutionResult memory
    ){
        UserOpInfo memory opInfo;
        _simulationOnlyValidations(op);
        (
            uint256 validationData,
            uint256 paymasterValidationData
        ) = _validatePrepayment(0, op, opInfo);

        uint256 paid = _executeUserOp(0, op, opInfo);
        bool targetSuccess;
        bytes memory targetResult;
        if (target != address(0)) {
            (targetSuccess, targetResult) = target.call(targetCallData);
        }
        return ExecutionResult(
            opInfo.preOpGas,
            paid,
            validationData,
            paymasterValidationData,
            targetSuccess,
            targetResult
        );
    }

    function _simulationOnlyValidations(
        PackedUserOperation calldata userOp
    )
    internal
    {
        // Initialize senderCreator(). we can't rely on constructor
        initSenderCreator();

        try
        this.validateSenderAndPaymaster(
            userOp.initCode,
            userOp.sender,
            userOp.paymasterAndData
        )
        // solhint-disable-next-line no-empty-blocks
        {} catch Error(string memory revertReason) {
            if (bytes(revertReason).length != 0) {
                revert FailedOp(0, revertReason);
            }
        }
    }

    /**
     * Called only during simulation by the EntryPointSimulation contract itself and is not meant to be called by external contracts.
     * This function always reverts to prevent warm/cold storage differentiation in simulation vs execution.
     * @param initCode         - The smart account constructor code.
     * @param sender           - The sender address.
     * @param paymasterAndData - The paymaster address (followed by other params, ignored by this method)
     */
    function validateSenderAndPaymaster(
        bytes calldata initCode,
        address sender,
        bytes calldata paymasterAndData
    ) external view {
        if (initCode.length == 0 && sender.code.length == 0) {
            // it would revert anyway. but give a meaningful message
            revert("AA20 account not deployed");
        }
        if (paymasterAndData.length >= 20) {
            address paymaster = address(bytes20(paymasterAndData[0 : 20]));
            if (paymaster.code.length == 0) {
                // It would revert anyway. but give a meaningful message.
                revert("AA30 paymaster not deployed");
            }
        }
        // always revert
        revert("");
    }

    // Make sure depositTo cost is more than normal EntryPoint's cost,
    // to mitigate DoS vector on the bundler
    // empiric test showed that without this wrapper, simulation depositTo costs less..
    function depositTo(address account) public override(IStakeManager, StakeManager) payable {
        unchecked{
        // silly code, to waste some gas to make sure depositTo is always little more
        // expensive than on-chain call
            uint256 x = 1;
            while (x < 5) {
                x++;
            }
            StakeManager.depositTo(account);
        }
    }

    // Copied from EIP712.sol
    bytes32 private constant TYPE_HASH =
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    function __buildDomainSeparator() private view returns (bytes32) {
        bytes32 _hashedName = keccak256(bytes(DOMAIN_NAME));
        bytes32 _hashedVersion = keccak256(bytes(DOMAIN_VERSION));
        return keccak256(abi.encode(TYPE_HASH, _hashedName, _hashedVersion, block.chainid, address(this)));
    }

    // Can't rely on "immutable" (constructor-initialized) variables" in simulation
    function _initDomainSeparator() internal {
        __domainSeparatorV4 = __buildDomainSeparator();
    }

    function getDomainSeparatorV4() public override view returns (bytes32) {
        return __domainSeparatorV4;
    }

    function supportsInterface(bytes4) public view virtual override returns (bool) {
        return false;
    }

    /*************************/

    struct EstimateCallGasArgs {
        uint256 callGasLimitMin;
        uint256 callGasLimitMax;
        uint256 tolerance;
        bool isContinuation;
        bool isCheckOnce;
    }

    error EstimateCallGasContinuation(uint256 minGas, uint256 maxGas, uint256 numRounds);

    error EstimateCallGasRevertAtMax(bytes revertData);

    error SimulationResult(uint256 verificationGasLimit, uint256 callGasLimitMax, uint256 numRounds);

    function simulateHandleOpMod(PackedUserOperation calldata op, EstimateCallGasArgs calldata args) external {
         UserOpInfo memory opInfo;
        _simulationOnlyValidations(op);
        (
            uint256 validationData,
            uint256 paymasterValidationData
        ) = _validatePrepayment(0, op, opInfo);

        uint256 callGasLimitMin = args.callGasLimitMin;
        uint256 callGasLimitMax = args.callGasLimitMax;
        uint256 highestGasUsed = 0;

        if (!args.isContinuation) {
            // Make one call at full gas to make sure success is even possible.
            (
                bool success,
                uint256 gasUsed,
                bytes memory revertData
            ) = innerCall(op.sender, op.callData, callGasLimitMax);
            if (!success) {
                revert EstimateCallGasRevertAtMax(revertData);
            }
            if(args.isCheckOnce) {
                revert SimulationResult(opInfo.preOpGas - op.preVerificationGas, 0, 0);
            }
            highestGasUsed = gasUsed;
            callGasLimitMin = highestGasUsed;
        }

        //dividing here by five instead of two for the first guess in the binry search
        //as the calldata gaslimit is probably not more than 20% than the gas used
        uint256 guess = callGasLimitMin + ((callGasLimitMax - callGasLimitMin) / 5);

        uint256 numRounds = 0;
        while (callGasLimitMin + args.tolerance < callGasLimitMax) {
            numRounds++;

            if (!isEnoughGasForGuess(guess)) {
                revert EstimateCallGasContinuation(callGasLimitMin, callGasLimitMax,numRounds);
            }

            (bool success, uint256 gasUsed, ) = innerCall(
                op.sender,
                op.callData,
                guess
            );
            
            if (success && gasUsed >= highestGasUsed) {
                callGasLimitMax = guess;
                highestGasUsed = gasUsed;
            } else {
                callGasLimitMin = guess + 1;
            }
            guess = callGasLimitMin + ((callGasLimitMax - callGasLimitMin) / 2);
        }
        revert SimulationResult(opInfo.preOpGas - op.preVerificationGas, callGasLimitMax, numRounds);
    }

    error _InnerCallResult(bool success, uint256 gasUsed, bytes revertData);

    function innerCall(
        address sender,
        bytes calldata callData,
        uint256 gas
    ) private returns (bool success, uint256 gasUsed, bytes memory revertData) {
        try this.callGasLimitCheck(sender, callData, gas) {
            // Should never happen. _innerCall should always revert.
            revert();
        } catch (bytes memory innerCallRevertData) {
            require(bytes4(innerCallRevertData) == _InnerCallResult.selector);
            assembly {
                innerCallRevertData := add(innerCallRevertData, 0x04)
            }
            (success, gasUsed, revertData) = abi.decode(
                innerCallRevertData,
                (bool, uint256, bytes)
            );
        }
    }

    /**
     * call the "initCode" factory to create and return the sender account address if initCode exists
     * and call the sender constract with the callData to check the gas used and if the transaction was
     * successful with the provided callGasLimit
     * @param sender the initCode value from a UserOp. contains 20 bytes of factory address, followed by calldata
     * @param callData the method call to execute on this account.
     * @param callGasLimit the gas limit passed to the callData method call.
     * @return success true if the callData execution successful.
     * @return gasUsed aproximate gas used during callData execution, used by the bundler to estimate the maximum and minimum callGasLimit values.
     * @return data the returned data from callData execution.
     */
    function callGasLimitCheck(address sender, bytes calldata callData, uint256 callGasLimit)public returns (bool success, uint256 gasUsed, bytes memory data){
        uint256 preGas = gasleft();

        (success, data) = sender.call{gas: callGasLimit}(callData);

        gasUsed = preGas - gasleft();
        bytes memory revertData = success ? bytes("") : data;
        revert _InnerCallResult(success, gasUsed, revertData);
    }

    function isEnoughGasForGuess(uint256 guess) private view returns (bool) {
        // Because of the 1/64 rule and the fact that we need two levels of
        // calls, we need
        //
        //   guess < (63/64)^2 * (gas - some_overhead)
        //
        // We'll take the overhead to be 50000, which should leave plenty left
        // over for us to hand the result back to the EntryPoint to return.
        return (64 * 64 * guess) / (63 * 63) + 50000 < gasleft();
    }
}

