// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.28;

/**
 * Required Functions:
 * - validateSignature
 * - getPubKey
 * - execute
 *
 * -------
 * Next step:
 * - changePublicKey
 * - changeAggregator
 */
import {BaseAccount} from "account-abstraction/core/BaseAccount.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {_packValidationData, ValidationData} from "account-abstraction/core/Helpers.sol";

import {BLS} from "solady/utils/ext/ithaca/BLS.sol";

import {console2 as console} from "forge-std/console2.sol";

contract BLSAccount is BaseAccount {
    address private s_aggregator;
    EntryPoint private s_entryPoint;
    BLS.G1Point private s_pubKey;

    constructor(address _aggregator, EntryPoint _entryPoint, BLS.G1Point memory _pubKey) {
        s_aggregator = _aggregator;
        s_entryPoint = _entryPoint;
        s_pubKey = _pubKey;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return s_entryPoint;
    }

    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        override
        returns (uint256)
    {
        (userOp, userOpHash);
        ValidationData memory data = ValidationData(s_aggregator, 0, 0);
        return _packValidationData(data);
    }

    function getPubKey() public view returns (BLS.G1Point memory) {
        return s_pubKey;
    }
}
