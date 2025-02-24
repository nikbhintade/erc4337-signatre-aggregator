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

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {console2 as console} from "forge-std/console2.sol";

contract BLSAccount is BaseAccount, Ownable {
    event PubKeyChanged(BLS.G1Point oldPubKey, BLS.G1Point newPubKey);
    event AggregatorChanged(address oldAggregator, address newAggregator);

    address private s_aggregator;
    EntryPoint private s_entryPoint;
    BLS.G1Point private s_pubKey;

    constructor(address _owner, address _aggregator, EntryPoint _entryPoint, BLS.G1Point memory _pubKey)
        Ownable(_owner)
    {
        s_aggregator = _aggregator;
        s_entryPoint = _entryPoint;
        s_pubKey = _pubKey;
    }

    function changePubKey(BLS.G1Point calldata newPubKey) public onlyOwner {
        emit PubKeyChanged(s_pubKey, newPubKey);
        s_pubKey = newPubKey;
    }

    function changeAggregator(address newAggreagtor) public onlyOwner {
        emit AggregatorChanged(s_aggregator, newAggreagtor);
        s_aggregator = newAggreagtor;
    }

    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        override
        returns (uint256)
    {
        (userOp, userOpHash);
        return _packValidationData(ValidationData(s_aggregator, 0, 0));
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return s_entryPoint;
    }

    function getPubKey() public view returns (BLS.G1Point memory) {
        return s_pubKey;
    }

    function getAggregator() public view returns (address) {
        return s_aggregator;
    }
}
