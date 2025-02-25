// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.28;

/**
 * Required Function:
 * - validateUserOpSignature: verify the signature in the userOp
 * - aggregateSignatures: Aggregated all the public keys of userOp from the userOps array
 * - validateSignatures: verify aggregated signature
 */
import {IAggregator} from "account-abstraction/interfaces/IAggregator.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {UserOperationLib} from "account-abstraction/core/UserOperationLib.sol";

import {BLS} from "solady/utils/ext/ithaca/BLS.sol";

import {BLSAccount} from "src/BLSAccount.sol";

import {console2 as console} from "forge-std/console2.sol";

contract Aggregator is IAggregator {
    using UserOperationLib for PackedUserOperation;

    /// @notice The negated generator point in G1 (-G1), derived from EIP-2537's standard G1 generator.
    BLS.G1Point NEGATED_G1_GENERATOR = BLS.G1Point(
        bytes32(uint256(31827880280837800241567138048534752271)),
        bytes32(uint256(88385725958748408079899006800036250932223001591707578097800747617502997169851)),
        bytes32(uint256(22997279242622214937712647648895181298)),
        bytes32(uint256(46816884707101390882112958134453447585552332943769894357249934112654335001290))
    );

    function validateUserOpSignature(PackedUserOperation calldata userOp)
        external
        view
        returns (bytes memory sigForUserOp)
    {
        BLS.G1Point[] memory g1Points = new BLS.G1Point[](2);
        BLS.G2Point[] memory g2Points = new BLS.G2Point[](2);

        BLS.G2Point memory hm = BLS.hashToG2(userOp.encode());

        g1Points[0] = NEGATED_G1_GENERATOR;
        g1Points[1] = BLSAccount(userOp.sender).getPubKey();

        g2Points[0] = abi.decode(userOp.signature, (BLS.G2Point));
        g2Points[1] = hm;

        BLS.pairing(g1Points, g2Points);

        return "";
    }

    function aggregateSignatures(PackedUserOperation[] calldata userOps)
        external
        view
        returns (bytes memory aggregatedSignature)
    {}

    function validateSignatures(PackedUserOperation[] calldata userOps, bytes calldata signature) external view {}
}
