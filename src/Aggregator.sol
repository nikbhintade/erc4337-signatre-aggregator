// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.28;


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
    {
        (BLS.G2Point memory aggregatedSignatureG2) = abi.decode(userOps[0].signature, (BLS.G2Point));

        for (uint256 i = 1; i < userOps.length; i++) {
            (BLS.G2Point memory userOpSignature) = abi.decode(userOps[i].signature, (BLS.G2Point));
            aggregatedSignatureG2 = BLS.add(aggregatedSignatureG2, userOpSignature);
        }

        return abi.encode(aggregatedSignatureG2);
    }

    function validateSignatures(PackedUserOperation[] calldata userOps, bytes calldata signature) external view {
        // create g1 & g2 array of userOps.length + 1
        uint256 len = userOps.length;

        BLS.G1Point[] memory g1 = new BLS.G1Point[](len + 1);
        BLS.G2Point[] memory g2 = new BLS.G2Point[](len + 1);

        for (uint256 i = 0; i < len; i++) {
            g1[i] = BLSAccount(userOps[i].sender).getPubKey();
            (g2[i]) = abi.decode(userOps[i].signature, (BLS.G2Point));
        }

        g1[len] = NEGATED_G1_GENERATOR;
        (g2[len]) = abi.decode(signature, (BLS.G2Point));

        BLS.pairing(g1, g2);
    }
}
