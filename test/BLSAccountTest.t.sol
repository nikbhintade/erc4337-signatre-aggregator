// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.28;

import {BLSAccount} from "src/BLSAccount.sol";

import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {_parseValidationData, ValidationData} from "account-abstraction/core/Helpers.sol";

import {BLS} from "solady/utils/ext/ithaca/BLS.sol";

import {Test} from "forge-std/Test.sol";

contract BLSAccountTest is Test {
    function G1_GENERATOR() internal pure returns (BLS.G1Point memory) {
        return BLS.G1Point(
            bytes32(uint256(31827880280837800241567138048534752271)),
            bytes32(uint256(88385725958748408079899006800036250932223001591707578097800747617502997169851)),
            bytes32(uint256(11568204302792691131076548377920244452)),
            bytes32(uint256(114417265404584670498511149331300188430316142484413708742216858159411894806497))
        );
    }

    function createPublicKey() internal returns (BLS.G1Point memory) {
        bytes32 privateKey = bytes32(vm.randomUint());

        BLS.G1Point[] memory g1Points = new BLS.G1Point[](1);
        bytes32[] memory scalars = new bytes32[](1);

        g1Points[0] = G1_GENERATOR();
        scalars[0] = privateKey;

        return BLS.msm(g1Points, scalars);
    }

    function testBLSAccountSetup() public {
        BLS.G1Point memory pubKey = createPublicKey();
        EntryPoint entryPoint = new EntryPoint();
        address aggregator = makeAddr("aggregator");

        BLSAccount blsAccount = new BLSAccount(aggregator, entryPoint, pubKey);

        assertEq(entryPoint, blsAccount.entryPoint());
        assertEq(keccak256(pubKey), keccak256(blsAccount.getPubKey()));
    }
}
