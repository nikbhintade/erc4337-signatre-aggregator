// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.28;

import {BLSAccount} from "src/BLSAccount.sol";

import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {_parseValidationData, _packValidationData, ValidationData} from "account-abstraction/core/Helpers.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

import {BLS} from "solady/utils/ext/ithaca/BLS.sol";

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {Test, console2 as console} from "forge-std/Test.sol";

contract BLSAccountTest is Test {
    BLSAccount private s_blsAccount;
    EntryPoint private s_entryPoint;
    address private s_aggregator;
    address private s_owner;

    function setUp() public {
        BLS.G1Point memory pubKey = createPublicKey();
        s_entryPoint = new EntryPoint();
        s_aggregator = makeAddr("aggregator");
        s_owner = makeAddr("s_owner");

        s_blsAccount = new BLSAccount(s_owner, s_aggregator, s_entryPoint, pubKey);
        vm.deal(address(s_blsAccount), 100 ether);
    }

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
        address owner = makeAddr("owner");

        BLSAccount blsAccount = new BLSAccount(owner, aggregator, entryPoint, pubKey);

        assertEq(address(entryPoint), address(blsAccount.entryPoint()));
        assertEq(keccak256(abi.encode(pubKey)), keccak256(abi.encode(blsAccount.getPubKey())));
    }

    function testValidationReturnsAggregator() public {
        PackedUserOperation memory userOp = PackedUserOperation(
            address(s_blsAccount),
            0,
            bytes(vm.randomBytes(10)),
            bytes(vm.randomBytes(10)),
            bytes32(0),
            0,
            bytes32(0),
            bytes(vm.randomBytes(10)),
            bytes(vm.randomBytes(10))
        );

        bytes32 userOpHash = bytes32(vm.randomBytes(32));

        vm.prank(address(s_entryPoint));
        uint256 validationData = s_blsAccount.validateUserOp(userOp, userOpHash, vm.randomUint());

        ValidationData memory parsedValidationData = _parseValidationData(validationData);
        uint48 expectedTimestamp = 0;

        assertEq(parsedValidationData.aggregator, s_aggregator);
        assertEq(parsedValidationData.validAfter, expectedTimestamp);

        assertEq(parsedValidationData.validUntil, type(uint48).max);
    }

    function testChangePubKeyEventAndAccess() public {
        BLS.G1Point memory newPubKey = createPublicKey();

        // --------------------
        vm.expectEmit(false, false, false, true, address(s_blsAccount));
        emit BLSAccount.PubKeyChanged(s_blsAccount.getPubKey(), newPubKey);
        vm.prank(s_owner);
        s_blsAccount.changePubKey(newPubKey);
        // --------------------

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        s_blsAccount.changePubKey(newPubKey);
    }

    function testChangeAggregatorEventAndAccess() public {
        address newAggregator = makeAddr("newAggregator");

        vm.expectEmit(false, false, false, true, address(s_blsAccount));
        emit BLSAccount.AggregatorChanged(s_blsAccount.getAggregator(), newAggregator);
        vm.prank(s_owner);
        s_blsAccount.changeAggregator(newAggregator);

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        s_blsAccount.changeAggregator(newAggregator);
    }
}
