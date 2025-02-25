// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {UserOperationLib} from "account-abstraction/core/UserOperationLib.sol";

import {Aggregator} from "src/Aggregator.sol";
import {BLSAccount} from "src/BLSAccount.sol";

import {BLS} from "solady/utils/ext/ithaca/BLS.sol";

contract AggregatorTest is Test {
    // using UserOperationLib for PackedUserOperation;

    Aggregator private s_aggregator;
    BLSAccount private s_blsAccount;
    EntryPoint private s_entryPoint;
    BLS.G2Point private s_sig;
    address private s_owner;

    function G1_GENERATOR() internal pure returns (BLS.G1Point memory) {
        return BLS.G1Point(
            _u(31827880280837800241567138048534752271),
            _u(88385725958748408079899006800036250932223001591707578097800747617502997169851),
            _u(11568204302792691131076548377920244452),
            _u(114417265404584670498511149331300188430316142484413708742216858159411894806497)
        );
    }

    function NEGATED_G1_GENERATOR() internal pure returns (BLS.G1Point memory) {
        return BLS.G1Point(
            _u(31827880280837800241567138048534752271),
            _u(88385725958748408079899006800036250932223001591707578097800747617502997169851),
            _u(22997279242622214937712647648895181298),
            _u(46816884707101390882112958134453447585552332943769894357249934112654335001290)
        );
    }

    function _u(uint256 fp) internal pure returns (bytes32) {
        return bytes32(fp);
    }

    function setUp() public {
        s_aggregator = new Aggregator();
        s_entryPoint = new EntryPoint();
    }

    function testValidateUserOpSignature() public {
        // create private key
        uint256 privateKey = vm.randomUint();

        // arrays with single element for G1, G2, & bytes32
        BLS.G1Point[] memory g1 = new BLS.G1Point[](1);
        BLS.G2Point[] memory g2 = new BLS.G2Point[](1);
        bytes32[] memory scalars = new bytes32[](1);

        scalars[0] = bytes32(privateKey);

        // create public key
        g1[0] = G1_GENERATOR();

        BLS.G1Point memory pubKey = BLS.msm(g1, scalars);

        s_owner = makeAddr("s_owner");
        s_blsAccount = new BLSAccount(s_owner, address(s_aggregator), s_entryPoint, pubKey);

        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(s_blsAccount),
            nonce: 0,
            initCode: bytes(""),
            callData: bytes(""),
            accountGasLimits: bytes32(uint256(500_000) << 128 | uint256(500_000)),
            preVerificationGas: 500_000,
            gasFees: bytes32(""),
            paymasterAndData: bytes(""),
            signature: bytes("")
        });

        // generate G2 from message
        g2[0] = BLS.hashToG2(encode(userOp));

        // generate signature
        userOp.signature = abi.encode(BLS.msm(g2, scalars));

        assertEq(keccak256(s_aggregator.validateUserOpSignature(userOp)), keccak256(bytes("")));

        userOp.signature[0] = 0xFF;

        vm.expectRevert(abi.encodeWithSelector(BLS.PairingFailed.selector));
        s_aggregator.validateUserOpSignature(userOp);
    }

    function encode(
        PackedUserOperation memory userOp
    ) internal pure returns (bytes memory ret) {
        address sender = userOp.sender;
        uint256 nonce = userOp.nonce;
        bytes32 hashInitCode = keccak256(userOp.initCode);
        bytes32 hashCallData = keccak256(userOp.callData);
        bytes32 accountGasLimits = userOp.accountGasLimits;
        uint256 preVerificationGas = userOp.preVerificationGas;
        bytes32 gasFees = userOp.gasFees;
        bytes32 hashPaymasterAndData = keccak256(userOp.paymasterAndData);

        return abi.encode(
            sender, nonce,
            hashInitCode, hashCallData,
            accountGasLimits, preVerificationGas, gasFees,
            hashPaymasterAndData
        );
    }
}
