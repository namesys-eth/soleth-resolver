// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import "../src/isDev.sol";
import "../src/Utils.sol";

contract isDevTest is Test {
    using Utils for *;

    isDev public _isdev = new isDev();

    function setUp() public {}

    function testSigner() public {
        uint256 SignerKey = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
        address _signer = vm.addr(SignerKey);
        string memory _message = string.concat(
            "Requesting Signature To Approve ENS Records Signer\n",
            "\nGithub: ",
            "0xc0de4c0ffee.github.io",
            "\nApproved Signer: eip155:5:",
            _signer.toChecksumAddress(),
            "\nResolver: eip155:",
            "5",
            ":",
            address(this).toChecksumAddress()
        );
        bytes32 _digest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n", (bytes(_message).length).uintToString(), _message)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SignerKey, _digest);
        bytes memory _signature = abi.encodePacked(r, s, v);
        assertEq(_signer, _isdev.getSigner(_message, _signature));
        _signature = abi.encodePacked(r, s, uint256(v));
        assertEq(_signer, _isdev.getSigner(_message, _signature));
        bytes32 vs = bytes32(uint256(v - 27) << 255) | s;
        _signature = abi.encodePacked(r, vs);
        assertEq(_signer, _isdev.getSigner(_message, _signature));
    }

    function testChecksumAddress() public {
        assertEq(
            address(0xEa97bb00DaA1880E0A575B38E723066A398595eA).toChecksumAddress(),
            "0xEa97bb00DaA1880E0A575B38E723066A398595eA"
        );
        assertEq(
            address(0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045).toChecksumAddress(),
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        );
        assertEq(
            address(0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401).toChecksumAddress(),
            "0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401"
        );
    }

    function testBytesToHexString() public {
        assertEq(
            string("0000000000000000000000000000000000000000000000000000000000000000"),
            (hex"0000000000000000000000000000000000000000000000000000000000000000").bytesToHexString()
        );
        assertEq(
            string("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            (hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").bytesToHexString()
        );
        assertEq(
            string("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            (hex"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").bytesToHexString()
        );
    }

    function testUintToString() public {
        assertEq(string("123456789"), 123456789.uintToString());
        assertEq(string("0"), 0.uintToString());
        assertEq(string("11111"), 11111.uintToString());
        assertEq(string("99999"), 99999.uintToString());
        assertEq(
            string("123456789123456789123456789123456789123456789123456789"),
            (123456789123456789123456789123456789123456789123456789).uintToString()
        );
        assertEq(
            string("115792089237316195423570985008687907853269984665640564039457584007913129639935"),
            (type(uint256).max).uintToString()
        );
    }

    function testLog10() public {
        assertEq(1234567890.log10(), 9);
        assertEq(0.log10(), 0);
        assertEq(type(uint256).max.log10(), 77);
    }
}

/// @dev Utility functions
contract Helper {
    function Decode(bytes calldata _encoded) external pure returns (string memory _path, string memory _domain) {
        uint256 n = 1;
        uint256 len = uint8(bytes1(_encoded[0]));
        bytes memory _label;
        _label = _encoded[1:n += len];
        _path = string(_label);
        _domain = _path;
        while (_encoded[n] > 0x0) {
            len = uint8(bytes1(_encoded[n:++n]));
            _label = _encoded[n:n += len];
            _domain = string.concat(_domain, ".", string(_label));
            _path = string.concat(string(_label), "/", _path);
        }
    }

    function Encode(bytes[] memory _names) public pure returns (bytes32 _namehash, bytes memory _name) {
        uint256 i = _names.length;
        _name = abi.encodePacked(bytes1(0));
        _namehash = bytes32(0);
        unchecked {
            while (i > 0) {
                --i;
                _name = bytes.concat(bytes1(uint8(_names[i].length)), _names[i], _name);
                _namehash = keccak256(abi.encodePacked(_namehash, keccak256(_names[i])));
            }
        }
    }

    function getBytes(bytes calldata _b, uint256 _start, uint256 _end) external pure returns (bytes memory) {
        return _b[_start:_end == 0 ? _b.length : _end];
    }
}
