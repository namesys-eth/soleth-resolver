// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import  "../src/isDev.sol";

contract isDevTest is Test {
    isDev public _isdev;
    function setUp() public {
        _isdev = new isDev();
    }


    function testBytesToHexString() public {
        assertEq(
            string("0x0000000000000000000000000000000000000000000000000000000000000000"),
            _isdev.bytesToHexString(hex"0000000000000000000000000000000000000000000000000000000000000000", true)
        );
        assertEq(
            string("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            _isdev.bytesToHexString(hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", true)
        );        
        assertEq(
            string("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
            _isdev.bytesToHexString(hex"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", false)
        );
        assertEq(
            string("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            _isdev.bytesToHexString(hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", false)
        );
    }

    function testUintToString() public {
        assertEq(string("123456789"), _isdev.uintToString(123456789));
        assertEq(string("0"), _isdev.uintToString(0));
        assertEq(string("11111"), _isdev.uintToString(11111));
        assertEq(string("99999"), _isdev.uintToString(99999));
        assertEq(
            string("123456789123456789123456789123456789123456789123456789"),
            _isdev.uintToString(123456789123456789123456789123456789123456789123456789)
        );
        assertEq(
            string("115792089237316195423570985008687907853269984665640564039457584007913129639935"),
            _isdev.uintToString(type(uint256).max)
        );
    }

    function testLog10() public {
        assertEq(_isdev.log10(1234567890)+1, 10);
        assertEq(_isdev.log10(0), 0);
    }
}

/// @dev Utility functions
contract Utils {
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