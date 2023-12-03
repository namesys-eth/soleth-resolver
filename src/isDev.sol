// SPDX-License-Identifier: WTFPL.ETH
pragma solidity >0.8.0 <0.9.0;

import "./Interface.sol";

contract isDev is iERC165 {
    address public owner;

    function supportsInterface(bytes4 _selector) external pure returns (bool) {
        return (_selector == isDev.resolve.selector ||
            _selector == isDev.supportsInterface.selector);
    }

    mapping(address => uint) signer;
    mapping(bytes4 => string) public funcMap;

    constructor() {
        funcMap[iResolver.addr.selector] = "address/60";
        funcMap[iResolver.pubkey.selector] = "pubkey";
        funcMap[iResolver.name.selector] = "name";
        funcMap[iResolver.contenthash.selector] = "contenthash";
    }

    function resolve(
        bytes calldata name,
        bytes calldata request
    ) external view returns (bytes memory output) {
        uint256 level;
        uint256 ptr;
        uint256 len;
        bytes[] memory _labels = new bytes[](42);
        string memory _path;
        while (name[ptr] > 0x0) {
            len = uint8(bytes1(name[ptr:++ptr]));
            _labels[level++] = name[ptr:ptr += len];
            _path = string.concat(string(_labels[level++]), "/", _path);
        }
        if (level < 3) {
            //isdev.eth
            _path = string.concat(
                "https://namesys-eth.github.io/isdev.eth/.well-known/",
                _path,
                "/",
                jsonFile(request),
                ".json"
            );
        } else {
            //user.isdev.eth
            _path = string.concat(
                "https://",
                string(_labels[level - 3]),
                ".github.io/.well-known/",
                _path,
                "/",
                jsonFile(request),
                ".json?{data}"
            );
        }
        bytes32 _checkhash = keccak256(
            abi.encodePacked(this, blockhash(block.number - 1), name, request)
        );
        string[] memory _gateway = new string[](2);
        _gateway[0] = _path;
        _gateway[1] = _path;
        revert OffchainLookup(
            address(this),
            _gateway,
            abi.encodePacked(uint16(block.timestamp)),
            isDev.___callback.selector,
            abi.encode(block.number, name, request, _checkhash)
        );
    }

    error OffchainLookup(
        address _to,
        string[] _gateways,
        bytes _data,
        bytes4 _callbackFunction,
        bytes _extradata
    );

    function ___callback() external view returns (bytes memory) {

    }

    function jsonFile(
        bytes calldata _request
    ) public view returns (string memory _jsonFile) {
        bytes4 func = bytes4(_request[:4]);
        if (bytes(funcMap[func]).length > 0) {
            _jsonFile = funcMap[func];
        } else if (func == iResolver.text.selector) {
            (, string memory _key) = abi.decode(
                _request[4:],
                (bytes32, string)
            );
            _jsonFile = string.concat("text/", _key);
        } else if (func == iOverloadResolver.addr.selector) {
            _jsonFile = string.concat(
                "address/",
                uintToString(abi.decode(_request[36:], (uint256)))
            );
        } else if (func == iResolver.interfaceImplementer.selector) {
            (, bytes4 _interface) = abi.decode(_request[4:], (bytes32, bytes4));
            _jsonFile = string.concat(
                "interface/",
                bytesToHexString(abi.encodePacked(_interface))
            );
        } else if (func == iResolver.ABI.selector) {
            (, uint _abi) = abi.decode(_request[4:], (bytes32, uint));
            _jsonFile = string.concat("abi/", uintToString(_abi));
        } else {
            revert FeatureNotImplemented(func);
        }
    }

    error FeatureNotImplemented(bytes4 _selector);
    bytes16 internal constant b16 = "0123456789abcdef";

    function bytesToHexString(
        bytes memory _buffer
    ) internal pure returns (string memory) {
        unchecked {
            uint256 len = _buffer.length;
            bytes memory result = new bytes(len * 2);
            uint8 _b;
            for (uint256 i = 0; i < len; i++) {
                _b = uint8(_buffer[i]);
                result[i * 2] = b16[_b / 16];
                result[(i * 2) + 1] = b16[_b % 16];
            }
            return string.concat("0x", string(result));
        }
    }

    function uintToString(uint256 value) internal pure returns (string memory) {
        if (value == 0) return "0";
        uint256 len;
        unchecked {
            len = log10(value) + 1;
            bytes memory buffer = new bytes(len);
            while (value > 0) {
                buffer[--len] = bytes1(uint8(48 + (value % 10)));
                value /= 10;
            }
            return string(buffer);
        }
    }

    /// @dev
    function log10(uint256 value) internal pure returns (uint256 result) {
        unchecked {
            if (value >= 1e64) {
                value /= 1e64;
                result += 64;
            }
            if (value >= 1e32) {
                value /= 1e32;
                result += 32;
            }
            if (value >= 1e16) {
                value /= 1e16;
                result += 16;
            }
            if (value >= 1e8) {
                value /= 1e8;
                result += 8;
            }
            if (value >= 10000) {
                value /= 10000;
                result += 4;
            }
            if (value >= 100) {
                value /= 100;
                result += 2;
            }
            if (value >= 10) {
                ++result;
            }
        }
    }
}
