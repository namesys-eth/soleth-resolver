// SPDX-License-Identifier: WTFPL.ETH
pragma solidity >0.8.0 <0.9.0;

import "./Interface.sol";

contract isDev is iERC165 {
    address public owner;

    error OffchainLookup(address _to, string[] _gatewayss, bytes _data, bytes4 _callbackFunction, bytes _extradata);
    error ChecksumFailed(bytes32);
    error InvalidRequest(string);
    error InvalidSignature(string _msg);
    error FeatureNotImplemented(bytes4 _selector);

    string public chainID = block.chainid == 1 ? "1" : "5";

    function setChainID() external {
        chainID = uintToString(block.chainid);
    }

    bytes16 public constant b16 = "0123456789abcdef";
    bytes16 public constant B16 = "0123456789ABCDEF";

    function supportsInterface(bytes4 _selector) external pure returns (bool) {
        return (_selector == isDev.resolve.selector || _selector == isDev.supportsInterface.selector);
    }

    mapping(address => uint256) public signer;
    mapping(bytes4 => string) public funcMap;
    constructor() {
        funcMap[iResolver.addr.selector] = "address/60";
        funcMap[iResolver.pubkey.selector] = "pubkey";
        funcMap[iResolver.name.selector] = "name";
        funcMap[iResolver.contenthash.selector] = "contenthash";
    }

    function resolve(bytes calldata name, bytes calldata request) external view returns (bytes memory) {
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
        string[] memory _gateways = new string[](2);
        string memory _jsonFile = jsonFile(request);
        string memory _username = string(_labels[level - 3]);
        string memory _domain = string.concat(_username, ".isdev.eth");
        if (level > 2) {
            //user.isdev.eth
            _gateways[0] =
                string.concat("https://", _username, ".github.io/.well-known/", _path, "/", _jsonFile, ".json?{data}");
            _gateways[1] = string.concat(
                "https://raw.githubusercontent.com/",
                _username,
                "/",
                _username,
                ".github.io/main/.well-known/",
                _path,
                "/",
                _jsonFile,
                ".json?{data}"
            );
        } else {
            //isdev.eth
            _gateways[0] =
                string.concat("https://namesys-eth.github.io/isdev.eth/.well-known/", _path, "/", _jsonFile, ".json");
            _gateways[1] = string.concat(
                "https://raw.githubusercontent.com/namesys-eth/isdev.eth/main/.well-known/",
                _path,
                "/",
                _jsonFile,
                ".json"
            );
        }
        // https://raw.githubusercontent.com/0xc0de4c0ffee/.well-known/main/index.html
        bytes32 _callhash = keccak256(msg.data);
        bytes32 _checkhash = keccak256(abi.encodePacked(this, blockhash(block.number - 1), _callhash));
        revert OffchainLookup(
            address(this),
            _gateways,
            abi.encodePacked(uint16(block.timestamp / 60)),
            isDev.__callback.selector,
            abi.encode(block.number, _callhash, _checkhash, _domain, _jsonFile)
        );
    }

    function __callback(bytes calldata response, bytes calldata extradata)
        external
        view
        returns (bytes memory result)
    {
        (uint256 _blocknumber, bytes32 _callhash, bytes32 _checkhash, string memory _domain, string memory _recType) =
            abi.decode(extradata[1:], (uint256, bytes32, bytes32, string, string));
        if (block.number > _blocknumber + 5) {
            revert InvalidRequest("BLOCK_TIMEOUT");
        }
        if (_checkhash != keccak256(abi.encodePacked(this, blockhash(_blocknumber - 1), _callhash))) {
            revert ChecksumFailed(_checkhash);
        }
        if (response[0] == 0x00) return response[1:]; // result is already abi encoded
        (address _signer, bytes memory _approvedSig, bytes memory _recordSig, bytes memory _record) =
            abi.decode(response[1:], (address, bytes, bytes, bytes));
        address _approved = isDev(this).getSigner(
            string.concat(
                "Requesting Signature To Approve ENS Records Signer\n",
                "\nOrigin: ",
                _domain,
                "\nApproved Signer: eip155:",
                chainID,
                ":",
                toChecksumAddress(_signer),
                "\nResolver: eip155:",
                chainID,
                ":",
                toChecksumAddress(address(this))
            ),
            _approvedSig
        );
        if (signer[_approved] < block.timestamp) {
            revert InvalidRequest("BAD_Approved");
        }
        string memory signRequest = string.concat(
            "Requesting Signature To Update ENS Record\n",
            "\nOrigin: ",
            _domain,
            "\nRecord Type: ",
            _recType,
            "\nExtradata: ",
            bytesToHexString(abi.encodePacked(keccak256(_record)), true),
            "\nSigned By: eip155:",
            chainID,
            ":",
            toChecksumAddress(_signer)
        );
        if (_signer != isDev(this).getSigner(signRequest, _recordSig)) {
            revert InvalidRequest("BAD_SIGNED_RECORD");
        }
    }

    function jsonFile(bytes calldata _request) public view returns (string memory) {
        bytes4 func = bytes4(_request[:4]);
        if (bytes(funcMap[func]).length > 0) {
            return funcMap[func];
        } else if (func == iResolver.text.selector) {
            (, string memory _key) = abi.decode(_request[4:], (bytes32, string));
            return string.concat("text/", _key);
        } else if (func == iOverloadResolver.addr.selector) {
            (, uint256 _coinId) = abi.decode(_request[4:], (bytes32, uint256));
            return string.concat("address/", uintToString(_coinId));
        } else if (func == iResolver.interfaceImplementer.selector) {
            (, bytes4 _interface) = abi.decode(_request[4:], (bytes32, bytes4));
            return string.concat("interface/", bytesToHexString(abi.encodePacked(_interface), true));
        } else if (func == iResolver.ABI.selector) {
            (, uint256 _abi) = abi.decode(_request[4:], (bytes32, uint256));
            return string.concat("abi/", uintToString(_abi));
        }
        revert FeatureNotImplemented(func);
    }


    /**
     * @dev Checks if a signature is valid
     * @param _message - String-formatted message that was signed
     * @param _signature - Compact signature to verify
     * @return _signer - Signer of message
     * @notice - Signature Format:
     * a) 64 bytes - bytes32(r) + bytes32(vs) ~ compact, or
     * b) 65 bytes - bytes32(r) + bytes32(s) + uint8(v) ~ packed, or
     * c) 96 bytes - bytes32(r) + bytes32(s) + uint256(v) ~ longest
     */
    function getSigner(string calldata _message, bytes calldata _signature) external pure returns (address _signer) {
        bytes32 r = bytes32(_signature[:32]);
        bytes32 s;
        uint8 v;
        uint256 len = _signature.length;
        if (len == 64) {
            bytes32 vs = bytes32(_signature[32:]);
            s = vs & bytes32(0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
            v = uint8((uint256(vs) >> 255) + 27);
        } else if (len == 65) {
            s = bytes32(_signature[32:64]);
            v = uint8(bytes1(_signature[64:]));
        } else if (len == 96) {
            s = bytes32(_signature[32:64]);
            v = uint8(uint256(bytes32(_signature[64:])));
        } else {
            revert InvalidSignature("BAD_SIG_LENGTH");
        }
        if (s > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert InvalidSignature("INVALID_S_VALUE");
        }
        bytes32 digest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n", uintToString(bytes(_message).length), _message)
        );
        _signer = ecrecover(digest, v, r, s);
        if (_signer == address(0)) {
            revert InvalidSignature("ZERO_ADDR");
        }
    }

    function toChecksumAddress(address _addr) public pure returns (string memory) {
        if (_addr == address(0)) {
            return "0x0000000000000000000000000000000000000000";
        }
        bytes memory _buffer = abi.encodePacked(_addr);
        bytes memory result = new bytes(40);
        bytes32 hash = keccak256(abi.encodePacked(bytesToHexString(_buffer, true)));
        uint256 d;
        uint256 r;
        unchecked {
            for (uint256 i = 0; i < 20; i++) {
                d = uint8(_buffer[i]) / 16;
                r = uint8(_buffer[i]) % 16;
                result[i * 2] = uint8(hash[i]) / 16 > 7 ? B16[d] : b16[d];
                result[i * 2 + 1] = uint8(hash[i]) % 16 > 7 ? B16[r] : b16[r];
            }
        }
        return string.concat("0x", string(result));
    }

    function bytesToHexString(bytes memory _buffer, bool _prefix) public pure returns (string memory) {
        unchecked {
            uint256 len = _buffer.length;
            bytes memory result = new bytes(len * 2);
            uint8 _b;
            for (uint256 i = 0; i < len; i++) {
                _b = uint8(_buffer[i]);
                result[i * 2] = b16[_b / 16];
                result[(i * 2) + 1] = b16[_b % 16];
            }
            return _prefix ? string.concat("0x", string(result)) : string(result);
        }
    }

    function uintToString(uint256 value) public pure returns (string memory) {
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
    function log10(uint256 value) public pure returns (uint256 result) {
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

    fallback() external payable {
        revert();
    }

    receive() external payable{
        revert();
    }
}
