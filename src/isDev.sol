// SPDX-License-Identifier: WTFPL.ETH
pragma solidity >0.8.0 <0.9.0;

import "./Interface.sol";
import "./Utils.sol";

contract isDev is iERC165, iERC173 {
    using Utils for *;
    address public owner;
    
    iENS public immutable ENS = iENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);

    error OffchainLookup(address _to, string[] _urlss, bytes _data, bytes4 _callbackFunction, bytes _extradata);
    error InvalidRequest(string);
    error InvalidSignature(string);
    error FeatureNotImplemented(bytes4);

    string public chainID = block.chainid == 1 ? "1" : "5";

    function supportsInterface(bytes4 _selector) external pure returns (bool) {
        return (_selector == isDev.resolve.selector || _selector == isDev.supportsInterface.selector);
    }

    mapping(address => uint256) public subManager;
    mapping(bytes4 => string) public funcMap;
    mapping(bytes32 => string) public web2Gateway;
    mapping(bytes32 => bool) public coreDomain;
    mapping(address => mapping(address => bool)) public isApprovedfor;
    mapping(address => bool) public isWrapper;
    bytes32 public immutable ENSROOT = keccak256(abi.encodePacked(bytes32(0), "eth"));

    constructor() {
        funcMap[iResolver.addr.selector] = "address/60";
        funcMap[iResolver.pubkey.selector] = "pubkey";
        funcMap[iResolver.name.selector] = "name"; // NOT used fo reverse lookup
        funcMap[iResolver.contenthash.selector] = "contenthash";

        bytes32 _namehash = keccak256(abi.encodePacked(bytes32(0), "eth"));
        bytes32 _nh = keccak256(abi.encodePacked(_namehash, "isdev"));
        coreDomain[_nh] = true;
        web2Gateway[_nh] = "namesys-eth.github.io/isdev.eth";
        _nh = keccak256(abi.encodePacked(_namehash, "hello123"));
        coreDomain[_nh] = true;
        web2Gateway[_nh] = "namesys-eth.github.io";
        isWrapper[0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401] = true;
    }
    /**
     * ENSIP10 Resolve Fucntion
     * @param name - DNS encoded sub./domain.eth
     * @param request - ENS Resolver request
     */

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
        string[] memory _urls;
        string memory _recordType = jsonFile(request);
        string memory _gateway;
        bytes32 _namehash = keccak256(abi.encodePacked(bytes32(0), _labels[level - 1]));
        _namehash = keccak256(abi.encodePacked(_namehash, _labels[level - 2]));
        if (coreDomain[_namehash]) {
            _urls = new string[](3);
            if (level > 2) {
                _gateway = string.concat(string(_labels[level - 3]), ".github.io");
                //user.isdev.eth
                _urls[0] = string.concat("https://", _gateway, "/.well-known/", _path, "/", _recordType, ".json?{data}");
                _urls[1] = string.concat(
                    "https://raw.githubusercontent.com/",
                    string(_labels[level - 3]),
                    "/",
                    _gateway,
                    "/main/.well-known/",
                    _path,
                    "/",
                    _recordType,
                    ".json?{data}"
                );
                _urls[2] = string.concat(
                    "https://raw.githubusercontent.com/",
                    string(_labels[level - 3]),
                    "/",
                    _gateway,
                    "/main/docs/.well-known/",
                    _path,
                    "/",
                    _recordType,
                    ".json?{data}"
                );
            } else {
                _urls = new string[](2);
                _urls[0] = string.concat(
                    "https://", web2Gateway[_namehash], "/.well-known/", _path, "/", _recordType, ".json?{data}"
                );
                _urls[1] = _urls[0]; // retry
            }
        } else if (bytes(web2Gateway[_namehash]).length != 0) {
            _urls = new string[](2);
            _urls[0] = string.concat(
                "https://", web2Gateway[_namehash], "/.well-known/", _path, "/", _recordType, ".json?{data}"
            );
            _urls[1] = _urls[0]; // retry
        } else {
            revert InvalidRequest("BAD_GATEWAY");
        }
        bytes32 _callhash = keccak256(msg.data);
        bytes32 _checkhash = keccak256(abi.encodePacked(this, blockhash(block.number - 1), _callhash));
        revert OffchainLookup(
            address(this),
            _urls,
            abi.encodePacked(uint16(block.timestamp / 60)),
            isDev.__callback.selector,
            abi.encode(block.number, _callhash, _checkhash, _namehash, _gateway, _recordType)
        );
    }

    function __callback(bytes calldata response, bytes calldata extradata)
        external
        view
        returns (bytes memory result)
    {
        (
            uint256 _blocknumber,
            bytes32 _callhash,
            bytes32 _checkhash,
            bytes32 _namehash,
            string memory _gateway,
            string memory _recType
        ) = abi.decode(extradata, (uint256, bytes32, bytes32, bytes32, string, string));
        if (block.number > _blocknumber + 5) {
            revert InvalidRequest("BLOCK_TIMEOUT");
        }
        if (_checkhash != keccak256(abi.encodePacked(this, blockhash(_blocknumber - 1), _callhash))) {
            revert InvalidRequest("CHECKSUM_FAILED");
        }
        //bytes4 _type = bytes4(response[:4]);
        // result must be abi encoded to resolver's request type
        if (bytes4(response[:4]) == iCallbackType.plaintextRecord.selector) {
            return response[4:];
        } else if (bytes4(response[:4]) != iCallbackType.signedRecord.selector) {
            revert InvalidRequest("BAD_RECORD_PREFIX");
        }
        (address _signer, bytes memory _recordSig, bytes memory _approvedSig, bytes memory _result) =
            abi.decode(response[4:], (address, bytes, bytes, bytes));
        address _manager = ENS.owner(_namehash);
        if (isWrapper[_manager]) {
            _manager = iToken(_manager).ownerOf(uint256(_namehash));
        }
        if (_approvedSig.length > 63) {
            address _approvedBy = isDev(this).getSigner(
                string.concat(
                    "Requesting Signature To Approve ENS Records Signer\n",
                    "\nGateway: https://",
                    _gateway,
                    "\nResolver: eip155:",
                    chainID,
                    ":",
                    address(this).toChecksumAddress(),
                    "\nApproved Signer: eip155:",
                    chainID,
                    ":",
                    _signer.toChecksumAddress()
                ),
                _approvedSig
            );
            if (coreDomain[_namehash] && subManager[_approvedBy] < block.timestamp) {
                revert InvalidRequest("BAD_APPROVED_SIG");
            } else if (_approvedBy != _manager && !isApprovedfor[_manager][_approvedBy]) {
                revert InvalidRequest("BAD_MANAGER_SIG");
            }
        } else if (_signer != _manager && !isApprovedfor[_manager][_signer]) {
            revert InvalidRequest("BAD_SIGNER");
        }
        address _signedBy = isDev(this).getSigner(
            string.concat(
                "Requesting Signature To Update ENS Record\n",
                "\nGateway: https://",
                _gateway,
                "\nRecord Type: ",
                _recType,
                "\nExtradata: 0x",
                abi.encodePacked(keccak256(_result)).bytesToHexString(),
                "\nSigned By: eip155:",
                chainID,
                ":",
                _signer.toChecksumAddress()
            ),
            _recordSig
        );
        if (_signer != _signedBy) {
            revert InvalidRequest("BAD_SIGNED_RECORD");
        }
        return _result;
    }

    function jsonFile(bytes calldata _request) public view returns (string memory) {
        bytes4 func = bytes4(_request[:4]);
        if (bytes(funcMap[func]).length > 0) {
            return funcMap[func];
        } else if (func == iResolver.text.selector) {
            (, string memory _key) = abi.decode(_request[4:], (bytes32, string));
            return string.concat("text/", _key);
        } else if (func == iOverloadResolver.addr.selector) {
            (, uint256 _coinType) = abi.decode(_request[4:], (bytes32, uint256));
            return string.concat("address/", _coinType.uintToString());
        } else if (func == iResolver.interfaceImplementer.selector) {
            (, bytes4 _interface) = abi.decode(_request[4:], (bytes32, bytes4));
            return string.concat("interface/0x", abi.encodePacked(_interface).bytesToHexString());
        } else if (func == iResolver.ABI.selector) {
            (, uint256 _abi) = abi.decode(_request[4:], (bytes32, uint256));
            return string.concat("abi/", _abi.uintToString());
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
            abi.encodePacked("\x19Ethereum Signed Message:\n", (bytes(_message).length).uintToString(), _message)
        );
        _signer = ecrecover(digest, v, r, s);
        if (_signer == address(0)) {
            revert InvalidSignature("ZERO_ADDR");
        }
    }

    /// @dev extra functions

    function transferOwnership(address _newOwner) external payable {
        if (msg.sender != owner) revert InvalidRequest("ONLY_OWNER");
        emit OwnershipTransferred(owner, _newOwner);
        owner = _newOwner;
    }

    function setSubManager(address _addr, uint256 _validity) external payable {
        if (msg.sender != owner) revert InvalidRequest("ONLY_OWNER");
        subManager[_addr] = _validity;
    }

    function addCoreDomain(string calldata _label, string calldata _gateway) external payable {
        if (msg.sender != owner) revert InvalidRequest("ONLY_OWNER");
        bytes32 _namehash = keccak256(abi.encodePacked(ENSROOT, _label));
        if (bytes(web2Gateway[_namehash]).length > 0) revert InvalidRequest("INVALID_DOMAIN");
        web2Gateway[_namehash] = _gateway;
        coreDomain[_namehash] = true;
    }

    function removeCoreDomain(bytes32 _namehash) external payable {
        if (msg.sender != owner) revert InvalidRequest("ONLY_OWNER");
        if (!coreDomain[_namehash]) revert InvalidRequest("NOT_CORE_DOMAIN");
        delete web2Gateway[_namehash];
        coreDomain[_namehash] = false;
    }

    function addYourENS(string calldata _label, string calldata _gateway) external payable {
        bytes32 _namehash = keccak256(abi.encodePacked(ENSROOT, _label));
        address _manager = ENS.owner(_namehash);
        if (isWrapper[_manager]) {
            _manager = iToken(_manager).ownerOf(uint256(_namehash));
        }
        if (msg.sender != _manager) revert InvalidRequest("NOT_MANAGER");
        web2Gateway[_namehash] = _gateway;
    }

    function addYourENS(string calldata _label, string calldata _gateway, address _signer) external payable {
        bytes32 _namehash = keccak256(abi.encodePacked(ENSROOT, _label));
        address _manager = ENS.owner(_namehash);
        if (isWrapper[_manager]) {
            _manager = iToken(_manager).ownerOf(uint256(_namehash));
        }
        if (msg.sender != _manager) revert InvalidRequest("NOT_MANAGER");
        web2Gateway[_namehash] = _gateway;
        isApprovedfor[_manager][_signer] = true;
    }

    function setChainID() external {
        chainID = block.chainid.uintToString();
    }

    function withdraw(address _token, uint256 _balance) external {
        iToken(_token).transfer(owner, _balance);
    }

    function withdraw() external {
        payable(owner).transfer(address(this).balance);
    }
    fallback() external payable {
        revert();
    }

    receive() external payable {
        revert();
    }

}
