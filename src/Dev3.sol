// SPDX-License-Identifier: WTFPL.ETH
pragma solidity >0.8.0 <0.9.0;

import "./Interface.sol";
import "./Utils.sol";

contract Dev3 is iERC165, iERC173 {
    using Utils for *;

    address public owner;

    iENS public immutable ENS = iENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);

    error OffchainLookup(address _to, string[] _urlss, bytes _data, bytes4 _callbackFunction, bytes _extradata);
    error InvalidRequest(string);
    error InvalidSignature(string);
    error FeatureNotImplemented(bytes4);

    string public chainID = block.chainid == 1 ? "1" : "5";

    function supportsInterface(bytes4 _selector) external pure returns (bool) {
        return (_selector == Dev3.resolve.selector || _selector == Dev3.supportsInterface.selector);
    }

    //mapping(address => uint256) public subManager;
    struct Space {
        bool _core;
        string _path;
    }

    mapping(bytes32 => Space) public subSpace;
    mapping(bytes4 => string) public funcMap;
    mapping(address => mapping(address => bool)) public isApprovedSigner;
    mapping(address => bool) public isWrapper;

    constructor() {
        owner = msg.sender;
        funcMap[iResolver.addr.selector] = "address/60";
        funcMap[iResolver.pubkey.selector] = "pubkey";
        funcMap[iResolver.name.selector] = "name"; // NOT used for reverse lookup
        funcMap[iResolver.contenthash.selector] = "contenthash";

        bytes32 _root = keccak256(abi.encodePacked(bytes32(0), keccak256("eth")));
        bytes32 _node = keccak256(abi.encodePacked(_root, keccak256("dev3")));
        subSpace[_node] = Space(true, "namesys-eth.github.io");
        _node = keccak256(abi.encodePacked(_root, keccak256("isdev")));
        subSpace[_node] = Space(true, "namesys-eth.github.io");
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
        bytes[] memory _labels = new bytes[](43);
        string memory _path;
        while (name[ptr] > 0x0) {
            len = uint8(bytes1(name[ptr:++ptr]));
            _labels[level] = name[ptr:ptr += len];
            _path = string.concat(string(_labels[level++]), "/", _path);
        }
        string[] memory _urls = new string[](2);
        string memory _recordType = jsonFile(request);
        string memory _gateway;
        bytes32 _namehash = keccak256(abi.encodePacked(bytes32(0), keccak256(_labels[level - 1])));
        _namehash = keccak256(abi.encodePacked(_namehash, keccak256(_labels[level - 2])));
        if (subSpace[_namehash]._core) {
            if (level > 2) {
                _gateway = string.concat(string(_labels[level - 3]), ".github.io");
                //user.isdev.eth
                _urls[0] = string.concat("https://", _gateway, "/.well-known/", _path, _recordType, ".json?{data}");
                _urls[1] = string.concat(
                    "https://raw.githubusercontent.com/",
                    string(_labels[level - 3]),
                    "/",
                    _gateway,
                    "/gh-pages/.well-known/",
                    _path,
                    _recordType,
                    ".json?{data}"
                );
            } else {
                _urls[0] = string.concat(
                    "https://", subSpace[_namehash]._path, "/.well-known/", _path, _recordType, ".json?{data}"
                );
                _urls[1] = _urls[0]; // retry
            }
        } else if (bytes(subSpace[_namehash]._path).length != 0) {
            _urls[0] = string.concat(
                "https://", subSpace[_namehash]._path, "/.well-known/", _path, _recordType, ".json?{data}"
            );
            _urls[1] = _urls[0]; // retry
        } else {
            revert InvalidRequest("BAD_GATEWAY");
        }
        bytes32 _callhash = keccak256(msg.data);
        uint256 _blockNum = block.number - 1;
        bytes32 _checkhash = keccak256(abi.encodePacked(this, blockhash(_blockNum), _callhash));
        revert OffchainLookup(
            address(this),
            _urls,
            abi.encodePacked(uint16(block.timestamp / 60)),
            Dev3.__callback.selector,
            abi.encode(_blockNum, _callhash, _checkhash, _namehash, _gateway, _recordType)
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
        if (block.number > _blocknumber + 4) {
            revert InvalidRequest("CALLBACK_TIMEOUT");
        }
        if (_checkhash != keccak256(abi.encodePacked(this, blockhash(_blocknumber), _callhash))) {
            revert InvalidRequest("CHECKSUM_FAILED");
        }
        if (bytes4(response[:4]) != iCallbackType.signedRecord.selector) {
            revert InvalidRequest("BAD_RECORD_PREFIX");
        }
        (address _signer, bytes memory _recordSig, bytes memory _approvedSig, bytes memory _result) =
            abi.decode(response[4:], (address, bytes, bytes, bytes));
        address _manager = ENS.owner(_namehash);
        if (isWrapper[_manager]) {
            _manager = iToken(_manager).ownerOf(uint256(_namehash));
        }
        if (subSpace[_namehash]._core || _approvedSig.length > 63) {
            address _approvedBy = Dev3(this).getSigner(
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
            if (!isApprovedSigner[_manager][_approvedBy] && _approvedBy != _manager) {
                revert InvalidRequest("BAD_APPROVED_SIG");
            }
        } else if (!isApprovedSigner[_manager][_signer]) {
            revert InvalidRequest("BAD_SIGNER");
        }
        address _signedBy = Dev3(this).getSigner(
            string.concat(
                "Requesting Signature To Update ENS Record\n",
                "\nGateway: https://",
                _gateway,
                "\nResolver: eip155:",
                chainID,
                ":",
                address(this).toChecksumAddress(),
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
    modifier onlyOwner {
        if (msg.sender != owner) revert InvalidRequest("ONLY_OWNER");
        _;
    }
    function transferOwnership(address _newOwner) external payable onlyOwner {
        emit OwnershipTransferred(owner, _newOwner);
        owner = _newOwner;
    }

    /*function setSubManager(address _addr, uint256 _validity) external payable onlyOwner {
        subManager[_addr] = _validity;
    }*/

    function addDomain(bytes32 _node, string calldata _gateway) external payable onlyOwner {
        if (bytes(subSpace[_node]._path).length > 0) {
            revert InvalidRequest("ACTIVE_DOMAIN");
        }
        subSpace[_node] = Space(true, _gateway);
    }

    function removeDomain(bytes32 _node) external payable onlyOwner {
        if (!subSpace[_node]._core) revert InvalidRequest("NOT_CORE_DOMAIN");
        delete subSpace[_node];
    }

    function addYourENS(bytes32 _node, string calldata _gateway) external payable {
        address _manager = ENS.owner(_node);
        if (isWrapper[_manager]) {
            _manager = iToken(_manager).ownerOf(uint256(_node));
        }
        if (msg.sender != _manager) revert InvalidRequest("ONLY_MANAGER");
        subSpace[_node] = Space(false, _gateway);
    }

    function addYourENS(bytes32 _node, address _signer, string calldata _gateway) external payable {
        address _manager = ENS.owner(_node);
        if (isWrapper[_manager]) {
            _manager = iToken(_manager).ownerOf(uint256(_node));
        }
        if (msg.sender != _manager) revert InvalidRequest("ONLY_MANAGER");
        subSpace[_node] = Space(false, _gateway);
        isApprovedSigner[_manager][_signer] = true;
    }

    function setYourSigner(bytes32 _node, address _signer, bool _set) external payable {
        if (bytes(subSpace[_node]._path).length == 0) {
            revert InvalidRequest("NOT_ACTIVE");
        }
        address _manager = ENS.owner(_node);
        if (isWrapper[_manager]) {
            _manager = iToken(_manager).ownerOf(uint256(_node));
        }
        if (msg.sender != _manager) revert InvalidRequest("ONLY_MANAGER");
        isApprovedSigner[_manager][_signer] = _set;
    }

    function setCoreApprover(bytes32 _node, address _approver, bool _set) external payable onlyOwner{
        if (!subSpace[_node]._core) revert InvalidRequest("NOT_CORE_DOMAIN");
        address _manager = ENS.owner(_node);
        if (isWrapper[_manager]) {
            _manager = iToken(_manager).ownerOf(uint256(_node));
        }
        isApprovedSigner[_manager][_approver] = _set;
    }
    
    function setChainID() external {
        chainID = (block.chainid).uintToString();
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
