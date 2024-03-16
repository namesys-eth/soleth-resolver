// SPDX-License-Identifier: WTFPL.ETH
pragma solidity >0.8.0 <0.9.0;

import "./Interface.sol";
import "./Utils.sol";

/**
 * @title - dev3.eth : ENS-on-Github Resolver implementing CCIP-Read & Wildcard Resolution
 * @author - sshmatrix.eth, freetib.eth
 * @notice - https://dev3.eth.limo
 * https://github.com/namesys-eth/dev3-eth-resolver
 */
contract SolanaNameResolver is iSNR {
    using Utils for *;

    address public owner;
    iENS public constant ENS = iENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);

    error InvalidRequest(string);
    error BadSignature(string);
    error NotImplemented(bytes4);

    string public PrimaryGateway = "sol.casa";
    string public FallbackGateway = "fallback.sol.casa";
    //string public chainID = block.chainid == 1 ? "1" : "5";

    event GatewaySigner(string indexed _domain, address indexed _signer, bool indexed _set);
    //event DomainSetup(bytes32 indexed _node, string _gateway, bool _core);
    event WrapperUpdate(address indexed _wrapper, bool indexed _set);
    event FunctionMapUpdate(bytes4 indexed _func, string _name);
    event ThankYou(address indexed _addr, uint256 indexed _value);

    //function supportsInterface(bytes4 _selector) external view returns (bool) {
    //    return bytes(funcMap[_selector]).length > 0;
    //return (_selector == iResolveWithContext.resolve.selector || _selector == iENSIP10.resolve.selector || _selector == iERC165.supportsInterface.selector);
    //}

    mapping(address => bool) public gatewaySigner;
    mapping(bytes4 => string) public funcMap;
    mapping(bytes4 => bool) public supportsInterface;
    mapping(address => bool) public isWrapper;
    mapping(uint256 => string) public coinToSymbol;

    struct Gateway {
        string domain;
        address signer;
    }

    Gateway[] public Gateways;

    function listGateways() external view returns (Gateway[] memory gateways) {
        uint256 len = Gateways.length;
        gateways = new Gateway[](len);
        for (uint256 i; i < len; i++) {
            gateways[i] = Gateways[i];
        }
    }

    function randomGateways(string memory _fullPath) public view returns (string[] memory urls) {
        uint256 total = Gateways.length;
        uint256 len = (total / 2) + 1;
        if (len > 3) {
            len = 3;
        }
        urls = new string[](len);
        bytes32 seed = keccak256(abi.encodePacked(blockhash(block.number - 1), _fullPath));
        uint256 _index = 42;
        for (uint256 i = 0; i < len;) {
            seed = keccak256(abi.encodePacked(seed, i, _index));
            if (uint256(seed) % total != _index) {
                _index = uint256(seed) % total;
                urls[i] = string.concat("https://", Gateways[_index].domain, _fullPath);
                i++;
            }
        }
    }

    string public THIS;

    constructor() {
        THIS = address(this).toChecksumAddress();
        owner = msg.sender;
        funcMap[iResolver.addr.selector] = "address/eth";
        funcMap[iResolver.pubkey.selector] = "publickey";
        funcMap[iResolver.name.selector] = "name"; // NOT used for reverse lookup
        funcMap[iResolver.contenthash.selector] = "contenthash";
        //funcMap[iResolver.zonehash.selector] = "dns_zonehash"; // ? linkup cname/A??
        //funcMap[iResolver.recordVersions.selector] = "version"; // ? not used

        gatewaySigner[0xae9Cc8813ab095cD38F3a8d09Aecd66b2B2a2d35] = true;
        //emit GatewaySigner(0xae9Cc8813ab095cD38F3a8d09Aecd66b2B2a2d35, true);
        isWrapper[0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401] = true;
    }

    function dnsDecode(bytes calldata name)
        public
        pure
        returns (uint256 levels, string memory _domain, string memory _path, bytes[] memory labels)
    {
        levels = 1;
        uint256 ptr = 1;
        uint256 len = uint8(bytes1(name[0]));
        labels = new bytes[](12);
        labels[0] = name[1:ptr += len];
        _path = string(labels[0]);
        _domain = _path;
        while (name[ptr] > 0x0) {
            len = uint8(bytes1(name[ptr:++ptr]));
            labels[levels] = name[ptr:ptr += len];
            _domain = string.concat(_domain, ".", string(labels[levels]));
            _path = string.concat(string(labels[levels++]), "/", _path);
        }
    }
    /**
     * @dev Resolves a given ENS name and returns the corresponding record (ENSIP-10)
     * @param name DNS-encoded subdomain or domain.eth
     * @param request ENS Resolver request
     * @return result The resolved record
     */

    function resolve(bytes calldata name, bytes calldata request) public view returns (bytes memory) {
        (uint256 levels, string memory _domain, string memory _path, bytes[] memory labels) = dnsDecode(name);
        bytes32 _namehash = keccak256(abi.encodePacked(bytes32(0), keccak256(labels[--levels])));
        bytes32 _node;
        while (levels > 0) {
            _namehash = keccak256(abi.encodePacked(_namehash, keccak256(labels[--levels])));
            if (ENS.resolver(_namehash) == address(this)) {
                _node = _namehash;
            }
        }
        //require(_namehash == bytes32(request[4:36]), "BAD_REQUEST");
        string memory _recordType = jsonFile(request);
        string[] memory _urls = randomGateways(string.concat("/.well-known/", _path, _recordType, ".json?t={data}"));
        bytes32 _callhash = keccak256(request);
        uint256 _blockNum = block.number - 1;
        bytes32 _checkhash = keccak256(abi.encodePacked(this, blockhash(_blockNum), _callhash));
        revert OffchainLookup(
            address(this),
            _urls,
            abi.encodePacked(uint16(block.timestamp / 300)),
            iENSIP10.__callback.selector,
            abi.encode(_blockNum, _callhash, _checkhash, _node, _domain, _recordType)
        );
    }

    /**
     * @dev Callback function called by ENSIP-10 resolver to handle off-chain lookup
     * @param response The response from the off-chain lookup
     * @param data Extra data for processing the off-chain lookup response
     * @return result The result of the off-chain lookup
     */
    function __callback(bytes calldata response, bytes calldata data) external view returns (bytes memory result) {
        (
            uint256 _blocknumber,
            bytes32 _callhash,
            bytes32 _checkhash,
            bytes32 _node,
            string memory _domain,
            string memory _recType
        ) = abi.decode(data, (uint256, bytes32, bytes32, bytes32, string, string));
        if (block.number > _blocknumber + 3) {
            revert InvalidRequest("CALLBACK_TIMEOUT");
        }
        if (_checkhash != keccak256(abi.encodePacked(this, blockhash(_blocknumber), _callhash))) {
            revert InvalidRequest("CHECKSUM_FAILED");
        }
        if (bytes4(response[:4]) != iCallbackType.MultiSignedRecord.selector) {
            revert InvalidRequest("BAD_RECORD_PREFIX");
        }
        (bytes memory _result, bytes memory _sigs, bytes memory _extradata) =
            abi.decode(response[4:], (bytes, bytes, bytes));
        string memory message;
        bytes32 digest;
        if (_node != 0x0) {
            bytes memory _approvedSig;
            string memory solanaName;
            //if()
            (_approvedSig, solanaName, _extradata) = this.formatApproval(_extradata);
            if (_approvedSig.length < 64) {
                revert InvalidRequest("BAD_LINK_SIG");
            }
            message = string.concat(
                "Requesting Signature To Mirror ENS Records From SNS\n",
                "\nENS Domain: ",
                _domain,
                "\nSNS Domain: ",
                solanaName,
                "\nResolver: eip155:1:",
                THIS
            );
            digest = keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n", (bytes(message).length).uintToString(), message)
            );
            address _approvedBy = this.getSigner(digest, _approvedSig);
            address _manager = ENS.owner(_node);
            if (isWrapper[_manager]) {
                _manager = iToken(_manager).ownerOf(uint256(_node));
            }
            if (_manager != _approvedBy) {
                revert BadSignature("APPROVAL");
            }
        }
        uint256 expiration = abi.decode(_extradata, (uint256));
        if(block.timestamp > expiration){
            revert InvalidRequest("SIG_EXPIRED");
        }
        message = string.concat(
            "Requesting Signature For ENS Record\n",
            "\nDomain: ",
            _domain,
            "\nResolver: eip155:1:",
            THIS,
            "\nRecord Type: ",
            _recType,
            "\nResult Hash: 0x",
            abi.encodePacked(keccak256(_result)).bytesToHexString(),
            "\nExpiry: ",
            expiration.uintToString()
        );
        digest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n", (bytes(message).length).uintToString(), message)
        );
        uint256 quorum = (Gateways.length / 2) + 1;
        if (quorum > 3) {
            quorum = 3;
        }
        bytes[] memory _recordSigs = this.formatSignatures(_sigs);
        uint256 sigLen = _recordSigs.length;
        if (sigLen < quorum) {
            revert InvalidRequest("NOT_ENOUGH_QUORUM");
        }
        address[] memory signers = new address[](sigLen);
        for (uint256 i = 0; i < sigLen; i++) {
            address _signer = this.getSigner(digest, _recordSigs[i]);
            if (!gatewaySigner[_signer]) {
                revert BadSignature("NOT_SIGNER");
            }
            for (uint256 k = i; k > 0;) {
                if (_signer == signers[--k]) {
                    revert BadSignature("DUPLICATE_SIGNER");
                }
            }
            signers[i] = _signer;
        }
        /*
        for (uint256 j = 0; j < sigLen; j++) {
            for (uint256 k = j+1; k < sigLen; k++) {
                if(signers[j] == signers[k]){
                    revert InvalidRequest("DUPLICATE_GATEWAY_SIGNER");
                }
            }
        }*/
        return _result;
    }

    function formatApproval(bytes calldata _req)
        external
        pure
        returns (bytes memory, string memory, bytes memory)
    {
        if (bytes4(_req[:4]) != iCallbackType.ExtradataWithApproval.selector) {
            revert InvalidRequest("BAD_APPROVAL_PREFIX");
        }
        return abi.decode(_req[4:], (bytes, string, bytes));
    }

    function formatSignatures(bytes calldata _sigs) external pure returns (bytes[] memory _multiSigs) {
        unchecked {
            uint256 len = _sigs.length;
            if (len % 64 > 0) {
                revert InvalidRequest("BAD_SIG_LENTH");
            }
            _multiSigs = new bytes[](len / 64);
            uint256 p = 0;
            for (uint256 i = 0; i < len;) {
                _multiSigs[p++] = _sigs[i:i += 64];
            }
        }
    }

    /**
     * @dev Converts a resolver request to a JSON file format
     * @param _request The resolver request
     * @return _recType The record type in JSON file format
     */
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
        }
        /* 
            else if (func == iResolver.interfaceImplementer.selector) {
                (, bytes4 _interface) = abi.decode(_request[4:], (bytes32, bytes4));
                return string.concat("interface_0x", abi.encodePacked(_interface).bytesToHexString());
            } else if (func == iResolver.ABI.selector) {
                (, uint256 _abi) = abi.decode(_request[4:], (bytes32, uint256));
                return string.concat("abi_", _abi.uintToString());
            } else if (func == iOverloadResolver.dnsRecord.selector) {
                (, bytes memory _name, uint16 resource) = abi.decode(_request[4:], (bytes32, bytes, uint16));
                return string.concat("dns_0x", _name.bytesToHexString(), "_", resource.uintToString());
            } else if (func == iResolver.dnsRecord.selector) {
                (, bytes32 _name, uint16 resource) = abi.decode(_request[4:], (bytes32, bytes32, uint16));
                return string.concat("dns_0x", abi.encodePacked(_name).bytesToHexString(), "_", resource.uintToString());
            }
        */
        revert NotImplemented(func);
    }

    /**
     * @dev Checks if a signature is valid
     * @param digest - String-formatted message that was signed
     * @param _signature - Compact signature to verify
     * @return _signer - Signer of message
     * @notice - Signature Format:
     * 64 bytes - bytes32(r) + bytes32(vs) ~ compact, only
     */
    function getSigner(bytes32 digest, bytes calldata _signature) external pure returns (address _signer) {
        bytes32 r = bytes32(_signature[:32]);
        bytes32 s;
        uint8 v;
        uint256 len = _signature.length;
        if (len == 64) {
            bytes32 vs = bytes32(_signature[32:]);
            s = vs & bytes32(0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
            v = uint8((uint256(vs) >> 255) + 27);
        }
        /* 
            else if (len == 65) {
                s = bytes32(_signature[32:64]);
                v = uint8(bytes1(_signature[64:]));
            } else if (len == 96) {
                s = bytes32(_signature[32:64]);
                v = uint8(uint256(bytes32(_signature[64:])));
            }
        */
        else {
            revert BadSignature("SIG_LENGTH");
        }
        if (s > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert BadSignature("S_VALUE");
        }
        _signer = ecrecover(digest, v, r, s);
        if (_signer == address(0)) {
            revert BadSignature("ZERO_ADDR");
        }
    }

    /// @dev Extra functions
    /**
     * @dev Modifier to restrict access to only the owner of the contract
     */
    modifier onlyDev() {
        if (msg.sender != owner) revert InvalidRequest("ONLY_DEV");
        _;
    }

    /**
     * @dev Transfers ownership of the SolanaNameResolver contract to a new owner
     * @param _newOwner The address of the new owner
     */
    function transferOwnership(address _newOwner) external payable onlyDev {
        emit OwnershipTransferred(owner, _newOwner);
        owner = _newOwner;
    }

    /**
     * @dev Sets the approval status of a signer for a specific ENS node
     * @param _domain gateway domain.tld without "https://"
     * @param _signer gateway signer address
     */
    function addGatewaySigner(string memory _domain, address _signer) external payable onlyDev {
        if (gatewaySigner[_signer]) {
            revert InvalidRequest("DUPLICATE_SIGNER");
        }
        Gateways.push(Gateway(_domain, _signer));
        gatewaySigner[_signer] = true;
        emit GatewaySigner(_domain, _signer, true);
    }

    /**
     * @dev Sets the status of a wrapper contract
     * @param _wrapper The address of the wrapper contract
     * @param _set The status to set (true/false)
     */
    function setWrapper(address _wrapper, bool _set) external payable onlyDev {
        isWrapper[_wrapper] = _set;
        emit WrapperUpdate(_wrapper, _set);
    }

    /**
     * @dev Sets the function to JSON filename
     * @param _func bytes4 function selector to map
     * @param _name String mapped to function for JSON filename
     */
    function setFunctionMap(bytes4 _func, string calldata _name) external payable onlyDev {
        funcMap[_func] = _name;
        emit FunctionMapUpdate(_func, _name);
    }

    /**
     * @dev Withdraws a specified balance of a given token to the owner
     * @param _token The address of the token
     * @param _balance The amount to withdraw
     */
    function withdraw(address _token, uint256 _balance) external {
        iToken(_token).transfer(owner, _balance);
    }

    /**
     * @dev Withdraws the entire balance of Ether to the owner
     */
    function withdraw() external {
        payable(owner).transfer(address(this).balance);
    }

    fallback() external payable {
        revert();
    }

    receive() external payable {
        emit ThankYou(msg.sender, msg.value);
    }
}
