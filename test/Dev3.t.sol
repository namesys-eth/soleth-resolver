// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import "../src/Dev3.sol";
import "../src/Utils.sol";

contract Dev3Test is Test {
    using Utils for *;
    using Helper for *;

    Dev3 public DEV3 = new Dev3();
    xENS public ENS = xENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);

    function setUp() public {}

    function testDomain() public {
        //vm.roll(1234);
        //vm.warp(12345678);
        bytes[] memory _name = new bytes[](2);
        _name[0] = "dev3";
        _name[1] = "eth";
        (bytes32 _node, bytes memory _encoded) = Helper.Encode(_name);

        uint256 ApproverKey = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
        //uint256 OwnerKey = 0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd;
        uint256 SignerKey = 0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc;
        address _approver = vm.addr(ApproverKey);
        address _signer = vm.addr(SignerKey);
        bytes32 dev3Node = keccak256(abi.encodePacked(bytes32(0), keccak256("eth")));
        dev3Node = keccak256(abi.encodePacked(dev3Node, keccak256("dev3")));
        //vm.prank(ENS.owner(_node));
        //ENS.setOwner(_node, _approver);
        //bytes memory _recordhash =
        //    hex"e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c";
        //vm.prank(_owner);
        //ccip2eth.setRecordhash(_node, _recordhash);

        (string memory _path, string memory _domain) = _encoded.Decode();
        bytes memory _request = abi.encodeWithSelector(iResolver.addr.selector, _node);
        bytes memory _calldata = abi.encodeWithSelector(Dev3.resolve.selector, _encoded, _request);
        string memory _recType = DEV3.jsonFile(_request);
        bytes32 _callhash = keccak256(_calldata);
        bytes32 _checkhash = keccak256(abi.encodePacked(address(DEV3), blockhash(block.number - 1), _callhash));
        string memory _gateway = "namesys-eth.github.io";
        string[] memory _urls = new string[](2);
        _urls[0] = "https://namesys-eth.github.io/.well-known/eth/dev3/address/60.json?{data}";
        _urls[1] = "https://dev3.namesys.xyz/.well-known/eth/dev3/address/60.json?{data}=retry";
        bytes memory _extradata =
            abi.encode(block.number - 1, _callhash, _checkhash, dev3Node, _gateway, string("address/60"));
        vm.expectRevert(
            abi.encodeWithSelector(
                iENSIP10.OffchainLookup.selector,
                address(DEV3),
                _urls,
                abi.encodePacked(uint16(block.timestamp / 60)),
                Dev3.__callback.selector,
                _extradata
            )
        );
        DEV3.resolve(_encoded, _request);

        bytes memory _result = abi.encode(address(type(uint160).max));
        bytes32 _approvalDigest = address(DEV3).GetApprovalDigest(_signer, "namesys-eth.github.io", chainID);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ApproverKey, _approvalDigest);
        bytes memory _approvalSig = abi.encodePacked(r, s, v);
        bytes32 _signerDigest = address(DEV3).GetRecordDigest(_signer, "namesys-eth.github.io", "address/60", _result, chainID);
        (v, r, s) = vm.sign(SignerKey, _signerDigest);
        bytes memory _recSig = abi.encodePacked(r, s, v);
        DEV3.setCoreApprover(dev3Node, _approver, true);
        bytes memory _response =
            abi.encodeWithSelector(iCallbackType.signedRecord.selector, _signer, _recSig, _approvalSig, _result);

        assertEq(DEV3.__callback(_response, _extradata), _result);
    }

    function testFlow() public {
        //vm.roll(1234);
        //vm.warp(12345678);
        bytes[] memory _name = new bytes[](3);
        _name[0] = "0xc0de4c0ffee";
        _name[1] = "dev3";
        _name[2] = "eth";
        (bytes32 _node, bytes memory _encoded) = Helper.Encode(_name);
        uint256 ApproverKey = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
        uint256 SignerKey = 0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc;
        address _approver = vm.addr(ApproverKey);
        address _signer = vm.addr(SignerKey);

        //vm.prank(ENS.owner(_node));
        //ENS.setOwner(_node, _owner);
        //bytes memory _recordhash =
        //    hex"e50101720024080112203c5aba6c9b5055a5fa12281c486188ed8ae2b6ef394b3d981b00d17a4b51735c";
        //vm.prank(_owner);
        //ccip2eth.setRecordhash(_node, _recordhash);

        (string memory _path, string memory _domain) = _encoded.Decode();
        bytes memory _request = abi.encodeWithSelector(iResolver.addr.selector, _node);
        bytes memory _calldata = abi.encodeWithSelector(Dev3.resolve.selector, _encoded, _request);
        string memory _recType = DEV3.jsonFile(_request);
        bytes32 _callhash = keccak256(_calldata);
        bytes32 _checkhash = keccak256(abi.encodePacked(address(DEV3), blockhash(block.number - 1), _callhash));
        string memory _gateway = "0xc0de4c0ffee.github.io";
        string[] memory _urls = new string[](2);
        _urls[0] = "https://0xc0de4c0ffee.github.io/.well-known/eth/dev3/0xc0de4c0ffee/address/60.json?{data}";
        _urls[1] =
            "https://raw.githubusercontent.com/0xc0de4c0ffee/0xc0de4c0ffee.github.io/main/.well-known/eth/dev3/0xc0de4c0ffee/address/60.json?{data}";

        bytes32 dev3Node = keccak256(abi.encodePacked(bytes32(0), keccak256("eth")));
        dev3Node = keccak256(abi.encodePacked(dev3Node, keccak256("dev3")));
        bytes memory _extradata =
            abi.encode(block.number - 1, _callhash, _checkhash, dev3Node, _gateway, string("address/60"));
        vm.expectRevert(
            abi.encodeWithSelector(
                iENSIP10.OffchainLookup.selector,
                address(DEV3),
                _urls,
                abi.encodePacked(uint16(block.timestamp / 60)),
                Dev3.__callback.selector,
                _extradata
            )
        );
        DEV3.resolve(_encoded, _request);
        bytes memory _result = abi.encode(address(type(uint160).max));
        bytes32 _approvalDigest = address(DEV3).GetApprovalDigest(_signer, "0xc0de4c0ffee.github.io", chainID);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ApproverKey, _approvalDigest);
        bytes memory _approvalSig = abi.encodePacked(r, s, v);
        bytes32 _signerDigest = address(DEV3).GetRecordDigest(_signer, "0xc0de4c0ffee.github.io", "address/60", _result, chainID);
        (v, r, s) = vm.sign(SignerKey, _signerDigest);
        bytes memory _recSig = abi.encodePacked(r, s, v);
        DEV3.setCoreApprover(dev3Node, _approver, true);
        bytes memory _response =
            abi.encodeWithSelector(iCallbackType.signedRecord.selector, _signer, _recSig, _approvalSig, _result);
        assertEq(DEV3.__callback(_response, _extradata), _result);
    }

    string public chainID = block.chainid == 1 ? "1" : "5";

    function testApproverSig() public {
        uint256 ApproverKey = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
        uint256 SignerKey = 0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc;
        address _approver = vm.addr(ApproverKey);
        address _signer = vm.addr(SignerKey);
        string memory _gateway = "namesys-eth.github.io";
        string memory _message = string.concat(
            "Requesting Signature To Approve ENS Records Signer\n",
            "\nGateway: https://",
            _gateway,
            "\nResolver: eip155:",
            chainID,
            ":",
            address(DEV3).toChecksumAddress(),
            "\nApproved Signer: eip155:",
            chainID,
            ":",
            _signer.toChecksumAddress()
        );
        bytes32 _digest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n", (bytes(_message).length).uintToString(), _message)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ApproverKey, _digest);
        bytes memory _signature = abi.encodePacked(r, s, v);
        assertEq(_approver, DEV3.getSigner(_message, _signature));
        _signature = abi.encodePacked(r, s, uint256(v));
        assertEq(_approver, DEV3.getSigner(_message, _signature));
        bytes32 vs = bytes32(uint256(v - 27) << 255) | s;
        _signature = abi.encodePacked(r, vs);
        assertEq(_approver, DEV3.getSigner(_message, _signature));
    }

    function testSignerSig() public {
        uint256 SignerKey = 0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc;
        address _signer = vm.addr(SignerKey);
        string memory _gateway = "namesys-eth.github.io";
        string memory _recType = "address/60";
        bytes memory _result = abi.encode(address(type(uint160).max));
        string memory _message = string.concat(
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
            );
        bytes32 _digest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n", (bytes(_message).length).uintToString(), _message)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SignerKey, _digest);
        bytes memory _signature = abi.encodePacked(r, s, v);
        assertEq(_signer, DEV3.getSigner(_message, _signature));
        _signature = abi.encodePacked(r, s, uint256(v));
        assertEq(_signer, DEV3.getSigner(_message, _signature));
        bytes32 vs = bytes32(uint256(v - 27) << 255) | s;
        _signature = abi.encodePacked(r, vs);
        assertEq(_signer, DEV3.getSigner(_message, _signature));
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
        assertEq(
            address(0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF).toChecksumAddress(),
            "0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF"
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
//0x7a819cebeb5ae713d09ffa208a16e9018d0b272122f86b6c0ab10e3d65a11431
/// @dev Utility functions

interface xENS is iENS {
    //function setResolver(bytes32 node, address resolver) external;
    function setOwner(bytes32 node, address owner) external;
}

library Helper {
    using Utils for *;

    function GetRecordDigest(
        address _resolver,
        address _signer,
        string memory _gateway,
        string memory _recType,
        bytes memory _result,
        string memory chainID
    ) public pure returns (bytes32 _digest) {
        //uint256 SignerKey = _privKey;
        //address _signer = vm.addr(SignerKey);
        string memory _recSig = string.concat(
                "Requesting Signature To Update ENS Record\n",
                "\nGateway: https://",
                _gateway,
                "\nResolver: eip155:",
                chainID,
                ":",
                address(_resolver).toChecksumAddress(),
                "\nRecord Type: ",
                _recType,
                "\nExtradata: 0x",
                abi.encodePacked(keccak256(_result)).bytesToHexString(),
                "\nSigned By: eip155:",
                chainID,
                ":",
                _signer.toChecksumAddress()
            );

        _digest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n", (bytes(_recSig).length).uintToString(), _recSig)
        );
        //(uint8 v, bytes32 r, bytes32 s) = vm.sign(SignerKey, _digest);
        //return abi.encodePacked(r, s, v);
    }
    function GetApprovalDigest(address _resolver, address _signer, string memory _gateway, string memory chainID)
        public
        pure
        returns (bytes32 _digest)
    {
        string memory _message = string.concat(
            "Requesting Signature To Approve ENS Records Signer\n",
            "\nGateway: https://",
            _gateway,
            "\nResolver: eip155:",
            chainID,
            ":",
            _resolver.toChecksumAddress(),
            "\nApproved Signer: eip155:",
            chainID,
            ":",
            _signer.toChecksumAddress()
        );
        _digest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n", (bytes(_message).length).uintToString(), _message)
        );
    }

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

    function Encode(bytes[] memory _names) external pure returns (bytes32 _namehash, bytes memory _name) {
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
