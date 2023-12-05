// SPDX-License-Identifier: WTFPL.ETH
pragma solidity >0.8.0 <0.9.0;

interface iERC165 {
    function supportsInterface(bytes4 interfaceID) external view returns (bool);
}

interface iERC173 {
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function owner() external view returns (address);
    function transferOwnership(address _newOwner) external payable;
}

interface iENS {
    function owner(bytes32 node) external view returns (address);
    function resolver(bytes32 node) external view returns (address);
    function ttl(bytes32 node) external view returns (uint64);
    function recordExists(bytes32 node) external view returns (bool);
    function isApprovedForAll(address owner, address operator) external view returns (bool);
}

interface iENSIP10 {
    error OffchainLookup(address _to, string[] _gateways, bytes _data, bytes4 _callbackFunction, bytes _extradata);

    function resolve(bytes memory _name, bytes memory _data) external view returns (bytes memory);
}

interface iIsDev is iENSIP10, iERC173 {
    function __callback(bytes calldata _response, bytes calldata _extraData)
        external
        view
        returns (bytes memory _result);

    function getSigner(string calldata _signRequest, bytes calldata _signature)
        external
        view
        returns (address _signer);
    function plaintext(bytes calldata _record) external view returns (bytes memory);
    function signed(address _signer, bytes calldata _recordSig, bytes calldata _record, bytes calldata _approvalSig)
        external
        view
        returns (bytes memory);
}

interface iResolver {
    function contenthash(bytes32 node) external view returns (bytes memory);
    function addr(bytes32 node) external view returns (address payable);
    function pubkey(bytes32 node) external view returns (bytes32 x, bytes32 y);
    function text(bytes32 node, string calldata key) external view returns (string memory value);
    function name(bytes32 node) external view returns (string memory);
    function ABI(bytes32 node, uint256 contentTypes) external view returns (uint256, bytes memory);
    function interfaceImplementer(bytes32 node, bytes4 interfaceID) external view returns (address);
    function recordVersions(bytes32 node) external view returns (uint64);
    function approved(bytes32 _node, address _signer) external view returns (bool);
}

interface iOverloadResolver {
    function addr(bytes32 node, uint256 coinType) external view returns (bytes memory);
}

interface iToken {
    function ownerOf(uint256 id) external view returns (address);
    function transferFrom(address from, address to, uint256 bal) external;
    function transfer(address to, uint256 bal) external;
    function balanceOf(address to) external view returns (uint256 bal);
    function safeTransferFrom(address from, address to, uint256 bal) external;
}

interface iCallbackType {
    function signedRecord(
        address recordSigner, // Manager OR On-Chain Manager OR Off-Chain Manager
        bytes memory recordSignature, // Signature from signer for result value
        bytes memory approvedSignature, // Signature to approve record signer
        bytes memory result // ABI-encoded result
    ) external pure returns (bytes memory);
    function plaintextRecord(
        bytes memory result // ABI-encoded result
    ) external pure returns (bytes memory);
}
