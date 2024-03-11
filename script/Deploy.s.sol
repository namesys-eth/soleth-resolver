// SPDX-License-Identifier: WTFPL.ETH
pragma solidity >0.8.0 <0.9.0;

import "forge-std/Script.sol";
import "src/SolanaNameResolver.sol";

/**
 * @title - dev3.eth : Deployer
 * @author - sshmatrix.eth, freetib.eth
 * @notice - https://dev3.eth.limo
 * https://github.com/namesys-eth/dev3-eth-resolver
 */
contract SolanaNameResolverDeploy is Script {
    function run() external {
        vm.startBroadcast();
        new SolanaNameResolver();
        vm.stopBroadcast();
    }
}
