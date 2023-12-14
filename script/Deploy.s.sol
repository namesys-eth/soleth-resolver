// SPDX-License-Identifier: WTFPL.ETH
pragma solidity >0.8.0 <0.9.0;

import "forge-std/Script.sol";
import "src/Dev3.sol";

contract CCIP2ETHDeploy is Script {
    function run() external {
        vm.startBroadcast();
        new Dev3();
        vm.stopBroadcast();
    }
}
