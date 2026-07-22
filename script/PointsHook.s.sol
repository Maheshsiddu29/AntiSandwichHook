// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.8.26;

import {Script} from "forge-std/Script.sol";
import {PointsHook} from "../src/PointsHook.sol";

contract PointsHookScript is Script {
    function run() external {
        vm.startBroadcast();
        // new PointsHook(IPoolManager(0x)); // Replace with the actual PoolManager address
        vm.stopBroadcast();
    }
}