// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Script, console} from "forge-std/Script.sol";

import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";

import {HookMiner} from "v4-periphery/test/shared/HookMiner.sol";

import {AntiSandwichHook} from "../src/AntiSandwichHook.sol";

/// @title AntiSandwichHook deploy script
/// @author Mahesh aka ZKPExplorer
/// @notice Mines a CREATE2 salt that produces a hook address with exactly the
///         beforeSwap | afterSwap | afterSwapReturnDelta permission bits set, then deploys
///         `AntiSandwichHook` to that address via the canonical CREATE2 deployer proxy.
/// @dev Target: Polygon Amoy testnet (chainId 80002).
///
///      !!! ACTION REQUIRED BEFORE RUNNING !!!
///      `POOL_MANAGER` below is a placeholder and is NOT a verified Amoy PoolManager address.
///      Uniswap v4 addresses move around across deployments/testnets and are not hardcoded here
///      on purpose. Before running this script:
///        1. Look up the current, official Uniswap v4 `PoolManager` address for Polygon Amoy from
///           Uniswap's official deployments list (e.g. docs.uniswap.org / the v4-deploy-addresses
///           repo) - do not trust a random block explorer contract labeled "PoolManager".
///        2. Replace the placeholder below with that verified address.
///        3. Double-check it on Amoy's block explorer (verified source, matches v4-core's
///           `PoolManager` bytecode/ABI) before broadcasting with real funds.
contract AntiSandwichHookScript is Script {
    /// @dev PLACEHOLDER - replace with the verified Polygon Amoy PoolManager address. Do NOT run
    ///      this script against a mainnet or otherwise value-bearing chain with this left unset.
    address constant POOL_MANAGER = address(0); // <-- FILL IN AFTER VERIFYING, SEE NOTE ABOVE

    /// @dev Canonical, chain-agnostic CREATE2 deployer proxy (Arachnid's deterministic deployer),
    ///      present on essentially every EVM chain including Polygon Amoy. `HookMiner.find` mines
    ///      salts assuming this address is the deployer.
    address constant CREATE2_DEPLOYER = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

    function run() external returns (AntiSandwichHook hook) {
        require(POOL_MANAGER != address(0), "AntiSandwichHookScript: set POOL_MANAGER first, see comment above");

        // Exact permission bits this hook needs: beforeSwap, afterSwap, afterSwapReturnDelta.
        uint160 flags = uint160(
            Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG | Hooks.AFTER_SWAP_RETURNS_DELTA_FLAG
        );

        bytes memory constructorArgs = abi.encode(IPoolManager(POOL_MANAGER));
        (address predictedHookAddress, bytes32 salt) =
            HookMiner.find(CREATE2_DEPLOYER, flags, type(AntiSandwichHook).creationCode, constructorArgs);

        vm.startBroadcast();
        hook = new AntiSandwichHook{salt: salt}(IPoolManager(POOL_MANAGER));
        vm.stopBroadcast();

        require(address(hook) == predictedHookAddress, "AntiSandwichHookScript: hook address mismatch");

        console.log("AntiSandwichHook deployed at:", address(hook));
        console.log("Salt used:", vm.toString(salt));
    }
}
