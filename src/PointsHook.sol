// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;
 
import {BaseHook} from "v4-hooks-public/src/base/BaseHook.sol";

import {ERC1155} from "solmate/src/tokens/ERC1155.sol";

import {PoolKey} from "v4-core/types/PoolKey.sol";
import {PoolId} from "v4-core/types/PoolId.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";
import {SwapParams} from "v4-core/types/PoolOperation.sol";
 
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
 
import {Hooks} from "v4-core/libraries/Hooks.sol";


contract PointsHook is BaseHook, ERC1155 {

    constructor(IPoolManager _manager) BaseHook(_manager) {
        // ..
    }
 
	// Set up hook permissions to return `true`
	// for the two hook functions we are using
    function getHookPermissions()
        public
        pure
        override
        returns (Hooks.Permissions memory)
    {
        return
            Hooks.Permissions({
                beforeInitialize: false,
                afterInitialize: false,
                beforeAddLiquidity: false,
                beforeRemoveLiquidity: false,
                afterAddLiquidity: false,
                afterRemoveLiquidity: false,
                beforeSwap: false,
                afterSwap: true,
                beforeDonate: false,
                afterDonate: false,
                beforeSwapReturnDelta: false,
                afterSwapReturnDelta: false,
                afterAddLiquidityReturnDelta: false,
                afterRemoveLiquidityReturnDelta: false
            });
    }
 
    // Implement the ERC1155 `uri` function
    function uri(uint256) public view virtual override returns (string memory) {
        return "https://api.example.com/token/{id}";
    }
 
	// Stub implementation of `afterSwap`
    // 1. Make sure this is an ETH - TOKEN pool
    // 2. Make sure this swap is to buy TOKEN in exchange for ETH
    // 3. Mint points equal to 20% of the amount of ETH being swapped in
	function _afterSwap(
        address,
        PoolKey calldata key,
        SwapParams calldata swapParams,
        BalanceDelta delta,
        bytes calldata hookData
    ) internal override returns (bytes4, int128) {
        // Validate that this is an ETH / TOKEN pool
        if (!key.currency0.isAddressZero()) {
            return (this.afterSwap.selector, 0);
        }

        // Validate that the currency1 is TOKEN
        // TODO: Currently don't have TOKEN address.

        // We only mint points if the user is buying TOKEN with ETH
        if (!swapParams.zeroForOne) {
            return (this.afterSwap.selector, 0);
        }

        // Mint points equal to 20% of the amount of ETH they spent.
        // Since we know it's a zeroForOne swap:
        // if amountSpecified < 0:
        //    this is an exact input for output
        //    amount of ETH they spent is equal to `amountSpecified`
        // if amountSpecified > 0:
        //    this is exact output for input
        //    the amount of ETH they spent is equal to BalanceDelta.amount0()

        uint256 ethSpendAmount = uint256(int256(-delta.amount0()));
        uint256 pointsForSwap = ethSpendAmount / 5;

        // Mint the points being assigned
        _assignPoints(key.toId(), hookData, pointsForSwap);

		// We'll add more code here shortly
		return (this.afterSwap.selector, 0);
    }

    function _assignPoints(
        PoolId poolId,  // bytes32
        bytes calldata hookData,
        uint256 points
    ) internal {
        // If no hookData is passed in, no points will be assign to the user
        if (hookData.length == 0) return;

        // Extract the user address from the hookData
        address user = abi.decode(hookData, (address));

        // If there is hookData but not in the format that we're looking for, or set to the
        // zero address, then nobody gets any points
        if (user == address(0)) return;

        // Mint the points to the user
        uint256 poolIdUint = uint256(PoolId.unwrap(poolId));
        _mint(user, poolIdUint, points, '');
    }
}