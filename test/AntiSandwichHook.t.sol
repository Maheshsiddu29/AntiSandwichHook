// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";

import {Deployers} from "v4-core-test/utils/Deployers.sol";

import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {IHooks} from "v4-core/interfaces/IHooks.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {StateLibrary} from "v4-core/libraries/StateLibrary.sol";
import {FullMath} from "v4-core/libraries/FullMath.sol";
import {FixedPoint96} from "v4-core/libraries/FixedPoint96.sol";
import {PoolId} from "v4-core/types/PoolId.sol";
import {PoolKey} from "v4-core/types/PoolKey.sol";
import {ModifyLiquidityParams} from "v4-core/types/PoolOperation.sol";

import {HookMiner} from "v4-periphery/test/shared/HookMiner.sol";

import {AntiSandwichHook} from "../src/AntiSandwichHook.sol";

/// @title AntiSandwichHook tests
/// @author Mahesh aka ZKPExplorer
/// @notice Basic Foundry tests for `AntiSandwichHook`: a same-block sandwich signature gets
///         clawed back, same-direction / cross-block flow does not.
contract AntiSandwichHookTest is Test, Deployers {
    using StateLibrary for IPoolManager;

    // keccak256("SandwichClawback(bytes32,address,uint256,uint256,uint160,uint160)"), topic0 for the
    // hook's event (deviationBps, excessAmount, referenceSqrtPriceX96, postSwapSqrtPriceX96 are data).
    bytes32 constant SANDWICH_CLAWBACK_TOPIC0 =
        keccak256("SandwichClawback(bytes32,address,uint256,uint256,uint160,uint160)");

    // keccak256("Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)"), topic0 for
    // PoolManager's raw pre-hook-adjustment swap event (IPoolManager.sol).
    bytes32 constant SWAP_TOPIC0 = keccak256("Swap(bytes32,address,int128,int128,uint160,uint128,int24,uint24)");

    // keccak256("Donate(bytes32,address,uint256,uint256)"), topic0 for PoolManager's donate event.
    bytes32 constant DONATE_TOPIC0 = keccak256("Donate(bytes32,address,uint256,uint256)");

    uint256 constant BPS_DENOMINATOR = 10_000;
    uint256 constant DEVIATION_THRESHOLD_BPS = 100;
    uint256 constant MAX_CLAWBACK_BPS = 5_000;

    AntiSandwichHook hook;

    function setUp() public {
        // Deploys a fresh PoolManager + all the standard test routers (swap/donate/modifyLiquidity).
        deployFreshManagerAndRouters();
        // Deploys two mock ERC20s, sorts them into currency0/currency1, and approves every router.
        deployMintAndApprove2Currencies();

        // Mine a salt so the hook address's low bits encode exactly beforeSwap | afterSwap |
        // afterSwapReturnDelta, then deploy via CREATE2 at that address (mirrors what the real
        // deploy script does, just with `address(this)` as the deployer instead of the CREATE2
        // deployer proxy since the test contract deploys directly).
        uint160 flags =
            uint160(Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG | Hooks.AFTER_SWAP_RETURNS_DELTA_FLAG);
        bytes memory constructorArgs = abi.encode(manager);
        (address hookAddress, bytes32 salt) =
            HookMiner.find(address(this), flags, type(AntiSandwichHook).creationCode, constructorArgs);

        hook = new AntiSandwichHook{salt: salt}(IPoolManager(address(manager)));
        assertEq(address(hook), hookAddress, "hook not deployed to mined address");

        // Initialize a 0.3% pool at price 1:1 with the default narrow-range liquidity (ticks
        // -120..120, L=1e18)...
        (key,) = initPoolAndAddLiquidity(currency0, currency1, IHooks(address(hook)), 3000, SQRT_PRICE_1_1);

        // ...plus a wider position of *comparable* magnitude (not orders of magnitude deeper - that
        // would swamp any test-sized swap's price impact to ~0%). This keeps liquidity continuous
        // well past +-120 ticks so a large test swap moves price by tracking real liquidity the whole
        // way, instead of exhausting the narrow band and hitting a liquidity cliff.
        ModifyLiquidityParams memory wideParams =
            ModifyLiquidityParams({tickLower: -6_000, tickUpper: 6_000, liquidityDelta: 2e18, salt: 0});
        modifyLiquidityRouter.modifyLiquidity(key, wideParams, ZERO_BYTES);
    }

    /// @notice First swap in a block sets the reference and is never restricted, regardless of size.
    function test_firstSwap_neverClawedBack() public {
        Vm.Log[] memory logs = _swapAndCaptureLogs(true, -1e18);
        assertEq(_findClawbackAmount(logs), 0, "first swap must never be clawed back");
    }

    /// @notice Same-direction swaps in the same block (normal concurrent flow) are never clawed back.
    function test_sameDirection_sameBlock_notClawedBack() public {
        swap(key, true, -1e15, ZERO_BYTES); // first swap: sets the reference, direction zeroForOne
        Vm.Log[] memory logs = _swapAndCaptureLogs(true, -1e18); // same direction, later, same block
        assertEq(_findClawbackAmount(logs), 0, "same-direction swap must not be clawed back");
    }

    /// @notice Core scenario: first swap sets the reference, then a large opposite-direction swap in
    ///         the SAME block (the sandwich signature) deviates past threshold and gets clawed back,
    ///         with the excess donated back to the pool (LPs).
    function test_oppositeDirection_sameBlock_clawedBack() public {
        PoolId poolId = key.toId();

        // Tiny first swap: sets the reference block/price/direction without moving price much.
        swap(key, true, -1, ZERO_BYTES);

        (, uint256 feeGrowthGlobal1Before) = manager.getFeeGrowthGlobals(poolId);

        // Large opposite-direction swap in the SAME block: the back-run leg of a sandwich.
        Vm.Log[] memory logs = _swapAndCaptureLogsDirection(false, -5e17);

        uint256 excessAmount = _findClawbackAmount(logs);
        assertGt(excessAmount, 0, "opposite-direction deviation should have been clawed back");

        // The clawback must have been donated back into the pool (feeGrowthGlobal1 increases beyond
        // whatever the ordinary 0.3% swap fee alone would have contributed) rather than sitting with
        // the hook or the swapper.
        (, uint256 feeGrowthGlobal1After) = manager.getFeeGrowthGlobals(poolId);
        assertGt(feeGrowthGlobal1After, feeGrowthGlobal1Before, "clawback must be donated back to the pool");
    }

    /// @notice The reference resets every new block: an opposite-direction swap in a LATER block is
    ///         just that block's own (new) first swap, so it must never be clawed back.
    function test_oppositeDirection_nextBlock_notClawedBack() public {
        swap(key, true, -1, ZERO_BYTES); // block N: sets reference, direction zeroForOne

        vm.roll(block.number + 1); // advance to block N+1

        // Opposite direction, but now the FIRST swap of block N+1 -> establishes its own reference,
        // trivially "same direction as itself", so no restriction applies.
        Vm.Log[] memory logs = _swapAndCaptureLogsDirection(false, -5e17);
        assertEq(_findClawbackAmount(logs), 0, "new block must reset the reference - no clawback");
    }

    /// @notice THE test that proves the tick-aware upgrade did its job: a liquidity GAP (a tick range
    ///         with zero liquidity) sits between an inner and an outer position. A large
    ///         opposite-direction swap teleports through the gap for almost no input, which the OLD
    ///         linear model (execution price = |amount1|/|amount0| from the raw swap delta) would read
    ///         as barely any price movement, since the gap swallows most of the PRICE distance while
    ///         contributing almost none of the token AMOUNT the ratio is computed from. The NEW
    ///         tick-aware model measures deviation from the real post-swap sqrtPrice directly, so it
    ///         is not fooled by the free teleport. Assert new > old (computing "old" inline here from
    ///         the raw `Swap` event, exactly the formula the previous version of this hook used).
    function test_liquidityGap_tickAwareExceedsLinearModel() public {
        // A separate pool (distinct fee -> distinct poolId) with a deliberate liquidity GAP: an inner
        // position [-200, 200], nothing from 200 to 2000, then an outer position [2000, 8000].
        (PoolKey memory gapKey,) = initPool(currency0, currency1, IHooks(address(hook)), 10_000, SQRT_PRICE_1_1);
        modifyLiquidityRouter.modifyLiquidity(
            gapKey, ModifyLiquidityParams({tickLower: -200, tickUpper: 200, liquidityDelta: 1e18, salt: 0}), ZERO_BYTES
        );
        modifyLiquidityRouter.modifyLiquidity(
            gapKey,
            ModifyLiquidityParams({tickLower: 2000, tickUpper: 8000, liquidityDelta: 2e18, salt: 0}),
            ZERO_BYTES
        );

        swap(gapKey, true, -1, ZERO_BYTES); // tiny first swap: sets the reference near price 1:1

        (, uint160 referenceSqrtPriceX96,) = hook.blockReference(gapKey.toId());

        // Large opposite-direction swap: exhausts the inner position, teleports through the gap for
        // almost no input, then continues into the outer position.
        vm.recordLogs();
        swap(gapKey, false, -1e17, ZERO_BYTES);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        uint256 newExcess = _findClawbackAmount(logs);
        assertGt(newExcess, 0, "tick-aware model should have detected and clawed back the gap-teleport swap");

        (int128 rawAmount0, int128 rawAmount1) = _findSwapAmounts(logs);
        uint256 oldExcess =
            _oldLinearExcessAmount(referenceSqrtPriceX96, rawAmount0, rawAmount1, /* unspecifiedIsCurrency1 */ false);

        assertGt(
            newExcess,
            oldExcess,
            "tick-aware clawback must strictly exceed what the old linear (BalanceDelta-ratio) model would have taken"
        );
    }

    /// @notice Continuous-liquidity IDENTITY control: on a single constant-liquidity segment, the OLD
    ///         ratio-based deviation and the NEW price-space deviation relate by an EXACT closed form,
    ///         not a fuzzy approximation:
    ///
    ///             new_dev = (1 + old_dev)^2 - 1        (equivalently old_dev = sqrt(1 + new_dev) - 1)
    ///
    ///         WHY: over a single constant-liquidity segment, `amount1/amount0` for a swap from sqrtP0
    ///         to sqrtP1 is a standard CPMM identity -
    ///             amount1 = L*(sqrtP1 - sqrtP0),  amount0 = L*(1/sqrtP0 - 1/sqrtP1)
    ///             => amount1/amount0 = (sqrtP1-sqrtP0) / [(sqrtP1-sqrtP0)/(sqrtP0*sqrtP1)] = sqrtP0*sqrtP1
    ///         i.e. the OLD model's "execution price" is the GEOMETRIC MEAN of the start/end sqrtPrices.
    ///         Dividing by the reference price (sqrtP0^2) gives old_dev = sqrtP1/sqrtP0 - 1 - the OLD
    ///         model is measuring deviation in sqrtPrice space. The NEW model measures
    ///         new_dev = (sqrtP1/sqrtP0)^2 - 1 directly in price space. Substituting r = sqrtP1/sqrtP0:
    ///         old_dev = r-1, new_dev = r^2-1 = (1+old_dev)^2-1. Exact, no approximation on either side.
    ///
    ///         This is the complement to `test_liquidityGap_tickAwareExceedsLinearModel`: that test
    ///         shows a liquidity gap breaks this identity and lets old undercount without bound; THIS
    ///         test shows that without a gap, the tick-aware model reduces to exactly the correct
    ///         closed form - proving the upgrade didn't regress the single-segment case, it just
    ///         stopped silently halving (roughly) the deviation the old ratio-based model reported.
    function test_continuousLiquidity_identityHoldsOnSingleSegment() public {
        // A DEDICATED, FEE-FREE pool with ONE uniform liquidity position spanning the whole range the
        // swap will traverse - genuinely a single constant-liquidity segment (not the two-tier
        // narrow+wide `key` from setUp), which the identity above requires. Fee = 0 matters: the
        // identity is derived from the frictionless CPMM relationship amount1/amount0 = sqrtP0*sqrtP1;
        // a nonzero LP fee deducts from the input before that curve math runs, perturbing the exact
        // identity by roughly the fee's own magnitude (observed: ~144 bps of drift at a 0.5% fee tier,
        // which would swamp a tight rounding-only tolerance) - a real, separate effect from anything
        // this test is trying to isolate.
        (PoolKey memory uniformKey,) = initPool(currency0, currency1, IHooks(address(hook)), 0, 100, SQRT_PRICE_1_1);
        modifyLiquidityRouter.modifyLiquidity(
            uniformKey,
            ModifyLiquidityParams({tickLower: -10_000, tickUpper: 10_000, liquidityDelta: 1e18, salt: 0}),
            ZERO_BYTES
        );

        swap(uniformKey, true, -1, ZERO_BYTES); // tiny first swap: sets the reference

        // Opposite-direction swap, clearly past threshold, staying well inside the single position
        // (capacity to the tick-10_000 edge is ~6.5e17 at this liquidity; 2e17 lands around tick
        // ~3_600, comfortably short of it) so it never crosses into a different liquidity regime.
        // Log recording starts here (not before the first swap too) so `_findSwapAmounts` below picks
        // up THIS swap's raw `Swap` event, not the tiny reference-setting one's.
        vm.recordLogs();
        swap(uniformKey, false, -2e17, ZERO_BYTES);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        (bool found, uint256 newDevBps, uint256 excessAmount, uint160 referenceSqrtPriceX96,) =
            _findClawbackEvent(logs);
        assertTrue(found, "expected a clawback to fire in the identity control case");
        assertGt(excessAmount, 0);

        // Independently reconstruct the OLD model's deviation from the RAW pre-hook `Swap` event
        // amounts (via `_findSwapAmounts`) - deliberately NOT from sqrtPrices (that would make the
        // identity a tautology - it would just be re-deriving new_dev from itself) and NOT from the
        // swap router's RETURNED BalanceDelta (that value is already net of this same clawback, since
        // it is what the trader actually settles for post-hook - reconstructing "old" from it would
        // contaminate the comparison with the very effect being cross-checked). The raw `Swap` event
        // amounts are exactly what the pre-upgrade hook's `_afterSwap(..., BalanceDelta delta, ...)`
        // parameter contained, so this is a like-for-like reproduction of the old computation.
        (int128 rawAmount0, int128 rawAmount1) = _findSwapAmounts(logs);
        (,, uint256 oldDevBps) = _oldDeviationBpsFromDelta(referenceSqrtPriceX96, rawAmount0, rawAmount1);
        assertGt(oldDevBps, DEVIATION_THRESHOLD_BPS, "sanity: old model should also see this as past-threshold");

        // The identity, in integer bps: new_bps = 2*old_bps + old_bps^2 / 10_000.
        uint256 predictedNewDevBps = 2 * oldDevBps + FullMath.mulDiv(oldDevBps, oldDevBps, BPS_DENOMINATOR);

        assertApproxEqAbs(
            newDevBps,
            predictedNewDevBps,
            10, // bps - rounding-only tolerance; this is a near-exact analytical oracle, not a fuzzy bound
            "new-model deviation must match the exact (1+old)^2-1 identity on a single constant-liquidity segment"
        );
    }

    /// @notice The 50%-of-output solvency cap binds under an extreme deviation, and the amount
    ///         actually donated to the pool matches the emitted (capped) clawback amount EXACTLY -
    ///         proving the hook never donates a different number than the one it reports/takes.
    function test_capBinds_donatedMatchesEmittedExactly() public {
        // A shallow-but-WIDE pool: shallow enough that a modest input pushes price deep into
        // cap-binding territory (>51% deviation - needed since excessBps = deviationBps - 100 must
        // exceed the 5000 bps cap), but wide enough that (a) the swap does not exhaust ALL liquidity
        // and teleport to MAX_SQRT_PRICE (which would zero out post-swap liquidity and, combined with
        // the bounded tick walk, make the tick-aware estimate collapse to an under-estimating 0 - a
        // real, documented limitation, just not the scenario this test wants), and (b) the post-swap
        // tick stays within MAX_TICK_CROSS_ITERATIONS * tickSpacing of the reference tick, so the walk
        // actually reaches the threshold instead of exhausting its budget in the empty void beyond.
        (PoolKey memory shallowKey,) = initPool(currency0, currency1, IHooks(address(hook)), 100, 60, SQRT_PRICE_1_1);
        modifyLiquidityRouter.modifyLiquidity(
            shallowKey,
            ModifyLiquidityParams({tickLower: -6_000, tickUpper: 6_000, liquidityDelta: 1e15, salt: 0}),
            ZERO_BYTES
        );

        swap(shallowKey, true, -1, ZERO_BYTES); // tiny first swap: sets the reference

        vm.recordLogs();
        swap(shallowKey, false, -260_000_000_000_000, ZERO_BYTES); // pushes ~55-60% past reference, well past the cap
        Vm.Log[] memory logs = vm.getRecordedLogs();

        uint256 excessAmount = _findClawbackAmount(logs);
        assertGt(excessAmount, 0, "expected a clawback in the cap-binding scenario");

        (int128 rawAmount0,) = _findSwapAmounts(logs);
        uint256 unspecifiedAmountAbs = uint256(uint128(rawAmount0 < 0 ? -rawAmount0 : rawAmount0));
        uint256 expectedCap = FullMath.mulDiv(unspecifiedAmountAbs, MAX_CLAWBACK_BPS, BPS_DENOMINATOR);
        assertEq(excessAmount, expectedCap, "cap should bind exactly at MAX_CLAWBACK_BPS of the adjustable leg");

        uint256 donatedAmount0 = _findDonateAmount0(logs);
        assertEq(donatedAmount0, excessAmount, "donated amount must exactly equal the emitted (capped) clawback");
    }

    // -----------------------------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------------------------

    function _swapAndCaptureLogs(bool zeroForOne, int256 amountSpecified) internal returns (Vm.Log[] memory logs) {
        return _swapAndCaptureLogsDirection(zeroForOne, amountSpecified);
    }

    function _swapAndCaptureLogsDirection(bool zeroForOne, int256 amountSpecified)
        internal
        returns (Vm.Log[] memory logs)
    {
        vm.recordLogs();
        swap(key, zeroForOne, amountSpecified, ZERO_BYTES);
        logs = vm.getRecordedLogs();
    }

    /// @notice Scans recorded logs for a `SandwichClawback` event and returns its `excessAmount`
    ///         (0 if none was emitted).
    function _findClawbackAmount(Vm.Log[] memory logs) internal pure returns (uint256 excessAmount) {
        (,, excessAmount,,) = _findClawbackEvent(logs);
    }

    /// @notice Scans recorded logs for a `SandwichClawback` event and decodes all of its fields.
    ///         `found` is false (all other return values zero) if no such event was emitted.
    function _findClawbackEvent(Vm.Log[] memory logs)
        internal
        pure
        returns (
            bool found,
            uint256 deviationBps,
            uint256 excessAmount,
            uint160 referenceSqrtPriceX96,
            uint160 postSwapSqrtPriceX96
        )
    {
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length > 0 && logs[i].topics[0] == SANDWICH_CLAWBACK_TOPIC0) {
                (deviationBps, excessAmount, referenceSqrtPriceX96, postSwapSqrtPriceX96) =
                    abi.decode(logs[i].data, (uint256, uint256, uint160, uint160));
                return (true, deviationBps, excessAmount, referenceSqrtPriceX96, postSwapSqrtPriceX96);
            }
        }
    }

    /// @notice Scans recorded logs for PoolManager's raw `Swap` event and returns its (pre-hook,
    ///         pre-clawback) `amount0`/`amount1` - the same raw values the OLD linear model consumed.
    function _findSwapAmounts(Vm.Log[] memory logs) internal pure returns (int128 amount0, int128 amount1) {
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length > 0 && logs[i].topics[0] == SWAP_TOPIC0) {
                (amount0, amount1,,,,) = abi.decode(logs[i].data, (int128, int128, uint160, uint128, int24, uint24));
                return (amount0, amount1);
            }
        }
        revert("Swap event not found");
    }

    /// @notice Scans recorded logs for PoolManager's `Donate` event and returns its `amount0`.
    function _findDonateAmount0(Vm.Log[] memory logs) internal pure returns (uint256 amount0) {
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length > 0 && logs[i].topics[0] == DONATE_TOPIC0) {
                (amount0,) = abi.decode(logs[i].data, (uint256, uint256));
                return amount0;
            }
        }
        revert("Donate event not found");
    }

    /// @notice Reproduces the OLD (pre-upgrade) ratio-based deviation calculation from the RAW
    ///         pre-hook `Swap` event amounts: execution price = |amount1|/|amount0| (Q96, "price of
    ///         token1 per token0" - direction-agnostic since both amounts are taken as absolute
    ///         values), compared against the block's referenceSqrtPriceX96 squared into the same
    ///         units. This is exactly what the pre-upgrade hook computed internally from its
    ///         `_afterSwap(..., BalanceDelta delta, ...)` parameter, which is why callers must pass
    ///         the RAW pre-hook `Swap` event amounts (via `_findSwapAmounts`) rather than the swap
    ///         router's returned (post-hook, post-clawback) BalanceDelta - see callers for why.
    function _oldDeviationBpsFromDelta(uint160 referenceSqrtPriceX96, int128 rawAmount0, int128 rawAmount1)
        internal
        pure
        returns (uint256 amount0Abs, uint256 amount1Abs, uint256 deviationBps)
    {
        amount0Abs = uint256(uint128(rawAmount0 < 0 ? -rawAmount0 : rawAmount0));
        amount1Abs = uint256(uint128(rawAmount1 < 0 ? -rawAmount1 : rawAmount1));
        if (amount0Abs == 0) return (amount0Abs, amount1Abs, 0);

        uint256 executionPriceX96 = FullMath.mulDiv(amount1Abs, FixedPoint96.Q96, amount0Abs);
        uint256 referencePriceX96 =
            FullMath.mulDiv(uint256(referenceSqrtPriceX96), uint256(referenceSqrtPriceX96), FixedPoint96.Q96);

        uint256 diff = executionPriceX96 > referencePriceX96
            ? executionPriceX96 - referencePriceX96
            : referencePriceX96 - executionPriceX96;
        deviationBps = FullMath.mulDiv(diff, BPS_DENOMINATOR, referencePriceX96);
    }

    /// @notice Reproduces the OLD (pre-upgrade) linear clawback formula exactly, from the raw `Swap`
    ///         event amounts: `_oldDeviationBpsFromDelta`'s deviation, then a linear penalty above
    ///         threshold, same cap. Used only to compute a comparison value in tests - the hook itself
    ///         no longer contains this code path.
    function _oldLinearExcessAmount(
        uint160 referenceSqrtPriceX96,
        int128 rawAmount0,
        int128 rawAmount1,
        bool unspecifiedIsCurrency1
    ) internal pure returns (uint256) {
        (uint256 amount0Abs, uint256 amount1Abs, uint256 deviationBps) =
            _oldDeviationBpsFromDelta(referenceSqrtPriceX96, rawAmount0, rawAmount1);
        if (deviationBps <= DEVIATION_THRESHOLD_BPS) return 0;

        uint256 unspecifiedAmountAbs = unspecifiedIsCurrency1 ? amount1Abs : amount0Abs;
        uint256 excessBps = deviationBps - DEVIATION_THRESHOLD_BPS;
        uint256 rawExcess = FullMath.mulDiv(unspecifiedAmountAbs, excessBps, BPS_DENOMINATOR);

        uint256 cap = FullMath.mulDiv(unspecifiedAmountAbs, MAX_CLAWBACK_BPS, BPS_DENOMINATOR);
        uint256 capped = rawExcess > cap ? cap : rawExcess;
        if (capped > unspecifiedAmountAbs) capped = unspecifiedAmountAbs;
        return capped;
    }
}
