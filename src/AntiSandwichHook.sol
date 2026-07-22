// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {BaseHook} from "v4-hooks-public/src/base/BaseHook.sol";

import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {Hooks} from "v4-core/libraries/Hooks.sol";
import {StateLibrary} from "v4-core/libraries/StateLibrary.sol";
import {FullMath} from "v4-core/libraries/FullMath.sol";
import {FixedPoint96} from "v4-core/libraries/FixedPoint96.sol";
import {TickMath} from "v4-core/libraries/TickMath.sol";
import {SqrtPriceMath} from "v4-core/libraries/SqrtPriceMath.sol";

import {PoolKey} from "v4-core/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/types/PoolId.sol";
import {BalanceDelta} from "v4-core/types/BalanceDelta.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "v4-core/types/BeforeSwapDelta.sol";
import {SwapParams} from "v4-core/types/PoolOperation.sol";

/// @title AntiSandwichHook
/// @author Mahesh aka ZKPExplorer
/// @notice A Uniswap v4 hook that makes sandwich attacks unprofitable by clawing back the value a
///         same-block, opposite-direction trade extracts through intra-block price manipulation,
///         and redirecting that clawback back into the pool for liquidity providers.
/// @dev DESIGN PHILOSOPHY
///      This hook does NOT try to hide swaps from the mempool or prevent reordering - that is a
///      mempool/proposer-level problem that a smart-contract hook has no visibility into. Instead,
///      it corrects the *economic outcome* at settlement time: if a swap in the same block reverses
///      the direction of that block's first swap and, in doing so, pushes execution price far enough
///      away from the block-opening reference price, the excess value is clawed back from that swap
///      and donated back to the pool (i.e. to LPs pro-rata) instead of being extracted by the attacker.
///
///      VERSION-SPECIFIC INTERFACE NOTES (resolved by reading the installed lib/ sources directly,
///      NOT from memory - see lib/v4-hooks-public/{src,lib/v4-core/src} at the commit vendored here):
///        - `BaseHook` (lib/v4-hooks-public/src/base/BaseHook.sol) exposes `_beforeSwap` /
///          `_afterSwap` as the internal overridable hooks (not `beforeSwap`/`afterSwap` themselves -
///          those are the external, `onlyPoolManager`-gated entry points implemented by BaseHook that
///          delegate to the internal `_*` functions we override here).
///        - `_beforeSwap` returns `(bytes4, BeforeSwapDelta, uint24)` - a selector, a packed
///          before-swap delta (specified/unspecified amounts), and an LP fee override.
///        - `_afterSwap` returns `(bytes4, int128)` - a selector and a single `int128` delta,
///          denominated in the swap's "unspecified" currency (see `_isUnspecifiedCurrency1` below).
///          Returning a non-zero value here requires the `afterSwapReturnDelta` permission flag.
///        - Current pool price is read via `StateLibrary.getSlot0(manager, poolId)`
///          (lib/v4-core/src/libraries/StateLibrary.sol), which does a raw `extsload` of the
///          packed `Slot0` word and returns `(sqrtPriceX96, tick, protocolFee, lpFee)`. This replaces
///          older patterns that read `slot0` via a dedicated public getter on PoolManager itself.
///        - `SwapParams` and `ModifyLiquidityParams` now live in `v4-core/types/PoolOperation.sol`
///          (not inline in `IPoolManager`).
///        - `SqrtPriceMath.getAmount0Delta` / `getAmount1Delta` take
///          `(uint160 sqrtPriceAX96, uint160 sqrtPriceBX96, uint128 liquidity, bool roundUp)` and
///          return `uint256`; `TickMath.getSqrtPriceAtTick(int24)` / `getTickAtSqrtPrice(uint160)`
///          and `TickMath.MIN_TICK` / `MAX_TICK` are unchanged from their well-known v3/v4 shape.
///          `StateLibrary.getLiquidity(manager, poolId)` returns the pool's current active `uint128`
///          liquidity; `getTickLiquidity(manager, poolId, tick)` returns
///          `(uint128 liquidityGross, int128 liquidityNet)` for a given tick. All of these matched
///          what was assumed going in - re-read directly from lib/ to confirm before use, not memory.
///        - A hook only has `StateLibrary`'s `extsload`-based getters, not direct access to the
///          pool's internal `mapping(int16 => uint256) tickBitmap` storage, so it cannot call
///          `TickBitmap.nextInitializedTickWithinOneWord` to binary-search for the next
///          *initialized* tick the way `Pool.swap` does internally. `_sumAmountAcrossExcessBand`
///          below instead walks every tickSpacing-aligned tick in fixed steps; querying
///          `getTickLiquidity` on an uninitialized tick simply returns `liquidityNet = 0` (a no-op),
///          so this is correct, just potentially more loop iterations than a bitmap search would
///          need - exactly what `MAX_TICK_CROSS_ITERATIONS` bounds.
contract AntiSandwichHook is BaseHook {
    using StateLibrary for IPoolManager;
    using PoolIdLibrary for PoolKey;

    // ---------------------------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------------------------

    /// @notice Basis-point denominator (10_000 = 100%).
    uint256 internal constant BPS_DENOMINATOR = 10_000;

    /// @notice Deviation threshold above which a same-block, opposite-direction swap is treated as
    ///         the back-leg of a sandwich. Starts at 1% (100 bps) per spec; tune with real data.
    uint256 public constant DEVIATION_THRESHOLD_BPS = 100;

    /// @notice Solvency/UX safety cap: never claw back more than this fraction of the swap's own
    ///         adjustable ("unspecified") leg, no matter how large the measured deviation is. This
    ///         guarantees the trader always keeps at least (100% - this) of their own proceeds and
    ///         that the hook can never create a debt it cannot cover out of the swap itself.
    uint256 public constant MAX_CLAWBACK_BPS = 5_000; // 50%

    /// @notice Hard cap on how many tickSpacing-aligned ticks `_sumAmountAcrossExcessBand` will walk
    ///         while pricing the excess band. Bounds worst-case gas regardless of how far price moved
    ///         or how sparse liquidity is. If hit, the function returns whatever it accumulated so far
    ///         - a safe UNDER-estimate, never an over-estimate (see function docs).
    uint256 public constant MAX_TICK_CROSS_ITERATIONS = 100;

    // ---------------------------------------------------------------------------------------
    // State
    // ---------------------------------------------------------------------------------------

    /// @notice Per-pool record of the current block's reference swap.
    /// @dev Reset implicitly every new block: `_beforeSwap` overwrites the whole struct whenever
    ///      `block.number != referenceBlock`, so there is no explicit "reset" step required.
    struct BlockReference {
        /// @notice The block number this reference was captured in.
        uint256 referenceBlock;
        /// @notice The pool's sqrtPriceX96 immediately before the block's first swap executed.
        uint160 referenceSqrtPriceX96;
        /// @notice The direction (`zeroForOne`) of the block's first swap.
        bool referenceZeroForOne;
    }

    /// @notice poolId => this block's reference price/direction.
    mapping(PoolId => BlockReference) public blockReference;

    // ---------------------------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------------------------

    /// @notice Emitted whenever a same-block, opposite-direction swap is clawed back.
    /// @param poolId The pool the swap occurred in.
    /// @param sender The address that initiated the swap (as seen by the hook / PoolManager).
    /// @param deviationBps The measured deviation of the real post-swap price from the block's
    ///        reference price, in basis points (price space, i.e. `postPrice/referencePrice - 1`,
    ///        NOT a sqrtPrice-space ratio - see `_deviationBps`).
    /// @param excessAmount The amount clawed back and donated to the pool, denominated in the
    ///        swap's unspecified currency.
    /// @param referenceSqrtPriceX96 The block's first-swap reference sqrtPrice this was measured
    ///        against - real on-chain telemetry, useful for monitoring/auditing without needing to
    ///        separately query `blockReference` at the right block.
    /// @param postSwapSqrtPriceX96 The pool's sqrtPrice read fresh in `_afterSwap`, i.e. the real
    ///        settlement endpoint this swap's deviation was measured against.
    event SandwichClawback(
        PoolId indexed poolId,
        address indexed sender,
        uint256 deviationBps,
        uint256 excessAmount,
        uint160 referenceSqrtPriceX96,
        uint160 postSwapSqrtPriceX96
    );

    /// @param _poolManager The Uniswap v4 PoolManager this hook is deployed against.
    constructor(IPoolManager _poolManager) BaseHook(_poolManager) {}

    // ---------------------------------------------------------------------------------------
    // Hook permissions
    // ---------------------------------------------------------------------------------------

    /// @inheritdoc BaseHook
    /// @dev Only `beforeSwap`, `afterSwap`, and `afterSwapReturnDelta` are enabled - everything
    ///      else (liquidity hooks, donate hooks, initialize hooks, beforeSwapReturnDelta) is off.
    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: false,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: true,
            afterSwap: true,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: true,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    // ---------------------------------------------------------------------------------------
    // beforeSwap: establish / preserve this block's reference
    // ---------------------------------------------------------------------------------------

    /// @notice Records the block's reference price and direction on the first swap seen this block;
    ///         leaves the reference untouched for every subsequent swap in the same block.
    /// @dev Never applies any restriction here - the block's first swap always executes freely.
    ///      All clawback logic happens in `_afterSwap`, once we know the realized execution price.
    function _beforeSwap(address, PoolKey calldata key, SwapParams calldata params, bytes calldata)
        internal
        override
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        PoolId poolId = key.toId();

        if (block.number != blockReference[poolId].referenceBlock) {
            // First swap this block for this pool: capture the pre-swap price as the reference,
            // along with this swap's direction and the current block number.
            blockReference[poolId] = BlockReference({
                referenceBlock: block.number,
                referenceSqrtPriceX96: _getCurrentPrice(poolId),
                referenceZeroForOne: params.zeroForOne
            });
        }
        // Else: a later swap in the same block. Leave the reference untouched - it must keep
        // pointing at the block-opening price for the whole block, not the latest intermediate one.

        // No-op return: zero delta adjustment, no LP fee override.
        return (this.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }

    // ---------------------------------------------------------------------------------------
    // afterSwap: detect + claw back the sandwich signature
    // ---------------------------------------------------------------------------------------

    /// @notice Claws back excess value from same-block, opposite-direction swaps that deviate too
    ///         far from the block's reference price, and donates the clawback back to the pool.
    /// @dev Sign/return-slot convention: the `int128` this function returns is interpreted by
    ///      `Hooks.afterSwap` (v4-core) as a delta in the swap's *unspecified* currency - i.e. the
    ///      currency not fixed by `amountSpecified` (the output currency for exact-input swaps, the
    ///      input currency for exact-output swaps). A positive value here reduces what the pool pays
    ///      out (or increases what it collects) on that leg by exactly that amount, and credits this
    ///      hook contract with the same amount inside the PoolManager's transient accounting. We then
    ///      immediately re-donate that exact amount back into the pool via `poolManager.donate`, which
    ///      nets the hook's credit back to zero (no token ever leaves the PoolManager) while crediting
    ///      current in-range LPs through `feeGrowthGlobal` - i.e. the clawback is redirected to LPs,
    ///      never captured by the hook itself.
    function _afterSwap(address, PoolKey calldata key, SwapParams calldata params, BalanceDelta delta, bytes calldata)
        internal
        override
        returns (bytes4, int128)
    {
        PoolId poolId = key.toId();
        BlockReference memory ref = blockReference[poolId];

        // Defensive: `_beforeSwap` always runs first and stamps `referenceBlock = block.number` for
        // every swap, so this should be unreachable in practice. Fail safe (no clawback) rather than
        // revert if it's ever false, so a hook bug can never brick a swap.
        if (ref.referenceBlock != block.number) {
            return (this.afterSwap.selector, 0);
        }

        // Same direction as the block's reference swap. This single check covers BOTH:
        //   (a) the block's first swap itself - `_beforeSwap` just set
        //       `referenceZeroForOne = params.zeroForOne` for THIS swap, so the equality holds
        //       trivially - and
        //   (b) later same-direction swaps, i.e. normal concurrent flow following the same trend.
        // Neither is the sandwich signature, so no restriction applies.
        if (params.zeroForOne == ref.referenceZeroForOne) {
            return (this.afterSwap.selector, 0);
        }

        // Opposite direction within the same reference block: this is the sandwich signature
        // (the "back-run" leg reversing the block's opening trade). Measure how far it pushed
        // execution price away from the block-opening reference.
        uint256 unspecifiedAmountAbs = _unspecifiedAmountAbs(params, delta);
        if (unspecifiedAmountAbs == 0) {
            // Degenerate swap (e.g. zero output) - nothing to claw back from.
            return (this.afterSwap.selector, 0);
        }

        // Fresh, POST-swap price read - `Pool.swap` has already executed by the time `_afterSwap`
        // runs, so this is the real settlement endpoint of the price move, not an approximation of
        // it. This replaces the old BalanceDelta-ratio-derived "execution price", which understated
        // deviation whenever the swap crossed low-/zero-liquidity ticks (see contract header).
        uint160 postSqrtPriceX96 = _getCurrentPrice(poolId);
        uint256 deviationBps = _deviationBps(ref.referenceSqrtPriceX96, postSqrtPriceX96);

        if (deviationBps <= DEVIATION_THRESHOLD_BPS) {
            // Within tolerance - ordinary two-sided flow / normal price impact, not a sandwich.
            return (this.afterSwap.selector, 0);
        }

        bool unspecifiedIsCurrency1 = _isUnspecifiedCurrency1(params);
        int128 excessAmount = _computeExcessAmount(
            poolId, key.tickSpacing, unspecifiedIsCurrency1, ref.referenceSqrtPriceX96, postSqrtPriceX96, unspecifiedAmountAbs
        );
        if (excessAmount == 0) {
            return (this.afterSwap.selector, 0);
        }

        // Redirect the clawback into the pool for LPs instead of letting the hook (or anyone else)
        // capture it.
        _donateToPool(key, params, excessAmount);

        emit SandwichClawback(
            poolId, tx.origin, deviationBps, uint256(uint128(excessAmount)), ref.referenceSqrtPriceX96, postSqrtPriceX96
        );

        return (this.afterSwap.selector, excessAmount);
    }

    // ---------------------------------------------------------------------------------------
    // Price read - isolated so it can be swapped for precise tick-math later
    // ---------------------------------------------------------------------------------------

    /// @notice Reads the pool's current sqrtPriceX96.
    /// @dev APPROXIMATION BOUNDARY: this reads the pool's raw spot price via `StateLibrary.getSlot0`
    ///      (an `extsload` of the packed `Slot0` word - see version notes at the top of this file).
    ///      It is intentionally the *only* place that touches live pool price state, so it can later
    ///      be swapped for a more precise / manipulation-resistant source (e.g. a TWAP oracle, or
    ///      tick-boundary-aware pricing) without touching any control flow in `_beforeSwap`.
    function _getCurrentPrice(PoolId poolId) internal view returns (uint160 sqrtPriceX96) {
        (sqrtPriceX96,,,) = poolManager.getSlot0(poolId);
    }

    // ---------------------------------------------------------------------------------------
    // Tick-aware price-deviation + excess-amount computation
    // ---------------------------------------------------------------------------------------
    //
    // Upgrade note: the previous version derived "execution price" linearly from the swap's
    // BalanceDelta (|amount1| / |amount0|) and applied a flat linear penalty to the output amount.
    // That understated deviation whenever a swap crossed low-/zero-liquidity ticks, because price can
    // "teleport" across such ticks while consuming almost no input - exactly the large, manipulative
    // swaps this hook most needs to catch. This version instead:
    //   1. measures deviation directly in PRICE space from two sqrtPrices (reference vs. real
    //      post-swap price - `_deviationBps`), and
    //   2. prices the portion of the move beyond the threshold ("the excess band") against the
    //      REAL per-tick liquidity via `SqrtPriceMath`, not a flat ratio (`_computeExcessAmount` /
    //      `_sumAmountAcrossExcessBand`).
    //
    // REMAINING LIMITATIONS (honest accounting - this is tick-AWARE, not tick-EXACT):
    //   - It does not re-simulate `Pool.swap`'s inner loop. In particular it does not model
    //     fee-on-input or protocol-fee effects on the amounts inside the excess band; it prices the
    //     raw `SqrtPriceMath` amount for the price move only. A fully exact version would replicate
    //     the swap engine step-for-step (including fee deduction per step).
    //   - `_sumAmountAcrossExcessBand` walks every tickSpacing-aligned tick rather than binary
    //     searching the tick bitmap for the next *initialized* tick (see the header comment on why -
    //     a hook cannot reach the pool's internal tickBitmap storage). This is still correct
    //     (uninitialized ticks contribute liquidityNet = 0, a no-op) but costs more iterations for
    //     very wide, sparsely-initialized ranges.
    //   - If `MAX_TICK_CROSS_ITERATIONS` is exhausted before the walk reaches the reference/threshold
    //     tick, the function returns the accumulated-so-far amount by design: a safe UNDER-estimate
    //     of the true excess, never an over-estimate, so the cap/solvency guarantees below still hold.

    /// @notice Computes the deviation, in bps, between the reference and post-swap sqrt prices.
    /// @dev Squares both sqrtPrices (via `FullMath.mulDiv`, safe from overflow up to `MAX_SQRT_PRICE`)
    ///      to compare them as real prices (token1 per token0, Q96), then takes a plain linear
    ///      percentage difference. This is the same threshold semantics as the previous version - the
    ///      only change is that both sides are now real sqrtPrices (reference vs. actual post-swap
    ///      state), not a BalanceDelta-derived ratio.
    function _deviationBps(uint160 referenceSqrtPriceX96, uint160 postSqrtPriceX96) internal pure returns (uint256) {
        if (referenceSqrtPriceX96 == 0 || postSqrtPriceX96 == 0) return 0;

        uint256 referencePriceX96 = _priceX96(referenceSqrtPriceX96);
        uint256 postPriceX96 = _priceX96(postSqrtPriceX96);
        if (referencePriceX96 == 0) return 0;

        uint256 diff = postPriceX96 > referencePriceX96
            ? postPriceX96 - referencePriceX96
            : referencePriceX96 - postPriceX96;

        return FullMath.mulDiv(diff, BPS_DENOMINATOR, referencePriceX96);
    }

    /// @notice Computes the clawback amount for a swap whose post-swap price deviated past the
    ///         threshold, by pricing the excess band `[thresholdSqrtPriceX96, postSqrtPriceX96]`
    ///         against the pool's real in-range liquidity.
    /// @dev Solvency (unchanged from the linear version): the result is capped at `MAX_CLAWBACK_BPS`
    ///      (50%) of `unspecifiedAmountAbs`, and as an absolute backstop can never exceed
    ///      `unspecifiedAmountAbs` itself - i.e. the hook can never claw back more than the trade's
    ///      own proceeds on that leg. The value returned here is exactly the value `_afterSwap` both
    ///      donates to the pool and returns as the clawback delta - never two different numbers.
    function _computeExcessAmount(
        PoolId poolId,
        int24 tickSpacing,
        bool unspecifiedIsCurrency1,
        uint160 referenceSqrtPriceX96,
        uint160 postSqrtPriceX96,
        uint256 unspecifiedAmountAbs
    ) internal view returns (int128) {
        BandWalk memory walk;
        walk.poolId = poolId;
        walk.tickSpacing = tickSpacing;
        walk.unspecifiedIsCurrency1 = unspecifiedIsCurrency1;
        walk.increased = postSqrtPriceX96 > referenceSqrtPriceX96;

        uint256 referencePriceX96 = _priceX96(referenceSqrtPriceX96);

        // Price at which the "allowed" (within-threshold) band ends and the excess band begins.
        // Converting this back to a sqrtPrice is exact up to a single integer-sqrt floor rounding:
        // Q96 == 2^96 has an EXACT integer square root (2^48), so sqrtPrice = sqrt(price) * 2^48
        // introduces no meaningful approximation error (~1 part in 2^48 relative - negligible next to
        // a 100 bps threshold).
        uint256 thresholdPriceX96 = walk.increased
            ? FullMath.mulDiv(referencePriceX96, BPS_DENOMINATOR + DEVIATION_THRESHOLD_BPS, BPS_DENOMINATOR)
            : FullMath.mulDiv(referencePriceX96, BPS_DENOMINATOR - DEVIATION_THRESHOLD_BPS, BPS_DENOMINATOR);
        walk.thresholdSqrtPriceX96 = uint160(_sqrt(thresholdPriceX96) << 48);

        uint256 rawExcess = _sumAmountAcrossExcessBand(walk, postSqrtPriceX96);

        uint256 cap = FullMath.mulDiv(unspecifiedAmountAbs, MAX_CLAWBACK_BPS, BPS_DENOMINATOR);
        uint256 capped = rawExcess > cap ? cap : rawExcess;

        // Absolute solvency backstop, independent of MAX_CLAWBACK_BPS: never take more than exists.
        if (capped > unspecifiedAmountAbs) capped = unspecifiedAmountAbs;

        // Safe: capped <= unspecifiedAmountAbs, which itself originated from an int128 amount.
        return int128(uint128(capped));
    }

    /// @notice Per-call context for `_sumAmountAcrossExcessBand`, bundled into a memory struct (rather
    ///         than passed as separate parameters) purely to keep the function's stack footprint
    ///         under the EVM's 16-slot limit for legacy (non-IR) codegen - it has no semantic meaning
    ///         beyond that.
    struct BandWalk {
        PoolId poolId;
        int24 tickSpacing;
        bool unspecifiedIsCurrency1;
        bool increased;
        uint160 thresholdSqrtPriceX96;
    }

    /// @notice Tick-aware pricing of the excess band `[walk.thresholdSqrtPriceX96, postSqrtPriceX96]`
    ///         against the pool's real per-tick liquidity, bounded by `MAX_TICK_CROSS_ITERATIONS`.
    /// @dev Walks BACKWARD from the post-swap price (the only liquidity value directly observable via
    ///      `StateLibrary.getLiquidity`, since it reflects whatever tick the pool is *currently* in)
    ///      toward the threshold price, one tickSpacing-aligned tick at a time. Each step:
    ///        1. prices the sub-range between the current position and the next tick boundary (or the
    ///           band's far edge, whichever comes first) using the liquidity active in THAT sub-range,
    ///           via `SqrtPriceMath.getAmount0Delta`/`getAmount1Delta` (rounding down - the safe,
    ///           conservative direction for a clawback amount), then
    ///        2. if a real tick boundary was crossed (not yet at the band's edge), updates the running
    ///           liquidity by UNDOING that tick's `liquidityNet` - since we are walking in reverse
    ///           relative to the swap's own direction of travel, a tick that was originally crossed
    ///           upward (liquidityNet added) has that addition subtracted back out here, and vice
    ///           versa for a downward-crossed tick.
    ///      See the section header above for the tick-walk and gas-bound limitations.
    function _sumAmountAcrossExcessBand(BandWalk memory walk, uint160 postSqrtPriceX96)
        internal
        view
        returns (uint256 amount)
    {
        int256 liquidity = int256(uint256(poolManager.getLiquidity(walk.poolId)));

        uint160 segmentEndSqrtPriceX96 = postSqrtPriceX96;
        int24 boundaryTick = _floorAlignedTick(TickMath.getTickAtSqrtPrice(postSqrtPriceX96), walk.tickSpacing);
        if (!walk.increased) {
            // Walking upward (post price < threshold price): the first boundary strictly above the
            // current tick is one tickSpacing above its floor-aligned tick.
            boundaryTick += walk.tickSpacing;
        }

        for (uint256 i = 0; i < MAX_TICK_CROSS_ITERATIONS; i++) {
            if (boundaryTick < TickMath.MIN_TICK || boundaryTick > TickMath.MAX_TICK) break;

            uint160 boundarySqrtPriceX96 = TickMath.getSqrtPriceAtTick(boundaryTick);

            // Clamp to the band's far edge if this tick boundary would overshoot it.
            bool reachedThreshold = walk.increased
                ? boundarySqrtPriceX96 <= walk.thresholdSqrtPriceX96
                : boundarySqrtPriceX96 >= walk.thresholdSqrtPriceX96;
            uint160 segmentStartSqrtPriceX96 = reachedThreshold ? walk.thresholdSqrtPriceX96 : boundarySqrtPriceX96;

            amount += _amountForSegment(
                walk.unspecifiedIsCurrency1, segmentStartSqrtPriceX96, segmentEndSqrtPriceX96, liquidity
            );

            if (reachedThreshold) break;

            // Cross `boundaryTick`, undoing its liquidityNet (see @dev above for why "undoing").
            (, int128 liquidityNet) = poolManager.getTickLiquidity(walk.poolId, boundaryTick);
            liquidity = walk.increased ? liquidity - int256(liquidityNet) : liquidity + int256(liquidityNet);

            segmentEndSqrtPriceX96 = boundarySqrtPriceX96;
            boundaryTick = walk.increased ? boundaryTick - walk.tickSpacing : boundaryTick + walk.tickSpacing;
        }
    }

    /// @notice Prices one sub-range of the excess band at a given (possibly negative/zero-clamped)
    ///         liquidity. Split out from `_sumAmountAcrossExcessBand`'s loop body purely to keep that
    ///         function's stack footprint under the legacy codegen's 16-slot limit.
    function _amountForSegment(
        bool unspecifiedIsCurrency1,
        uint160 segmentStartSqrtPriceX96,
        uint160 segmentEndSqrtPriceX96,
        int256 liquidity
    ) internal pure returns (uint256) {
        uint128 activeLiquidity = liquidity > 0 ? uint128(uint256(liquidity)) : 0;
        return unspecifiedIsCurrency1
            ? SqrtPriceMath.getAmount1Delta(segmentStartSqrtPriceX96, segmentEndSqrtPriceX96, activeLiquidity, false)
            : SqrtPriceMath.getAmount0Delta(segmentStartSqrtPriceX96, segmentEndSqrtPriceX96, activeLiquidity, false);
    }

    /// @notice `price = sqrtPriceX96^2 / Q96`, as a Q96 fixed-point value (token1 per token0).
    function _priceX96(uint160 sqrtPriceX96) internal pure returns (uint256) {
        return FullMath.mulDiv(uint256(sqrtPriceX96), uint256(sqrtPriceX96), FixedPoint96.Q96);
    }

    /// @notice Largest tickSpacing-aligned tick `<= tick` (floor alignment towards negative infinity).
    /// @dev Mirrors `TickBitmap.compress`'s alignment rule for negative ticks under Solidity's
    ///      truncating `/`/`%` (which round towards zero, not towards negative infinity).
    function _floorAlignedTick(int24 tick, int24 tickSpacing) internal pure returns (int24) {
        int24 compressed = tick / tickSpacing;
        if (tick < 0 && tick % tickSpacing != 0) compressed -= 1;
        return compressed * tickSpacing;
    }

    /// @notice Floor integer square root (Babylonian method) - standard, well-known algorithm (the
    ///         same one used by e.g. Uniswap V2's `Math.sqrt` / OpenZeppelin's `Math.sqrt`).
    function _sqrt(uint256 x) internal pure returns (uint256 y) {
        if (x == 0) return 0;
        uint256 z = (x + 1) / 2;
        y = x;
        while (z < y) {
            y = z;
            z = (x / z + z) / 2;
        }
    }

    // ---------------------------------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------------------------------

    /// @notice Whether the swap's "unspecified" (adjustable) currency is currency1.
    /// @dev Mirrors the exact convention `Hooks.afterSwap` (v4-core) uses to slot the `int128` this
    ///      contract returns into the correct side of the final `BalanceDelta`:
    ///      `(amountSpecified < 0) == zeroForOne` <=> specified side is currency0, unspecified is
    ///      currency1. This is the same check used by v4-core's own `FeeTakingHook` test hook.
    function _isUnspecifiedCurrency1(SwapParams calldata params) internal pure returns (bool) {
        return (params.amountSpecified < 0) == params.zeroForOne;
    }

    /// @notice Absolute amount of the swap's unspecified currency, from the post-swap `BalanceDelta`.
    function _unspecifiedAmountAbs(SwapParams calldata params, BalanceDelta delta) internal pure returns (uint256) {
        int128 raw = _isUnspecifiedCurrency1(params) ? delta.amount1() : delta.amount0();
        return _abs128(raw);
    }

    /// @notice Donates the clawed-back amount back into the pool, in whichever currency it was taken
    ///         from, so it flows to LPs via `feeGrowthGlobal` instead of being extractable by anyone.
    /// @dev Calling back into `poolManager` from within `_afterSwap` is safe: `PoolManager.donate` is
    ///      gated by `onlyWhenUnlocked`, a transient flag that stays true for the entire outer
    ///      `unlock()` callback (i.e. for the whole swap-router transaction), not a per-call
    ///      reentrancy mutex - so nested calls back into the manager from a hook are an expected,
    ///      supported pattern (the same one v4-core's own test hooks use for `take`/`settle`).
    ///      `donate` does not itself move any tokens; it only requires pool liquidity > 0 (true here,
    ///      since a swap against that same pool/liquidity just executed) and records a negative delta
    ///      for the caller (this hook) that exactly nets against the positive credit the swap's
    ///      `hookDelta` accounting gives this hook for the same currency/amount - so no token ever
    ///      actually leaves the PoolManager; it simply is never paid out to the swapper.
    function _donateToPool(PoolKey calldata key, SwapParams calldata params, int128 excessAmount) internal {
        uint256 amount = uint256(uint128(excessAmount));
        if (_isUnspecifiedCurrency1(params)) {
            poolManager.donate(key, 0, amount, "");
        } else {
            poolManager.donate(key, amount, 0, "");
        }
    }

    /// @notice Absolute value of an `int128`, as a `uint256`.
    function _abs128(int128 x) internal pure returns (uint256) {
        return x < 0 ? uint256(uint128(-x)) : uint256(uint128(x));
    }
}
