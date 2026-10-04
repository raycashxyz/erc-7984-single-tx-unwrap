// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ISwapPool} from "../examples/UnwrapAndSwap.sol";

/// @notice Minimal constant-product pool (x · y = k, 0.3% fee) standing in for a DEX in tests.
contract MockSwapPool is ISwapPool {
    using SafeERC20 for IERC20;

    IERC20 public immutable token0;
    IERC20 public immutable token1;

    error UnknownToken(IERC20 token);
    error InsufficientOutput(uint256 amountOut, uint256 minAmountOut);

    constructor(IERC20 token0_, IERC20 token1_) {
        token0 = token0_;
        token1 = token1_;
    }

    function swap(IERC20 tokenIn, uint256 amountIn, uint256 minAmountOut, address to) external returns (uint256 amountOut) {
        require(tokenIn == token0 || tokenIn == token1, UnknownToken(tokenIn));
        IERC20 tokenOut = tokenIn == token0 ? token1 : token0;
        uint256 reserveIn = tokenIn.balanceOf(address(this));
        uint256 reserveOut = tokenOut.balanceOf(address(this));
        tokenIn.safeTransferFrom(msg.sender, address(this), amountIn);
        uint256 inWithFee = amountIn * 997;
        amountOut = (inWithFee * reserveOut) / (reserveIn * 1000 + inWithFee);
        require(amountOut >= minAmountOut, InsufficientOutput(amountOut, minAmountOut));
        tokenOut.safeTransfer(to, amountOut);
    }
}
