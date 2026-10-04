// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {SingleTxUnwrapWrapper} from "../SingleTxUnwrapWrapper.sol";

/// @notice A swap venue: pulls `amountIn` of `tokenIn` from the caller and sends the output to `to`.
interface ISwapPool {
    function swap(IERC20 tokenIn, uint256 amountIn, uint256 minAmountOut, address to) external returns (uint256);
}

/**
 * @title UnwrapAndSwap
 * @notice Composability example: unwrap confidential tokens and swap the released ERC-20 in one
 *         transaction. With the two-step unwrap this needs two transactions and a wait for the
 *         public decryption in between; here the swap's `minOut` and the unwrap succeed or revert
 *         together.
 *
 *         The holder makes this contract an ERC-7984 operator once (`wrapper.setOperator`). Each
 *         call then unwraps the caller's own balance: the KMS user decryption in `signed` is bound
 *         to the caller's live balance handle, so nobody else's decryption can be replayed here.
 */
contract UnwrapAndSwap {
    using SafeERC20 for IERC20;

    event UnwrappedAndSwapped(address indexed holder, uint64 amount, IERC20 tokenOut, uint256 amountOut);

    function unwrapAndSwap(
        SingleTxUnwrapWrapper wrapper,
        uint64 amount,
        SingleTxUnwrapWrapper.SignedDigests calldata signed,
        bytes calldata proof,
        ISwapPool pool,
        IERC20 tokenOut,
        uint256 minAmountOut
    ) external returns (uint256 amountOut) {
        wrapper.unwrapWithProof(msg.sender, address(this), amount, signed, proof);
        IERC20 underlying = IERC20(wrapper.underlying());
        uint256 released = amount * wrapper.rate();
        underlying.forceApprove(address(pool), released);
        amountOut = pool.swap(underlying, released, minAmountOut, msg.sender);
        emit UnwrappedAndSwapped(msg.sender, amount, tokenOut, amountOut);
    }
}
