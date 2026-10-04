// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {ERC7984} from "@openzeppelin/confidential-contracts/token/ERC7984/ERC7984.sol";
import {ERC7984ERC20Wrapper} from "@openzeppelin/confidential-contracts/token/ERC7984/extensions/ERC7984ERC20Wrapper.sol";

/// @notice OpenZeppelin's {ERC7984ERC20Wrapper} as is: the two-step `unwrap` → public decryption →
///         `finalizeUnwrap` baseline the gas comparison runs against.
contract StandardERC7984Wrapper is ERC7984ERC20Wrapper, ZamaEthereumConfig {
    constructor(IERC20 underlying_, string memory name_, string memory symbol_)
        ERC7984(name_, symbol_, "")
        ERC7984ERC20Wrapper(underlying_)
    {}
}
