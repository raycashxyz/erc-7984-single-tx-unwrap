// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IUnwrapProofVerifier} from "../IUnwrapProofVerifier.sol";

/**
 * @title MockUnwrapProofVerifier
 * @notice Test double that keeps soundness: a proof exists only for public inputs a test registers
 *         with {prove}, standing in for "the holder ran a prover on these shares". The real verifiers
 *         are exercised separately with real proofs.
 */
contract MockUnwrapProofVerifier is IUnwrapProofVerifier {
    mapping(bytes32 inputsId => bool) public proven;

    function prove(bytes32[] calldata publicInputs) external {
        proven[keccak256(abi.encode(publicInputs))] = true;
    }

    function verify(bytes calldata, bytes32[] calldata publicInputs) external view returns (bool) {
        return proven[keccak256(abi.encode(publicInputs))];
    }
}
