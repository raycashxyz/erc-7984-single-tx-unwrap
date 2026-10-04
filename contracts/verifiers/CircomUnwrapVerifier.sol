// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IUnwrapProofVerifier} from "../IUnwrapProofVerifier.sol";

/// @dev The snarkjs-generated verifier for `circuits/circom` (31 public inputs).
interface IUnwrapGroth16Verifier {
    function verifyProof(
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256[31] calldata pubSignals
    ) external view returns (bool);
}

/**
 * @title CircomUnwrapVerifier
 * @notice Serves {SingleTxUnwrapWrapper} with Groth16 proofs of `circuits/circom`: the proof is
 *         `abi.encode(uint256[2] a, uint256[2][2] b, uint256[2] c)` (256 bytes), and the public
 *         inputs are the same 31 values the UltraHonk verifier takes.
 */
contract CircomUnwrapVerifier is IUnwrapProofVerifier {
    IUnwrapGroth16Verifier public immutable groth16;

    error UnexpectedPublicInputs(uint256 count);

    constructor(IUnwrapGroth16Verifier groth16_) {
        groth16 = groth16_;
    }

    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool) {
        if (publicInputs.length != 31) revert UnexpectedPublicInputs(publicInputs.length);
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) =
            abi.decode(proof, (uint256[2], uint256[2][2], uint256[2]));
        uint256[31] memory signals;
        for (uint256 i; i < 31; ++i) {
            signals[i] = uint256(publicInputs[i]);
        }
        return groth16.verifyProof(a, b, c, signals);
    }
}
