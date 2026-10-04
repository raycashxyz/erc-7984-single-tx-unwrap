// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/**
 * @notice Verifies a proof of the unwrap statement for the public inputs
 *         {KmsUserDecryption.publicInputs}. This is the interface of the bb-generated UltraHonk
 *         verifier; {CircomUnwrapVerifier} adapts the snarkjs Groth16 verifier to it.
 */
interface IUnwrapProofVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}
