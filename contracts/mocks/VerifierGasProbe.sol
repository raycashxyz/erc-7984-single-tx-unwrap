// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {IUnwrapProofVerifier} from "../IUnwrapProofVerifier.sol";

/// @notice Measures the gas one verification costs (via `eth_call`), so the gas benchmark can swap a
///         mock verifier's cost for a real proof's.
contract VerifierGasProbe {
    function verifyGas(IUnwrapProofVerifier verifier, bytes calldata proof, bytes32[] calldata publicInputs)
        external
        view
        returns (uint256 gasUsed)
    {
        uint256 start = gasleft();
        verifier.verify(proof, publicInputs);
        gasUsed = start - gasleft();
    }
}
