// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {KmsUserDecryption} from "../KmsUserDecryption.sol";

/// @notice Exposes {KmsUserDecryption} for tests against real KMS data.
contract KmsUserDecryptionHarness {
    function link(bytes32 handle, address user, bytes32 pkKeccak, bytes32 domainSeparator)
        external
        pure
        returns (bytes32)
    {
        return KmsUserDecryption.link(handle, user, pkKeccak, domainSeparator);
    }

    function shareDigest(bytes calldata share, bytes32 linkHash, address user, bytes32 encKeyHash)
        external
        pure
        returns (bytes32)
    {
        return KmsUserDecryption.shareDigest(share, linkHash, user, encKeyHash);
    }

    function checkSignedDigests(
        address[] memory signers,
        uint8[9] calldata parties,
        bytes32[9] memory digests,
        bytes calldata signatures
    ) external pure {
        KmsUserDecryption.checkSignedDigests(signers, parties, digests, signatures);
    }

    function publicInputs(
        bytes32 linkHash,
        address user,
        uint64 amount,
        uint8[9] calldata parties,
        bytes32[9] memory digests
    ) external pure returns (bytes32[] memory) {
        return KmsUserDecryption.publicInputs(linkHash, user, amount, parties, digests);
    }

    function reconstruct(uint8[9] calldata parties, bytes calldata shares, bytes calldata poly)
        external
        pure
        returns (uint64)
    {
        return KmsUserDecryption.reconstruct(parties, shares, poly);
    }
}
