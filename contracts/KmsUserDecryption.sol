// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/// @dev 2t + 1 shares for the n = 13, t = 4 KMS (file-level so other contracts can size arrays by it).
uint256 constant KMS_SHARES = 9;

/**
 * @title KmsUserDecryption
 * @notice On-chain checks over Zama KMS user-decryption shares for a euint64 (formats identical in
 *         zama-ai/kms v0.12 through v0.15).
 *
 *         A KMS node signs each share before encrypting it to the user, with ECDSA (secp256k1) over
 *
 *           digest = SHA-256("USER_DEC" ‖ bincode(SigncryptionPayload{share, link}) ‖ user ‖ H(enc_key))
 *
 *         where `link` is the EIP-712 hash of (publicKey, [handle], user) on the Gateway `Decryption`
 *         domain. The plaintext share is therefore authenticated and bound to (handle, user) by the
 *         node's signature alone; the encryption only hides it in transit.
 *
 *         Shares are Shamir shares of degree t = 4 over GR(2^128, 4) = Z_{2^128}[X] / (X^4 + X + 1),
 *         party p evaluated at the ring element whose coefficients are p's bits. 2t + 1 = 9 shares
 *         from distinct nodes on one polynomial fix the value even if t nodes collude.
 */
library KmsUserDecryption {
    uint256 internal constant SHARES = KMS_SHARES;
    uint256 internal constant KMS_NODES = 13;
    uint256 internal constant DEGREE = 4;
    uint256 internal constant ELEMENTS = 4;
    uint256 internal constant ELEMENT_BYTES = 64;
    uint256 internal constant SHARE_BYTES = ELEMENTS * ELEMENT_BYTES;
    /// r ‖ s ‖ v: the KMS signs r ‖ s; the client adds the recovery byte so one `ecrecover` suffices.
    uint256 internal constant SIGNATURE_BYTES = 65;
    uint256 internal constant POLY_BYTES = (DEGREE + 1) * SHARE_BYTES;

    bytes32 private constant LINKER_TYPEHASH =
        keccak256("UserDecryptionLinker(bytes publicKey,bytes32[] handles,address userAddress)");
    /// "USER_DEC" ‖ u64le(len(TypedPlaintext.bytes) = 264) ‖ u64le(4 ring elements)
    bytes private constant MESSAGE_PREFIX = hex"555345525f44454308010000000000000400000000000000";
    /// i32le(FheTypes::Uint64 = 5) ‖ u64le(len(link) = 32)
    bytes private constant MESSAGE_MIDDLE = hex"050000002000000000000000";
    uint256 private constant MASK128 = type(uint128).max;
    bytes32 private constant LOW128 = bytes32(MASK128);
    /// @dev link (2) + user + amount + parties (9) + digests (9 × 2).
    uint256 internal constant PUBLIC_INPUTS = 4 + 3 * SHARES;
    uint256 private constant BYTE_MASK = 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff;
    uint256 private constant SHORT_MASK = 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff;
    uint256 private constant WORD_MASK = 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff;
    uint256 private constant DWORD_MASK = 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff;
    /// secp256k1 n / 2: the KMS only emits low-s signatures.
    uint256 private constant HALF_ORDER = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    /// Δ = 2^123 (4 message+carry bits + padding on a 128-bit torus); the top Δ band is negative noise.
    uint256 private constant NEGATIVE_BAND = (1 << 128) - (1 << 123);

    error UnsupportedKmsSignerSet(uint256 nodes);
    error UnknownParty(uint8 party);
    error DuplicateParty(uint8 party);
    error InvalidShareSignature(uint8 party);
    error ShareOffPolynomial(uint8 party);
    error MalformedShares();

    /// @notice EIP-712 hash of `UserDecryptionLinker(publicKey, [handle], user)`; `pkKeccak` is
    ///         keccak256 of the user's single-use ML-KEM public key.
    function link(
        bytes32 handle,
        address user,
        bytes32 pkKeccak,
        bytes32 decryptionDomainSeparator
    ) internal pure returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(LINKER_TYPEHASH, pkKeccak, keccak256(abi.encode(handle)), user));
        return keccak256(abi.encodePacked(hex"1901", decryptionDomainSeparator, structHash));
    }

    /// @notice The SHA-256 digest a node signs for one 256-byte share.
    function shareDigest(
        bytes calldata share,
        bytes32 linkHash,
        address user,
        bytes32 encKeyHash
    ) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(MESSAGE_PREFIX, share, MESSAGE_MIDDLE, linkHash, user, encKeyHash));
    }

    /// @notice True iff the low-s `signature` (r ‖ s ‖ v) over `digest` recovers to `signer`.
    function isSignedBy(bytes32 digest, bytes calldata signature, address signer) internal pure returns (bool) {
        bytes32 r = bytes32(signature[:32]);
        bytes32 s = bytes32(signature[32:64]);
        if (uint256(s) > HALF_ORDER) return false;
        return ecrecover(digest, uint8(signature[64]), r, s) == signer;
    }

    /// @notice Requires 2t + 1 distinct known parties whose node signed the matching digest. Party p
    ///         is `signers[p - 1]` (the order of `KMSVerifier.getKmsSigners()`).
    function checkSignedDigests(
        address[] memory signers,
        uint8[SHARES] calldata parties,
        bytes32[SHARES] memory digests,
        bytes calldata signatures
    ) internal pure {
        if (signers.length != KMS_NODES) revert UnsupportedKmsSignerSet(signers.length);
        if (signatures.length != SHARES * SIGNATURE_BYTES) revert MalformedShares();
        uint256 seen;
        for (uint256 i; i < SHARES; ++i) {
            uint8 party = parties[i];
            if (party == 0 || party > KMS_NODES) revert UnknownParty(party);
            if (seen & (1 << party) != 0) revert DuplicateParty(party);
            seen |= 1 << party;
            bytes calldata signature = signatures[i * SIGNATURE_BYTES:(i + 1) * SIGNATURE_BYTES];
            if (!isSignedBy(digests[i], signature, signers[party - 1])) revert InvalidShareSignature(party);
        }
    }

    /// @notice Public inputs of the unwrap circuits (`circuits/noir`, `circuits/circom`), in circuit
    ///         order: link (two 128-bit halves) ‖ user ‖ amount ‖ parties ‖ digests (two halves each).
    function publicInputs(
        bytes32 linkHash,
        address user,
        uint64 amount,
        uint8[SHARES] calldata parties,
        bytes32[SHARES] memory digests
    ) internal pure returns (bytes32[] memory inputs) {
        inputs = new bytes32[](PUBLIC_INPUTS);
        inputs[0] = linkHash >> 128;
        inputs[1] = linkHash & LOW128;
        inputs[2] = bytes32(uint256(uint160(user)));
        inputs[3] = bytes32(uint256(amount));
        for (uint256 i; i < SHARES; ++i) {
            inputs[4 + i] = bytes32(uint256(parties[i]));
            inputs[4 + SHARES + 2 * i] = digests[i] >> 128;
            inputs[5 + SHARES + 2 * i] = digests[i] & LOW128;
        }
    }

    /// @notice Requires every share to lie on `poly` ((t + 1) rows × 4 elements × 64 bytes) and
    ///         returns the decoded constant term — the plaintext euint64.
    function reconstruct(
        uint8[SHARES] calldata parties,
        bytes calldata shares,
        bytes calldata poly
    ) internal pure returns (uint64) {
        if (shares.length != SHARES * SHARE_BYTES || poly.length != POLY_BYTES) revert MalformedShares();
        uint256[(DEGREE + 1) * ELEMENTS * 4] memory c;
        for (uint256 i; i < c.length; i += 2) {
            (c[i], c[i + 1]) = le128Pair(poly, i * 16);
        }
        for (uint256 i; i < SHARES; ++i) {
            uint8 party = parties[i];
            for (uint256 j; j < ELEMENTS; ++j) {
                if (!onPolynomial(c, shares, i * SHARE_BYTES + j * ELEMENT_BYTES, j, party)) {
                    revert ShareOffPolynomial(party);
                }
            }
        }
        return decode(poly[:SHARE_BYTES]);
    }

    /// @dev Whether ring element `j` of the share at `at` equals the polynomial at the party's point.
    function onPolynomial(
        uint256[(DEGREE + 1) * ELEMENTS * 4] memory c,
        bytes calldata shares,
        uint256 at,
        uint256 j,
        uint8 party
    ) private pure returns (bool) {
        (uint256 a0, uint256 a1, uint256 a2, uint256 a3) = evaluate(c, j, party);
        (uint256 s0, uint256 s1) = le128Pair(shares, at);
        if (a0 != s0 || a1 != s1) return false;
        (s0, s1) = le128Pair(shares, at + 32);
        return a2 == s0 && a3 == s1;
    }

    /// @notice TFHE decode of 16 four-bit blocks (packing factor 2) from the secret's coefficients.
    function decode(bytes calldata secret) internal pure returns (uint64 value) {
        if (secret.length != SHARE_BYTES) revert MalformedShares();
        for (uint256 b; b < 16; b += 2) {
            (uint256 raw0, uint256 raw1) = le128Pair(secret, b * 16);
            value |= uint64(decodeBlock(raw0) << (4 * b)) | uint64(decodeBlock(raw1) << (4 * (b + 1)));
        }
    }

    function decodeBlock(uint256 raw) private pure returns (uint256) {
        return raw >= NEGATIVE_BAND ? 0 : ((raw + (1 << 122)) >> 123) & 15;
    }

    /// @dev Horner evaluation of ring element `j`'s polynomial at the party's point, over
    ///      GR(2^128, 4) = Z_{2^128}[X] / (X^4 + X + 1). The point x = b0 + b1 X + b2 X^2 + b3 X^3
    ///      (the party's bits), so a · x is a sum of shifted copies of a:
    ///        X a   = (-a3, a0 - a3, a1, a2)
    ///        X^2 a = (-a2, -(a3 + a2), a0 - a3, a1)
    ///        X^3 a = (-a1, -(a2 + a1), -(a3 + a2), a0 - a3)
    ///      Wrapping uint256 arithmetic is exact mod 2^128. In assembly because this loop runs
    ///      36 × 4 times and Solidity's bounds-checked memory indexing dominated its cost.
    ///      `c[(k * 4 + j) * 4 + a]` is coefficient `a` of ring element `j` of the degree-`k` term.
    function evaluate(
        uint256[(DEGREE + 1) * ELEMENTS * 4] memory c,
        uint256 j,
        uint8 party
    ) private pure returns (uint256 a0, uint256 a1, uint256 a2, uint256 a3) {
        assembly ("memory-safe") {
            let mask := 0xffffffffffffffffffffffffffffffff
            // degree-4 term of element j: c + 32 * ((4 * 4 + j) * 4) = c + 128 * (16 + j)
            let at := add(c, shl(7, add(16, j)))
            a0 := mload(at)
            a1 := mload(add(at, 32))
            a2 := mload(add(at, 64))
            a3 := mload(add(at, 96))
            for { let k := 4 } gt(k, 0) { k := sub(k, 1) } {
                let d := sub(a0, a3)
                let r0 := 0
                let r1 := 0
                let r2 := 0
                let r3 := 0
                if and(party, 1) {
                    r0 := a0
                    r1 := a1
                    r2 := a2
                    r3 := a3
                }
                if and(party, 2) {
                    r0 := sub(r0, a3)
                    r1 := add(r1, d)
                    r2 := add(r2, a1)
                    r3 := add(r3, a2)
                }
                if and(party, 4) {
                    r0 := sub(r0, a2)
                    r1 := sub(sub(r1, a3), a2)
                    r2 := add(r2, d)
                    r3 := add(r3, a1)
                }
                if and(party, 8) {
                    r0 := sub(r0, a1)
                    r1 := sub(sub(r1, a2), a1)
                    r2 := sub(sub(r2, a3), a2)
                    r3 := add(r3, d)
                }
                // degree-(k - 1) term of element j: c + 128 * ((k - 1) * 4 + j)
                at := add(c, shl(7, add(shl(2, sub(k, 1)), j)))
                a0 := and(add(r0, mload(at)), mask)
                a1 := and(add(r1, mload(add(at, 32))), mask)
                a2 := and(add(r2, mload(add(at, 64))), mask)
                a3 := and(add(r3, mload(add(at, 96))), mask)
            }
        }
    }

    /// @dev The two little-endian u128 at `offset` and `offset + 16`, from one 256-bit byte
    ///      reversal. Callers check `data` is long enough (lengths are validated up front).
    function le128Pair(bytes calldata data, uint256 offset) private pure returns (uint256 first, uint256 second) {
        uint256 v;
        assembly ("memory-safe") {
            v := calldataload(add(data.offset, offset))
        }
        v = ((v >> 8) & BYTE_MASK) | ((v & BYTE_MASK) << 8);
        v = ((v >> 16) & SHORT_MASK) | ((v & SHORT_MASK) << 16);
        v = ((v >> 32) & WORD_MASK) | ((v & WORD_MASK) << 32);
        v = ((v >> 64) & DWORD_MASK) | ((v & DWORD_MASK) << 64);
        v = (v >> 128) | (v << 128);
        first = v & MASK128;
        second = v >> 128;
    }
}
