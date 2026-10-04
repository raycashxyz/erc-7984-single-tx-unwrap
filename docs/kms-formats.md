# KMS user-decryption formats, byte by byte

Everything the client parses and everything the contract and circuits hash, for a user decryption of
one `euint64` handle. Identical in zama-ai/kms v0.12, v0.14.2 and v0.15.0-1. Implemented in
[`src/response.ts`](../src/response.ts), [`src/kms.ts`](../src/kms.ts),
[`contracts/KmsUserDecryption.sol`](../contracts/KmsUserDecryption.sol) and both circuits.

bincode below is `bc2wrap`'s legacy configuration: little-endian, fixed-width integers, `u64` lengths.

## The link

Every node's share is bound to the request through

```
link = keccak256(0x1901 ‖ domainSeparator ‖ keccak256(abi.encode(
         keccak256("UserDecryptionLinker(bytes publicKey,bytes32[] handles,address userAddress)"),
         keccak256(publicKey),          // the request's ML-KEM public key, as signed in the request
         keccak256(abi.encode(handle)), // bytes32[] with the one handle
         user)))
domainSeparator = EIP-712 domain { name: "Decryption", version: "1", chainId: <Gateway chain>,
                                   verifyingContract: <Gateway Decryption contract> }
```

The host chain's `KMSVerifier.eip712Domain()` returns that Gateway domain.

## A node's response

`UserDecryptionResponsePayload` (bincode), as the relayer returns it, plus the node's EIP-712
signature of it (not used here):

| field | type |
|---|---|
| verification_key | `Vec<u8>` |
| digest | `Vec<u8>` |
| signcrypted_ciphertexts | `Vec<TypedSigncryptedCiphertext>` — one per handle |
| party_id | `u32` (1-based; party p is `KMSVerifier.getKmsSigners()[p − 1]`) |
| degree | `u32` (t) |

`TypedSigncryptedCiphertext { fhe_type: i32, signcrypted_ciphertext: Vec<u8>, external_handle: Vec<u8>, packing_factor: u32 }`.

`signcrypted_ciphertext` is bincode `HybridKemCt { nonce: [u8; 12], kem_ct: Vec<u8>, payload_ct: Vec<u8> }`:

```
shared   = ML-KEM-512.Decaps(dk, kem_ct)                 // dk: the request's 1632-byte decapsulation key
plain    = AES-256-GCM.Decrypt(key = shared[0..32], nonce, payload_ct)
plain    = msg ‖ signature (64: r ‖ s) ‖ H(server verification key) (32)
```

## The signed message

`msg` is bincode `SigncryptionPayload { plaintext: TypedPlaintext { bytes, fhe_type }, link }`:

| offset | bytes | content |
|---|---|---|
| 0 | 8 | `u64` len(plaintext.bytes) = 264 |
| 8 | 8 | `u64` len(Vec of ring elements) = 4 |
| 16 | 256 | the share: 4 ring elements × 4 little-endian `u128` coefficients |
| 272 | 4 | `i32` fhe_type = 5 (Uint64) |
| 276 | 8 | `u64` len(link) = 32 |
| 284 | 32 | link |

The node signs, with secp256k1 ECDSA (low-s, no recovery byte) over SHA-256:

```
"USER_DEC" ‖ msg ‖ user (20) ‖ H(enc_key) (32)        = 376 bytes = 7 SHA-256 blocks after padding
H(enc_key) = SHAKE-256("SIGNCRYP" ‖ u64 len(ek) = 800 ‖ ek)[0..32]
```

`ek` is the request's ML-KEM-512 encapsulation key (bytes 768..1568 of `dk`; the tail of the request's
`publicKey`).

## The shares

Shares are Shamir shares of degree t = 4 over GR(2^128, 4) = Z<sub>2^128</sub>[X] / (X⁴ + X + 1).
Party p is evaluated at the element whose coefficients are p's bits (`p = 5 → 1 + X²`). Distinct party
points differ by units, so Lagrange interpolation works over the ring.

The secret is 4 ring elements = 16 coefficients, each a TFHE-encoded 4-bit block of the value,
little-endian: block k is coefficient (k mod 4) of element ⌊k / 4⌋. With Δ = 2^123,

```
decode(raw) = 0                                  if raw ≥ 2^128 − Δ   (negative noise around 0)
            = ((raw + 2^122) >> 123) mod 16      otherwise
value       = Σ decode(block_k) · 16^k
```

## What the contract passes the circuits

31 field elements, in order:

| index | value |
|---|---|
| 0, 1 | link, high and low 128 bits |
| 2 | user |
| 3 | amount |
| 4 – 12 | parties |
| 13 – 30 | digests, each as high and low 128 bits |
