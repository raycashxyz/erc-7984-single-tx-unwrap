/**
 * What a Zama KMS node signs for one user-decryption share of a euint64, byte for byte, and the
 * TFHE decode of the reconstructed value. Mirrors `contracts/KmsUserDecryption.sol` and both
 * circuits.
 *
 * Each node signs before it encrypts (zama-ai/kms `core/service/src/cryptography/signcryption.rs`):
 *
 *   digest = SHA-256("USER_DEC" ‖ bincode(SigncryptionPayload { plaintext, link }) ‖ user ‖ H(enc_key))
 *
 * with `link` the EIP-712 hash of `UserDecryptionLinker(publicKey, [handle], user)` on the Gateway
 * `Decryption` domain, and H(enc_key) = SHAKE-256("SIGNCRYP" ‖ bincode(ML-KEM public key)).
 */
import {
  concat, domainSeparator, encodeAbiParameters, keccak256, numberToHex, sha256, toHex,
} from "viem";
import type { Address, Hex } from "viem";
import type { Gr } from "./ring";

/** 2t + 1 shares for the n = 13, t = 4 KMS. */
export const SHARES = 9;
/** t: the sharing polynomial's degree. */
export const DEGREE = 4;
/** Ring elements per euint64 share: 16 four-bit blocks, packing factor 2. */
export const ELEMENTS = 4;
export const SHARE_BYTES = 256;

/** "USER_DEC" ‖ u64 len(TypedPlaintext.bytes) = 264 ‖ u64 len(Vec<element>) = 4. */
export const MESSAGE_PREFIX: Hex = "0x555345525f44454308010000000000000400000000000000";
/** i32 fhe_type = Uint64 (5) ‖ u64 len(link) = 32. */
export const MESSAGE_MIDDLE: Hex = "0x050000002000000000000000";

const LINKER_TYPEHASH = keccak256(toHex("UserDecryptionLinker(bytes publicKey,bytes32[] handles,address userAddress)"));
const MASK128 = (1n << 128n) - 1n;

export const decryptionDomainSeparator = (gatewayChainId: bigint, decryptionContract: Address): Hex =>
  domainSeparator({
    domain: {
      name: "Decryption",
      version: "1",
      chainId: gatewayChainId,
      verifyingContract: decryptionContract,
    },
  });

/** The link every node's share is bound to: request public key, the one handle, and the user. */
export const userDecryptionLink = (params: {
  handle: Hex;
  user: Address;
  pkKeccak: Hex;
  decryptionDomainSeparator: Hex;
}): Hex => {
  const structHash = keccak256(encodeAbiParameters(
    [{ type: "bytes32" }, { type: "bytes32" }, { type: "bytes32" }, { type: "address" }],
    [LINKER_TYPEHASH, params.pkKeccak, keccak256(params.handle), params.user],
  ));
  return keccak256(concat(["0x1901", params.decryptionDomainSeparator, structHash]));
};

/** The SHA-256 digest a node signs for its share. */
export const shareDigest = (params: { share: Hex; link: Hex; user: Address; encKeyHash: Hex }): Hex =>
  sha256(concat([MESSAGE_PREFIX, params.share, MESSAGE_MIDDLE, params.link, params.user, params.encKeyHash]));

// --- TFHE decode (4 message+carry bits on a 128-bit torus, Δ = 2^123) ---------------------------

const DELTA = 1n << 123n;
const NEGATIVE_BAND = (1n << 128n) - DELTA;

/** raw >= 2^128 − Δ is negative noise around 0; otherwise round to the nearest multiple of Δ. */
export const decodeBlock = (raw: bigint): bigint =>
  raw >= NEGATIVE_BAND ? 0n : ((raw + (1n << 122n)) >> 123n) & 15n;

/** The euint64 in a secret of 4 ring elements: 16 four-bit blocks, little-endian. */
export const decodeUint64 = (secret: readonly Gr[]): bigint =>
  secret.flatMap((g) => [...g]).reduce((acc, raw, k) => acc | (decodeBlock(raw) << BigInt(4 * k)), 0n);

/** A secret that decodes to `value`, each block carrying `noise` (kept well under Δ/2). */
export const encodeUint64 = (value: bigint, noise: (block: number) => bigint): Gr[] =>
  Array.from({ length: ELEMENTS }, (_, j): Gr => {
    const block = (a: number): bigint =>
      (((value >> BigInt(4 * (4 * j + a))) & 15n) * DELTA + (noise(4 * j + a) & ((1n << 100n) - 1n))) & MASK128;
    return [block(0), block(1), block(2), block(3)];
  });

// --- Circuit public inputs ----------------------------------------------------------------------

/** A 32-byte word as its two 128-bit halves, high first — each fits a BN254 field element. */
const halves = (word: Hex): Hex[] => [
  numberToHex(BigInt(word) >> 128n, { size: 32 }),
  numberToHex(BigInt(word) & MASK128, { size: 32 }),
];

/**
 * The 31 public inputs both circuits take, in order: link (2) ‖ user ‖ amount ‖ parties (9) ‖
 * digests (9 × 2). `KmsUserDecryption.publicInputs` builds the same vector on-chain.
 */
export const publicInputs = (params: {
  link: Hex;
  user: Address;
  amount: bigint;
  parties: readonly number[];
  digests: readonly Hex[];
}): Hex[] => [
  ...halves(params.link),
  numberToHex(BigInt(params.user), { size: 32 }),
  numberToHex(params.amount, { size: 32 }),
  ...params.parties.map((party) => numberToHex(party, { size: 32 })),
  ...params.digests.flatMap(halves),
];
