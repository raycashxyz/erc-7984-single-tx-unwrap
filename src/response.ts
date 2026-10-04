/**
 * Client side of a Zama KMS user decryption, without the KMS crates or WASM: parse each node's
 * response and decrypt its signcrypted share with the request's single-use ML-KEM key.
 *
 * - A response payload is bincode (`bc2wrap`, legacy config) of `UserDecryptionResponsePayload
 *   { verification_key, digest, signcrypted_ciphertexts, party_id, degree }`.
 * - A signcrypted ciphertext is bincode `HybridKemCt { nonce: [u8; 12], kem_ct, payload_ct }`:
 *   ML-KEM-512 encapsulation, then AES-256-GCM under the shared secret.
 * - The plaintext is `msg ‖ sig (64) ‖ H(server verification key) (32)`, where `msg` is bincode
 *   `SigncryptionPayload { plaintext: TypedPlaintext { bytes, fhe_type }, link }` and `sig` the
 *   node's ECDSA signature over `"USER_DEC" ‖ msg ‖ user ‖ H(enc_key)`.
 *
 * Same formats in zama-ai/kms v0.12 (the Sepolia fixture) through v0.14.2 and v0.15.0-1:
 * `SigncryptionPayload` V0 is format-locked upstream and the response proto is unchanged.
 */
import { gcm } from "@noble/ciphers/aes.js";
import { shake256 } from "@noble/hashes/sha3.js";
import { ml_kem512 } from "@noble/post-quantum/ml-kem.js";
import {
  bytesToHex, concat, hexToBytes, keccak256, toBytes,
} from "viem";
import type { Address, Hex } from "viem";
import { SHARE_BYTES } from "./kms";

// --- A minimal bincode (legacy config: little-endian, u64 lengths) reader ----------------------

type Parser<T> = (bytes: Uint8Array, at: number) => readonly [T, number];

const u32: Parser<number> = (bytes, at) => [new DataView(bytes.buffer, bytes.byteOffset).getUint32(at, true), at + 4];
const u64: Parser<number> = (bytes, at) =>
  [Number(new DataView(bytes.buffer, bytes.byteOffset).getBigUint64(at, true)), at + 8];
const fixed = (length: number): Parser<Uint8Array> => (bytes, at) => [bytes.slice(at, at + length), at + length];
const vecBytes: Parser<Uint8Array> = (bytes, at) => {
  const [length, start] = u64(bytes, at);
  return fixed(length)(bytes, start);
};
const vecOf = <T>(item: Parser<T>): Parser<T[]> => (bytes, at) => {
  const [count, start] = u64(bytes, at);
  return Array.from({ length: count }).reduce<readonly [T[], number]>(([items, offset]) => {
    const [value, next] = item(bytes, offset);
    return [[...items, value], next];
  }, [[], start]);
};

interface SigncryptedCiphertext { fheType: number; signcrypted: Uint8Array }

const signcryptedCiphertext: Parser<SigncryptedCiphertext> = (bytes, at) => {
  const [fheType, a] = u32(bytes, at);
  const [signcrypted, b] = vecBytes(bytes, a);
  const [, c] = vecBytes(bytes, b); // external_handle
  const [, d] = u32(bytes, c); // packing_factor
  return [{ fheType, signcrypted }, d];
};

const responsePayload: Parser<{ ciphertexts: SigncryptedCiphertext[]; partyId: number; degree: number }> = (bytes, at) => {
  const [, a] = vecBytes(bytes, at); // verification_key
  const [, b] = vecBytes(bytes, a); // digest
  const [ciphertexts, c] = vecOf(signcryptedCiphertext)(bytes, b);
  const [partyId, d] = u32(bytes, c);
  const [degree, e] = u32(bytes, d);
  return [{ ciphertexts, partyId, degree }, e];
};

const hybridKemCt: Parser<{ nonce: Uint8Array; kemCt: Uint8Array; payloadCt: Uint8Array }> = (bytes, at) => {
  const [nonce, a] = fixed(12)(bytes, at);
  const [kemCt, b] = vecBytes(bytes, a);
  const [payloadCt, c] = vecBytes(bytes, b);
  return [{ nonce, kemCt, payloadCt }, c];
};

// --- The user decryption ------------------------------------------------------------------------

/** One KMS node's response, as the relayer returns it. */
export interface KmsResponse {
  payload: Hex;
  signature: Hex;
}

/** A user decryption of `handle` for `user`: the request's ML-KEM key pair and the nodes' responses. */
export interface UserDecryption {
  handle: Hex;
  user: Address;
  /** The request's public key exactly as signed in the EIP-712 request (tfhe safe serialization). */
  publicKey: Hex;
  /** bincode ML-KEM-512 decapsulation key: u64 length ‖ 1632 bytes. */
  encSk: Hex;
  responses: KmsResponse[];
}

export interface DecryptedShare {
  party: number;
  degree: number;
  share: Hex;
  /** The node's inner ECDSA signature, r ‖ s. */
  signature: Hex;
}

const SIG_BYTES = 64;
/** The plaintext ends in the 64-byte signature and a 32-byte server-key digest. */
const TRAILER_BYTES = SIG_BYTES + 32;
/** FIPS 203 ML-KEM-512 decapsulation key: dk_pke (768) ‖ ek (800) ‖ H(ek) ‖ z. */
const EK_OFFSET = 768;
const EK_BYTES = 800;

const decapsulationKey = (encSk: Hex): Uint8Array => {
  const [dk] = vecBytes(hexToBytes(encSk), 0);
  if (dk.length !== 1632) throw new Error(`ML-KEM-512 decapsulation key has ${dk.length} bytes`);
  return dk;
};

/** H(enc_key) as the nodes sign it: SHAKE-256("SIGNCRYP" ‖ bincode(encapsulation key)), 32 bytes. */
export const encKeyHash = (encapsulationKey: Uint8Array): Hex => {
  const length = new Uint8Array(8);
  new DataView(length.buffer).setBigUint64(0, BigInt(encapsulationKey.length), true);
  return bytesToHex(shake256(concat([toBytes("SIGNCRYP"), length, encapsulationKey]), { dkLen: 32 }));
};

/** Decrypts one node's euint64 share. Checks only the layout: the inner signature, which the
 *  contract (or the circuit's public digests) checks, is what authenticates the share. */
export const decryptShare = (payload: Hex, dk: Uint8Array): DecryptedShare => {
  const [{ ciphertexts, partyId, degree }] = responsePayload(hexToBytes(payload), 0);
  const [ciphertext] = ciphertexts;
  if (ciphertexts.length !== 1 || ciphertext === undefined) {
    throw new Error("expected exactly one signcrypted ciphertext");
  }
  const [{ nonce, kemCt, payloadCt }] = hybridKemCt(ciphertext.signcrypted, 0);
  const shared = ml_kem512.decapsulate(kemCt, dk);
  const plain = gcm(shared.slice(0, 32), nonce).decrypt(payloadCt);
  const msg = plain.slice(0, plain.length - TRAILER_BYTES);
  const [bytesLength] = u64(msg, 0);
  const [elements] = u64(msg, 8);
  if (bytesLength !== SHARE_BYTES + 8 || elements !== 4) throw new Error("not a euint64 share of 4 ring elements");
  return {
    party: partyId,
    degree,
    share: bytesToHex(msg.slice(16, 16 + SHARE_BYTES)),
    signature: bytesToHex(plain.slice(msg.length, msg.length + SIG_BYTES)),
  };
};

/** Decrypts every node's share, and derives the request-key values the nodes signed over. */
export const decryptUserDecryption = (decryption: UserDecryption): {
  shares: DecryptedShare[];
  pkKeccak: Hex;
  encKeyHash: Hex;
} => {
  const dk = decapsulationKey(decryption.encSk);
  const ek = dk.slice(EK_OFFSET, EK_OFFSET + EK_BYTES);
  const publicKey = hexToBytes(decryption.publicKey);
  if (bytesToHex(publicKey.slice(publicKey.length - EK_BYTES)) !== bytesToHex(ek)) {
    throw new Error("publicKey does not carry encSk's encapsulation key");
  }
  return {
    shares: decryption.responses.map((r) => decryptShare(r.payload, dk)),
    pkKeccak: keccak256(publicKey),
    encKeyHash: encKeyHash(ek),
  };
};
