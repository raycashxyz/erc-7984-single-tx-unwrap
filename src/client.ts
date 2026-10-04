/**
 * The holder's side, end to end: a KMS user decryption in, the `SingleTxUnwrapWrapper` arguments
 * out. Everything here runs off-chain, locally — the shares never leave the holder's machine on the
 * proof path.
 */
import { bytesToHex, concat, recoverAddress, toHex } from "viem";
import type { Address, Hex } from "viem";
import { SHARES } from "./kms";
import { decryptUserDecryption } from "./response";
import type { DecryptedShare, UserDecryption } from "./response";
import { toBytes as grToBytes } from "./ring";
import { unwrapWitness } from "./witness";
import type { UnwrapWitness } from "./witness";

export type Nine<T> = readonly [T, T, T, T, T, T, T, T, T];

export const nine = <T>(xs: readonly T[]): Nine<T> => {
  const [a, b, c, d, e, f, g, h, i] = xs;
  if (xs.length !== SHARES || a === undefined || b === undefined || c === undefined || d === undefined
    || e === undefined || f === undefined || g === undefined || h === undefined || i === undefined) {
    throw new Error(`expected ${SHARES} elements, got ${xs.length}`);
  }
  return [a, b, c, d, e, f, g, h, i];
};

/** `SingleTxUnwrapWrapper.SignedDigests`: what {unwrapWithProof} checks the KMS signatures over. */
export interface SignedDigests {
  parties: Nine<number>;
  digests: Nine<Hex>;
  signatures: Hex;
  pkKeccak: Hex;
}

/** `SingleTxUnwrapWrapper.RevealedShares`: what {unwrapAllWithShares} reconstructs from. */
export interface RevealedShares {
  parties: Nine<number>;
  shares: Hex;
  signatures: Hex;
  poly: Hex;
  pkKeccak: Hex;
  encKeyHash: Hex;
}

/**
 * The KMS signs r ‖ s; the contract takes r ‖ s ‖ v so one `ecrecover` per share suffices. Finds the
 * parity under which `signature` over `digest` recovers to `signer`.
 */
export const withRecoveryByte = async (params: { digest: Hex; signature: Hex; signer: Address }): Promise<Hex> => {
  const r = `0x${params.signature.slice(2, 66)}` as const;
  const s = `0x${params.signature.slice(66, 130)}` as const;
  const recovered = await Promise.all([0, 1].map((yParity) =>
    recoverAddress({ hash: params.digest, signature: { r, s, yParity } })));
  const yParity = recovered.findIndex((a) => a.toLowerCase() === params.signer.toLowerCase());
  if (yParity < 0) throw new Error(`signature over ${params.digest} is not from ${params.signer}`);
  return concat([r, s, toHex(27 + yParity, { size: 1 })]);
};

export interface PreparedUnwrap {
  witness: UnwrapWitness;
  signed: SignedDigests;
  revealed: RevealedShares;
}

/**
 * Builds the witness and both calldata shapes from decrypted shares. `kmsSigners` is
 * `KMSVerifier.getKmsSigners()` (party p is `kmsSigners[p - 1]`).
 */
export const prepareFromShares = async (params: {
  handle: Hex;
  user: Address;
  amount: bigint;
  shares: readonly DecryptedShare[];
  pkKeccak: Hex;
  encKeyHash: Hex;
  kmsSigners: readonly Address[];
  decryptionDomainSeparator: Hex;
}): Promise<PreparedUnwrap> => {
  const witness = unwrapWitness(params);
  const used = params.shares.slice(0, SHARES);
  const signatures = await Promise.all(used.map((s, i) => {
    const signer = params.kmsSigners[s.party - 1];
    const digest = witness.digests[i];
    if (signer === undefined || digest === undefined) throw new Error(`unknown KMS party ${s.party}`);
    return withRecoveryByte({ digest, signature: s.signature, signer });
  }));
  const parties = nine(witness.parties);
  return {
    witness,
    signed: {
      parties,
      digests: nine(witness.digests),
      signatures: concat(signatures),
      pkKeccak: params.pkKeccak,
    },
    revealed: {
      parties,
      shares: concat(witness.shares),
      signatures: concat(signatures),
      poly: bytesToHex(Uint8Array.from(witness.poly.flat().flatMap((g) => Array.from(grToBytes(g))))),
      pkKeccak: params.pkKeccak,
      encKeyHash: params.encKeyHash,
    },
  };
};

/** Same, straight from the relayer's user-decryption response and the request's key pair. */
export const prepareUnwrap = (params: {
  decryption: UserDecryption;
  amount: bigint;
  kmsSigners: readonly Address[];
  decryptionDomainSeparator: Hex;
}): Promise<PreparedUnwrap> => {
  const { shares, pkKeccak, encKeyHash } = decryptUserDecryption(params.decryption);
  return prepareFromShares({
    handle: params.decryption.handle,
    user: params.decryption.user,
    amount: params.amount,
    shares,
    pkKeccak,
    encKeyHash,
    kmsSigners: params.kmsSigners,
    decryptionDomainSeparator: params.decryptionDomainSeparator,
  });
};
