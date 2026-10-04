/**
 * Turns decrypted shares into the witness both circuits prove over, and renders it for each prover
 * (Noir `Prover.toml`, circom `input.json`).
 */
import { bytesToHex, hexToBytes } from "viem";
import type { Address, Hex } from "viem";
import {
  DEGREE, ELEMENTS, SHARES, decodeUint64, publicInputs, shareDigest, userDecryptionLink,
} from "./kms";
import {
  elementsOf, evaluate, interpolate, partyPoint, ZERO,
} from "./ring";
import type { Gr } from "./ring";

export interface UnwrapWitness {
  link: Hex;
  user: Address;
  amount: bigint;
  /** The 9 parties used, 1-based KMS party ids. */
  parties: number[];
  /** The digests those parties signed, in `parties` order. */
  digests: Hex[];
  encKeyHash: Hex;
  /** 9 × 256-byte decrypted shares, in `parties` order. */
  shares: Hex[];
  /** The sharing polynomial: (t + 1) rows × 4 ring elements, constant term first. */
  poly: Gr[][];
}

/**
 * Picks 2t + 1 shares, interpolates the sharing polynomial from t + 1 of them and checks every
 * share lies on it — the zero-error reconstruction the circuits and the contract re-check.
 */
export const unwrapWitness = (params: {
  handle: Hex;
  user: Address;
  amount: bigint;
  pkKeccak: Hex;
  encKeyHash: Hex;
  decryptionDomainSeparator: Hex;
  shares: readonly { party: number; share: Hex }[];
}): UnwrapWitness => {
  const chosen = params.shares.slice(0, SHARES);
  if (chosen.length < SHARES) throw new Error(`need ${SHARES} shares, got ${params.shares.length}`);
  const link = userDecryptionLink({
    handle: params.handle,
    user: params.user,
    pkKeccak: params.pkKeccak,
    decryptionDomainSeparator: params.decryptionDomainSeparator,
  });
  const elements = chosen.map((s) => elementsOf(hexToBytes(s.share)));
  const basis = chosen.slice(0, DEGREE + 1);
  const perElement = Array.from({ length: ELEMENTS }, (_, j) => interpolate(
    basis.map((s) => partyPoint(s.party)),
    basis.map((_, i) => elements[i]?.[j] ?? ZERO),
  ));
  const poly = Array.from({ length: DEGREE + 1 }, (_, k) => perElement.map((coefs) => coefs[k] ?? ZERO));

  const offPolynomial = chosen.find((s, i) => perElement.some((coefs, j) =>
    evaluate(coefs, partyPoint(s.party)).some((c, a) => c !== elements[i]?.[j]?.[a])));
  if (offPolynomial !== undefined) throw new Error(`party ${offPolynomial.party}'s share is off the polynomial`);
  const value = decodeUint64(poly[0] ?? []);
  if (value < params.amount) throw new Error(`the decrypted value ${value} is below ${params.amount}`);

  return {
    link,
    user: params.user,
    amount: params.amount,
    parties: chosen.map((s) => s.party),
    digests: chosen.map((s) => shareDigest({
      share: s.share,
      link,
      user: params.user,
      encKeyHash: params.encKeyHash,
    })),
    encKeyHash: params.encKeyHash,
    shares: chosen.map((s) => s.share),
    poly,
  };
};

export const witnessPublicInputs = (w: UnwrapWitness): Hex[] => publicInputs(w);

const hexOf = (v: bigint): string => `"0x${v.toString(16)}"`;
const byteList = (bytes: Uint8Array): string => `[${Array.from(bytes).join(", ")}]`;
const halvesOf = (word: Hex): [bigint, bigint] => [BigInt(word) >> 128n, BigInt(word) & ((1n << 128n) - 1n)];

/** `circuits/noir`'s Prover.toml. */
export const noirProverToml = (w: UnwrapWitness): string => {
  const [linkHi, linkLo] = halvesOf(w.link);
  const encWords = Array.from({ length: 8 }, (_, k) => BigInt(bytesToHex(hexToBytes(w.encKeyHash).slice(4 * k, 4 * k + 4))));
  return [
    `link = [${hexOf(linkHi)}, ${hexOf(linkLo)}]`,
    `user = ${hexOf(BigInt(w.user))}`,
    `amount = "${w.amount}"`,
    `parties = [${w.parties.join(", ")}]`,
    `digests = [\n${w.digests.map((d) => `  [${halvesOf(d).map(hexOf).join(", ")}],`).join("\n")}\n]`,
    `enc_key_hash = [${encWords.join(", ")}]`,
    `shares = [\n${w.shares.map((s) => `  ${byteList(hexToBytes(s))},`).join("\n")}\n]`,
    `poly = [\n${w.poly.map((row) => `  [${row.map((g) => `[${g.map(hexOf).join(", ")}]`).join(", ")}],`).join("\n")}\n]`,
  ].join("\n") + "\n";
};

/** `circuits/circom`'s input.json (decimal strings). */
export const circomInput = (w: UnwrapWitness): Record<string, unknown> => {
  const dec = (v: bigint): string => v.toString();
  return {
    link: halvesOf(w.link).map(dec),
    user: dec(BigInt(w.user)),
    amount: dec(w.amount),
    parties: w.parties.map(String),
    digests: w.digests.map((d) => halvesOf(d).map(dec)),
    encKeyHash: halvesOf(w.encKeyHash).map(dec),
    shares: w.shares.map((s) => Array.from(hexToBytes(s)).map(String)),
    poly: w.poly.map((row) => row.map((g) => g.map(dec))),
  };
};
