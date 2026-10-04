/**
 * Plays the 13 KMS nodes of a user decryption in tests: Shamir-shares a value over GR(2^128, 4),
 * and signs each node's share the way the node does (sign-then-encrypt; the encryption to the
 * user is skipped because the test is the user). Output has the same shape as
 * `decryptUserDecryption`, so tests go through the same client code as real KMS data.
 */
import { concat, keccak256, toHex } from "viem";
import type { Address, Hex } from "viem";
import { sign } from "viem/accounts";
import {
  DEGREE, ELEMENTS, encodeUint64, shareDigest, userDecryptionLink,
} from "../../src/kms";
import type { DecryptedShare } from "../../src/response";
import {
  evaluate, partyPoint, toBytes, ZERO,
} from "../../src/ring";
import type { Gr } from "../../src/ring";
import { KMS_NODE_KEYS } from "./environment";

const MASK128 = (1n << 128n) - 1n;

export interface SimulatedDecryption {
  shares: DecryptedShare[];
  pkKeccak: Hex;
  encKeyHash: Hex;
}

export const simulateUserDecryption = async (params: {
  value: bigint;
  handle: Hex;
  user: Address;
  decryptionDomainSeparator: Hex;
  parties?: readonly number[];
  seed?: string;
}): Promise<SimulatedDecryption> => {
  const parties = params.parties ?? [1, 2, 3, 4, 5, 6, 7, 8, 9];
  const seed = params.seed ?? `${params.handle}/${params.user}`;
  const random = (label: string, i: number): bigint => BigInt(keccak256(toHex(`${seed}/${label}/${i}`))) & MASK128;
  const secret = encodeUint64(params.value, (block) => random("noise", block));
  const coefficient = (k: number, j: number) => (a: number): bigint => random("coefficients", (k * ELEMENTS + j) * 4 + a);
  const poly: Gr[][] = [secret, ...Array.from({ length: DEGREE }, (_, k) => Array.from({ length: ELEMENTS }, (_, j): Gr => {
    const c = coefficient(k, j);
    return [c(0), c(1), c(2), c(3)];
  }))];
  const pkKeccak = keccak256(toHex(`${seed}/ml-kem-public-key`));
  const encKeyHash = keccak256(toHex(`${seed}/H(enc_key)`));
  const link = userDecryptionLink({
    handle: params.handle,
    user: params.user,
    pkKeccak,
    decryptionDomainSeparator: params.decryptionDomainSeparator,
  });
  const shares = await Promise.all(parties.map(async (party): Promise<DecryptedShare> => {
    const share = concat(Array.from({ length: ELEMENTS }, (_, j) =>
      toHex(toBytes(evaluate(poly.map((row) => row[j] ?? ZERO), partyPoint(party))))));
    const key = KMS_NODE_KEYS[party - 1];
    if (key === undefined) throw new Error(`no KMS node ${party}`);
    const { r, s } = await sign({
      hash: shareDigest({
        share,
        link,
        user: params.user,
        encKeyHash,
      }),
      privateKey: key,
    });
    return {
      party,
      degree: DEGREE,
      share,
      signature: concat([r, s]),
    };
  }));
  return { shares, pkKeccak, encKeyHash };
};
