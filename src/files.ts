/** JSON shapes of the inputs and outputs the scripts and tests exchange. */
import { z } from "zod";
import type { Address, Hex } from "viem";

const hex = z.string().regex(/^0x[0-9a-fA-F]*$/).transform((s): Hex => `0x${s.slice(2)}`);
const address = z.string().regex(/^0x[0-9a-fA-F]{40}$/).transform((s): Address => `0x${s.slice(2)}`);

/** A user decryption as the client holds it: the relayer's responses plus the request's key pair. */
export const userDecryptionFile = z.object({
  handle: hex,
  user: address,
  kmsSigners: z.array(address),
  gatewayChainId: z.number().transform(BigInt),
  gatewayDecryption: address,
  publicKey: hex,
  encSk: hex,
  responses: z.array(z.object({ payload: hex, signature: hex })),
});

/** `scripts/prove.ts` output: a proof and the public inputs the wrapper will recompute. */
export const proofFile = z.object({
  system: z.enum(["noir", "circom"]),
  amount: z.string().transform(BigInt),
  proof: hex,
  publicInputs: z.array(hex),
  provingMs: z.number(),
});
