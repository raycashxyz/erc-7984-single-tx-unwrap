/**
 * Glamsterdam repricing estimate for a mined transaction, from its prestate diff.
 *
 * Prices only what the fork changes for these transactions — intrinsic gas (EIP-2780), cold account
 * access and storage writes (EIP-8038), new state (EIP-8037) and the calldata floor (EIP-7976) — with
 * the values on the execution-specs `forks/amsterdam` branch (2026-10-02; 8037/8038 not final).
 * Opcode and precompile prices (MULMOD, ecMul, ecPairing, MODEXP, SHA-256, ecrecover) and standard
 * calldata pricing are unchanged. Cold-vs-warm write pricing and the refund cap are approximated.
 */

import { z } from "zod";
import type { Address } from "viem";

const accountState = z.object({ storage: z.record(z.string(), z.string()).default({}) });

/** `debug_traceTransaction` with `prestateTracer` in diff mode: every touched account before, changes after. */
export const prestateDiff = z.object({
  pre: z.record(z.string(), accountState),
  post: z.record(z.string(), accountState),
});
export type PrestateDiff = z.infer<typeof prestateDiff>;

export const GLAMSTERDAM = {
  /** EIP-2780: 21,000 → 15,000 for a zero-value contract call. */
  intrinsicDelta: -6_000n,
  /** EIP-8038: cold account access 2,600 → 3,000. */
  coldAccountDelta: 400n,
  /** EIP-8037 + EIP-8038: SSTORE 0 → non-zero 22,100 → 110,020 (97,920 of it state gas). */
  newSlotDelta: 87_920n,
  /** EIP-8038: SSTORE non-zero → other 5,000 → 12,100. */
  changedSlotDelta: 7_100n,
  /** EIP-8038: storage-clear refund 4,800 → 11,616. */
  clearRefundDelta: 6_816n,
  /** EIP-7976: calldata floor 15,000 + 64 gas per byte. */
  floorBase: 15_000n,
  floorPerByte: 64n,
} as const;

export interface StorageWrites {
  newSlots: number;
  changedSlots: number;
  clearedSlots: number;
  coldAccounts: number;
}

const isZero = (value: string): boolean => BigInt(value === "0x" ? "0x0" : value) === 0n;

/** Lowest non-precompile address: 0x00…00 (tevm's coinbase) through 0xff are warm or precompiles. */
const FIRST_CONTRACT_ADDRESS = 0x100n;

/**
 * Classifies every slot the transaction wrote (pre vs post) and counts the accounts it touched other
 * than `warm` (sender and recipient), the coinbase and precompiles — each a cold access.
 */
export const storageWrites = (diff: PrestateDiff, warm: readonly Address[]): StorageWrites => {
  const writes = Object.entries(diff.post).flatMap(([address, account]) => {
    const before = diff.pre[address] ?? { storage: {} };
    return Object.entries(account.storage).map(([slot, after]) => ({
      before: isZero(before.storage[slot] ?? "0x0"),
      after: isZero(after),
    }));
  });
  const warmSet = new Set(warm.map((a) => a.toLowerCase()));
  return {
    newSlots: writes.filter((w) => w.before && !w.after).length,
    changedSlots: writes.filter((w) => !w.before && !w.after).length,
    clearedSlots: writes.filter((w) => !w.before && w.after).length,
    coldAccounts: Object.keys(diff.pre)
      .filter((a) => !warmSet.has(a.toLowerCase()) && BigInt(a) >= FIRST_CONTRACT_ADDRESS).length,
  };
};

/** `gasUsed` today → estimated gas after Glamsterdam, given the transaction's writes and calldata size. */
export const glamsterdamGas = (gasUsed: bigint, writes: StorageWrites, calldataBytes: number): bigint => {
  const repriced = gasUsed
    + GLAMSTERDAM.intrinsicDelta
    + BigInt(writes.coldAccounts) * GLAMSTERDAM.coldAccountDelta
    + BigInt(writes.newSlots) * GLAMSTERDAM.newSlotDelta
    + BigInt(writes.changedSlots + writes.clearedSlots) * GLAMSTERDAM.changedSlotDelta
    - BigInt(writes.clearedSlots) * GLAMSTERDAM.clearRefundDelta;
  const floor = GLAMSTERDAM.floorBase + BigInt(calldataBytes) * GLAMSTERDAM.floorPerByte;
  return repriced > floor ? repriced : floor;
};
