import {
  BaseError, ContractFunctionRevertedError, decodeErrorResult,
} from "viem";
import type { Abi, Hex } from "viem";

const revertData = (error: unknown): Hex | undefined => {
  if (error instanceof BaseError) {
    const reverted = error.walk((e) => e instanceof ContractFunctionRevertedError);
    if (reverted instanceof ContractFunctionRevertedError && reverted.raw !== undefined && reverted.raw !== "0x") {
      return reverted.raw;
    }
  }
  // tevm surfaces some reverts only as "custom error 0x…" in the message.
  const match = (error instanceof Error ? error.message : String(error)).match(/custom error (0x[0-9a-fA-F]+)/);
  return match?.[1] === undefined ? undefined : `0x${match[1].slice(2)}`;
};

/** Requires `call` to revert with the custom error `errorName` of `abi`. */
export const expectRevert = async (call: Promise<unknown>, abi: Abi, errorName: string): Promise<void> => {
  const outcome = await call.then(() => "succeeded" as const, (error: unknown) => error);
  if (outcome === "succeeded") throw new Error(`expected a revert with ${errorName}`);
  const data = revertData(outcome);
  const decoded = data === undefined ? undefined : decodeErrorResult({ abi, data }).errorName;
  if (decoded !== errorName) {
    throw new Error(`expected ${errorName}, got ${decoded ?? (outcome instanceof Error ? outcome.message : String(outcome))}`);
  }
};
