/**
 * Gas: OpenZeppelin's two-step unwrap (`unwrap` → public decryption → `finalizeUnwrap`) vs the
 * one-transaction unwraps, on a KMS shaped like Zama's networks (13 nodes, threshold 7). Each path
 * runs with its own holder and wrapper instance, so no path finds another's ACL entries written.
 *
 * The proof paths run against `MockUnwrapProofVerifier`; the real verifiers' cost is measured by
 * `VerifierGasProbe` on real proofs of the Sepolia fixture, then swapped in:
 *
 *   one-tx (real) = unwrapWithProof (mock) − probe(mock) + probe(real verifier) + calldata(real proof)
 *
 * (`test/unwrap.test.ts` runs the same transactions with real proofs end to end.) A second table
 * estimates each path after Glamsterdam from its storage writes (`test/setup/glamsterdam.ts`).
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import {
  describe, expect, it,
} from "vitest";
import {
  createClient, custom, parseEventLogs, parseUnits, rpcSchema, size,
} from "viem";
import type { Address, Hex, TransactionReceipt } from "viem";
import { prepareFromShares } from "../src/client";
import { proofFile } from "../src/files";
import { publicInputs } from "../src/kms";
import { getOrDeployCircomUnwrapVerifier } from "../src/deployers/CircomUnwrapVerifier";
import { getOrDeployMockERC20 } from "../src/deployers/MockERC20";
import { getOrDeployMockSwapPool } from "../src/deployers/MockSwapPool";
import { getOrDeployMockUnwrapProofVerifier } from "../src/deployers/MockUnwrapProofVerifier";
import { getOrDeploySingleTxUnwrapWrapper } from "../src/deployers/SingleTxUnwrapWrapper";
import { getOrDeployStandardERC7984Wrapper } from "../src/deployers/StandardERC7984Wrapper";
import { getOrDeployUnwrapAndSwap } from "../src/deployers/UnwrapAndSwap";
import { getOrDeployUnwrapGroth16Verifier } from "../src/deployers/UnwrapGroth16Verifier";
import { getOrDeployUnwrapHonkVerifier } from "../src/deployers/UnwrapHonkVerifier";
import { getOrDeployVerifierGasProbe } from "../src/deployers/VerifierGasProbe";
import {
  createEnvironment, fheTxOpts, KMS_NODES, KMS_PUBLIC_DECRYPTION_THRESHOLD, txOpts,
} from "./setup/environment";
import type { WalletWithAccount } from "./setup/environment";
import {
  glamsterdamGas, prestateDiff, storageWrites,
} from "./setup/glamsterdam";
import type { StorageWrites } from "./setup/glamsterdam";
import { simulateUserDecryption } from "./setup/kms-simulator";
import { deployerOptions } from "./setup/wrapper";

const AMOUNT = parseUnits("400", 6);
const FIXTURES = path.join(__dirname, "../fixtures/sepolia-2025-10");
const loadProof = (file: string) => proofFile.parse(JSON.parse(readFileSync(path.join(FIXTURES, file), "utf8")));

/** Intrinsic calldata gas (EIP-2028): 16 per non-zero byte, 4 per zero byte. */
const calldataGas = (data: Hex): bigint => Array.from({ length: size(data) }, (_, i) => data.slice(2 + 2 * i, 4 + 2 * i))
  .reduce((gas, byte) => gas + (byte === "00" ? 4n : 16n), 0n);
/** A `bytes` argument's ABI size: padded to whole words. */
const paddedSize = (data: Hex): number => Math.ceil(size(data) / 32) * 32;

/** tevm's `debug_traceTransaction` takes one object parameter. */
type TevmTraceSchema = [{
  Method: "debug_traceTransaction";
  Parameters: [{ transactionHash: Hex; tracer: "prestateTracer"; tracerConfig: { diffMode: true } }];
  ReturnType: unknown;
}];

const setupGas = async () => {
  const env = await createEnvironment();
  const opts = deployerOptions(env);
  const { contract: usdc } = await getOrDeployMockERC20({ ...opts, args: ["USD Coin", "USDC", 6] });
  const { contract: weth } = await getOrDeployMockERC20({ ...opts, args: ["Wrapped Ether", "WETH", 18] });
  const { contract: pool } = await getOrDeployMockSwapPool({ ...opts, args: [usdc.address, weth.address] });
  const { contract: router } = await getOrDeployUnwrapAndSwap({ ...opts, args: [] });
  const { contract: mockVerifier } = await getOrDeployMockUnwrapProofVerifier({ ...opts, args: [] });
  const { contract: honk } = await getOrDeployUnwrapHonkVerifier({ ...opts, args: [] });
  const { contract: groth16 } = await getOrDeployUnwrapGroth16Verifier({ ...opts, args: [] });
  const { contract: circom } = await getOrDeployCircomUnwrapVerifier({ ...opts, args: [groth16.address] });
  const { contract: probe } = await getOrDeployVerifierGasProbe({ ...opts, args: [] });
  const { contract: baseline } = await getOrDeployStandardERC7984Wrapper({ ...opts, args: [usdc.address, "Baseline cUSDC", "bcUSDC"] });
  // One wrapper per path: FHEVM handles are deterministic, so paths sharing a wrapper and holder
  // would find some of each other's ACL entries already written.
  const singleTxWrapper = async (symbol: string) => (await getOrDeploySingleTxUnwrapWrapper({
    ...opts,
    args: [usdc.address, `${symbol} cUSDC`, symbol, mockVerifier.address],
  })).contract;
  const proofWrapper = await singleTxWrapper("pcUSDC");
  const revealWrapper = await singleTxWrapper("rcUSDC");
  const swapWrapper = await singleTxWrapper("scUSDC");

  const sendAndWait = async (tx: Promise<Hex>): Promise<TransactionReceipt> => {
    const receipt = await env.publicClient.waitForTransactionReceipt({ hash: await tx });
    if (receipt.status !== "success") throw new Error(`transaction ${receipt.transactionHash} to ${receipt.to} reverted`);
    return receipt;
  };
  await sendAndWait(usdc.write.mint([pool.address, parseUnits("4000000", 6)], txOpts(env.deployer.account)));
  await sendAndWait(weth.write.mint([pool.address, parseUnits("1000", 18)], txOpts(env.deployer.account)));

  const fund = async (wrapper: Address, holder: WalletWithAccount, amount: bigint): Promise<void> => {
    await sendAndWait(usdc.write.mint([holder.account.address, amount], txOpts(holder.account)));
    await sendAndWait(usdc.write.approve([wrapper, amount], txOpts(holder.account)));
    await sendAndWait(holder.writeContract({
      address: wrapper,
      abi: proofWrapper.abi,
      functionName: "wrap",
      args: [holder.account.address, amount],
      ...fheTxOpts(holder.account),
    }));
  };

  /** The simulated KMS's user decryption of `holder`'s live balance on `wrapper`, prepared for `amount`. */
  const prepare = async (wrapper: typeof proofWrapper, holder: Address, balance: bigint, amount: bigint) => {
    const [kms, handle] = await Promise.all([env.kms(), wrapper.read.confidentialBalanceOf([holder])]);
    const decryption = await simulateUserDecryption({
      value: balance,
      handle,
      user: holder,
      decryptionDomainSeparator: kms.decryptionDomainSeparator,
    });
    return prepareFromShares({
      handle,
      user: holder,
      amount,
      shares: decryption.shares,
      pkKeccak: decryption.pkKeccak,
      encKeyHash: decryption.encKeyHash,
      kmsSigners: kms.signers,
      decryptionDomainSeparator: kms.decryptionDomainSeparator,
    });
  };

  const rpc = createClient({ transport: custom(env.publicClient), rpcSchema: rpcSchema<TevmTraceSchema>() });
  /** The transaction's storage writes and calldata size, replayed with tevm's prestate tracer. */
  const writesOf = async (receipt: TransactionReceipt): Promise<StorageWrites & { calldataBytes: number }> => {
    const diff = prestateDiff.parse(await rpc.request({
      method: "debug_traceTransaction",
      params: [{ transactionHash: receipt.transactionHash, tracer: "prestateTracer", tracerConfig: { diffMode: true } }],
    }));
    const { input } = await env.publicClient.getTransaction({ hash: receipt.transactionHash });
    return {
      ...storageWrites(diff, receipt.to === null ? [receipt.from] : [receipt.from, receipt.to]),
      calldataBytes: size(input),
    };
  };

  return {
    env,
    usdc,
    weth,
    pool,
    router,
    mockVerifier,
    honk,
    circom,
    probe,
    baseline,
    proofWrapper,
    revealWrapper,
    swapWrapper,
    sendAndWait,
    fund,
    prepare,
    writesOf,
  };
};

describe("gas", () => {
  it("compares the two-step unwrap with the one-transaction unwraps", async () => {
    const {
      env, usdc, weth, pool, router, mockVerifier, honk, circom, probe, baseline, proofWrapper, revealWrapper, swapWrapper,
      sendAndWait, fund, prepare, writesOf,
    } = await setupGas();
    const kms = await env.kms();
    expect(kms.signers.length).toBe(KMS_NODES);
    const [alice, bob, carol, dave] = [env.alice, env.bob, env.carol, env.walletAt(4)];

    // --- OpenZeppelin two-step: unwrap (burn + makePubliclyDecryptable) → public decryption → finalize
    await fund(baseline.address, alice, AMOUNT);
    const unwrapReceipt = await sendAndWait(baseline.write.unwrap([
      alice.account.address,
      alice.account.address,
      await baseline.read.confidentialBalanceOf([alice.account.address]),
    ], fheTxOpts(alice.account)));
    const [requested] = parseEventLogs({ abi: baseline.abi, eventName: "UnwrapRequested", logs: unwrapReceipt.logs });
    if (requested === undefined) throw new Error("no UnwrapRequested");
    const { cleartext, decryptionProof } = await env.publicDecrypt(requested.args.unwrapRequestId);
    const finalizeReceipt = await sendAndWait(baseline.write.finalizeUnwrap([
      requested.args.unwrapRequestId,
      cleartext,
      decryptionProof,
    ], fheTxOpts(alice.account)));
    expect(await usdc.read.balanceOf([alice.account.address])).toBe(AMOUNT);
    // ... and swapping what arrived takes two more transactions.
    const approveReceipt = await sendAndWait(usdc.write.approve([pool.address, AMOUNT], txOpts(alice.account)));
    const swapReceipt = await sendAndWait(pool.write.swap([usdc.address, AMOUNT, 0n, alice.account.address], fheTxOpts(alice.account)));

    // --- One transaction with a proof (mock verifier)
    await fund(proofWrapper.address, bob, AMOUNT);
    const proved = await prepare(proofWrapper, bob.account.address, AMOUNT, AMOUNT);
    await sendAndWait(mockVerifier.write.prove([publicInputs(proved.witness)], txOpts(env.deployer.account)));
    const proofReceipt = await sendAndWait(proofWrapper.write.unwrapWithProof([
      bob.account.address,
      bob.account.address,
      AMOUNT,
      proved.signed,
      "0x",
    ], fheTxOpts(bob.account)));
    expect(await usdc.read.balanceOf([bob.account.address])).toBe(AMOUNT);

    // --- One transaction, no proof
    await fund(revealWrapper.address, carol, AMOUNT);
    const revealed = await prepare(revealWrapper, carol.account.address, AMOUNT, AMOUNT);
    const revealReceipt = await sendAndWait(revealWrapper.write.unwrapAllWithShares([
      carol.account.address,
      carol.account.address,
      revealed.revealed,
    ], fheTxOpts(carol.account)));
    expect(await usdc.read.balanceOf([carol.account.address])).toBe(AMOUNT);

    // --- One transaction: unwrap and swap (mock verifier)
    await fund(swapWrapper.address, dave, AMOUNT);
    await sendAndWait(swapWrapper.write.setOperator([router.address, 2 ** 40], txOpts(dave.account)));
    const swapped = await prepare(swapWrapper, dave.account.address, AMOUNT, AMOUNT);
    await sendAndWait(mockVerifier.write.prove([publicInputs(swapped.witness)], txOpts(env.deployer.account)));
    const unwrapSwapReceipt = await sendAndWait(router.write.unwrapAndSwap([
      swapWrapper.address,
      AMOUNT,
      swapped.signed,
      "0x",
      pool.address,
      weth.address,
      0n,
    ], fheTxOpts(dave.account)));
    expect(await weth.read.balanceOf([dave.account.address])).toBeGreaterThan(0n);

    // --- Swap the mock verifier for the real ones, measured on real proofs of the Sepolia fixture
    const mockVerifyGas = await probe.read.verifyGas([mockVerifier.address, "0x", publicInputs(proved.witness)]);
    const noir = loadProof("noir-proof.json");
    const groth = loadProof("circom-proof.json");
    const honkVerifyGas = await probe.read.verifyGas([honk.address, noir.proof, noir.publicInputs]);
    const circomVerifyGas = await probe.read.verifyGas([circom.address, groth.proof, groth.publicInputs]);
    expect(honkVerifyGas).toBeGreaterThan(mockVerifyGas);
    expect(circomVerifyGas).toBeGreaterThan(mockVerifyGas);
    const withVerifier = (gas: bigint, verifyGas: bigint, proof: Hex): bigint => gas - mockVerifyGas + verifyGas + calldataGas(proof);
    const honkOneTx = withVerifier(proofReceipt.gasUsed, honkVerifyGas, noir.proof);
    const circomOneTx = withVerifier(proofReceipt.gasUsed, circomVerifyGas, groth.proof);
    const honkSwap = withVerifier(unwrapSwapReceipt.gasUsed, honkVerifyGas, noir.proof);
    const circomSwap = withVerifier(unwrapSwapReceipt.gasUsed, circomVerifyGas, groth.proof);
    const twoStep = unwrapReceipt.gasUsed + finalizeReceipt.gasUsed;
    const twoStepSwap = twoStep + approveReceipt.gasUsed + swapReceipt.gasUsed;

    console.table({
      "two-step unwrap, tx 1 (unwrap)": { gas: unwrapReceipt.gasUsed },
      "two-step unwrap, tx 2 (finalizeUnwrap, 7-of-13 KMS signatures)": { gas: finalizeReceipt.gasUsed },
      "two-step unwrap, total (2 tx)": { gas: twoStep },
      "unwrapWithProof, mock verifier": { gas: proofReceipt.gasUsed },
      "  UltraHonk verify": { gas: honkVerifyGas },
      "  UltraHonk proof calldata (9,536 bytes)": { gas: calldataGas(noir.proof) },
      "unwrapWithProof, Noir/UltraHonk (1 tx)": { gas: honkOneTx },
      "  Groth16 verify (incl. adapter)": { gas: circomVerifyGas },
      "  Groth16 proof calldata (256 bytes)": { gas: calldataGas(groth.proof) },
      "unwrapWithProof, circom/Groth16 (1 tx)": { gas: circomOneTx },
      "unwrapAllWithShares, no proof (1 tx)": { gas: revealReceipt.gasUsed },
      "two-step unwrap + approve + swap (4 tx)": { gas: twoStepSwap },
      "unwrapAndSwap, Noir/UltraHonk (1 tx)": { gas: honkSwap },
      "unwrapAndSwap, circom/Groth16 (1 tx)": { gas: circomSwap },
    });

    // --- After Glamsterdam: the same transactions, repriced from their storage writes. Real-proof
    // rows reuse the mock runs' writes (verifiers only read) and add the real proof's calldata.
    const [unwrapWrites, finalizeWrites, proofWrites, revealWrites, unwrapSwapWrites] = await Promise.all([
      writesOf(unwrapReceipt),
      writesOf(finalizeReceipt),
      writesOf(proofReceipt),
      writesOf(revealReceipt),
      writesOf(unwrapSwapReceipt),
    ]);
    const after = (gas: bigint, writes: StorageWrites & { calldataBytes: number }, extraCalldata = 0) => ({
      today: gas,
      glamsterdam: glamsterdamGas(gas, writes, writes.calldataBytes + extraCalldata),
      newSlots: writes.newSlots,
      changedSlots: writes.changedSlots,
      clearedSlots: writes.clearedSlots,
      coldAccounts: writes.coldAccounts,
    });
    const tx1 = after(unwrapReceipt.gasUsed, unwrapWrites);
    const tx2 = after(finalizeReceipt.gasUsed, finalizeWrites);
    console.table({
      "two-step unwrap, tx 1": tx1,
      "two-step unwrap, tx 2": tx2,
      "two-step unwrap, total (2 tx)": { today: twoStep, glamsterdam: tx1.glamsterdam + tx2.glamsterdam },
      "unwrapWithProof, Noir/UltraHonk (1 tx)": after(honkOneTx, proofWrites, paddedSize(noir.proof)),
      "unwrapWithProof, circom/Groth16 (1 tx)": after(circomOneTx, proofWrites, paddedSize(groth.proof)),
      "unwrapAllWithShares, no proof (1 tx)": after(revealReceipt.gasUsed, revealWrites),
      "unwrapAndSwap, Noir/UltraHonk (1 tx)": after(honkSwap, unwrapSwapWrites, paddedSize(noir.proof)),
    });
    expect(KMS_PUBLIC_DECRYPTION_THRESHOLD).toBe(7);
  });
});
