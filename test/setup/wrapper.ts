/**
 * A `SingleTxUnwrapWrapper` over a mock USDC, on a fresh FHEVM environment, with the helpers every
 * test needs: fund a holder, read their balance, and play the KMS for a user decryption of it.
 */
import { existsSync } from "node:fs";
import path from "node:path";
import type { Address, Hex, TransactionReceipt } from "viem";
import { prepareFromShares } from "../../src/client";
import type { PreparedUnwrap } from "../../src/client";
import { publicInputs } from "../../src/kms";
import { getOrDeployCircomUnwrapVerifier } from "../../src/deployers/CircomUnwrapVerifier";
import { getOrDeployMockERC20 } from "../../src/deployers/MockERC20";
import { getOrDeployMockUnwrapProofVerifier } from "../../src/deployers/MockUnwrapProofVerifier";
import { getOrDeploySingleTxUnwrapWrapper } from "../../src/deployers/SingleTxUnwrapWrapper";
import { getOrDeployUnwrapGroth16Verifier } from "../../src/deployers/UnwrapGroth16Verifier";
import { getOrDeployUnwrapHonkVerifier } from "../../src/deployers/UnwrapHonkVerifier";
import { CIRCOM_BUILD, NOIR_DIR } from "../../src/prove";
import {
  createEnvironment, fheTxOpts, txOpts,
} from "./environment";
import type { Environment, WalletWithAccount } from "./environment";
import { simulateUserDecryption } from "./kms-simulator";

export type ProofSystem = "mock" | "noir" | "circom";

const onPath = (binary: string): boolean =>
  (process.env.PATH ?? "").split(path.delimiter).some((dir) => existsSync(path.join(dir, binary)));

/** Whether the real provers can run here: nargo + bb on PATH, and the circom build (proving key). */
export const canProveNoir = (): boolean => onPath("nargo") && onPath("bb") && existsSync(path.join(NOIR_DIR, "Nargo.toml"));
export const canProveCircom = (): boolean => existsSync(path.join(CIRCOM_BUILD, "unwrap.zkey"));

export const deployerOptions = (env: Environment) => ({
  walletClient: env.deployer,
  publicClient: env.publicClient,
  store: env.store,
  redeploymentStrategy: "always",
} as const);

/** The `IUnwrapProofVerifier` for a proof system: a registry mock, or the generated verifier. */
export const deployProofVerifier = async (env: Environment, system: ProofSystem): Promise<Address> => {
  const opts = deployerOptions(env);
  if (system === "noir") return (await getOrDeployUnwrapHonkVerifier({ ...opts, args: [] })).contract.address;
  if (system === "circom") {
    const { contract: groth16 } = await getOrDeployUnwrapGroth16Verifier({ ...opts, args: [] });
    return (await getOrDeployCircomUnwrapVerifier({ ...opts, args: [groth16.address] })).contract.address;
  }
  return (await getOrDeployMockUnwrapProofVerifier({ ...opts, args: [] })).contract.address;
};

export const setupWrapper = async ({ system = "mock" }: { system?: ProofSystem } = {}) => {
  const env = await createEnvironment();
  const opts = deployerOptions(env);
  const { contract: usdc } = await getOrDeployMockERC20({ ...opts, args: ["USD Coin", "USDC", 6] });
  const { contract: mockVerifier } = await getOrDeployMockUnwrapProofVerifier({ ...opts, args: [] });
  const verifier = system === "mock" ? mockVerifier.address : await deployProofVerifier(env, system);
  const { contract: wrapper } = await getOrDeploySingleTxUnwrapWrapper({
    ...opts,
    args: [usdc.address, "Confidential USDC", "cUSDC", verifier],
  });

  const sendAndWait = async (tx: Promise<Hex>): Promise<TransactionReceipt> => {
    const receipt = await env.publicClient.waitForTransactionReceipt({ hash: await tx });
    if (receipt.status !== "success") throw new Error(`transaction ${receipt.transactionHash} to ${receipt.to} reverted`);
    return receipt;
  };

  /** Mints `amount` USDC to `holder` and wraps all of it. */
  const fund = async (holder: WalletWithAccount, amount: bigint): Promise<void> => {
    await sendAndWait(usdc.write.mint([holder.account.address, amount], txOpts(holder.account)));
    await sendAndWait(usdc.write.approve([wrapper.address, amount], txOpts(holder.account)));
    await sendAndWait(wrapper.write.wrap([holder.account.address, amount], fheTxOpts(holder.account)));
  };

  const balanceHandle = (holder: Address): Promise<Hex> => wrapper.read.confidentialBalanceOf([holder]);
  const decryptBalance = async (holder: WalletWithAccount): Promise<bigint> =>
    env.userDecrypt(await balanceHandle(holder.account.address), wrapper.address, holder);

  /**
   * What the holder gets from a user decryption of their live balance: the 13 simulated KMS nodes
   * share `balance` and sign, and the client prepares the unwrap of `amount` from 9 of the shares.
   */
  const userDecryption = async (params: {
    holder: Address;
    balance: bigint;
    amount: bigint;
    parties?: readonly number[];
  }): Promise<PreparedUnwrap> => {
    const [kms, handle] = await Promise.all([env.kms(), balanceHandle(params.holder)]);
    const decryption = await simulateUserDecryption({
      value: params.balance,
      handle,
      user: params.holder,
      decryptionDomainSeparator: kms.decryptionDomainSeparator,
      parties: params.parties,
    });
    return prepareFromShares({
      handle,
      user: params.holder,
      amount: params.amount,
      shares: decryption.shares,
      pkKeccak: decryption.pkKeccak,
      encKeyHash: decryption.encKeyHash,
      kmsSigners: kms.signers,
      decryptionDomainSeparator: kms.decryptionDomainSeparator,
    });
  };

  /** Stand-in for "the holder ran a prover": registers the statement's public inputs with the mock. */
  const proveOnMock = async (prepared: PreparedUnwrap): Promise<void> => {
    await sendAndWait(mockVerifier.write.prove([publicInputs(prepared.witness)], txOpts(env.deployer.account)));
  };

  /** Someone sends `to` an encrypted zero — which still replaces `to`'s balance handle. */
  const sendEncryptedZero = async (sender: WalletWithAccount, to: Address): Promise<void> => {
    const { handle, inputProof } = await env.encryptUint64(0n, wrapper.address, sender.account.address);
    await sendAndWait(wrapper.write.confidentialTransfer([to, handle, inputProof], fheTxOpts(sender.account)));
  };

  return {
    env,
    usdc,
    wrapper,
    mockVerifier,
    sendAndWait,
    fund,
    balanceHandle,
    decryptBalance,
    userDecryption,
    proveOnMock,
    sendEncryptedZero,
  };
};
