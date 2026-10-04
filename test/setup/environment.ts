/**
 * An in-memory EVM (tevm) with Zama's FHEVM host contracts — `ACL`, `FHEVMExecutor`, `KMSVerifier`,
 * `InputVerifier` from `@fhevm/host-contracts` — installed by `fhevm-tevm-mocks`, the same mock
 * coprocessor the FHEVM Hardhat plugin uses.
 *
 * The KMS is shaped like Zama's networks today (13 nodes, public-decryption threshold 7) and the
 * tests hold the 13 node keys, so they can sign user-decryption shares exactly as the nodes do.
 */
import { createTestClients } from "@deployoor/testing";
import { Wallet } from "ethers";
import { createFhevmTevmRuntime } from "fhevm-tevm-mocks";
import { createCommon } from "tevm/common";
import {
  bytesToHex, getAddress, keccak256, parseAbi, toHex,
} from "viem";
import type {
  Account, Address, Hex, PublicClient, WalletClient,
} from "viem";
import { hardhat } from "viem/chains";
import { decryptionDomainSeparator } from "../../src/kms";

export type WalletWithAccount = WalletClient & { account: Account };

export const KMS_NODES = 13;
export const KMS_PUBLIC_DECRYPTION_THRESHOLD = 7;
export const KMS_NODE_KEYS: readonly Hex[] = Array.from(
  { length: KMS_NODES },
  (_, i) => keccak256(toHex(`erc-7984-single-tx-unwrap/kms-node-${i + 1}`)),
);
/** FHE transactions the gas estimator under-shoots get an explicit limit. */
export const FHE_GAS = 15_000_000n;

const kmsVerifierAbi = parseAbi([
  "function getKmsSigners() view returns (address[])",
  "function eip712Domain() view returns (bytes1, string, string, uint256, address, bytes32, uint256[])",
]);

export const createEnvironment = async () => {
  const clients = await createTestClients({ common: createCommon({ ...hardhat }) });
  const runtime = await createFhevmTevmRuntime(clients.tevm, {
    fhevm: {
      kmsSigners: KMS_NODE_KEYS.map((key) => new Wallet(key)),
      kmsThreshold: KMS_PUBLIC_DECRYPTION_THRESHOLD,
    },
  });
  const publicClient: PublicClient = runtime.publicClient;
  const { instance, addresses } = runtime.fhevm;
  const walletAt = (index: number): WalletWithAccount => {
    const account = runtime.accounts[index];
    if (account === undefined) throw new Error(`no prefunded account at index ${index}`);
    return runtime.walletClientFor(account) as WalletWithAccount;
  };

  const readKms = <const F extends "getKmsSigners" | "eip712Domain">(functionName: F) => publicClient.readContract({
    address: addresses.KMSVerifierAddress,
    abi: kmsVerifierAbi,
    functionName,
  });

  /** `KMSVerifier.getKmsSigners()` (party order) and the Gateway `Decryption` domain separator. */
  const kms = async (): Promise<{ signers: Address[]; decryptionDomainSeparator: Hex }> => {
    const [signers, domain] = await Promise.all([readKms("getKmsSigners"), readKms("eip712Domain")]);
    return {
      signers: [...signers],
      decryptionDomainSeparator: decryptionDomainSeparator(domain[3], domain[4]),
    };
  };

  /** An encrypted euint64 input for `contract`, from `user`. */
  const encryptUint64 = async (value: bigint, contract: Address, user: Address): Promise<{ handle: Hex; inputProof: Hex }> => {
    const encrypted = await instance.createEncryptedInput(getAddress(contract), getAddress(user)).add64(value).encrypt();
    const [handle] = encrypted.handles;
    if (handle === undefined) throw new Error("no handle");
    return { handle: bytesToHex(handle), inputProof: bytesToHex(encrypted.inputProof) };
  };

  /** Public decryption with the KMS proof `finalizeUnwrap` checks. */
  const publicDecrypt = async (handle: Hex): Promise<{ cleartext: bigint; decryptionProof: Hex }> => {
    const result = await instance.publicDecrypt([handle]);
    const cleartext = result.clearValues[handle];
    if (cleartext === undefined) throw new Error(`no cleartext for ${handle}`);
    return { cleartext: BigInt(cleartext), decryptionProof: result.decryptionProof as Hex };
  };

  /** The holder's own view of a handle, through a regular user decryption. */
  const userDecrypt = async (handle: Hex, contract: Address, holder: WalletWithAccount): Promise<bigint> => {
    const keypair = instance.generateKeypair();
    const startTimestamp = Math.floor(Date.now() / 1000);
    const durationDays = 1;
    const eip712 = instance.createEIP712(keypair.publicKey, [getAddress(contract)], startTimestamp, durationDays);
    const { EIP712Domain: _domain, ...types } = eip712.types;
    const signature = await holder.signTypedData({
      account: holder.account,
      domain: eip712.domain,
      types,
      primaryType: eip712.primaryType,
      message: {
        ...eip712.message,
        startTimestamp: BigInt(eip712.message.startTimestamp),
        durationDays: BigInt(eip712.message.durationDays),
      },
    });
    const values = await instance.userDecrypt(
      [{ handle, contractAddress: getAddress(contract) }],
      keypair.privateKey,
      keypair.publicKey,
      signature,
      [getAddress(contract)],
      getAddress(holder.account.address),
      startTimestamp,
      durationDays,
    );
    const value = values[handle];
    if (value === undefined) throw new Error(`no value for ${handle}`);
    return BigInt(value);
  };

  return {
    publicClient,
    store: clients.store,
    chain: runtime.chain,
    deployer: walletAt(0),
    alice: walletAt(1),
    bob: walletAt(2),
    carol: walletAt(3),
    walletAt,
    kms,
    encryptUint64,
    publicDecrypt,
    userDecrypt,
  };
};

export type Environment = Awaited<ReturnType<typeof createEnvironment>>;

export const txOpts = (account: Account) => ({ account, chain: hardhat });
export const fheTxOpts = (account: Account) => ({ ...txOpts(account), gas: FHE_GAS });
