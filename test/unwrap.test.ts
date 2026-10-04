/**
 * `SingleTxUnwrapWrapper` on the FHEVM mock, with a 13-node KMS the tests play: the holder's balance
 * handle is shared and signed exactly as the nodes do it, and the client prepares the unwrap from
 * those shares.
 *
 * `MockUnwrapProofVerifier` stands in for the prover in most tests (a proof exists only for public
 * inputs a test registers). The last two suites prove for real with the Noir and circom circuits
 * when the toolchains are present (`nargo` + `bb` on PATH; `scripts/build-circom.sh` run).
 */
import {
  describe, expect, it,
} from "vitest";
import { hexToBytes, toHex, zeroAddress } from "viem";
import { nine } from "../src/client";
import { proveCircom, proveNoir } from "../src/prove";
import { expectRevert } from "./setup/assertions";
import { fheTxOpts, txOpts } from "./setup/environment";
import {
  canProveCircom, canProveNoir, setupWrapper,
} from "./setup/wrapper";

describe("unwrapWithProof", () => {
  it("burns the amount and releases the underlying in one transaction", async () => {
    const {
      env: { alice }, usdc, wrapper, fund, decryptBalance, userDecryption, proveOnMock, sendAndWait,
    } = await setupWrapper();
    await fund(alice, 1_000n);
    expect(await decryptBalance(alice)).toBe(1_000n);
    expect(await usdc.read.balanceOf([alice.account.address])).toBe(0n);
    const prepared = await userDecryption({ holder: alice.account.address, balance: 1_000n, amount: 400n });
    await proveOnMock(prepared);

    await sendAndWait(wrapper.write.unwrapWithProof([
      alice.account.address,
      alice.account.address,
      400n,
      prepared.signed,
      "0x",
    ], fheTxOpts(alice.account)));

    expect(await decryptBalance(alice)).toBe(600n);
    expect(await usdc.read.balanceOf([alice.account.address])).toBe(400n);
  });

  it("accepts any 9 of the 13 nodes", async () => {
    const {
      env: { alice }, usdc, wrapper, fund, userDecryption, proveOnMock, sendAndWait,
    } = await setupWrapper();
    await fund(alice, 1_000n);
    const prepared = await userDecryption({
      holder: alice.account.address,
      balance: 1_000n,
      amount: 1_000n,
      parties: [13, 2, 11, 4, 9, 6, 1, 8, 7],
    });
    await proveOnMock(prepared);
    expect(await usdc.read.balanceOf([alice.account.address])).toBe(0n);

    await sendAndWait(wrapper.write.unwrapWithProof([
      alice.account.address,
      alice.account.address,
      1_000n,
      prepared.signed,
      "0x",
    ], fheTxOpts(alice.account)));

    expect(await usdc.read.balanceOf([alice.account.address])).toBe(1_000n);
  });

  it("lets an operator unwrap to another recipient", async () => {
    const {
      env: { alice, carol }, usdc, wrapper, fund, userDecryption, proveOnMock, sendAndWait,
    } = await setupWrapper();
    await fund(alice, 1_000n);
    await sendAndWait(wrapper.write.setOperator([carol.account.address, 2 ** 40], txOpts(alice.account)));
    const prepared = await userDecryption({ holder: alice.account.address, balance: 1_000n, amount: 250n });
    await proveOnMock(prepared);
    expect(await usdc.read.balanceOf([carol.account.address])).toBe(0n);

    await sendAndWait(wrapper.write.unwrapWithProof([
      alice.account.address,
      carol.account.address,
      250n,
      prepared.signed,
      "0x",
    ], fheTxOpts(carol.account)));

    expect(await usdc.read.balanceOf([carol.account.address])).toBe(250n);
  });

  describe("reverts", () => {
    it("when the proof covers a different amount", async () => {
      const {
        env: { alice }, wrapper, fund, userDecryption, proveOnMock,
      } = await setupWrapper();
      await fund(alice, 1_000n);
      const prepared = await userDecryption({ holder: alice.account.address, balance: 1_000n, amount: 400n });
      await proveOnMock(prepared);

      await expectRevert(
        wrapper.write.unwrapWithProof([alice.account.address, alice.account.address, 500n, prepared.signed, "0x"], txOpts(alice.account)),
        wrapper.abi,
        "ProofInvalid",
      );
    });

    it("when a digest is attributed to another node", async () => {
      const {
        env: { alice }, wrapper, fund, userDecryption, proveOnMock,
      } = await setupWrapper();
      await fund(alice, 1_000n);
      const prepared = await userDecryption({ holder: alice.account.address, balance: 1_000n, amount: 400n });
      await proveOnMock(prepared);
      const parties = nine(prepared.signed.parties.map((p, i) => (i === 0 ? 10 : p)));

      await expectRevert(
        wrapper.write.unwrapWithProof([
          alice.account.address,
          alice.account.address,
          400n,
          { ...prepared.signed, parties },
          "0x",
        ], txOpts(alice.account)),
        wrapper.abi,
        "InvalidShareSignature",
      );
    });

    it("when an incoming transfer replaced the balance handle", async () => {
      const {
        env: { alice, bob }, wrapper, fund, userDecryption, proveOnMock, sendEncryptedZero,
      } = await setupWrapper();
      await fund(alice, 1_000n);
      await fund(bob, 1n);
      const prepared = await userDecryption({ holder: alice.account.address, balance: 1_000n, amount: 400n });
      await proveOnMock(prepared);
      await sendEncryptedZero(bob, alice.account.address);

      // The shares are bound to the old handle: the contract derives a different link from the new one.
      await expectRevert(
        wrapper.write.unwrapWithProof([alice.account.address, alice.account.address, 400n, prepared.signed, "0x"], txOpts(alice.account)),
        wrapper.abi,
        "ProofInvalid",
      );
    });

    it("when replaying the shares after the burn", async () => {
      const {
        env: { alice }, wrapper, fund, userDecryption, proveOnMock, sendAndWait,
      } = await setupWrapper();
      await fund(alice, 1_000n);
      const prepared = await userDecryption({ holder: alice.account.address, balance: 1_000n, amount: 400n });
      await proveOnMock(prepared);
      const args = [alice.account.address, alice.account.address, 400n, prepared.signed, "0x"] as const;
      await sendAndWait(wrapper.write.unwrapWithProof(args, fheTxOpts(alice.account)));

      await expectRevert(wrapper.write.unwrapWithProof(args, txOpts(alice.account)), wrapper.abi, "ProofInvalid");
    });

    it("when the caller is neither the holder nor an operator", async () => {
      const {
        env: { alice, bob }, wrapper, fund, userDecryption, proveOnMock,
      } = await setupWrapper();
      await fund(alice, 1_000n);
      const prepared = await userDecryption({ holder: alice.account.address, balance: 1_000n, amount: 400n });
      await proveOnMock(prepared);

      await expectRevert(
        wrapper.write.unwrapWithProof([alice.account.address, bob.account.address, 400n, prepared.signed, "0x"], txOpts(bob.account)),
        wrapper.abi,
        "ERC7984UnauthorizedSpender",
      );
    });

    it("for the zero recipient", async () => {
      const {
        env: { alice }, wrapper, fund, userDecryption, proveOnMock,
      } = await setupWrapper();
      await fund(alice, 1_000n);
      const prepared = await userDecryption({ holder: alice.account.address, balance: 1_000n, amount: 400n });
      await proveOnMock(prepared);

      await expectRevert(
        wrapper.write.unwrapWithProof([alice.account.address, zeroAddress, 400n, prepared.signed, "0x"], txOpts(alice.account)),
        wrapper.abi,
        "ERC7984InvalidReceiver",
      );
    });
  });
});

describe("unwrapAllWithShares", () => {
  it("burns the whole balance and releases it without a proof", async () => {
    const {
      env: { alice }, usdc, wrapper, fund, decryptBalance, userDecryption, sendAndWait,
    } = await setupWrapper();
    await fund(alice, 1_000n);
    expect(await decryptBalance(alice)).toBe(1_000n);
    const prepared = await userDecryption({ holder: alice.account.address, balance: 1_000n, amount: 1_000n });

    await sendAndWait(wrapper.write.unwrapAllWithShares([
      alice.account.address,
      alice.account.address,
      prepared.revealed,
    ], fheTxOpts(alice.account)));

    expect(await decryptBalance(alice)).toBe(0n);
    expect(await usdc.read.balanceOf([alice.account.address])).toBe(1_000n);
  });

  describe("reverts", () => {
    it("when a revealed share was tampered with", async () => {
      const {
        env: { alice }, wrapper, fund, userDecryption,
      } = await setupWrapper();
      await fund(alice, 1_000n);
      const prepared = await userDecryption({ holder: alice.account.address, balance: 1_000n, amount: 0n });
      const shares = toHex(hexToBytes(prepared.revealed.shares).map((b, i) => (i === 300 ? b ^ 1 : b)));

      await expectRevert(
        wrapper.write.unwrapAllWithShares([alice.account.address, alice.account.address, { ...prepared.revealed, shares }], txOpts(alice.account)),
        wrapper.abi,
        "InvalidShareSignature",
      );
    });

    it("when the polynomial misses the shares", async () => {
      const {
        env: { alice }, wrapper, fund, userDecryption,
      } = await setupWrapper();
      await fund(alice, 1_000n);
      const prepared = await userDecryption({ holder: alice.account.address, balance: 1_000n, amount: 0n });
      const poly = toHex(hexToBytes(prepared.revealed.poly).map((b, i) => (i === 64 * 5 + 1 ? b ^ 1 : b)));

      await expectRevert(
        wrapper.write.unwrapAllWithShares([alice.account.address, alice.account.address, { ...prepared.revealed, poly }], txOpts(alice.account)),
        wrapper.abi,
        "ShareOffPolynomial",
      );
    });

    it("when the shares are of a stale balance", async () => {
      const {
        env: { alice, bob }, wrapper, fund, userDecryption, sendEncryptedZero,
      } = await setupWrapper();
      await fund(alice, 1_000n);
      await fund(bob, 1n);
      const prepared = await userDecryption({ holder: alice.account.address, balance: 1_000n, amount: 0n });
      await sendEncryptedZero(bob, alice.account.address);

      await expectRevert(
        wrapper.write.unwrapAllWithShares([alice.account.address, alice.account.address, prepared.revealed], txOpts(alice.account)),
        wrapper.abi,
        "InvalidShareSignature",
      );
    });
  });
});

describe.runIf(canProveNoir())("unwrapWithProof with a real UltraHonk proof", () => {
  it("unwraps with a Noir proof made from the nodes' shares", async () => {
    const {
      env: { alice }, usdc, wrapper, fund, decryptBalance, userDecryption, sendAndWait,
    } = await setupWrapper({ system: "noir" });
    await fund(alice, 1_000n);
    expect(await decryptBalance(alice)).toBe(1_000n);
    const prepared = await userDecryption({ holder: alice.account.address, balance: 1_000n, amount: 400n });
    const { proof } = proveNoir(prepared.witness);

    await sendAndWait(wrapper.write.unwrapWithProof([
      alice.account.address,
      alice.account.address,
      400n,
      prepared.signed,
      proof,
    ], fheTxOpts(alice.account)));

    expect(await decryptBalance(alice)).toBe(600n);
    expect(await usdc.read.balanceOf([alice.account.address])).toBe(400n);
  });
});

describe.runIf(canProveCircom())("unwrapWithProof with a real Groth16 proof", () => {
  it("unwraps with a circom proof made from the nodes' shares", async () => {
    const {
      env: { alice }, usdc, wrapper, fund, decryptBalance, userDecryption, sendAndWait,
    } = await setupWrapper({ system: "circom" });
    await fund(alice, 1_000n);
    expect(await decryptBalance(alice)).toBe(1_000n);
    const prepared = await userDecryption({ holder: alice.account.address, balance: 1_000n, amount: 400n });
    const { proof } = await proveCircom(prepared.witness);

    await sendAndWait(wrapper.write.unwrapWithProof([
      alice.account.address,
      alice.account.address,
      400n,
      prepared.signed,
      proof,
    ], fheTxOpts(alice.account)));

    expect(await decryptBalance(alice)).toBe(600n);
    expect(await usdc.read.balanceOf([alice.account.address])).toBe(400n);
  });
});
