/**
 * A real user decryption from Sepolia (2025-10-02, 13 KMS nodes, t = 4): the TypeScript client, the
 * Solidity library and both circuits must agree byte for byte on what the nodes signed, and real
 * proofs from both circuits must verify on the generated verifiers.
 *
 * The expected link, digest and balance below were produced independently by the Rust and Go
 * implementations this repo grew out of.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import {
  describe, expect, it,
} from "vitest";
import { concat, hexToBytes, parseAbi, toHex } from "viem";
import { nine, prepareUnwrap } from "../src/client";
import { proofFile, userDecryptionFile } from "../src/files";
import {
  decodeUint64, decryptionDomainSeparator, publicInputs,
} from "../src/kms";
import { decryptUserDecryption } from "../src/response";
import { getOrDeployCircomUnwrapVerifier } from "../src/deployers/CircomUnwrapVerifier";
import { getOrDeployKmsUserDecryptionHarness } from "../src/deployers/KmsUserDecryptionHarness";
import { getOrDeployUnwrapGroth16Verifier } from "../src/deployers/UnwrapGroth16Verifier";
import { getOrDeployUnwrapHonkVerifier } from "../src/deployers/UnwrapHonkVerifier";
import { expectRevert } from "./setup/assertions";
import { createEnvironment } from "./setup/environment";
import { deployerOptions } from "./setup/wrapper";

const FIXTURES = path.join(__dirname, "../fixtures/sepolia-2025-10");
const read = (file: string): unknown => JSON.parse(readFileSync(path.join(FIXTURES, file), "utf8"));

const EXPECTED = {
  balance: 200_000_000n,
  parties: [9, 1, 12, 13, 2, 3, 5, 8, 4],
  link: "0x3147384f4f95ba18c61ea670ec187d693c3c49b8cd489d455d07e4ae16559b7c",
  firstDigest: "0x907f73a2121116e1eb40190ad5562c5bf46a86319a2a8a2dd1401965741b580f",
} as const;

/** The generated UltraHonk verifier reverts with these selectors (declared as constants, not errors). */
const honkErrorsAbi = parseAbi(["error SumcheckFailed()", "error ShpleminiFailed()"]);

const setupSepolia = async () => {
  const decryption = userDecryptionFile.parse(read("user-decryption.json"));
  const domain = decryptionDomainSeparator(decryption.gatewayChainId, decryption.gatewayDecryption);
  const prepared = await prepareUnwrap({
    decryption,
    amount: EXPECTED.balance,
    kmsSigners: decryption.kmsSigners,
    decryptionDomainSeparator: domain,
  });
  return {
    decryption,
    domain,
    prepared,
    noirProof: proofFile.parse(read("noir-proof.json")),
    circomProof: proofFile.parse(read("circom-proof.json")),
  };
};

const setupOnChain = async () => {
  const sepolia = await setupSepolia();
  const env = await createEnvironment();
  const opts = deployerOptions(env);
  const { contract: harness } = await getOrDeployKmsUserDecryptionHarness({ ...opts, args: [] });
  const { contract: honk } = await getOrDeployUnwrapHonkVerifier({ ...opts, args: [] });
  const { contract: groth16 } = await getOrDeployUnwrapGroth16Verifier({ ...opts, args: [] });
  const { contract: circom } = await getOrDeployCircomUnwrapVerifier({ ...opts, args: [groth16.address] });
  return {
    ...sepolia,
    harness,
    honk,
    circom,
  };
};

describe("the client, on a real Sepolia user decryption", () => {
  it("decrypts every node's share with the request's ML-KEM key", async () => {
    const { decryption } = await setupSepolia();
    const { shares } = decryptUserDecryption(decryption);

    expect(shares.map((s) => s.party)).toEqual(EXPECTED.parties);
    expect(shares.every((s) => hexToBytes(s.share).length === 256 && hexToBytes(s.signature).length === 64)).toBe(true);
  });

  it("reproduces the link and the digests the nodes signed", async () => {
    const { prepared } = await setupSepolia();

    expect(prepared.witness.link).toBe(EXPECTED.link);
    expect(prepared.witness.digests[0]).toBe(EXPECTED.firstDigest);
  });

  it("reconstructs the balance from the shares", async () => {
    const { prepared } = await setupSepolia();

    expect(decodeUint64(prepared.witness.poly[0] ?? [])).toBe(EXPECTED.balance);
  });

  it("refuses to prepare an unwrap above the balance", async () => {
    const { decryption, domain } = await setupSepolia();

    await expect(prepareUnwrap({
      decryption,
      amount: EXPECTED.balance + 1n,
      kmsSigners: decryption.kmsSigners,
      decryptionDomainSeparator: domain,
    })).rejects.toThrow("below");
  });
});

describe("the contracts, on a real Sepolia user decryption", () => {
  it("recompute the link and the digests in Solidity", async () => {
    const {
      harness, decryption, domain, prepared,
    } = await setupOnChain();
    const { pkKeccak, encKeyHash } = decryptUserDecryption(decryption);
    const link = await harness.read.link([decryption.handle, decryption.user, pkKeccak, domain]);
    const digests = await Promise.all(prepared.witness.shares.map((share) =>
      harness.read.shareDigest([share, link, decryption.user, encKeyHash])));

    expect(link).toBe(EXPECTED.link);
    expect(digests).toEqual(prepared.witness.digests);
  });

  it("accept the nine node signatures against the Sepolia signer set", async () => {
    const { harness, decryption, prepared } = await setupOnChain();

    await harness.read.checkSignedDigests([
      decryption.kmsSigners,
      prepared.signed.parties,
      prepared.signed.digests,
      prepared.signed.signatures,
    ]);
  });

  it("reconstruct and decode the balance in Solidity", async () => {
    const { harness, prepared } = await setupOnChain();

    expect(await harness.read.reconstruct([
      prepared.revealed.parties,
      prepared.revealed.shares,
      prepared.revealed.poly,
    ])).toBe(EXPECTED.balance);
  });

  it("build the same 31 public inputs as both provers", async () => {
    const {
      harness, prepared, noirProof, circomProof,
    } = await setupOnChain();
    const inputs = await harness.read.publicInputs([
      prepared.witness.link,
      prepared.witness.user,
      EXPECTED.balance,
      prepared.signed.parties,
      prepared.signed.digests,
    ]);

    expect(inputs).toEqual(noirProof.publicInputs);
    expect(inputs).toEqual(circomProof.publicInputs);
    expect(inputs).toEqual(publicInputs(prepared.witness));
  });

  it("verify the real UltraHonk proof", async () => {
    const { honk, noirProof } = await setupOnChain();

    expect(await honk.read.verify([noirProof.proof, noirProof.publicInputs])).toBe(true);
  });

  it("verify the real Groth16 proof", async () => {
    const { circom, circomProof } = await setupOnChain();

    expect(await circom.read.verify([circomProof.proof, circomProof.publicInputs])).toBe(true);
  });

  it("reject both proofs for a higher amount", async () => {
    const {
      honk, circom, prepared, noirProof, circomProof,
    } = await setupOnChain();
    const inputs = publicInputs({ ...prepared.witness, amount: EXPECTED.balance + 1n });

    await expectRevert(honk.read.verify([noirProof.proof, inputs]), honkErrorsAbi, "SumcheckFailed");
    expect(await circom.read.verify([circomProof.proof, inputs])).toBe(false);
  });

  describe("reverts", () => {
    it("on a digest no node signed", async () => {
      const { harness, decryption, prepared } = await setupOnChain();
      const digests = nine(prepared.signed.digests.map((d, i) => (i === 3 ? `0x${"11".repeat(32)}` as const : d)));

      await expectRevert(
        harness.read.checkSignedDigests([decryption.kmsSigners, prepared.signed.parties, digests, prepared.signed.signatures]),
        harness.abi,
        "InvalidShareSignature",
      );
    });

    it("on a duplicated party", async () => {
      const { harness, decryption, prepared } = await setupOnChain();
      const parties = nine(prepared.signed.parties.map((p, i) => (i === 1 ? prepared.signed.parties[0] : p)));

      await expectRevert(
        harness.read.checkSignedDigests([decryption.kmsSigners, parties, prepared.signed.digests, prepared.signed.signatures]),
        harness.abi,
        "DuplicateParty",
      );
    });

    it("on a party outside the KMS", async () => {
      const { harness, decryption, prepared } = await setupOnChain();
      const parties = nine(prepared.signed.parties.map((p, i) => (i === 0 ? 14 : p)));

      await expectRevert(
        harness.read.checkSignedDigests([decryption.kmsSigners, parties, prepared.signed.digests, prepared.signed.signatures]),
        harness.abi,
        "UnknownParty",
      );
    });

    it("on a KMS that is not 13 nodes", async () => {
      const { harness, decryption, prepared } = await setupOnChain();

      await expectRevert(
        harness.read.checkSignedDigests([
          decryption.kmsSigners.slice(0, 12),
          prepared.signed.parties,
          prepared.signed.digests,
          prepared.signed.signatures,
        ]),
        harness.abi,
        "UnsupportedKmsSignerSet",
      );
    });

    it("on a polynomial the shares do not lie on", async () => {
      const { harness, prepared } = await setupOnChain();
      const poly = hexToBytes(prepared.revealed.poly).map((b, i) => (i === 256 + 5 ? b ^ 1 : b));

      await expectRevert(
        harness.read.reconstruct([prepared.revealed.parties, prepared.revealed.shares, toHex(poly)]),
        harness.abi,
        "ShareOffPolynomial",
      );
    });

    it("on a signature in the high-s form the KMS never emits", async () => {
      const { harness, decryption, prepared } = await setupOnChain();
      const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
      const signatures = hexToBytes(prepared.signed.signatures);
      const first = signatures.slice(0, 65);
      const highS = toHex(order - BigInt(toHex(first.slice(32, 64))), { size: 32 });
      const flipped = concat([toHex(first.slice(0, 32)), highS, toHex(first[64] === 27 ? 28 : 27, { size: 1 })]);

      await expectRevert(
        harness.read.checkSignedDigests([
          decryption.kmsSigners,
          prepared.signed.parties,
          prepared.signed.digests,
          concat([flipped, toHex(signatures.slice(65))]),
        ]),
        harness.abi,
        "InvalidShareSignature",
      );
    });
  });
});
