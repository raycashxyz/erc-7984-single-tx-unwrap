/**
 * Proves an unwrap from a KMS user-decryption response.
 *
 *   pnpm prove <user-decryption.json> <noir|circom> <out.json> [amount]
 *
 * The input is the relayer's response plus the request's ML-KEM key pair (see
 * fixtures/sepolia-2025-10/user-decryption.json). `amount` defaults to the decrypted value.
 * circom proofs use rapidsnark when RAPIDSNARK points at its `prover` binary, snarkjs otherwise.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { prepareUnwrap } from "../src/client";
import { decodeUint64, decryptionDomainSeparator } from "../src/kms";
import { proveCircom, proveNoir } from "../src/prove";
import { userDecryptionFile } from "../src/files";

const main = async () => {
  const [input, system, out, amountArg] = process.argv.slice(2);
  if (input === undefined || (system !== "noir" && system !== "circom") || out === undefined) {
    throw new Error("usage: prove <user-decryption.json> <noir|circom> <out.json> [amount]");
  }
  const decryption = userDecryptionFile.parse(JSON.parse(readFileSync(input, "utf8")));
  const domain = decryptionDomainSeparator(decryption.gatewayChainId, decryption.gatewayDecryption);
  const full = await prepareUnwrap({
    decryption,
    amount: 0n,
    kmsSigners: decryption.kmsSigners,
    decryptionDomainSeparator: domain,
  });
  const amount = amountArg === undefined ? decodeUint64(full.witness.poly[0] ?? []) : BigInt(amountArg);
  const { witness, signed } = await prepareUnwrap({
    decryption,
    amount,
    kmsSigners: decryption.kmsSigners,
    decryptionDomainSeparator: domain,
  });
  const proof = system === "noir" ? proveNoir(witness) : await proveCircom(witness);
  writeFileSync(out, `${JSON.stringify({ system, amount: amount.toString(), ...proof, signed }, null, 2)}\n`);
  console.log(`wrote ${out}: ${system} proof of >= ${amount} in ${proof.provingMs} ms`);
};

// snarkjs keeps its curve worker threads alive, so exit explicitly.
main().then(() => process.exit(0), (error: unknown) => {
  console.error(error);
  process.exit(1);
});
