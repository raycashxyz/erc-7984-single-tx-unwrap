/**
 * Runs the two provers on an unwrap witness and returns what `SingleTxUnwrapWrapper.unwrapWithProof`
 * takes: the proof bytes, and the public inputs the contract will recompute.
 *
 * - Noir / UltraHonk: `nargo execute` + `bb prove -t evm` (ZK, keccak transcript).
 * - circom / Groth16: witness with the circom WASM, proof with rapidsnark if `RAPIDSNARK` points
 *   at its `prover` binary, otherwise snarkjs.
 */
import { execFileSync } from "node:child_process";
import {
  cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import * as snarkjs from "snarkjs";
import { bytesToHex, encodeAbiParameters, numberToHex } from "viem";
import type { Hex } from "viem";
import { circomInput, noirProverToml } from "./witness";
import type { UnwrapWitness } from "./witness";

export interface UnwrapProof {
  proof: Hex;
  publicInputs: Hex[];
  provingMs: number;
}

const ROOT = path.resolve(__dirname, "..");
export const NOIR_DIR = path.join(ROOT, "circuits/noir");
export const CIRCOM_BUILD = path.join(ROOT, "circuits/circom/build");

const withTempDir = <T>(prefix: string, f: (dir: string) => T): T => {
  const dir = mkdtempSync(path.join(tmpdir(), prefix));
  try {
    return f(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
};

const words = (bytes: Uint8Array): Hex[] =>
  Array.from({ length: bytes.length / 32 }, (_, i) => bytesToHex(bytes.slice(32 * i, 32 * (i + 1))));

/** UltraHonk proof with nargo + bb (both on PATH). Works in a temp copy of the Noir package. */
export const proveNoir = (w: UnwrapWitness): UnwrapProof => withTempDir("unwrap-noir-", (dir) => {
  cpSync(path.join(NOIR_DIR, "Nargo.toml"), path.join(dir, "Nargo.toml"));
  cpSync(path.join(NOIR_DIR, "src"), path.join(dir, "src"), { recursive: true });
  writeFileSync(path.join(dir, "Prover.toml"), noirProverToml(w));
  execFileSync("nargo", ["execute", "--silence-warnings"], { cwd: dir, stdio: "ignore" });
  const target = path.join(dir, "target");
  const circuit = path.join(target, "unwrap.json");
  execFileSync("bb", ["write_vk", "-b", circuit, "-o", target, "-t", "evm"], { stdio: "ignore" });
  const started = performance.now();
  execFileSync("bb", [
    "prove",
    "-b",
    circuit,
    "-w",
    path.join(target, "unwrap.gz"),
    "-k",
    path.join(target, "vk"),
    "-o",
    target,
    "-t",
    "evm",
  ], { stdio: "ignore" });
  const provingMs = Math.round(performance.now() - started);
  return {
    proof: bytesToHex(readFileSync(path.join(target, "proof"))),
    publicInputs: words(readFileSync(path.join(target, "public_inputs"))),
    provingMs,
  };
});

/** The Solidity verifier's (a, b, c) for a snarkjs proof, as one ABI-encoded `bytes`. */
const encodeGroth16 = async (proof: unknown, publicSignals: readonly string[]): Promise<Hex> => {
  const calldata = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
  const [a, b, c] = JSON.parse(`[${calldata}]`) as [[Hex, Hex], [[Hex, Hex], [Hex, Hex]], [Hex, Hex]];
  return encodeAbiParameters(
    [{ type: "uint256[2]" }, { type: "uint256[2][2]" }, { type: "uint256[2]" }],
    [[BigInt(a[0]), BigInt(a[1])], [[BigInt(b[0][0]), BigInt(b[0][1])], [BigInt(b[1][0]), BigInt(b[1][1])]], [BigInt(c[0]), BigInt(c[1])]],
  );
};

/** Groth16 proof of `circuits/circom` (built by `scripts/build-circom.sh`). */
export const proveCircom = async (w: UnwrapWitness, build: string = CIRCOM_BUILD): Promise<UnwrapProof> => {
  const wasm = path.join(build, "unwrap_js/unwrap.wasm");
  const zkey = path.join(build, "unwrap.zkey");
  const rapidsnark = process.env.RAPIDSNARK;
  if (rapidsnark === undefined || rapidsnark === "") {
    const started = performance.now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(circomInput(w), wasm, zkey);
    const provingMs = Math.round(performance.now() - started);
    return {
      proof: await encodeGroth16(proof, publicSignals),
      publicInputs: publicSignals.map((s) => numberToHex(BigInt(s), { size: 32 })),
      provingMs,
    };
  }
  const dir = mkdtempSync(path.join(tmpdir(), "unwrap-circom-"));
  try {
    const witness = path.join(dir, "witness.wtns");
    await snarkjs.wtns.calculate(circomInput(w), wasm, witness);
    const proofPath = path.join(dir, "proof.json");
    const publicPath = path.join(dir, "public.json");
    const started = performance.now();
    execFileSync(rapidsnark, [zkey, witness, proofPath, publicPath], { stdio: "ignore" });
    const provingMs = Math.round(performance.now() - started);
    const publicSignals = JSON.parse(readFileSync(publicPath, "utf8")) as string[];
    return {
      proof: await encodeGroth16(JSON.parse(readFileSync(proofPath, "utf8")), publicSignals),
      publicInputs: publicSignals.map((s) => numberToHex(BigInt(s), { size: 32 })),
      provingMs,
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
};
