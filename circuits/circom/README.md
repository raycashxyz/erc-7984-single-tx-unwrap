# circuits/circom

The unwrap statement in circom 2.2, proved with Groth16 (snarkjs or rapidsnark). Same statement and
same 31 public inputs as [`../noir`](../noir), so the same wrapper verifies either proof through
[`CircomUnwrapVerifier`](../../contracts/verifiers/CircomUnwrapVerifier.sol). See the
[top-level README](../../README.md#the-circuits) for the numbers.

SHA-256 is circomlib's (210,691 constraints per 376-byte message, 98% of the circuit's 1,926,807).

```bash
bash ../../scripts/build-circom.sh   # compile, dev Groth16 setup over the PSE 2^21 ptau, export the verifier
```

The build writes `build/unwrap.zkey` (1.1 GB) and the WASM witness generator; neither is committed.
The committed verifier and `fixtures/sepolia-2025-10/circom-proof.json` match the key generated for
this repository, so a new setup means re-proving the fixture.
