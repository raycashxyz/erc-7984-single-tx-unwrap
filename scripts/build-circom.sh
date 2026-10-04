#!/usr/bin/env bash
# Compiles circuits/circom, runs a development Groth16 setup over the PSE perpetual powers of tau
# (2^21, 80 contributions), and regenerates contracts/verifiers/UnwrapGroth16Verifier.sol.
#
# Needs circom 2.2.x on PATH. Roughly 9 GB of RAM to compile and 30 GB for the setup, ~10 minutes,
# and a 1.1 GB proving key in circuits/circom/build. The phase-2 setup has a single contribution:
# fine for development, production needs a multi-party ceremony. Each run produces a new key, so
# re-prove the fixture afterwards (see the last line).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
snarkjs="$root/node_modules/.bin/snarkjs"
ptau="${PTAU:-$HOME/.cache/circom-ptau/ppot_0080_21.ptau}"
build="$root/circuits/circom/build"

if [ ! -f "$ptau" ]; then
  mkdir -p "$(dirname "$ptau")"
  curl -fL --retry 20 --retry-all-errors -C - -o "$ptau" \
    https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_21.ptau
fi

mkdir -p "$build"
circom "$root/circuits/circom/unwrap.circom" --r1cs --wasm --O2 -o "$build"

export NODE_OPTIONS=--max-old-space-size=30000
"$snarkjs" groth16 setup "$build/unwrap.r1cs" "$ptau" "$build/unwrap_0000.zkey"
"$snarkjs" zkey contribute "$build/unwrap_0000.zkey" "$build/unwrap.zkey" \
  --name="development contribution" -e="$(head -c 64 /dev/urandom | xxd -p | tr -d '\n')"
rm "$build/unwrap_0000.zkey"
"$snarkjs" zkey export verificationkey "$build/unwrap.zkey" "$build/verification_key.json"
"$snarkjs" zkey export solidityverifier "$build/unwrap.zkey" "$build/UnwrapGroth16Verifier.sol"
sed 's/^contract Groth16Verifier {/contract UnwrapGroth16Verifier {/' "$build/UnwrapGroth16Verifier.sol" \
  >"$root/contracts/verifiers/UnwrapGroth16Verifier.sol"
echo "wrote contracts/verifiers/UnwrapGroth16Verifier.sol; now re-prove the fixture:"
echo "  pnpm prove fixtures/sepolia-2025-10/user-decryption.json circom fixtures/sepolia-2025-10/circom-proof.json"
