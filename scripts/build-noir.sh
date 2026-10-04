#!/usr/bin/env bash
# Tests and compiles circuits/noir, then regenerates contracts/verifiers/UnwrapHonkVerifier.sol.
# Needs nargo 1.0.0-rc.2 and bb 6.0.0-rc.2 on PATH. UltraHonk uses a universal SRS, so the verifying
# key depends only on the circuit: anyone running this gets the same verifier.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/circuits/noir"

nargo test
nargo compile
mkdir -p target/evm
bb write_vk -b target/unwrap.json -o target/evm -t evm
bb write_solidity_verifier -k target/evm/vk -o target/evm/HonkVerifier.sol -t evm --optimized
sed 's/^contract HonkVerifier is/contract UnwrapHonkVerifier is/' target/evm/HonkVerifier.sol \
  >"$root/contracts/verifiers/UnwrapHonkVerifier.sol"
bb gates -b target/unwrap.json
echo "wrote contracts/verifiers/UnwrapHonkVerifier.sol"
