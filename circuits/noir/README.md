# circuits/noir

The unwrap statement in Noir, proved with Barretenberg's UltraHonk (ZK, keccak transcript for the EVM).
See the [top-level README](../../README.md#the-circuits) for the statement and the numbers.

The signed message is built as 32-bit words: the KMS format's constant parts are compile-time words,
the `link ‖ user ‖ H(enc_key)` tail is packed once for all nine messages, and each share's words are
packed from range-checked bytes. That keeps the circuit at 261,403 gates, inside a 2^18 domain.

```bash
nargo test                   # ring arithmetic, TFHE decode, SHA-256 padding, word packing
bash ../../scripts/build-noir.sh
```

Toolchain: nargo 1.0.0-rc.2, bb 6.0.0-rc.2.
