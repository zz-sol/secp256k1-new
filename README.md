Secp256k1 signature verification on Solana SBF
------

This repository contains a minimal Solana BPF/SBF program that verifies a
secp256k1 ECDSA signature without adding any new runtime syscalls.

On-chain verification uses only existing Solana syscalls exposed by the SDK
crates:

- `sol_keccak256`, through `solana_keccak_hasher::hash`
- `sol_secp256k1_recover`, through `solana_secp256k1_recover::secp256k1_recover`

The program has no account state. It succeeds when the recovered secp256k1
public key hashes to the supplied Ethereum-style address.

## Instruction layout

Instruction data is packed as:

```text
[0]       recovery id: 0..=1, or Ethereum-style 27..=28
[1..65]   secp256k1 signature, 64 bytes, r || s
[65..85]  expected Ethereum address, 20 bytes
[85..]    message bytes to Keccak-256 hash and verify
```

The program accepts both low- and high-`s` signatures, and rejects overflowing
recovery IDs `2`/`3` and `29`/`30`. For `personal_sign` or typed-data workflows,
pass the exact bytes that should be Keccak-hashed for that signing scheme.

## Build and test

```sh
cargo test
cargo build-sbf
```
