Secp256k1 signature verification on Solana SBF
------

This repository contains a minimal Solana BPF/SBF program that verifies a
secp256k1 ECDSA signature without adding any new runtime syscalls.

The goal is to migrate the secp256k1 precompile to BPF while emulating its API
and behavior exactly. The instruction format intentionally follows the
precompile, including parts that may not be intuitive for general-purpose use.

On-chain verification uses only existing Solana syscalls exposed by the SDK
crates:

- `sol_keccak256`, through `solana_keccak_hasher::hash`
- `sol_secp256k1_recover`, through `solana_secp256k1_recover::secp256k1_recover`

The program has no account state. It succeeds when the recovered secp256k1
public key hashes to the supplied Ethereum-style address.

## Instruction layout

Instruction data uses Solana's secp256k1 precompile layout:

```text
[0]                         number of signatures to verify
[1..1 + 11 * count]         secp256k1 signature offset records
[1 + 11 * count..]          payload bytes referenced by the offset records
```

Each 11-byte offset record is little-endian and matches Solana's
`SecpSignatureOffsets` format:

```text
[0..2]    signature offset, pointing to 64-byte r || s plus 1-byte recovery ID
[2]       signature instruction index
[3..5]    Ethereum address offset, pointing to 20 bytes
[5]       Ethereum address instruction index
[6..8]    message data offset
[8..10]   message data size
[10]      message instruction index
```

This SBF program receives only its own instruction data, so all three
instruction-index fields must be `0`. This currently assumes the secp256k1
instruction is at transaction index `0`; supporting other instruction indices
requires a runtime change to expose that data to the program.

The recovery ID must be in the precompile-compatible `0..=3` range.
Ethereum-style `27`/`28` recovery IDs are rejected in this wire format. The
program accepts both low- and high-`s` signatures. For `personal_sign` or
typed-data workflows, pass the exact bytes that should be Keccak-hashed for
that signing scheme.

## Build and test

```sh
cargo test
cargo build-sbf
```
