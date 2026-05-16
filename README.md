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
instruction-index fields must be `0`. The recovery ID is the Solana syscall
value `0..=3`; Ethereum-style `27`/`28` is not accepted in this wire format.
The program accepts both low- and high-`s` signatures, while overflowing
recovery IDs `2`/`3` fail during recovery. For `personal_sign` or typed-data
workflows, pass the exact bytes that should be Keccak-hashed for that signing
scheme.

## Build and test

```sh
cargo test
cargo build-sbf
```
