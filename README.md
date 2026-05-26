# secp256k1 — on-chain signature verification for Solana

A minimal Solana SBF program that re-verifies secp256k1 ECDSA signatures
on-chain without adding any new runtime syscalls.

## Motivation

The goal is to migrate the native [secp256k1 precompile] to SBF so that it can
be maintained and deployed like any other on-chain program. The instruction
format is intentionally identical to the precompile — including parts that are
not intuitive for general-purpose use — so that tools and clients built around
the precompile require no changes.

Being a regular SBF program also unlocks CPI: another program can invoke this
one and act on the explicit pass/fail result, rather than relying on
`sysvar::instructions` inspection to confirm a parallel precompile instruction
succeeded.

[secp256k1 precompile]: https://docs.solanalabs.com/runtime/programs#secp256k1-program

## Syscalls used

Verification relies only on existing Solana runtime syscalls:

| Syscall | SDK wrapper |
|---|---|
| `sol_keccak256` | `solana_keccak_hasher::hash` |
| `sol_secp256k1_recover` | `solana_secp256k1_recover::secp256k1_recover` |

The Makefile `build-sbf-secp256k1` target runs `scripts/check-sbf-symbols.sh`
after the build to ensure no unexpected unresolved symbols appear.

## Instruction format

```text
[0]                   number of signatures (u8)
[1 .. 1 + 11*N]       N × SecpSignatureOffsets records (11 bytes each, LE)
[1 + 11*N ..]         payload: signatures, addresses, messages (order flexible)
```

Each 11-byte offset record matches `solana_secp256k1_program::SecpSignatureOffsets`:

```text
[0..2]    signature_offset        — byte position of 64-byte r‖s + 1-byte recovery id
[2]       signature_instruction_index
[3..5]    eth_address_offset      — byte position of 20-byte Ethereum address
[5]       eth_address_instruction_index
[6..8]    message_data_offset     — byte position of the raw message
[8..10]   message_data_size
[10]      message_instruction_index
```

### Constraints

- **All instruction-index fields must be `0`.** An SBF program receives only
  its own instruction data; cross-instruction references require a future
  runtime change.
- **Recovery id must be `0`–`3`.** Ethereum-style `27`/`28` offsets are
  rejected at the wire level.
- **Zero-signature payloads** (`count == 0`) are accepted only when the buffer
  is exactly 1 byte. Any trailing bytes are treated as malformed.
- **No accounts.** The program takes no account arguments and returns
  `InvalidArgument` if any are supplied.

### Hashing

The program Keccak-256 hashes `message` before recovering the public key. Pass
the exact bytes that should be hashed for your signing scheme — for
`personal_sign`, include the `"\x19Ethereum Signed Message:\n{len}"` prefix;
for EIP-712 typed data, pass the preimage bytes `"\x19\x01" || domain_separator || struct_hash`
(66 bytes: 2 + 32 + 32) — the program hashes those for you; passing the 32-byte final digest would verify
`keccak256(digest)`, causing valid typed-data signatures to fail.

## Cargo features

| Feature | Default | Description |
|---|---|---|
| `no-entrypoint` | off | Omits the program entrypoint; use when embedding the crate in another program or in tests that call `process_instruction` directly. |
| `custom-heap` | off | Reserved for callers that provide a custom heap allocator. |

## Public API

`eth_address_from_pubkey` is re-exported from `solana_secp256k1_program` for
convenience:

```rust
pub use solana_secp256k1_program::eth_address_from_pubkey;
```

## Build and test

Stable Rust `1.93.1` is pinned in `rust-toolchain.toml`. Some Makefile targets
additionally require the nightly toolchain `nightly-2026-01-22` (clippy,
format-check, rustdoc, feature-powerset).

```sh
# Unit tests (host, no SBF toolchain required)
cargo test

# SBF build only
cargo build-sbf

# SBF build + unresolved-symbol check (via Makefile)
make build-sbf-secp256k1

# Tests with the SBF artifact on PATH (needed for integration tests)
make test-secp256k1

# Lint / format
make clippy-secp256k1
make format-check-secp256k1
```
