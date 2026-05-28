# solana-secp256k1-program: on-chain signature verification for Solana

A minimal Solana SBF program that re-verifies secp256k1 ECDSA signatures
on-chain without adding any new runtime syscalls.

## Motivation

The goal is to migrate the native [secp256k1 precompile] to SBF so that it can
be maintained and deployed like any other on-chain program. The instruction
format is intentionally identical to the precompile, including parts that are
not intuitive for general-purpose use, so that tools and clients built around
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

## Instruction format

```text
[0]                   number of signatures (u8)
[1 .. 1 + 11*N]       N × SecpSignatureOffsets records (11 bytes each, LE)
[1 + 11*N ..]         payload: signatures, addresses, messages (order flexible)
```

Each 11-byte offset record matches `SecpSignatureOffsets` exposed by this crate:

```text
[0..2]    signature_offset        - byte position of 64-byte r||s + 1-byte recovery id
[2]       signature_instruction_index
[3..5]    eth_address_offset      - byte position of 20-byte Ethereum address
[5]       eth_address_instruction_index
[6..8]    message_data_offset     - byte position of the raw message
[8..10]   message_data_size
[10]      message_instruction_index
```

### Constraints

- **All instruction-index fields must be `0`.** An SBF program receives only
  its own instruction data; cross-instruction references require a future
  runtime change.
- **Recovery id must be `0`–`3`.** Values `2`/`3` are accepted for
  compatibility with legacy Solana secp256k1 instruction data and are passed
  through to recovery, where overflowing signatures generally fail as
  `InvalidArgument`. Ethereum-style `27`/`28` offsets are rejected at the wire
  level.
- **Zero-signature payloads** (`count == 0`) are accepted only when the buffer
  is exactly 1 byte. Any trailing bytes are treated as malformed.
- **No accounts.** The program takes no account arguments and returns
  `InvalidArgument` if any are supplied.

### Hashing

The program Keccak-256 hashes `message` before recovering the public key. Pass
the exact bytes that should be hashed for your signing scheme. For
`personal_sign`, include the `"\x19Ethereum Signed Message:\n{len}"` prefix;
for EIP-712 typed data, pass `"\x19\x01" || domain_separator || struct_hash`
(66 bytes total). The program hashes those bytes for you. Passing the
32-byte final digest would verify `keccak256(digest)`, causing valid typed-data
signatures to fail.

## Cargo features

| Feature | Default | Description |
|---|---|---|
| `bincode` | off | Enables SDK-compatible instruction construction helpers. |
| `dev-context-only-utils` | off | Backward-compatible alias for `bincode`, matching the upstream helper crate feature. |
| `no-entrypoint` | off | Omits the program entrypoint; use when embedding the crate in another program or in tests that call `process_instruction` directly. |
| `custom-heap` | off | Reserved for callers that provide a custom heap allocator. |
| `serde` | off | Derives serde traits for `SecpSignatureOffsets`. |

## Public API

The SDK helpers and layout constants are exposed from `solana_secp256k1_program`:

```rust
use solana_secp256k1_program::{
    eth_address_from_pubkey, eth_address_from_sec1_pubkey,
    new_secp256k1_instruction_with_signature, try_new_secp256k1_instruction_with_signature,
    SecpSignatureOffsets,
};
```

`new_secp256k1_instruction_with_signature` keeps the upstream SDK return type
(`Instruction`) for source compatibility. Prefer
`try_new_secp256k1_instruction_with_signature` when callers need construction
errors instead of panics for invalid offsets, oversized messages, or invalid
recovery ids.

## Build and test

Stable Rust `1.93.1` is pinned in `rust-toolchain.toml`. Some make targets
also require the nightly Rust chain `nightly-2026-01-22` (`clippy`,
`format-check`, `rustdoc`, `feature-powerset`).

```sh
# Unit tests (host, no SBF toolchain required)
cargo test --manifest-path program/Cargo.toml

# SBF build only
cargo build-sbf --manifest-path program/Cargo.toml

# SBF build via Makefile
make build-sbf-program

# Host unit tests, then SBF integration tests via Mollusk
make test-program

# Print Mollusk compute-unit measurements for the SBF program
make cu-program

# Lint / format
make clippy-program
make format-check-program
```

The Mollusk tests in `program/tests/mollusk.rs` execute the built
`target/deploy/solana_secp256k1_program.so` artifact and report
`compute_units_consumed` for one-signature and two-signature verification
paths. Plain `cargo test --manifest-path program/Cargo.toml` still runs the
host tests without requiring the SBF Rust chain; the Mollusk tests skip
themselves unless `SBF_OUT_DIR` is set.
