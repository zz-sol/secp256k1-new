//! Solana program that re-verifies secp256k1 signatures on-chain.
//!
//! The native [`secp256k1` precompile] already validates signatures at the
//! transaction level, but this program performs an additional in-program
//! verification so that other programs can CPI into it and trust the result.
//!
//! # Instruction format
//!
//! The instruction data mirrors the layout consumed by the native secp256k1
//! precompile (see [`solana_secp256k1_program`]):
//!
//! ```text
//! [num_signatures: u8]
//! [SecpSignatureOffsets × num_signatures]   (11 bytes each, little-endian)
//! [signature || recovery_id | eth_address | message …]   (payload, order flexible)
//! ```
//!
//! All data references inside `SecpSignatureOffsets` must point into the same
//! instruction (index 0); cross-instruction references are rejected.
//!
//! [`secp256k1` precompile]: https://docs.solanalabs.com/runtime/programs#secp256k1-program

use solana_account_info::AccountInfo;
use solana_keccak_hasher::hash;
use solana_program_entrypoint::ProgramResult;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use solana_secp256k1_program::SecpSignatureOffsets;
use solana_secp256k1_recover::secp256k1_recover;

mod instruction_data;

use instruction_data::{get_signature_fields, iter_signature_offsets, SignatureFields};

pub use solana_secp256k1_program::eth_address_from_pubkey;

#[cfg(not(feature = "no-entrypoint"))]
solana_program_entrypoint::entrypoint!(process_instruction);

#[cfg(target_os = "solana")]
#[no_mangle]
pub extern "C" fn abort() -> ! {
    loop {}
}

/// Transaction index of the instruction whose data this program is verifying.
///
/// An SBF program only receives its own instruction data, so all offset fields
/// in `SecpSignatureOffsets` must reference index 0. Supporting other indices
/// would require a runtime change to expose sibling instruction data.
const CURRENT_INSTRUCTION_INDEX: u8 = 0;

/// Returns `true` when every offset field in `offsets` references the current
/// instruction (index 0) rather than a sibling instruction in the transaction.
fn references_current_instruction(offsets: &SecpSignatureOffsets) -> bool {
    offsets.signature_instruction_index == CURRENT_INSTRUCTION_INDEX
        && offsets.eth_address_instruction_index == CURRENT_INSTRUCTION_INDEX
        && offsets.message_instruction_index == CURRENT_INSTRUCTION_INDEX
}

/// Parses `instruction_data` and verifies every secp256k1 signature it
/// describes, returning an error on the first failure.
fn verify_secp256k1_instruction(instruction_data: &[u8]) -> ProgramResult {
    for offsets in iter_signature_offsets(instruction_data)? {
        verify_signature(instruction_data, &offsets?)?;
    }

    Ok(())
}

/// Program entrypoint.
///
/// Expects no accounts and instruction data in the secp256k1 precompile
/// format. Returns [`ProgramError::InvalidArgument`] if any accounts are
/// provided, or propagates errors from signature verification.
pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if !accounts.is_empty() {
        return Err(ProgramError::InvalidArgument);
    }

    verify_secp256k1_instruction(instruction_data)
}

/// Validates a single signature entry described by `offsets`.
///
/// Rejects offsets that reference instructions other than the current one,
/// then extracts the raw fields and delegates to [`verify_signature_fields`].
fn verify_signature(instruction_data: &[u8], offsets: &SecpSignatureOffsets) -> ProgramResult {
    if !references_current_instruction(offsets) {
        return Err(ProgramError::InvalidInstructionData);
    }

    let fields = get_signature_fields(instruction_data, offsets)?;
    verify_signature_fields(&fields)
}

/// Performs the cryptographic check for one signature entry.
///
/// Hashes `fields.message` with Keccak-256, recovers the secp256k1 public key
/// from the compact signature, derives its Ethereum address, and compares it
/// against `fields.expected_address`. Returns [`ProgramError::InvalidArgument`]
/// if recovery fails or the addresses do not match.
fn verify_signature_fields(fields: &SignatureFields) -> ProgramResult {
    let message_hash = hash(fields.message);
    let recovered_pubkey = secp256k1_recover(
        message_hash.as_bytes(),
        fields.recovery_id,
        fields.signature,
    )
    .map_err(|_| ProgramError::InvalidArgument)?;

    let recovered_address = eth_address_from_pubkey(&recovered_pubkey.to_bytes());
    if recovered_address.as_ref() != fields.expected_address {
        return Err(ProgramError::InvalidArgument);
    }

    Ok(())
}

#[cfg(test)]
mod tests;
