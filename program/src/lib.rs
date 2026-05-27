//! Solana program that verifies secp256k1 signatures on-chain.
//!
//! This program mirrors the native [`secp256k1` precompile] instruction format
//! so that other programs can CPI into it and trust the result.
//!
//! # Instruction format
//!
//! The instruction data mirrors the layout consumed by the native secp256k1
//! precompile (see the upstream `solana-secp256k1-program` SDK crate):
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
//! [`secp256k1` precompile]: https://solana.com/docs/core/programs/precompiles#verify-secp256k1-recovery

use solana_account_info::AccountInfo;
use solana_keccak_hasher::hash;
use solana_program_entrypoint::ProgramResult;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;
use solana_secp256k1_program_sdk::{eth_address_from_pubkey, SIGNATURE_SERIALIZED_SIZE};
use solana_secp256k1_recover::secp256k1_recover;

mod instruction_data;

use instruction_data::{
    get_signature_fields, iter_signature_offsets, SignatureFields, SignatureOffsets,
};

#[doc(hidden)]
pub use instruction_data::unpack_signature_offsets;

/// Program entry point for the VM v2 instruction-data pointer ABI.
///
/// # Safety
///
/// The Solana runtime must pass `input` as the serialized accounts buffer and
/// `instruction_data_addr` as the pointer to instruction data with its length
/// stored in the preceding 8 bytes.
#[cfg(target_os = "solana")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn entrypoint(input: *mut u8, instruction_data_addr: *const u8) -> u64 {
    let result = unsafe {
        let num_accounts = *(input as *const u64);
        if num_accounts != 0 {
            Err(ProgramError::InvalidArgument)
        } else {
            let instruction_data_len = *((instruction_data_addr as u64 - 8) as *const u64);
            let instruction_data =
                core::slice::from_raw_parts(instruction_data_addr, instruction_data_len as usize);
            verify_secp256k1_instruction(instruction_data)
        }
    };

    match result {
        Ok(()) => solana_program_entrypoint::SUCCESS,
        Err(error) => error.into(),
    }
}

solana_program_entrypoint::custom_heap_default!();
solana_program_entrypoint::custom_panic_default!();

#[cfg(target_os = "solana")]
#[unsafe(no_mangle)]
pub extern "C" fn abort() -> ! {
    let message = "abort";
    let file = file!();
    unsafe {
        solana_program_entrypoint::__log(message.as_ptr(), message.len() as u64);
        solana_program_entrypoint::__panic(
            file.as_ptr(),
            file.len() as u64,
            line!() as u64,
            column!() as u64,
        )
    }
}

/// Transaction index of the instruction whose data this program is verifying.
///
/// An SBF program only receives its own instruction data, so all offset fields
/// in `SecpSignatureOffsets` must reference index 0. Supporting other indices
/// would require a runtime change to expose sibling instruction data.
const CURRENT_INSTRUCTION_INDEX: u8 = 0;
const SIGNATURE_SCALAR_LENGTH: usize = 32;
const SECP256K1_ORDER: [u8; SIGNATURE_SCALAR_LENGTH] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
const SECP256K1_HALF_ORDER: [u8; SIGNATURE_SCALAR_LENGTH] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// Returns `true` when every offset field in `offsets` references the current
/// instruction (index 0) rather than a sibling instruction in the transaction.
fn references_current_instruction(offsets: &SignatureOffsets<'_>) -> bool {
    offsets.signature_instruction_index() == CURRENT_INSTRUCTION_INDEX
        && offsets.eth_address_instruction_index() == CURRENT_INSTRUCTION_INDEX
        && offsets.message_instruction_index() == CURRENT_INSTRUCTION_INDEX
}

/// Parses `instruction_data` and verifies every secp256k1 signature it
/// describes, returning an error on the first failure.
fn verify_secp256k1_instruction(instruction_data: &[u8]) -> ProgramResult {
    for offsets in iter_signature_offsets(instruction_data)? {
        verify_signature(instruction_data, &offsets?)?;
    }

    Ok(())
}

/// Program entry point.
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
fn verify_signature(instruction_data: &[u8], offsets: &SignatureOffsets<'_>) -> ProgramResult {
    if !references_current_instruction(offsets) {
        return Err(ProgramError::InvalidInstructionData);
    }

    let fields = get_signature_fields(instruction_data, offsets)?;
    verify_signature_fields(&fields)
}

/// Performs the signature check for one entry.
///
/// Hashes `fields.message` with Keccak-256, recovers the secp256k1 public key
/// from the compact signature, derives its Ethereum address, and compares it
/// against `fields.expected_address`. Returns [`ProgramError::InvalidArgument`]
/// if recovery fails or the addresses do not match.
fn verify_signature_fields(fields: &SignatureFields) -> ProgramResult {
    let message_hash = hash(fields.message);
    let mut normalized_signature = [0u8; SIGNATURE_SERIALIZED_SIZE];
    let (signature, recovery_id) = normalize_malleable_signature(
        fields.signature,
        fields.recovery_id,
        &mut normalized_signature,
    );
    let recovered_pubkey = secp256k1_recover(message_hash.as_bytes(), recovery_id, signature)
        .map_err(|_| ProgramError::InvalidArgument)?;

    let recovered_address = eth_address_from_pubkey(&recovered_pubkey.to_bytes());
    if recovered_address.as_ref() != fields.expected_address {
        return Err(ProgramError::InvalidArgument);
    }

    Ok(())
}

fn normalize_malleable_signature<'a>(
    signature: &'a [u8; SIGNATURE_SERIALIZED_SIZE],
    recovery_id: u8,
    normalized_signature: &'a mut [u8; SIGNATURE_SERIALIZED_SIZE],
) -> (&'a [u8; SIGNATURE_SERIALIZED_SIZE], u8) {
    let s = signature_s(signature);
    if s > SECP256K1_HALF_ORDER.as_slice() && s < SECP256K1_ORDER.as_slice() {
        for (destination, source) in normalized_signature.iter_mut().zip(signature.iter()) {
            *destination = *source;
        }
        subtract_s_from_order(&mut normalized_signature[SIGNATURE_SCALAR_LENGTH..]);
        (normalized_signature, recovery_id ^ 1)
    } else {
        (signature, recovery_id)
    }
}

fn signature_s(signature: &[u8; SIGNATURE_SERIALIZED_SIZE]) -> &[u8] {
    &signature[SIGNATURE_SCALAR_LENGTH..]
}

fn subtract_s_from_order(s: &mut [u8]) {
    let mut borrow = 0u16;
    for (byte, order_byte) in s.iter_mut().rev().zip(SECP256K1_ORDER.iter().rev()) {
        let subtrahend = u16::from(*byte) + borrow;
        let minuend = u16::from(*order_byte);
        if minuend >= subtrahend {
            *byte = (minuend - subtrahend) as u8;
            borrow = 0;
        } else {
            *byte = (minuend + 256 - subtrahend) as u8;
            borrow = 1;
        }
    }
}
