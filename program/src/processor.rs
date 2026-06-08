use {
    crate::{
        instruction::{eth_address_from_pubkey, SIGNATURE_SERIALIZED_SIZE},
        instruction_data::{
            get_signature_fields, iter_signature_offsets, SignatureFields, SignatureOffsets,
        },
    },
    solana_account_info::AccountInfo,
    solana_keccak_hasher::hash,
    solana_program_entrypoint::ProgramResult,
    solana_program_error::ProgramError,
    solana_pubkey::Pubkey,
    solana_secp256k1_recover::secp256k1_recover,
};

#[cfg(target_os = "solana")]
use solana_define_syscall::definitions::sol_get_stack_height;

/// Transaction index of the instruction whose data this program is verifying.
///
/// An SBF program only receives its own instruction data, so all offset fields
/// in `SecpSignatureOffsets` must reference index 0. Supporting other indices
/// would require a runtime change to expose sibling instruction data.
const CURRENT_INSTRUCTION_INDEX: u8 = 0;

/// Stack height of a transaction-level instruction. CPI frames are higher.
pub(crate) const TRANSACTION_LEVEL_STACK_HEIGHT: u64 = 1;

#[cfg(target_os = "solana")]
pub(crate) fn current_stack_height() -> u64 {
    // Runtime-provided zero-argument syscall.
    unsafe { sol_get_stack_height() }
}

#[cfg(not(target_os = "solana"))]
pub(crate) fn current_stack_height() -> u64 {
    TRANSACTION_LEVEL_STACK_HEIGHT
}

pub(crate) fn reject_cpi_stack_height(stack_height: u64) -> ProgramResult {
    if stack_height > TRANSACTION_LEVEL_STACK_HEIGHT {
        return Err(ProgramError::InvalidArgument);
    }

    Ok(())
}

const SIGNATURE_SCALAR_LENGTH: usize = 32;
const SECP256K1_ORDER: [u8; SIGNATURE_SCALAR_LENGTH] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
const SECP256K1_HALF_ORDER: [u8; SIGNATURE_SCALAR_LENGTH] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// Parses `instruction_data` and verifies every secp256k1 signature it
/// describes, returning an error on the first failure.
pub(crate) fn verify_secp256k1_instruction(instruction_data: &[u8]) -> ProgramResult {
    for offsets in iter_signature_offsets(instruction_data)? {
        verify_signature(instruction_data, &offsets?)?;
    }

    Ok(())
}

/// Program entry point.
///
/// Expects no accounts and instruction data in the secp256k1 precompile
/// format. Returns [`ProgramError::InvalidArgument`] if invoked through CPI or
/// if any accounts are provided, or propagates errors from signature
/// verification.
pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    reject_cpi_stack_height(current_stack_height())?;

    if !accounts.is_empty() {
        return Err(ProgramError::InvalidArgument);
    }

    verify_secp256k1_instruction(instruction_data)
}

/// Returns `true` when every offset field in `offsets` references the current
/// instruction (index 0) rather than a sibling instruction in the transaction.
fn references_current_instruction(offsets: &SignatureOffsets<'_>) -> bool {
    offsets.signature_instruction_index() == CURRENT_INSTRUCTION_INDEX
        && offsets.eth_address_instruction_index() == CURRENT_INSTRUCTION_INDEX
        && offsets.message_instruction_index() == CURRENT_INSTRUCTION_INDEX
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
        *normalized_signature = *signature;
        subtract_s_from_order(&mut normalized_signature[SIGNATURE_SCALAR_LENGTH..]);
        (normalized_signature, recovery_id ^ 1)
    } else {
        (signature, recovery_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_transaction_level_stack_height() {
        assert_eq!(
            reject_cpi_stack_height(TRANSACTION_LEVEL_STACK_HEIGHT),
            Ok(())
        );
    }

    #[test]
    fn rejects_cpi_stack_height() {
        assert_eq!(
            reject_cpi_stack_height(TRANSACTION_LEVEL_STACK_HEIGHT + 1),
            Err(ProgramError::InvalidArgument)
        );
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
