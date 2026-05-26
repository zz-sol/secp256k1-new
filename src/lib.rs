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

const CURRENT_INSTRUCTION_INDEX: u8 = 0;

// This SBF program currently receives only its own instruction data, so this
// assumes the secp256k1 instruction is at transaction index 0. Supporting other
// instruction indices requires a runtime change to expose that data here.
fn references_current_instruction(offsets: &SecpSignatureOffsets) -> bool {
    offsets.signature_instruction_index == CURRENT_INSTRUCTION_INDEX
        && offsets.eth_address_instruction_index == CURRENT_INSTRUCTION_INDEX
        && offsets.message_instruction_index == CURRENT_INSTRUCTION_INDEX
}

fn verify_secp256k1_instruction(instruction_data: &[u8]) -> ProgramResult {
    for offsets in iter_signature_offsets(instruction_data)? {
        verify_signature(instruction_data, &offsets?)?;
    }

    Ok(())
}

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

fn verify_signature(instruction_data: &[u8], offsets: &SecpSignatureOffsets) -> ProgramResult {
    if !references_current_instruction(offsets) {
        return Err(ProgramError::InvalidInstructionData);
    }

    let fields = get_signature_fields(instruction_data, offsets)?;
    verify_signature_fields(&fields)
}

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
