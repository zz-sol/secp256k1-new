//! Parsing helpers for the secp256k1 instruction data wire format.
//!
//! The on-wire layout (identical to the native secp256k1 precompile) is:
//!
//! ```text
//! Byte 0             : num_signatures (u8)
//! Bytes 1 …          : num_signatures × SecpSignatureOffsets (11 bytes each, LE)
//! Remaining bytes    : raw payload (signature+recovery_id, eth_address, message)
//! ```
//!
//! All offsets inside `SecpSignatureOffsets` are byte positions into the *same*
//! instruction data buffer.

use {
    solana_program_error::ProgramError,
    solana_secp256k1_program::{
        SecpSignatureOffsets, HASHED_PUBKEY_SERIALIZED_SIZE, SIGNATURE_OFFSETS_SERIALIZED_SIZE,
        SIGNATURE_SERIALIZED_SIZE,
    },
};

const RECOVERY_ID_LENGTH: usize = 1;
/// Total bytes for the compact signature followed by the recovery id byte.
const SIGNATURE_WITH_RECOVERY_ID_LENGTH: usize = SIGNATURE_SERIALIZED_SIZE + RECOVERY_ID_LENGTH;

/// Borrowed views into the raw signature fields for one entry.
///
/// All slices point directly into the instruction data buffer, so no copying
/// is required before passing them to the verification layer.
pub(crate) struct SignatureFields<'a> {
    /// 64-byte compact secp256k1 signature.
    pub(crate) signature: &'a [u8; SIGNATURE_SERIALIZED_SIZE],
    /// Recovery id needed to reconstruct the public key from the signature.
    pub(crate) recovery_id: u8,
    /// 20-byte Ethereum address (Keccak-256 of the uncompressed public key, last 20 bytes).
    pub(crate) expected_address: &'a [u8; HASHED_PUBKEY_SERIALIZED_SIZE],
    /// Raw message bytes that were signed (before hashing).
    pub(crate) message: &'a [u8],
}

/// Parses an 11-byte `SecpSignatureOffsets` record from `input`.
///
/// Returns [`ProgramError::InvalidInstructionData`] if `input` is not exactly
/// [`SIGNATURE_OFFSETS_SERIALIZED_SIZE`] bytes long.
fn unpack_signature_offsets(input: &[u8]) -> Result<SecpSignatureOffsets, ProgramError> {
    if input.len() != SIGNATURE_OFFSETS_SERIALIZED_SIZE {
        return Err(ProgramError::InvalidInstructionData);
    }

    Ok(SecpSignatureOffsets {
        signature_offset: decode_u16(input, 0)?,
        signature_instruction_index: get_u8(input, 2)?,
        eth_address_offset: decode_u16(input, 3)?,
        eth_address_instruction_index: get_u8(input, 5)?,
        message_data_offset: decode_u16(input, 6)?,
        message_data_size: decode_u16(input, 8)?,
        message_instruction_index: get_u8(input, 10)?,
    })
}

fn decode_u16(input: &[u8], index: usize) -> Result<u16, ProgramError> {
    let bytes: [u8; 2] = input
        .get(index..index + 2)
        .ok_or(ProgramError::InvalidInstructionData)?
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    Ok(u16::from_le_bytes(bytes))
}

fn get_u8(input: &[u8], index: usize) -> Result<u8, ProgramError> {
    input
        .get(index)
        .copied()
        .ok_or(ProgramError::InvalidInstructionData)
}

/// Returns `input[offset .. offset + length]`, checking bounds on both ends.
///
/// `offset` is a `u16` to match the field widths in `SecpSignatureOffsets`;
/// the arithmetic is promoted to `usize` with overflow protection.
fn get_instruction_data_slice(
    input: &[u8],
    offset: u16,
    length: usize,
) -> Result<&[u8], ProgramError> {
    let offset = usize::from(offset);
    let end = offset
        .checked_add(length)
        .ok_or(ProgramError::InvalidInstructionData)?;
    input
        .get(offset..end)
        .ok_or(ProgramError::InvalidInstructionData)
}

fn get_instruction_data_array<const N: usize>(
    input: &[u8],
    offset: u16,
) -> Result<&[u8; N], ProgramError> {
    get_instruction_data_slice(input, offset, N)?
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)
}

/// Extracts all signature fields for one entry from raw
/// `instruction_data` using the byte positions in `offsets`.
///
/// The recovery id is the byte immediately after the 64-byte signature; it is
/// validated by [`validate_recovery_id`] before being returned.
pub(crate) fn get_signature_fields<'a>(
    instruction_data: &'a [u8],
    offsets: &'a SecpSignatureOffsets,
) -> Result<SignatureFields<'a>, ProgramError> {
    let signature_with_recovery_id = get_instruction_data_slice(
        instruction_data,
        offsets.signature_offset,
        SIGNATURE_WITH_RECOVERY_ID_LENGTH,
    )?;
    let (&recovery_id, _) = signature_with_recovery_id
        .split_last()
        .ok_or(ProgramError::InvalidInstructionData)?;

    Ok(SignatureFields {
        signature: get_instruction_data_array(instruction_data, offsets.signature_offset)?,
        recovery_id: validate_recovery_id(recovery_id)?,
        expected_address: get_instruction_data_array(instruction_data, offsets.eth_address_offset)?,
        message: get_instruction_data_slice(
            instruction_data,
            offsets.message_data_offset,
            usize::from(offsets.message_data_size),
        )?,
    })
}

/// Parses the leading `num_signatures` byte and returns an iterator that yields
/// one `SecpSignatureOffsets` per entry.
///
/// # Special cases
///
/// - `num_signatures == 0` is valid only when the buffer is exactly 1 byte
///   (just the count, no trailing data). Any extra bytes are rejected because
///   the precompile treats them as malformed.
/// - Overflow in the total offsets size is rejected via `checked_mul`.
pub(crate) fn iter_signature_offsets(
    input: &[u8],
) -> Result<impl Iterator<Item = Result<SecpSignatureOffsets, ProgramError>> + '_, ProgramError> {
    let num_signatures = *input.first().ok_or(ProgramError::InvalidInstructionData)?;
    if num_signatures == 0 {
        if input.len() == 1 {
            return Ok(input[1..1]
                .chunks_exact(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
                .map(unpack_signature_offsets));
        }

        return Err(ProgramError::InvalidInstructionData);
    }

    let all_offsets_size = SIGNATURE_OFFSETS_SERIALIZED_SIZE
        .checked_mul(usize::from(num_signatures))
        .ok_or(ProgramError::InvalidInstructionData)?;
    let all_offsets_end = 1usize
        .checked_add(all_offsets_size)
        .ok_or(ProgramError::InvalidInstructionData)?;
    let all_offsets = input
        .get(1..all_offsets_end)
        .ok_or(ProgramError::InvalidInstructionData)?;

    Ok(all_offsets
        .chunks_exact(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
        .map(unpack_signature_offsets))
}

/// Accepts the four recovery id values defined by SEC 1. Values 4 through 255
/// (including the legacy Ethereum 27/28 offset)
/// are explicitly rejected rather than silently truncated.
fn validate_recovery_id(recovery_id: u8) -> Result<u8, ProgramError> {
    match recovery_id {
        0..=3 => Ok(recovery_id),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
