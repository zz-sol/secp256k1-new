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
    core::{iter, mem::size_of, slice::ChunksExact},
    solana_program_error::ProgramError,
    solana_secp256k1_program_sdk::{
        SecpSignatureOffsets, HASHED_PUBKEY_SERIALIZED_SIZE, SIGNATURE_OFFSETS_SERIALIZED_SIZE,
        SIGNATURE_SERIALIZED_SIZE,
    },
    solana_zero_copy::unaligned::U16,
};

#[repr(C)]
struct SignatureOffsetsBytes {
    signature_offset: U16,
    signature_instruction_index: u8,
    eth_address_offset: U16,
    eth_address_instruction_index: u8,
    message_data_offset: U16,
    message_data_size: U16,
    message_instruction_index: u8,
}

const _: [(); SIGNATURE_OFFSETS_SERIALIZED_SIZE] = [(); size_of::<SignatureOffsetsBytes>()];

/// Borrowed view into one serialized `SecpSignatureOffsets` record.
pub(crate) struct SignatureOffsets<'a> {
    bytes: &'a SignatureOffsetsBytes,
}

impl SignatureOffsets<'_> {
    pub(crate) fn signature_offset(&self) -> u16 {
        self.bytes.signature_offset.into()
    }

    pub(crate) fn signature_instruction_index(&self) -> u8 {
        self.bytes.signature_instruction_index
    }

    pub(crate) fn eth_address_offset(&self) -> u16 {
        self.bytes.eth_address_offset.into()
    }

    pub(crate) fn eth_address_instruction_index(&self) -> u8 {
        self.bytes.eth_address_instruction_index
    }

    pub(crate) fn message_data_offset(&self) -> u16 {
        self.bytes.message_data_offset.into()
    }

    pub(crate) fn message_data_size(&self) -> u16 {
        self.bytes.message_data_size.into()
    }

    pub(crate) fn message_instruction_index(&self) -> u8 {
        self.bytes.message_instruction_index
    }

    fn to_secp_signature_offsets(&self) -> SecpSignatureOffsets {
        SecpSignatureOffsets {
            signature_offset: self.signature_offset(),
            signature_instruction_index: self.signature_instruction_index(),
            eth_address_offset: self.eth_address_offset(),
            eth_address_instruction_index: self.eth_address_instruction_index(),
            message_data_offset: self.message_data_offset(),
            message_data_size: self.message_data_size(),
            message_instruction_index: self.message_instruction_index(),
        }
    }
}

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
#[doc(hidden)]
pub fn unpack_signature_offsets(input: &[u8]) -> Result<SecpSignatureOffsets, ProgramError> {
    Ok(signature_offsets_from_bytes(input)?.to_secp_signature_offsets())
}

fn signature_offsets_from_bytes(input: &[u8]) -> Result<SignatureOffsets<'_>, ProgramError> {
    if input.len() != SIGNATURE_OFFSETS_SERIALIZED_SIZE {
        return Err(ProgramError::InvalidInstructionData);
    }

    // SignatureOffsetsBytes is composed only of u8 and solana-zero-copy
    // unaligned integer wrappers, so it has alignment 1 and exactly matches
    // the 11-byte wire format checked above.
    let bytes = unsafe { &*input.as_ptr().cast::<SignatureOffsetsBytes>() };
    Ok(SignatureOffsets { bytes })
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
    offsets: &SignatureOffsets<'_>,
) -> Result<SignatureFields<'a>, ProgramError> {
    let recovery_id_offset = usize::from(offsets.signature_offset())
        .checked_add(SIGNATURE_SERIALIZED_SIZE)
        .ok_or(ProgramError::InvalidInstructionData)?;
    let recovery_id = instruction_data
        .get(recovery_id_offset)
        .copied()
        .ok_or(ProgramError::InvalidInstructionData)?;

    Ok(SignatureFields {
        signature: get_instruction_data_array(instruction_data, offsets.signature_offset())?,
        recovery_id: validate_recovery_id(recovery_id)?,
        expected_address: get_instruction_data_array(
            instruction_data,
            offsets.eth_address_offset(),
        )?,
        message: get_instruction_data_slice(
            instruction_data,
            offsets.message_data_offset(),
            usize::from(offsets.message_data_size()),
        )?,
    })
}

pub(crate) enum SignatureOffsetsIter<'a> {
    Empty(iter::Empty<Result<SignatureOffsets<'a>, ProgramError>>),
    Chunks(ChunksExact<'a, u8>),
}

impl<'a> Iterator for SignatureOffsetsIter<'a> {
    type Item = Result<SignatureOffsets<'a>, ProgramError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Empty(iter) => iter.next(),
            Self::Chunks(chunks) => chunks.next().map(signature_offsets_from_bytes),
        }
    }
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
) -> Result<SignatureOffsetsIter<'_>, ProgramError> {
    let num_signatures = *input.first().ok_or(ProgramError::InvalidInstructionData)?;
    if num_signatures == 0 {
        if input.len() == 1 {
            return Ok(SignatureOffsetsIter::Empty(iter::empty()));
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

    Ok(SignatureOffsetsIter::Chunks(
        all_offsets.chunks_exact(SIGNATURE_OFFSETS_SERIALIZED_SIZE),
    ))
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
