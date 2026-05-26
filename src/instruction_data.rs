use {
    solana_program_error::ProgramError,
    solana_secp256k1_program::{
        SecpSignatureOffsets, HASHED_PUBKEY_SERIALIZED_SIZE, SIGNATURE_OFFSETS_SERIALIZED_SIZE,
        SIGNATURE_SERIALIZED_SIZE,
    },
};

const RECOVERY_ID_LENGTH: usize = 1;
const SIGNATURE_WITH_RECOVERY_ID_LENGTH: usize = SIGNATURE_SERIALIZED_SIZE + RECOVERY_ID_LENGTH;

pub(crate) struct SignatureFields<'a> {
    pub(crate) signature: &'a [u8; SIGNATURE_SERIALIZED_SIZE],
    pub(crate) recovery_id: u8,
    pub(crate) expected_address: &'a [u8; HASHED_PUBKEY_SERIALIZED_SIZE],
    pub(crate) message: &'a [u8],
}

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

fn validate_recovery_id(recovery_id: u8) -> Result<u8, ProgramError> {
    match recovery_id {
        0..=3 => Ok(recovery_id),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
