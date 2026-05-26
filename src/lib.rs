use {
    solana_account_info::AccountInfo,
    solana_keccak_hasher::hash,
    solana_program_entrypoint::ProgramResult,
    solana_program_error::ProgramError,
    solana_pubkey::Pubkey,
    solana_secp256k1_program::{
        SecpSignatureOffsets, HASHED_PUBKEY_SERIALIZED_SIZE, SIGNATURE_OFFSETS_SERIALIZED_SIZE,
        SIGNATURE_SERIALIZED_SIZE,
    },
    solana_secp256k1_recover::secp256k1_recover,
};

#[cfg(test)]
use solana_secp256k1_program::{DATA_START, SECP256K1_PUBKEY_SIZE};

pub use solana_secp256k1_program::eth_address_from_pubkey;

#[cfg(not(feature = "no-entrypoint"))]
solana_program_entrypoint::entrypoint!(process_instruction);

#[cfg(target_os = "solana")]
#[no_mangle]
pub extern "C" fn abort() -> ! {
    loop {}
}

const RECOVERY_ID_LENGTH: usize = 1;
const CURRENT_INSTRUCTION_INDEX: u8 = 0;
const SIGNATURE_WITH_RECOVERY_ID_LENGTH: usize = SIGNATURE_SERIALIZED_SIZE + RECOVERY_ID_LENGTH;

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

// This SBF program currently receives only its own instruction data, so this
// assumes the secp256k1 instruction is at transaction index 0. Supporting other
// instruction indices requires a runtime change to expose that data here.
fn references_current_instruction(offsets: &SecpSignatureOffsets) -> bool {
    offsets.signature_instruction_index == CURRENT_INSTRUCTION_INDEX
        && offsets.eth_address_instruction_index == CURRENT_INSTRUCTION_INDEX
        && offsets.message_instruction_index == CURRENT_INSTRUCTION_INDEX
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

fn iter_signature_offsets(
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

    let signature_with_recovery_id = get_instruction_data_slice(
        instruction_data,
        offsets.signature_offset,
        SIGNATURE_WITH_RECOVERY_ID_LENGTH,
    )?;
    let (&recovery_id, signature) = signature_with_recovery_id
        .split_last()
        .ok_or(ProgramError::InvalidInstructionData)?;
    let signature: &[u8; SIGNATURE_SERIALIZED_SIZE] = signature
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let recovery_id = validate_recovery_id(recovery_id)?;
    let expected_address = get_instruction_data_slice(
        instruction_data,
        offsets.eth_address_offset,
        HASHED_PUBKEY_SERIALIZED_SIZE,
    )?;
    let message = get_instruction_data_slice(
        instruction_data,
        offsets.message_data_offset,
        usize::from(offsets.message_data_size),
    )?;

    let message_hash = hash(message);
    let recovered_pubkey = secp256k1_recover(message_hash.as_bytes(), recovery_id, signature)
        .map_err(|_| ProgramError::InvalidArgument)?;

    let recovered_address = eth_address_from_pubkey(&recovered_pubkey.to_bytes());
    if recovered_address != expected_address {
        return Err(ProgramError::InvalidArgument);
    }

    Ok(())
}

fn validate_recovery_id(recovery_id: u8) -> Result<u8, ProgramError> {
    match recovery_id {
        0..=3 => Ok(recovery_id),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

#[cfg(test)]
mod tests {
    use {super::*, k256::ecdsa::SigningKey};

    struct SignedPayload<'a> {
        signature: [u8; SIGNATURE_SERIALIZED_SIZE],
        recovery_id: u8,
        address: [u8; HASHED_PUBKEY_SERIALIZED_SIZE],
        message: &'a [u8],
    }

    fn signed_payload<'a>(signing_key: &SigningKey, message: &'a [u8]) -> SignedPayload<'a> {
        let message_hash = hash(message);
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(message_hash.as_bytes())
            .unwrap();
        let signature: [u8; SIGNATURE_SERIALIZED_SIZE] = signature.to_bytes().into();

        let verifying_key = signing_key.verifying_key();
        let encoded = verifying_key.to_encoded_point(false);
        // Drop the SEC1 0x04 prefix; Ethereum hashes only the 64-byte x||y body.
        let pubkey: [u8; SECP256K1_PUBKEY_SIZE] = encoded.as_bytes()[1..65].try_into().unwrap();
        let address = eth_address_from_pubkey(&pubkey);

        SignedPayload {
            signature,
            recovery_id: recovery_id.to_byte(),
            address,
            message,
        }
    }

    fn signed_instruction(messages: &[&[u8]]) -> Vec<u8> {
        let signing_key = SigningKey::from_slice(&[7; 32]).unwrap();
        let payloads = messages
            .iter()
            .map(|message| signed_payload(&signing_key, message))
            .collect::<Vec<_>>();
        let offsets_len = payloads.len() * SIGNATURE_OFFSETS_SERIALIZED_SIZE;
        let mut instruction = vec![0; 1 + offsets_len];
        instruction[0] = payloads.len() as u8;

        for (index, payload) in payloads.iter().enumerate() {
            let eth_address_offset = instruction.len();
            instruction.extend_from_slice(&payload.address);

            let signature_offset = instruction.len();
            instruction.extend_from_slice(&payload.signature);
            instruction.push(payload.recovery_id);

            let message_data_offset = instruction.len();
            instruction.extend_from_slice(payload.message);

            let offsets = SecpSignatureOffsets {
                signature_offset: u16::try_from(signature_offset).unwrap(),
                signature_instruction_index: 0,
                eth_address_offset: u16::try_from(eth_address_offset).unwrap(),
                eth_address_instruction_index: 0,
                message_data_offset: u16::try_from(message_data_offset).unwrap(),
                message_data_size: u16::try_from(payload.message.len()).unwrap(),
                message_instruction_index: 0,
            };
            write_offsets(
                &mut instruction[1 + index * SIGNATURE_OFFSETS_SERIALIZED_SIZE
                    ..1 + (index + 1) * SIGNATURE_OFFSETS_SERIALIZED_SIZE],
                &offsets,
            );
        }

        instruction
    }

    fn first_offsets(instruction: &[u8]) -> SecpSignatureOffsets {
        unpack_signature_offsets(&instruction[1..DATA_START]).unwrap()
    }

    fn write_offsets(output: &mut [u8], offsets: &SecpSignatureOffsets) {
        output[0..2].copy_from_slice(&offsets.signature_offset.to_le_bytes());
        output[2] = offsets.signature_instruction_index;
        output[3..5].copy_from_slice(&offsets.eth_address_offset.to_le_bytes());
        output[5] = offsets.eth_address_instruction_index;
        output[6..8].copy_from_slice(&offsets.message_data_offset.to_le_bytes());
        output[8..10].copy_from_slice(&offsets.message_data_size.to_le_bytes());
        output[10] = offsets.message_instruction_index;
    }

    #[test]
    fn verifies_matching_signature() {
        let program_id = Pubkey::default();
        let instruction = signed_instruction(&[b"hello secp256k1"]);

        assert_eq!(process_instruction(&program_id, &[], &instruction), Ok(()));
    }

    #[test]
    fn verifies_multiple_signatures() {
        let program_id = Pubkey::default();
        let instruction = signed_instruction(&[b"hello secp256k1", b"second message"]);

        assert_eq!(process_instruction(&program_id, &[], &instruction), Ok(()));
    }

    #[test]
    fn rejects_wrong_address() {
        let program_id = Pubkey::default();
        let mut instruction = signed_instruction(&[b"hello secp256k1"]);
        let offsets = first_offsets(&instruction);
        instruction[usize::from(offsets.eth_address_offset)] ^= 1;

        assert_eq!(
            process_instruction(&program_id, &[], &instruction),
            Err(ProgramError::InvalidArgument)
        );
    }

    #[test]
    fn rejects_corrupted_signature() {
        let program_id = Pubkey::default();
        let mut instruction = signed_instruction(&[b"hello secp256k1"]);
        let offsets = first_offsets(&instruction);
        instruction[usize::from(offsets.signature_offset)] ^= 1;

        assert_eq!(
            process_instruction(&program_id, &[], &instruction),
            Err(ProgramError::InvalidArgument)
        );
    }

    #[test]
    fn rejects_short_instruction() {
        let program_id = Pubkey::default();

        assert_eq!(
            process_instruction(&program_id, &[], &[]),
            Err(ProgramError::InvalidInstructionData)
        );
        assert_eq!(
            process_instruction(&program_id, &[], &[1]),
            Err(ProgramError::InvalidInstructionData)
        );
    }

    #[test]
    fn accepts_zero_signatures_only_when_data_has_no_payload() {
        let program_id = Pubkey::default();

        assert_eq!(process_instruction(&program_id, &[], &[0]), Ok(()));
        assert_eq!(
            process_instruction(&program_id, &[], &[0, 0]),
            Err(ProgramError::InvalidInstructionData)
        );
    }

    #[test]
    fn passes_supported_overflow_recovery_ids_to_recover() {
        let program_id = Pubkey::default();

        for recovery_id in [2, 3] {
            let mut instruction = signed_instruction(&[b"hello secp256k1"]);
            let offsets = first_offsets(&instruction);
            instruction[usize::from(offsets.signature_offset) + SIGNATURE_SERIALIZED_SIZE] =
                recovery_id;

            assert_eq!(
                process_instruction(&program_id, &[], &instruction),
                Err(ProgramError::InvalidArgument)
            );
        }
    }

    #[test]
    fn rejects_invalid_recovery_ids() {
        let program_id = Pubkey::default();

        for recovery_id in [4, 27, 28, 29, 30] {
            let mut instruction = signed_instruction(&[b"hello secp256k1"]);
            let offsets = first_offsets(&instruction);
            instruction[usize::from(offsets.signature_offset) + SIGNATURE_SERIALIZED_SIZE] =
                recovery_id;

            assert_eq!(
                process_instruction(&program_id, &[], &instruction),
                Err(ProgramError::InvalidInstructionData)
            );
        }
    }

    #[test]
    fn rejects_offsets_to_other_instructions() {
        let program_id = Pubkey::default();
        let mut instruction = signed_instruction(&[b"hello secp256k1"]);
        instruction[1 + 2] = 1;

        assert_eq!(
            process_instruction(&program_id, &[], &instruction),
            Err(ProgramError::InvalidInstructionData)
        );
    }

    #[test]
    fn rejects_out_of_bounds_offsets() {
        let program_id = Pubkey::default();
        let mut instruction = signed_instruction(&[b"hello secp256k1"]);
        let mut offsets = first_offsets(&instruction);
        offsets.message_data_size = u16::MAX;
        write_offsets(&mut instruction[1..DATA_START], &offsets);

        assert_eq!(
            process_instruction(&program_id, &[], &instruction),
            Err(ProgramError::InvalidInstructionData)
        );
    }
}
