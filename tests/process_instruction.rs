use {
    common::{first_offsets, signed_instruction, write_offsets},
    secp256k1::process_instruction,
    solana_program_error::ProgramError,
    solana_pubkey::Pubkey,
    solana_secp256k1_program::{DATA_START, SIGNATURE_SERIALIZED_SIZE},
};

mod common;

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
