use {
    common::{first_offsets, signed_instruction},
    mollusk_svm::Mollusk,
    solana_address::Address,
    solana_instruction::Instruction,
    std::{env, path::PathBuf},
};

mod common;

const PROGRAM_SO_STEM: &str = "solana_secp256k1_program";
const SINGLE_MESSAGE: &[u8] = b"deterministic secp256k1 verify benchmark";
const SECOND_MESSAGE: &[u8] = b"second deterministic secp256k1 verify benchmark";

fn sbf_program_path() -> Option<String> {
    if let Some(out_dir) = env::var_os("SBF_OUT_DIR") {
        let path = PathBuf::from(out_dir).join(PROGRAM_SO_STEM);
        let so_path = path.with_extension("so");
        assert!(
            so_path.exists(),
            "SBF artifact not found at {}; run make build-sbf-program first",
            so_path.display()
        );
        return Some(path.to_string_lossy().into_owned());
    }

    eprintln!("skipping Mollusk SBF tests: set SBF_OUT_DIR to target/deploy");
    None
}

fn make_mollusk() -> Option<(Mollusk, Address)> {
    let program_path = sbf_program_path()?;
    let program_id = Address::new_unique();
    let mollusk = Mollusk::new(&program_id, &program_path);
    Some((mollusk, program_id))
}

fn instruction(program_id: Address, data: Vec<u8>) -> Instruction {
    Instruction {
        program_id,
        accounts: vec![],
        data,
    }
}

#[test]
fn verifies_single_signature_on_sbf_and_reports_compute_units() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };
    let ix = instruction(program_id, signed_instruction(&[SINGLE_MESSAGE]));
    let result = mollusk.process_instruction(&ix, &[]);

    assert!(
        result.program_result.is_ok(),
        "verify failed: {:?}",
        result.program_result
    );
    println!(
        "secp256k1 verify: 1 signature, {} message bytes, {} CUs",
        SINGLE_MESSAGE.len(),
        result.compute_units_consumed
    );
}

#[test]
fn verifies_multiple_signatures_on_sbf_and_reports_compute_units() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };
    let ix = instruction(
        program_id,
        signed_instruction(&[SINGLE_MESSAGE, SECOND_MESSAGE]),
    );
    let result = mollusk.process_instruction(&ix, &[]);

    assert!(
        result.program_result.is_ok(),
        "verify failed: {:?}",
        result.program_result
    );
    println!(
        "secp256k1 verify: 2 signatures, {} total message bytes, {} CUs",
        SINGLE_MESSAGE.len() + SECOND_MESSAGE.len(),
        result.compute_units_consumed
    );
}

#[test]
fn rejects_tampered_message_on_sbf() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };
    let mut data = signed_instruction(&[SINGLE_MESSAGE]);
    let offsets = first_offsets(&data);
    data[usize::from(offsets.message_data_offset)] ^= 1;

    let result = mollusk.process_instruction(&instruction(program_id, data), &[]);
    assert!(
        result.program_result.is_err(),
        "expected failure on tampered message, got: {:?}",
        result.program_result
    );
}

#[test]
fn rejects_tampered_address_on_sbf() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };
    let mut data = signed_instruction(&[SINGLE_MESSAGE]);
    let offsets = first_offsets(&data);
    data[usize::from(offsets.eth_address_offset)] ^= 1;

    let result = mollusk.process_instruction(&instruction(program_id, data), &[]);
    assert!(
        result.program_result.is_err(),
        "expected failure on tampered address, got: {:?}",
        result.program_result
    );
}
