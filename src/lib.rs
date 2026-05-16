use {
    solana_account_info::AccountInfo,
    solana_keccak_hasher::hash,
    solana_program_entrypoint::ProgramResult,
    solana_program_error::ProgramError,
    solana_pubkey::Pubkey,
    solana_secp256k1_recover::{
        secp256k1_recover, SECP256K1_PUBLIC_KEY_LENGTH, SECP256K1_SIGNATURE_LENGTH,
    },
};

#[cfg(not(feature = "no-entrypoint"))]
solana_program_entrypoint::entrypoint!(process_instruction);

#[cfg(all(feature = "custom-panic", target_os = "solana"))]
#[no_mangle]
fn custom_panic(_info: &core::panic::PanicInfo<'_>) {}

#[cfg(target_os = "solana")]
#[no_mangle]
pub extern "C" fn abort() -> ! {
    loop {}
}

pub const ETH_ADDRESS_LENGTH: usize = 20;
pub const RECOVERY_ID_LENGTH: usize = 1;
pub const INSTRUCTION_HEADER_LENGTH: usize =
    RECOVERY_ID_LENGTH + SECP256K1_SIGNATURE_LENGTH + ETH_ADDRESS_LENGTH;

const SIGNATURE_OFFSET: usize = RECOVERY_ID_LENGTH;
const ETH_ADDRESS_OFFSET: usize = SIGNATURE_OFFSET + SECP256K1_SIGNATURE_LENGTH;
const MESSAGE_OFFSET: usize = ETH_ADDRESS_OFFSET + ETH_ADDRESS_LENGTH;

#[derive(Debug, Clone, Copy)]
pub struct VerifyInstruction<'a> {
    pub recovery_id: u8,
    pub signature: &'a [u8; SECP256K1_SIGNATURE_LENGTH],
    pub expected_eth_address: &'a [u8; ETH_ADDRESS_LENGTH],
    pub message: &'a [u8],
}

impl<'a> VerifyInstruction<'a> {
    pub fn unpack(input: &'a [u8]) -> Result<Self, ProgramError> {
        if input.len() < INSTRUCTION_HEADER_LENGTH {
            return Err(ProgramError::InvalidInstructionData);
        }

        let signature = input[SIGNATURE_OFFSET..ETH_ADDRESS_OFFSET]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        let expected_eth_address = input[ETH_ADDRESS_OFFSET..MESSAGE_OFFSET]
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;

        Ok(Self {
            recovery_id: normalize_recovery_id(input[0])?,
            signature,
            expected_eth_address,
            message: &input[MESSAGE_OFFSET..],
        })
    }
}

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if !accounts.is_empty() {
        return Err(ProgramError::InvalidArgument);
    }

    let instruction = VerifyInstruction::unpack(instruction_data)?;
    verify_ethereum_signature(instruction)
}

pub fn verify_ethereum_signature(instruction: VerifyInstruction<'_>) -> ProgramResult {
    let message_hash = hash(instruction.message);
    let recovered_pubkey = secp256k1_recover(
        message_hash.as_bytes(),
        instruction.recovery_id,
        instruction.signature,
    )
    .map_err(|_| ProgramError::InvalidArgument)?;

    let recovered_address = ethereum_address(&recovered_pubkey.to_bytes());
    if &recovered_address != instruction.expected_eth_address {
        return Err(ProgramError::InvalidArgument);
    }

    Ok(())
}

pub fn ethereum_address(pubkey: &[u8; SECP256K1_PUBLIC_KEY_LENGTH]) -> [u8; ETH_ADDRESS_LENGTH] {
    // Ethereum addresses hash the 64-byte uncompressed public key body, without the 0x04 prefix.
    let hash = hash(pubkey);
    let mut address = [0; ETH_ADDRESS_LENGTH];
    address.copy_from_slice(&hash.as_bytes()[12..]);
    address
}

fn normalize_recovery_id(recovery_id: u8) -> Result<u8, ProgramError> {
    match recovery_id {
        0..=1 => Ok(recovery_id),
        27..=28 => Ok(recovery_id - 27),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

#[cfg(test)]
mod tests {
    use {super::*, k256::ecdsa::SigningKey};

    fn signed_instruction(message: &[u8]) -> Vec<u8> {
        let signing_key = SigningKey::from_slice(&[7; 32]).unwrap();
        let message_hash = hash(message);
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(message_hash.as_bytes())
            .unwrap();
        let signature: [u8; SECP256K1_SIGNATURE_LENGTH] = signature.to_bytes().into();

        let verifying_key = signing_key.verifying_key();
        let encoded = verifying_key.to_encoded_point(false);
        // Drop the SEC1 0x04 prefix; Ethereum hashes only the 64-byte x||y body.
        let pubkey: [u8; SECP256K1_PUBLIC_KEY_LENGTH] =
            encoded.as_bytes()[1..65].try_into().unwrap();
        let address = ethereum_address(&pubkey);

        let mut instruction = Vec::with_capacity(INSTRUCTION_HEADER_LENGTH + message.len());
        instruction.push(recovery_id.to_byte());
        instruction.extend_from_slice(&signature);
        instruction.extend_from_slice(&address);
        instruction.extend_from_slice(message);
        instruction
    }

    #[test]
    fn verifies_matching_signature() {
        let program_id = Pubkey::default();
        let instruction = signed_instruction(b"hello secp256k1");

        assert_eq!(process_instruction(&program_id, &[], &instruction), Ok(()));
    }

    #[test]
    fn rejects_wrong_address() {
        let program_id = Pubkey::default();
        let mut instruction = signed_instruction(b"hello secp256k1");
        instruction[ETH_ADDRESS_OFFSET] ^= 1;

        assert_eq!(
            process_instruction(&program_id, &[], &instruction),
            Err(ProgramError::InvalidArgument)
        );
    }

    #[test]
    fn rejects_corrupted_signature() {
        let program_id = Pubkey::default();
        let mut instruction = signed_instruction(b"hello secp256k1");
        instruction[SIGNATURE_OFFSET] ^= 1;

        assert_eq!(
            process_instruction(&program_id, &[], &instruction),
            Err(ProgramError::InvalidArgument)
        );
    }

    #[test]
    fn rejects_short_instruction() {
        let program_id = Pubkey::default();

        assert_eq!(
            process_instruction(&program_id, &[], &[0; INSTRUCTION_HEADER_LENGTH - 1]),
            Err(ProgramError::InvalidInstructionData)
        );
    }

    #[test]
    fn accepts_ethereum_style_recovery_id() {
        let program_id = Pubkey::default();
        let mut instruction = signed_instruction(b"hello secp256k1");
        instruction[0] += 27;

        assert_eq!(process_instruction(&program_id, &[], &instruction), Ok(()));
    }

    #[test]
    fn rejects_overflow_recovery_ids() {
        let program_id = Pubkey::default();

        for recovery_id in [2, 3, 29, 30] {
            let mut instruction = signed_instruction(b"hello secp256k1");
            instruction[0] = recovery_id;

            assert_eq!(
                process_instruction(&program_id, &[], &instruction),
                Err(ProgramError::InvalidInstructionData)
            );
        }
    }
}
