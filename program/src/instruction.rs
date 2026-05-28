//! Secp256k1 instruction layout and construction helpers.
// This was adapted from `solana-sdk/secp256k1_program`

#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
#[cfg(all(
    feature = "bincode",
    not(any(target_os = "solana", target_arch = "bpf"))
))]
use solana_instruction::Instruction;
#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
use solana_signature::error::Error;

pub const SECP256K1_PUBKEY_SIZE: usize = 64;
pub const SECP256K1_PRIVATE_KEY_SIZE: usize = 32;
pub const HASHED_PUBKEY_SERIALIZED_SIZE: usize = 20;

pub const SIGNATURE_SERIALIZED_SIZE: usize = 64;
pub const SIGNATURE_OFFSETS_SERIALIZED_SIZE: usize = 11;
pub const DATA_START: usize = SIGNATURE_OFFSETS_SERIALIZED_SIZE + 1;

/// Offsets of signature data within a secp256k1 instruction.
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Default, Debug, Eq, PartialEq)]
pub struct SecpSignatureOffsets {
    /// Offset to 64-byte signature plus 1-byte recovery ID.
    pub signature_offset: u16,
    /// Within the transaction, the index of the instruction whose instruction data contains the signature.
    pub signature_instruction_index: u8,
    /// Offset to 20-byte Ethereum address.
    pub eth_address_offset: u16,
    /// Within the transaction, the index of the instruction whose instruction data contains the address.
    pub eth_address_instruction_index: u8,
    /// Offset to start of message data.
    pub message_data_offset: u16,
    /// Size of message data in bytes.
    pub message_data_size: u16,
    /// Within the transaction, the index of the instruction whose instruction data contains the message.
    pub message_instruction_index: u8,
}

/// Signs a message from the given private key bytes.
#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
pub fn sign_message(
    priv_key_bytes: &[u8; SECP256K1_PRIVATE_KEY_SIZE],
    message: &[u8],
) -> Result<([u8; SIGNATURE_SERIALIZED_SIZE], u8), Error> {
    let priv_key = k256::ecdsa::SigningKey::from_slice(priv_key_bytes)
        .map_err(|e| Error::from_source(format!("{e}")))?;
    let message_hash_arr = solana_keccak_hasher::hash(message).to_bytes();
    let (signature, recovery_id) = priv_key
        .sign_prehash_recoverable(&message_hash_arr)
        .map_err(|e| Error::from_source(format!("{e}")))?;
    Ok((signature.to_bytes().into(), recovery_id.to_byte()))
}

#[cfg(all(
    feature = "bincode",
    not(any(target_os = "solana", target_arch = "bpf"))
))]
pub fn new_secp256k1_instruction_with_signature(
    message_arr: &[u8],
    signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
    recovery_id: u8,
    eth_address: &[u8; HASHED_PUBKEY_SERIALIZED_SIZE],
) -> Instruction {
    let instruction_data_len = DATA_START
        .saturating_add(eth_address.len())
        .saturating_add(signature.len())
        .saturating_add(message_arr.len())
        .saturating_add(1);
    let mut instruction_data = vec![0; instruction_data_len];

    let eth_address_offset = DATA_START;
    instruction_data[eth_address_offset..eth_address_offset.saturating_add(eth_address.len())]
        .copy_from_slice(eth_address);

    let signature_offset = DATA_START.saturating_add(eth_address.len());
    instruction_data[signature_offset..signature_offset.saturating_add(signature.len())]
        .copy_from_slice(signature);

    instruction_data[signature_offset.saturating_add(signature.len())] = recovery_id;

    let message_data_offset = signature_offset
        .saturating_add(signature.len())
        .saturating_add(1);
    instruction_data[message_data_offset..].copy_from_slice(message_arr);

    let num_signatures = 1;
    instruction_data[0] = num_signatures;
    let offsets = SecpSignatureOffsets {
        signature_offset: signature_offset as u16,
        signature_instruction_index: 0,
        eth_address_offset: eth_address_offset as u16,
        eth_address_instruction_index: 0,
        message_data_offset: message_data_offset as u16,
        message_data_size: message_arr.len() as u16,
        message_instruction_index: 0,
    };
    let writer = std::io::Cursor::new(&mut instruction_data[1..DATA_START]);
    bincode::serialize_into(writer, &offsets).unwrap();

    Instruction {
        program_id: solana_sdk_ids::secp256k1_program::id(),
        accounts: vec![],
        data: instruction_data,
    }
}

/// Creates an Ethereum address from a secp256k1 public key.
pub fn eth_address_from_pubkey(
    pubkey: &[u8; SECP256K1_PUBKEY_SIZE],
) -> [u8; HASHED_PUBKEY_SERIALIZED_SIZE] {
    let pubkey_hash = solana_keccak_hasher::hash(pubkey);
    let address_offset = solana_keccak_hasher::HASH_BYTES - HASHED_PUBKEY_SERIALIZED_SIZE;
    let mut addr = [0u8; HASHED_PUBKEY_SERIALIZED_SIZE];
    addr.copy_from_slice(&pubkey_hash.as_bytes()[address_offset..]);
    addr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eth_address_from_pubkey() {
        let pubkey = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98, 0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4,
            0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19,
            0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
        ];

        assert_eq!(
            eth_address_from_pubkey(&pubkey),
            [
                0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12, 0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2,
                0x65, 0x90, 0x29, 0x39, 0x5b, 0xdf,
            ]
        );
    }
}
