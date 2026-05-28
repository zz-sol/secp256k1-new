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
pub const SECP256K1_UNCOMPRESSED_PUBKEY_SIZE: usize = SECP256K1_PUBKEY_SIZE + 1;
pub const SECP256K1_PRIVATE_KEY_SIZE: usize = 32;
pub const HASHED_PUBKEY_SERIALIZED_SIZE: usize = 20;

pub const SIGNATURE_SERIALIZED_SIZE: usize = 64;
pub const SIGNATURE_OFFSETS_SERIALIZED_SIZE: usize = 11;
pub const DATA_START: usize = SIGNATURE_OFFSETS_SERIALIZED_SIZE + 1;
#[cfg(all(
    feature = "bincode",
    not(any(target_os = "solana", target_arch = "bpf"))
))]
const RECOVERY_ID_SERIALIZED_SIZE: usize = 1;

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
        .map_err(|e| signature_error(e.to_string()))?;
    let message_hash_arr = solana_keccak_hasher::hash(message).to_bytes();
    let (signature, recovery_id) = priv_key
        .sign_prehash_recoverable(&message_hash_arr)
        .map_err(|e| signature_error(e.to_string()))?;
    Ok((signature.to_bytes().into(), recovery_id.to_byte()))
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
fn signature_error(message: impl Into<String>) -> Error {
    Error::from_source(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message.into(),
    ))
}

#[cfg(all(
    feature = "bincode",
    not(any(target_os = "solana", target_arch = "bpf"))
))]
/// Builds a single-signature secp256k1 instruction.
///
/// Returns an error if `message_arr` cannot be represented in the 16-bit wire
/// size field, if any offset cannot be represented in the 16-bit wire offset
/// fields, or if `recovery_id` is not in `0..=3`.
///
/// Recovery ids `2` and `3` are accepted for legacy wire-format compatibility.
/// New signatures normally use `0` or `1`; overflowing `2`/`3` signatures are
/// passed through to recovery rather than rejected during instruction
/// construction.
pub fn new_secp256k1_instruction_with_signature(
    message_arr: &[u8],
    signature: &[u8; SIGNATURE_SERIALIZED_SIZE],
    recovery_id: u8,
    eth_address: &[u8; HASHED_PUBKEY_SERIALIZED_SIZE],
) -> Result<Instruction, Error> {
    validate_recovery_id(recovery_id)?;

    let eth_address_offset = DATA_START;
    let signature_offset = eth_address_offset
        .checked_add(eth_address.len())
        .ok_or_else(|| signature_error("secp256k1 instruction length overflow"))?;
    let recovery_id_offset = signature_offset
        .checked_add(signature.len())
        .ok_or_else(|| signature_error("secp256k1 instruction length overflow"))?;
    let message_data_offset = recovery_id_offset
        .checked_add(RECOVERY_ID_SERIALIZED_SIZE)
        .ok_or_else(|| signature_error("secp256k1 instruction length overflow"))?;
    let message_data_end = message_data_offset
        .checked_add(message_arr.len())
        .ok_or_else(|| signature_error("secp256k1 instruction length overflow"))?;
    let instruction_data_len = message_data_end;

    let signature_offset = u16::try_from(signature_offset)
        .map_err(|_| signature_error("signature offset exceeds u16"))?;
    let eth_address_offset = u16::try_from(eth_address_offset)
        .map_err(|_| signature_error("ethereum address offset exceeds u16"))?;
    let message_data_offset = u16::try_from(message_data_offset)
        .map_err(|_| signature_error("message data offset exceeds u16"))?;
    let message_data_size = u16::try_from(message_arr.len())
        .map_err(|_| signature_error("message data size exceeds u16"))?;

    let mut instruction_data = vec![0; instruction_data_len];

    let eth_address_start = usize::from(eth_address_offset);
    let eth_address_end = eth_address_start + eth_address.len();
    instruction_data[eth_address_start..eth_address_end].copy_from_slice(eth_address);

    let signature_start = usize::from(signature_offset);
    let signature_end = signature_start + signature.len();
    instruction_data[signature_start..signature_end].copy_from_slice(signature);

    instruction_data[signature_end] = recovery_id;

    let message_data_start = usize::from(message_data_offset);
    instruction_data[message_data_start..message_data_end].copy_from_slice(message_arr);

    let num_signatures = 1;
    instruction_data[0] = num_signatures;
    let offsets = SecpSignatureOffsets {
        signature_offset,
        signature_instruction_index: 0,
        eth_address_offset,
        eth_address_instruction_index: 0,
        message_data_offset,
        message_data_size,
        message_instruction_index: 0,
    };
    serialize_signature_offsets(&mut instruction_data[1..DATA_START], &offsets)?;

    Ok(Instruction {
        program_id: solana_sdk_ids::secp256k1_program::id(),
        accounts: vec![],
        data: instruction_data,
    })
}

#[cfg(all(
    feature = "bincode",
    not(any(target_os = "solana", target_arch = "bpf"))
))]
fn validate_recovery_id(recovery_id: u8) -> Result<(), Error> {
    match recovery_id {
        0..=3 => Ok(()),
        _ => Err(signature_error("recovery id must be in 0..=3")),
    }
}

#[cfg(all(
    feature = "bincode",
    not(any(target_os = "solana", target_arch = "bpf"))
))]
fn serialize_signature_offsets(
    output: &mut [u8],
    offsets: &SecpSignatureOffsets,
) -> Result<(), Error> {
    if output.len() != SIGNATURE_OFFSETS_SERIALIZED_SIZE {
        return Err(signature_error("invalid signature offsets output length"));
    }

    output[0..2].copy_from_slice(&offsets.signature_offset.to_le_bytes());
    output[2] = offsets.signature_instruction_index;
    output[3..5].copy_from_slice(&offsets.eth_address_offset.to_le_bytes());
    output[5] = offsets.eth_address_instruction_index;
    output[6..8].copy_from_slice(&offsets.message_data_offset.to_le_bytes());
    output[8..10].copy_from_slice(&offsets.message_data_size.to_le_bytes());
    output[10] = offsets.message_instruction_index;

    Ok(())
}

/// Creates an Ethereum address from a 64-byte secp256k1 public key body.
///
/// The input must be the raw `x || y` bytes without the SEC 1 `0x04` prefix.
pub fn eth_address_from_pubkey(
    pubkey: &[u8; SECP256K1_PUBKEY_SIZE],
) -> [u8; HASHED_PUBKEY_SERIALIZED_SIZE] {
    let pubkey_hash = solana_keccak_hasher::hash(pubkey);
    let address_offset = solana_keccak_hasher::HASH_BYTES - HASHED_PUBKEY_SERIALIZED_SIZE;
    let mut addr = [0u8; HASHED_PUBKEY_SERIALIZED_SIZE];
    addr.copy_from_slice(&pubkey_hash.as_bytes()[address_offset..]);
    addr
}

/// Creates an Ethereum address from a SEC 1 uncompressed public key.
///
/// Returns `None` unless `pubkey` is a 65-byte uncompressed SEC 1 point with a
/// leading `0x04` tag.
pub fn eth_address_from_sec1_pubkey(
    pubkey: &[u8; SECP256K1_UNCOMPRESSED_PUBKEY_SIZE],
) -> Option<[u8; HASHED_PUBKEY_SERIALIZED_SIZE]> {
    if pubkey[0] != 0x04 {
        return None;
    }

    let pubkey_body = pubkey[1..].try_into().ok()?;
    Some(eth_address_from_pubkey(pubkey_body))
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

        let mut sec1_pubkey = [0; SECP256K1_UNCOMPRESSED_PUBKEY_SIZE];
        sec1_pubkey[0] = 0x04;
        sec1_pubkey[1..].copy_from_slice(&pubkey);
        assert_eq!(
            eth_address_from_sec1_pubkey(&sec1_pubkey),
            Some(eth_address_from_pubkey(&pubkey))
        );

        sec1_pubkey[0] = 0x02;
        assert_eq!(eth_address_from_sec1_pubkey(&sec1_pubkey), None);
    }

    #[cfg(all(
        feature = "bincode",
        not(any(target_os = "solana", target_arch = "bpf"))
    ))]
    #[test]
    fn test_instruction_builder_rejects_invalid_recovery_ids() {
        let signature = [1; SIGNATURE_SERIALIZED_SIZE];
        let eth_address = [2; HASHED_PUBKEY_SERIALIZED_SIZE];

        for recovery_id in [4, 27, u8::MAX] {
            assert!(new_secp256k1_instruction_with_signature(
                b"message",
                &signature,
                recovery_id,
                &eth_address
            )
            .is_err());
        }
    }

    #[cfg(all(
        feature = "bincode",
        not(any(target_os = "solana", target_arch = "bpf"))
    ))]
    #[test]
    fn test_instruction_builder_accepts_legacy_recovery_ids() {
        let signature = [1; SIGNATURE_SERIALIZED_SIZE];
        let eth_address = [2; HASHED_PUBKEY_SERIALIZED_SIZE];

        for recovery_id in 0..=3 {
            assert!(new_secp256k1_instruction_with_signature(
                b"message",
                &signature,
                recovery_id,
                &eth_address
            )
            .is_ok());
        }
    }

    #[cfg(all(
        feature = "bincode",
        not(any(target_os = "solana", target_arch = "bpf"))
    ))]
    #[test]
    fn test_instruction_builder_rejects_oversized_messages() {
        let signature = [1; SIGNATURE_SERIALIZED_SIZE];
        let eth_address = [2; HASHED_PUBKEY_SERIALIZED_SIZE];
        let max_message = vec![3; u16::MAX as usize];
        let oversized_message = vec![3; u16::MAX as usize + 1];

        assert!(new_secp256k1_instruction_with_signature(
            &max_message,
            &signature,
            0,
            &eth_address
        )
        .is_ok());
        assert!(new_secp256k1_instruction_with_signature(
            &oversized_message,
            &signature,
            0,
            &eth_address
        )
        .is_err());
    }
}
