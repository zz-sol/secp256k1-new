use {
    k256::ecdsa::SigningKey,
    solana_keccak_hasher::hash,
    solana_secp256k1_program::{
        eth_address_from_sec1_pubkey, SecpSignatureOffsets, HASHED_PUBKEY_SERIALIZED_SIZE,
        SECP256K1_UNCOMPRESSED_PUBKEY_SIZE, SIGNATURE_OFFSETS_SERIALIZED_SIZE,
        SIGNATURE_SERIALIZED_SIZE,
    },
};

/// Holds all cryptographic material for a single signed message.
struct SignedPayload<'a> {
    signature: [u8; SIGNATURE_SERIALIZED_SIZE],
    recovery_id: u8,
    address: [u8; HASHED_PUBKEY_SERIALIZED_SIZE],
    message: &'a [u8],
}

/// Signs `message` with `signing_key` and returns the compact signature,
/// recovery id, and the corresponding Ethereum address.
fn signed_payload<'a>(signing_key: &SigningKey, message: &'a [u8]) -> SignedPayload<'a> {
    let message_hash = hash(message);
    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(message_hash.as_bytes())
        .unwrap();
    let signature: [u8; SIGNATURE_SERIALIZED_SIZE] = signature.to_bytes().into();

    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false);
    let pubkey: [u8; SECP256K1_UNCOMPRESSED_PUBKEY_SIZE] = encoded.as_bytes().try_into().unwrap();
    let address = eth_address_from_sec1_pubkey(&pubkey).unwrap();

    SignedPayload {
        signature,
        recovery_id: recovery_id.to_byte(),
        address,
        message,
    }
}

/// Builds a valid secp256k1 instruction buffer containing one entry per
/// message, all signed by a fixed test key.
pub(crate) fn signed_instruction(messages: &[&[u8]]) -> Vec<u8> {
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

/// Parses and returns the first `SecpSignatureOffsets` entry from `instruction`.
pub(crate) fn first_offsets(instruction: &[u8]) -> SecpSignatureOffsets {
    let input = &instruction[1..1 + SIGNATURE_OFFSETS_SERIALIZED_SIZE];
    SecpSignatureOffsets {
        signature_offset: u16::from_le_bytes(input[0..2].try_into().unwrap()),
        signature_instruction_index: input[2],
        eth_address_offset: u16::from_le_bytes(input[3..5].try_into().unwrap()),
        eth_address_instruction_index: input[5],
        message_data_offset: u16::from_le_bytes(input[6..8].try_into().unwrap()),
        message_data_size: u16::from_le_bytes(input[8..10].try_into().unwrap()),
        message_instruction_index: input[10],
    }
}

/// Serializes `offsets` into the 11-byte little-endian wire format in `output`.
pub(crate) fn write_offsets(output: &mut [u8], offsets: &SecpSignatureOffsets) {
    output[0..2].copy_from_slice(&offsets.signature_offset.to_le_bytes());
    output[2] = offsets.signature_instruction_index;
    output[3..5].copy_from_slice(&offsets.eth_address_offset.to_le_bytes());
    output[5] = offsets.eth_address_instruction_index;
    output[6..8].copy_from_slice(&offsets.message_data_offset.to_le_bytes());
    output[8..10].copy_from_slice(&offsets.message_data_size.to_le_bytes());
    output[10] = offsets.message_instruction_index;
}
