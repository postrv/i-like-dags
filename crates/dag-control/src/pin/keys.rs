//! Binary key encoding for pin events
//!
//! This module provides safe, efficient binary key encoding for pin events
//! that avoids delimiter collision bugs and enables bounded range scans.
//!
//! ## Key Format
//!
//! Event keys: `[u32:pin_id_len_be] [pin_id_bytes] [u64:seq_be]`
//! This format ensures:
//! - No delimiter collision (pin IDs can contain any characters)
//! - Lexicographic ordering by (pin_id, sequence)
//! - Efficient bounded range scans for history queries

use std::borrow::Cow;

/// Encode an event key for storage in the events tree.
/// Format: [u32:pin_id_len_be] [pin_id_bytes] [u64:seq_be]
pub fn encode_event_key(pin_id: &str, seq: u64) -> Vec<u8> {
    let pin_id_bytes = pin_id.as_bytes();
    let mut key = Vec::with_capacity(4 + pin_id_bytes.len() + 8);

    // Length prefix for pin ID
    key.extend_from_slice(&(pin_id_bytes.len() as u32).to_be_bytes());
    // Pin ID bytes
    key.extend_from_slice(pin_id_bytes);
    // Sequence number
    key.extend_from_slice(&seq.to_be_bytes());

    key
}

/// Decode an event key back to (pin_id, sequence).
/// Returns None if the key format is invalid.
pub fn decode_event_key(key: &[u8]) -> Option<(Cow<'_, str>, u64)> {
    if key.len() < 4 {
        return None;
    }

    // Read pin ID length
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&key[..4]);
    let pin_id_len = u32::from_be_bytes(len_bytes) as usize;

    // Validate total key length
    if key.len() < 4 + pin_id_len + 8 {
        return None;
    }

    // Extract pin ID
    let pin_id_bytes = &key[4..4 + pin_id_len];
    let pin_id = std::str::from_utf8(pin_id_bytes).ok()?;

    // Extract sequence number
    let mut seq_bytes = [0u8; 8];
    seq_bytes.copy_from_slice(&key[4 + pin_id_len..4 + pin_id_len + 8]);
    let seq = u64::from_be_bytes(seq_bytes);

    Some((Cow::Borrowed(pin_id), seq))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_encoding() {
        let key = encode_event_key("test-pin", 42);
        let (decoded_id, decoded_seq) = decode_event_key(&key).unwrap();

        assert_eq!(decoded_id, "test-pin");
        assert_eq!(decoded_seq, 42);
    }

    #[test]
    fn test_special_characters() {
        // Test pin IDs with characters that would break delimiter-based encoding
        let test_cases = [
            "pin:with:colons",
            "pin with spaces",
            "pin/with/slashes",
            "pin.with.dots",
            "UPPER_and_lower",
            "123numeric",
            "αβγ-unicode",
        ];

        for (i, pin_id) in test_cases.iter().enumerate() {
            let seq = i as u64 + 1;
            let key = encode_event_key(pin_id, seq);
            let (decoded_id, decoded_seq) = decode_event_key(&key).unwrap();

            assert_eq!(decoded_id, *pin_id);
            assert_eq!(decoded_seq, seq);
        }
    }

    #[test]
    fn test_lexicographic_ordering() {
        // Keys should sort lexicographically by (pin_id, seq)
        let keys = vec![
            encode_event_key("a", 1),
            encode_event_key("a", 2),
            encode_event_key("b", 1),
            encode_event_key("b", 2),
        ];

        let mut sorted_keys = keys.clone();
        sorted_keys.sort();

        assert_eq!(keys, sorted_keys);
    }

    #[test]
    fn test_invalid_keys() {
        // Too short
        assert!(decode_event_key(&[1, 2, 3]).is_none());

        // Invalid length prefix
        let mut invalid = vec![0, 0, 0, 10]; // claims 10 bytes for pin ID
        invalid.extend_from_slice(b"short"); // but only provides 5
        invalid.extend_from_slice(&1u64.to_be_bytes()); // plus sequence
        assert!(decode_event_key(&invalid).is_none());

        // Invalid UTF-8
        let mut invalid_utf8 = vec![0, 0, 0, 2]; // 2 bytes for pin ID
        invalid_utf8.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
        invalid_utf8.extend_from_slice(&1u64.to_be_bytes()); // plus sequence
        assert!(decode_event_key(&invalid_utf8).is_none());
    }

    #[test]
    fn test_empty_pin_id() {
        let key = encode_event_key("", 1);
        let (decoded_id, decoded_seq) = decode_event_key(&key).unwrap();

        assert_eq!(decoded_id, "");
        assert_eq!(decoded_seq, 1);
    }
}
