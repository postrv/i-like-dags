//! Binary key encoding for pointer events
//!
//! This module provides safe, efficient binary key encoding for pointer events
//! that avoids delimiter collision bugs and enables fast prefix scans.
//!
//! ## Key Format
//!
//! Event keys: `[u32:pid_len_be] [pid_bytes] [u64:seq_be]`
//! Event prefixes: `[u32:pid_len_be] [pid_bytes]`
//!
//! This format ensures:
//! - No delimiter collision (pointer IDs can contain any characters)
//! - Lexicographic ordering by (pointer_id, sequence)
//! - Efficient prefix scans for history queries

use std::borrow::Cow;

/// Encode an event key for storage in the events tree.
/// Format: [u32:pid_len_be] [pid_bytes] [u64:seq_be]
pub fn encode_event_key(pointer_id: &str, seq: u64) -> Vec<u8> {
    let pid_bytes = pointer_id.as_bytes();
    let mut key = Vec::with_capacity(4 + pid_bytes.len() + 8);

    // Length prefix for pointer ID
    key.extend_from_slice(&(pid_bytes.len() as u32).to_be_bytes());
    // Pointer ID bytes
    key.extend_from_slice(pid_bytes);
    // Sequence number
    key.extend_from_slice(&seq.to_be_bytes());

    key
}

// There is deliberately no prefix encoder here. `PointerLog` reads history with
// a bounded range scan between `encode_event_key(id, from)` and
// `encode_event_key(id, to)`, which asks the store for exactly the sequences wanted
// rather than scanning every event for the pointer and filtering afterwards.

/// Decode an event key back to (pointer_id, sequence).
/// Returns None if the key format is invalid.
pub fn decode_event_key(key: &[u8]) -> Option<(Cow<'_, str>, u64)> {
    if key.len() < 4 {
        return None;
    }

    // Read pointer ID length
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&key[..4]);
    let pid_len = u32::from_be_bytes(len_bytes) as usize;

    // Validate total key length
    if key.len() < 4 + pid_len + 8 {
        return None;
    }

    // Extract pointer ID
    let pid_bytes = &key[4..4 + pid_len];
    let pointer_id = std::str::from_utf8(pid_bytes).ok()?;

    // Extract sequence number
    let mut seq_bytes = [0u8; 8];
    seq_bytes.copy_from_slice(&key[4 + pid_len..4 + pid_len + 8]);
    let seq = u64::from_be_bytes(seq_bytes);

    Some((Cow::Borrowed(pointer_id), seq))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_encoding() {
        let key = encode_event_key("test-pointer", 42);
        let (decoded_id, decoded_seq) = decode_event_key(&key).unwrap();

        assert_eq!(decoded_id, "test-pointer");
        assert_eq!(decoded_seq, 42);
    }

    #[test]
    fn test_special_characters() {
        // Test pointer IDs with characters that would break delimiter-based encoding
        let test_cases = [
            "pointer:with:colons",
            "pointer with spaces",
            "pointer/with/slashes",
            "pointer.with.dots",
            "UPPER_and_lower",
            "123numeric",
            "αβγ-unicode",
        ];

        for (i, pointer_id) in test_cases.iter().enumerate() {
            let seq = i as u64 + 1;
            let key = encode_event_key(pointer_id, seq);
            let (decoded_id, decoded_seq) = decode_event_key(&key).unwrap();

            assert_eq!(decoded_id, *pointer_id);
            assert_eq!(decoded_seq, seq);
        }
    }

    /// The range scan `PointerLog` relies on only returns the right events if
    /// keys for one pointer sort together and by sequence within that group.
    #[test]
    fn test_range_scan_selects_exactly_one_pointers_events() {
        let wanted = encode_event_key("test-pointer", 1)..encode_event_key("test-pointer", 3);

        for seq in [1u64, 2] {
            assert!(wanted.contains(&encode_event_key("test-pointer", seq)));
        }
        // Above the range's end, and a different pointer entirely.
        assert!(!wanted.contains(&encode_event_key("test-pointer", 3)));
        assert!(!wanted.contains(&encode_event_key("other-pointer", 1)));
    }

    #[test]
    fn test_lexicographic_ordering() {
        // Keys should sort lexicographically by (pointer_id, seq)
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
        let mut invalid = vec![0, 0, 0, 10]; // claims 10 bytes for pointer ID
        invalid.extend_from_slice(b"short"); // but only provides 5
        invalid.extend_from_slice(&1u64.to_be_bytes()); // plus sequence
        assert!(decode_event_key(&invalid).is_none());

        // Invalid UTF-8
        let mut invalid_utf8 = vec![0, 0, 0, 2]; // 2 bytes for pointer ID
        invalid_utf8.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
        invalid_utf8.extend_from_slice(&1u64.to_be_bytes()); // plus sequence
        assert!(decode_event_key(&invalid_utf8).is_none());
    }

    #[test]
    fn test_empty_pointer_id() {
        let key = encode_event_key("", 1);
        let (decoded_id, decoded_seq) = decode_event_key(&key).unwrap();

        assert_eq!(decoded_id, "");
        assert_eq!(decoded_seq, 1);
    }
}
