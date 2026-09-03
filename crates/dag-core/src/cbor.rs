//! Shared strict CBOR decoding for persisted and replicated values.

use std::io::Cursor;

use serde::de::DeserializeOwned;

use crate::CoreError;

/// Decode exactly one CBOR value and require the input to end with it.
///
/// `ciborium::de::from_reader` intentionally accepts a valid prefix. That is
/// useful for streams, but immutable event payloads and database rows are
/// framed by their enclosing chunk/row and must not accept a second value or
/// arbitrary trailing bytes. Callers remain responsible for enforcing their
/// type-specific byte ceiling before invoking this helper.
pub fn decode_cbor_exact<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CoreError> {
    let mut cursor = Cursor::new(bytes);
    let value = ciborium::de::from_reader(&mut cursor)
        .map_err(|error| CoreError::Deserialization(format!("CBOR decode error: {error}")))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(CoreError::Deserialization(
            "CBOR decode error: trailing data after value".into(),
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_decoder_rejects_a_second_value_and_arbitrary_garbage() {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&vec![1u8, 2, 3], &mut encoded).unwrap();
        assert_eq!(
            decode_cbor_exact::<Vec<u8>>(&encoded).unwrap(),
            vec![1, 2, 3]
        );

        let mut second_value = encoded.clone();
        second_value.push(0xf6); // CBOR null
        assert!(decode_cbor_exact::<Vec<u8>>(&second_value).is_err());

        let mut garbage = encoded;
        garbage.push(0xff); // break outside an indefinite container
        assert!(decode_cbor_exact::<Vec<u8>>(&garbage).is_err());
    }
}
