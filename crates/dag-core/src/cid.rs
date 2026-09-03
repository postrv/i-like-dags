use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;

/// Length of a CID in bytes: SHA-256 produces 32.
pub const CID_LEN: usize = 32;

/// Content identifier: the SHA-256 digest of a chunk's bytes.
///
/// Serialisation is format-dependent. Human-readable formats (JSON, and so the
/// HTTP API and the event stream) see a lowercase hex string; binary formats
/// (CBOR, and so everything on disk) see the raw digest exactly as the derived
/// implementation encoded it. That split keeps stored entries byte-identical —
/// and therefore keeps their CIDs stable — while making the wire format
/// readable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cid(Vec<u8>);

impl Serialize for Cid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            // Byte-for-byte what `#[derive(Serialize)]` on a newtype produced.
            serializer.serialize_newtype_struct("Cid", &self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Cid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let hex = String::deserialize(deserializer)?;
            Cid::from_hex(&hex).map_err(D::Error::custom)
        } else {
            deserializer.deserialize_newtype_struct("Cid", BinaryCidVisitor)
        }
    }
}

/// Decode the binary representation without first materialising an
/// attacker-sized `Vec`. `Cid` was originally a newtype over `Vec<u8>`, so its
/// frozen CBOR representation is a 32-element byte array. The byte-string form
/// was also accepted by the old `Vec<u8>` deserializer and remains accepted.
struct BinaryCidVisitor;

impl<'de> Visitor<'de> for BinaryCidVisitor {
    type Value = Cid;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a 32-byte CID")
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        // `deserialize_bytes` lets CBOR feed a definite/indefinite array
        // through `SeqAccess` without reserving from its declared length. It
        // also accepts the byte-string shape that `Vec<u8>` accepted before.
        deserializer.deserialize_bytes(CidBytesVisitor)
    }
}

struct CidBytesVisitor;

impl<'de> Visitor<'de> for CidBytesVisitor {
    type Value = Cid;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("exactly 32 bytes")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if let Some(length) = sequence.size_hint() {
            if length != CID_LEN {
                return Err(A::Error::invalid_length(length, &self));
            }
        }

        let mut bytes = [0_u8; CID_LEN];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = sequence
                .next_element()?
                .ok_or_else(|| A::Error::invalid_length(index, &self))?;
        }
        if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
            return Err(A::Error::invalid_length(CID_LEN + 1, &self));
        }
        Ok(Cid(bytes.to_vec()))
    }

    fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if bytes.len() != CID_LEN {
            return Err(E::invalid_length(bytes.len(), &self));
        }
        Ok(Cid(bytes.to_vec()))
    }

    fn visit_borrowed_bytes<E>(self, bytes: &'de [u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_bytes(bytes)
    }
}

impl Cid {
    pub fn compute(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self(hasher.finalize().to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Parse a CID from its lowercase hex form.
    ///
    /// The decoded length is checked, not just the hex alphabet. Without that
    /// check `""` and `"ab"` both parse happily, and a `Cid` shorter than the
    /// shard prefix panics [`chunk_path`] on a slice boundary — which is
    /// reachable from any caller that takes a CID as text, including the
    /// unauthenticated HTTP API.
    ///
    /// [`chunk_path`]: https://docs.rs/dag-storage
    pub fn from_hex(hex: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(hex)?;
        if bytes.len() != CID_LEN {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, std::io::Error> {
        if bytes.len() != CID_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid CID length: expected {} bytes, got {}",
                    CID_LEN,
                    bytes.len()
                ),
            ));
        }
        Ok(Self(bytes.to_vec()))
    }
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// There is deliberately no `From<Vec<u8>>`. An infallible conversion let any
// byte string become a `Cid`, including one too short to shard — which the
// store then panicked on. Every construction goes through `compute`,
// `from_bytes` or `from_hex`, all of which guarantee a 32-byte digest, so
// `chunk_path` and its callers can rely on the length.

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_cbor<T: Serialize>(value: &T) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(value, &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn from_hex_rejects_anything_that_is_not_a_full_digest() {
        // Regression: `from_hex` checked the hex alphabet but not the length,
        // so `""` and `"ab"` parsed into CIDs too short to be sharded — and
        // the store panicked slicing them. Reachable from anything that takes
        // a CID as text, including the unauthenticated HTTP API.
        for bad in ["", "ab", "abcd", &"ab".repeat(31), &"ab".repeat(33)] {
            assert!(
                Cid::from_hex(bad).is_err(),
                "from_hex accepted {:?} ({} chars)",
                bad,
                bad.len()
            );
        }

        // Odd length and non-hex characters are still rejected as before.
        assert!(Cid::from_hex("abc").is_err());
        assert!(Cid::from_hex(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn from_hex_round_trips_a_real_digest() {
        let cid = Cid::compute(b"hello");
        let hex = cid.to_hex();
        assert_eq!(hex.len(), CID_LEN * 2);
        assert_eq!(Cid::from_hex(&hex).unwrap(), cid);
    }

    #[test]
    fn test_cid_deterministic() {
        let data1 = b"hello world";
        let data2 = b"hello world";
        let data3 = b"hello world!";

        let cid1 = Cid::compute(data1);
        let cid2 = Cid::compute(data2);
        let cid3 = Cid::compute(data3);

        assert_eq!(cid1, cid2);
        assert_ne!(cid1, cid3);
    }

    #[test]
    fn test_cid_hex_roundtrip() {
        let data = b"test data";
        let cid = Cid::compute(data);
        let hex = cid.to_hex();
        let restored = Cid::from_hex(&hex).unwrap();
        assert_eq!(cid, restored);
    }

    #[test]
    fn cid_is_hex_in_json_and_roundtrips() {
        let cid = Cid::compute(b"hello");
        let json = serde_json::to_string(&cid).unwrap();
        assert_eq!(json, format!("\"{}\"", cid.to_hex()));
        assert_eq!(serde_json::from_str::<Cid>(&json).unwrap(), cid);
    }

    #[test]
    fn cid_cbor_encoding_is_unchanged() {
        // Locks the on-disk representation: a change here changes every stored
        // entry's bytes, and therefore every entry CID.
        let cid = Cid::compute(b"hello");
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&cid, &mut buf).unwrap();

        let mut expected = Vec::new();
        ciborium::ser::into_writer(&cid.as_bytes().to_vec(), &mut expected).unwrap();
        assert_eq!(
            buf, expected,
            "CBOR encoding must stay a plain byte sequence"
        );

        let back: Cid = ciborium::de::from_reader(&buf[..]).unwrap();
        assert_eq!(back, cid);
    }

    #[test]
    fn cid_cbor_refuses_wrong_shapes_and_lengths() {
        for length in [0, 1, CID_LEN - 1, CID_LEN + 1, 255] {
            let encoded = encode_cbor(&vec![0_u8; length]);
            assert!(
                ciborium::de::from_reader::<Cid, _>(encoded.as_slice()).is_err(),
                "accepted a {length}-element CID array"
            );
        }

        for malformed in [
            vec![0x00], // integer
            vec![0x60], // text
            vec![0xa0], // map
            vec![0xf6], // null
        ] {
            assert!(ciborium::de::from_reader::<Cid, _>(malformed.as_slice()).is_err());
        }

        // The old Vec<u8> decoder accepted a CBOR byte string as well as the
        // Rust serializer's array. Preserve that compatibility, but only at
        // the exact digest length.
        let exact_bytes = encode_cbor(&ciborium::Value::Bytes(vec![7; CID_LEN]));
        assert_eq!(
            ciborium::de::from_reader::<Cid, _>(exact_bytes.as_slice()).unwrap(),
            Cid::from_bytes(&[7; CID_LEN]).unwrap()
        );
        for length in [CID_LEN - 1, CID_LEN + 1] {
            let encoded = encode_cbor(&ciborium::Value::Bytes(vec![7; length]));
            assert!(ciborium::de::from_reader::<Cid, _>(encoded.as_slice()).is_err());
        }
    }

    #[test]
    fn cid_cbor_rejects_hostile_array_size_hints_without_reserving() {
        // Definite array(usize::MAX), deliberately without a body. The fixed
        // visitor rejects the declared length before attempting to read or
        // reserve storage for any elements.
        let huge_array = [0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let error = ciborium::de::from_reader::<Cid, _>(huge_array.as_slice()).unwrap_err();
        assert!(error.to_string().contains("invalid length"));

        // Likewise, a declared 33 elements fails from the header alone rather
        // than reading element 33 into a growing Vec.
        let thirty_three = [0x98, 0x21];
        assert!(ciborium::de::from_reader::<Cid, _>(thirty_three.as_slice()).is_err());
    }

    #[test]
    fn entry_cid_is_stable_across_serde_changes() {
        // Golden value captured before Cid gained a manual Serialize impl.
        use crate::{Entry, Link};
        let target = Cid::compute(b"link-target");
        let entry = Entry::new(
            b"payload".to_vec(),
            vec![Link::named(target, "named")],
            None,
        );
        let cid = Cid::compute(&entry.to_bytes_cbor().unwrap());
        assert_eq!(
            cid.to_hex(),
            "686ba7c54cb13307a8c92c1121b71fc59831d861ce5550e47703d6b50f91bb08"
        );
    }

    #[test]
    fn test_cid_sha256_known_value() {
        let data = b"hello";
        let cid = Cid::compute(data);
        // SHA256 of "hello"
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert_eq!(cid.to_hex(), expected);
    }
}
