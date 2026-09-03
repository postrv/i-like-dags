use crate::{Cid, CoreError, MetaHint, MAX_CHUNK_SIZE};
use serde::de::{Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::Cursor;

/// Structural ceiling for one immutable entry.
///
/// The encoded 4 MiB chunk ceiling is normally stricter (a link includes a
/// full 32-byte CID), but keeping the logical limit explicit makes a future
/// more compact encoding unable to turn one entry into unbounded traversal
/// work.
pub const MAX_ENTRY_LINKS: usize = 100_000;

// Entry text and payload were historically bounded only by the enclosing
// chunk. Keeping that exact bound preserves every Rust-generated entry while
// ensuring the strict decoder never treats an individual field as unbounded.
const MAX_ENTRY_FIELD_BYTES: usize = MAX_CHUNK_SIZE;
const MAX_ENTRY_FIELD_NAME_BYTES: usize = 32;
const ENTRY_FIELDS: &[&str] = &["payload", "links", "meta"];
const LINK_FIELDS: &[&str] = &["name", "target"];
const META_FIELDS: &[&str] = &["content_type", "encoding"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub target: Cid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub payload: Vec<u8>,
    pub links: Vec<Link>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<MetaHint>,
}

impl Link {
    pub fn new(target: Cid, name: Option<String>) -> Self {
        Self { name, target }
    }

    pub fn named(target: Cid, name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            target,
        }
    }

    pub fn unnamed(target: Cid) -> Self {
        Self { name: None, target }
    }
}

impl Entry {
    pub fn new(payload: Vec<u8>, links: Vec<Link>, meta: Option<MetaHint>) -> Self {
        Self {
            payload,
            links,
            meta,
        }
    }

    pub fn with_payload(payload: Vec<u8>) -> Self {
        Self {
            payload,
            links: Vec::new(),
            meta: None,
        }
    }

    pub fn with_links(links: Vec<Link>) -> Self {
        Self {
            payload: Vec::new(),
            links,
            meta: None,
        }
    }

    pub fn to_bytes_cbor(&self) -> Result<Vec<u8>, CoreError> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf)
            .map_err(|e| CoreError::Serialization(format!("CBOR encode error: {}", e)))?;

        // Enforce size limit
        if buf.len() > MAX_CHUNK_SIZE {
            return Err(CoreError::ChunkTooLarge {
                size: buf.len(),
                max_size: MAX_CHUNK_SIZE,
            });
        }

        Ok(buf)
    }

    pub fn from_bytes_cbor(bytes: &[u8]) -> Result<Self, CoreError> {
        if bytes.len() > MAX_CHUNK_SIZE {
            return Err(CoreError::ChunkTooLarge {
                size: bytes.len(),
                max_size: MAX_CHUNK_SIZE,
            });
        }

        let mut cursor = Cursor::new(bytes);
        let StrictEntry(entry) = ciborium::de::from_reader(&mut cursor)
            .map_err(|e| CoreError::Deserialization(format!("CBOR decode error: {e}")))?;
        if cursor.position() != bytes.len() as u64 {
            return Err(CoreError::Deserialization(
                "CBOR decode error: trailing data after entry".to_string(),
            ));
        }
        Ok(entry)
    }
}

/// Strict, allocation-bounded decoding wrappers used only at the immutable
/// entry boundary. The public data types retain their established serde/JSON
/// behaviour while stored CBOR must match the Rust map-shaped wire exactly.
struct StrictEntry(Entry);
struct StrictLink(Link);
struct StrictLinks(Vec<Link>);
struct StrictMeta(MetaHint);
struct BoundedBytes(Vec<u8>);
struct BoundedText(String);
struct BoundedFieldName(String);

impl<'de> Deserialize<'de> for StrictEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_struct("Entry", &["payload", "links", "meta"], StrictEntryVisitor)
    }
}

struct StrictEntryVisitor;

impl<'de> Visitor<'de> for StrictEntryVisitor {
    type Value = StrictEntry;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an Entry map containing payload, links, and optional meta")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        reject_oversized_map(&map, 3, "Entry")?;

        let mut payload = None;
        let mut links = None;
        let mut meta = None;
        let mut meta_seen = false;

        while let Some(BoundedFieldName(field)) = map.next_key()? {
            match field.as_str() {
                "payload" => {
                    if payload.is_some() {
                        return Err(A::Error::duplicate_field("payload"));
                    }
                    payload = Some(map.next_value::<BoundedBytes>()?.0);
                }
                "links" => {
                    if links.is_some() {
                        return Err(A::Error::duplicate_field("links"));
                    }
                    links = Some(map.next_value::<StrictLinks>()?.0);
                }
                "meta" => {
                    if meta_seen {
                        return Err(A::Error::duplicate_field("meta"));
                    }
                    meta_seen = true;
                    meta = map.next_value::<Option<StrictMeta>>()?.map(|value| value.0);
                }
                _ => return Err(A::Error::unknown_field(&field, ENTRY_FIELDS)),
            }
        }

        Ok(StrictEntry(Entry {
            payload: payload.ok_or_else(|| A::Error::missing_field("payload"))?,
            links: links.ok_or_else(|| A::Error::missing_field("links"))?,
            meta,
        }))
    }
}

impl<'de> Deserialize<'de> for StrictLink {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_struct("Link", &["name", "target"], StrictLinkVisitor)
    }
}

struct StrictLinkVisitor;

impl<'de> Visitor<'de> for StrictLinkVisitor {
    type Value = StrictLink;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a Link map containing optional name and target")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        reject_oversized_map(&map, 2, "Link")?;

        let mut name = None;
        let mut name_seen = false;
        let mut target = None;
        while let Some(BoundedFieldName(field)) = map.next_key()? {
            match field.as_str() {
                "name" => {
                    if name_seen {
                        return Err(A::Error::duplicate_field("name"));
                    }
                    name_seen = true;
                    name = map
                        .next_value::<Option<BoundedText>>()?
                        .map(|value| value.0);
                }
                "target" => {
                    if target.is_some() {
                        return Err(A::Error::duplicate_field("target"));
                    }
                    target = Some(map.next_value()?);
                }
                _ => return Err(A::Error::unknown_field(&field, LINK_FIELDS)),
            }
        }

        Ok(StrictLink(Link {
            name,
            target: target.ok_or_else(|| A::Error::missing_field("target"))?,
        }))
    }
}

impl<'de> Deserialize<'de> for StrictLinks {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(StrictLinksVisitor)
    }
}

struct StrictLinksVisitor;

impl<'de> Visitor<'de> for StrictLinksVisitor {
    type Value = StrictLinks;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "at most {MAX_ENTRY_LINKS} links")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if sequence
            .size_hint()
            .is_some_and(|length| length > MAX_ENTRY_LINKS)
        {
            return Err(A::Error::custom(format_args!(
                "entry has more than {MAX_ENTRY_LINKS} links"
            )));
        }

        // Do not reserve from the untrusted CBOR size hint. serde's generic
        // Vec visitor already caps preallocation at 1 MiB, but this boundary
        // can avoid attacker-directed reservation entirely.
        let mut links = Vec::new();
        while let Some(StrictLink(link)) = sequence.next_element()? {
            if links.len() == MAX_ENTRY_LINKS {
                return Err(A::Error::custom(format_args!(
                    "entry has more than {MAX_ENTRY_LINKS} links"
                )));
            }
            links.push(link);
        }
        Ok(StrictLinks(links))
    }
}

impl<'de> Deserialize<'de> for StrictMeta {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "MetaHint",
            &["content_type", "encoding"],
            StrictMetaVisitor,
        )
    }
}

struct StrictMetaVisitor;

impl<'de> Visitor<'de> for StrictMetaVisitor {
    type Value = StrictMeta;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a MetaHint map")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        reject_oversized_map(&map, 2, "MetaHint")?;

        let mut content_type = None;
        let mut content_type_seen = false;
        let mut encoding = None;
        let mut encoding_seen = false;
        while let Some(BoundedFieldName(field)) = map.next_key()? {
            match field.as_str() {
                "content_type" => {
                    if content_type_seen {
                        return Err(A::Error::duplicate_field("content_type"));
                    }
                    content_type_seen = true;
                    content_type = map
                        .next_value::<Option<BoundedText>>()?
                        .map(|value| value.0);
                }
                "encoding" => {
                    if encoding_seen {
                        return Err(A::Error::duplicate_field("encoding"));
                    }
                    encoding_seen = true;
                    encoding = map
                        .next_value::<Option<BoundedText>>()?
                        .map(|value| value.0);
                }
                _ => return Err(A::Error::unknown_field(&field, META_FIELDS)),
            }
        }

        Ok(StrictMeta(MetaHint {
            content_type,
            encoding,
        }))
    }
}

impl<'de> Deserialize<'de> for BoundedBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // `deserialize_byte_buf` handles the Rust wire's integer array via
        // `visit_seq`; byte strings are accumulated only from bytes actually
        // present in the already-bounded input, not from their declared size.
        deserializer.deserialize_byte_buf(BoundedBytesVisitor)
    }
}

struct BoundedBytesVisitor;

impl<'de> Visitor<'de> for BoundedBytesVisitor {
    type Value = BoundedBytes;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "a payload no larger than {MAX_ENTRY_FIELD_BYTES} bytes"
        )
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if sequence
            .size_hint()
            .is_some_and(|length| length > MAX_ENTRY_FIELD_BYTES)
        {
            return Err(A::Error::custom("entry payload exceeds chunk limit"));
        }

        let mut bytes = Vec::new();
        while let Some(byte) = sequence.next_element()? {
            if bytes.len() == MAX_ENTRY_FIELD_BYTES {
                return Err(A::Error::custom("entry payload exceeds chunk limit"));
            }
            bytes.push(byte);
        }
        Ok(BoundedBytes(bytes))
    }

    fn visit_byte_buf<E>(self, bytes: Vec<u8>) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if bytes.len() > MAX_ENTRY_FIELD_BYTES {
            return Err(E::custom("entry payload exceeds chunk limit"));
        }
        Ok(BoundedBytes(bytes))
    }

    fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if bytes.len() > MAX_ENTRY_FIELD_BYTES {
            return Err(E::custom("entry payload exceeds chunk limit"));
        }
        Ok(BoundedBytes(bytes.to_vec()))
    }
}

impl<'de> Deserialize<'de> for BoundedText {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_string(BoundedTextVisitor)
    }
}

impl<'de> Deserialize<'de> for BoundedFieldName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_identifier(BoundedFieldNameVisitor)
    }
}

struct BoundedFieldNameVisitor;

impl Visitor<'_> for BoundedFieldNameVisitor {
    type Value = BoundedFieldName;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "a textual schema field name of at most {MAX_ENTRY_FIELD_NAME_BYTES} bytes"
        )
    }

    fn visit_str<E>(self, field: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if field.len() > MAX_ENTRY_FIELD_NAME_BYTES {
            return Err(E::custom("entry field name exceeds schema limit"));
        }
        Ok(BoundedFieldName(field.to_owned()))
    }

    fn visit_string<E>(self, field: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if field.len() > MAX_ENTRY_FIELD_NAME_BYTES {
            return Err(E::custom("entry field name exceeds schema limit"));
        }
        Ok(BoundedFieldName(field))
    }
}

struct BoundedTextVisitor;

impl Visitor<'_> for BoundedTextVisitor {
    type Value = BoundedText;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "UTF-8 text no larger than {MAX_ENTRY_FIELD_BYTES} bytes"
        )
    }

    fn visit_str<E>(self, text: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if text.len() > MAX_ENTRY_FIELD_BYTES {
            return Err(E::custom("entry text exceeds chunk limit"));
        }
        Ok(BoundedText(text.to_owned()))
    }

    fn visit_string<E>(self, text: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if text.len() > MAX_ENTRY_FIELD_BYTES {
            return Err(E::custom("entry text exceeds chunk limit"));
        }
        Ok(BoundedText(text))
    }
}

fn reject_oversized_map<'de, A>(map: &A, max_fields: usize, kind: &str) -> Result<(), A::Error>
where
    A: MapAccess<'de>,
{
    if map
        .size_hint()
        .is_some_and(|field_count| field_count > max_fields)
    {
        return Err(A::Error::custom(format_args!(
            "{kind} map has more than {max_fields} fields"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value;

    fn encode_value(value: &Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(value, &mut bytes).unwrap();
        bytes
    }

    fn entry_value(entry: &Entry) -> Value {
        ciborium::de::from_reader(entry.to_bytes_cbor().unwrap().as_slice()).unwrap()
    }

    fn map_mut(value: &mut Value) -> &mut Vec<(Value, Value)> {
        match value {
            Value::Map(fields) => fields,
            other => panic!("expected map, got {other:?}"),
        }
    }

    #[test]
    fn test_link_creation() {
        let cid = Cid::compute(b"test data");

        let unnamed = Link::unnamed(cid.clone());
        assert_eq!(unnamed.target, cid);
        assert!(unnamed.name.is_none());

        let named = Link::named(cid.clone(), "test-link");
        assert_eq!(named.target, cid);
        assert_eq!(named.name, Some("test-link".to_string()));

        let constructed = Link::new(cid.clone(), Some("manual".to_string()));
        assert_eq!(constructed.target, cid);
        assert_eq!(constructed.name, Some("manual".to_string()));
    }

    #[test]
    fn test_entry_creation() {
        let payload = b"hello world".to_vec();
        let cid = Cid::compute(b"linked content");
        let link = Link::named(cid, "content");

        let entry = Entry::new(payload.clone(), vec![link.clone()], None);
        assert_eq!(entry.payload, payload);
        assert_eq!(entry.links, vec![link.clone()]);
        assert!(entry.meta.is_none());

        let payload_only = Entry::with_payload(payload.clone());
        assert_eq!(payload_only.payload, payload);
        assert!(payload_only.links.is_empty());

        let links_only = Entry::with_links(vec![link.clone()]);
        assert!(links_only.payload.is_empty());
        assert_eq!(links_only.links, vec![link]);
    }

    #[test]
    fn test_entry_cbor_roundtrip() {
        let payload = b"test payload data".to_vec();
        let cid1 = Cid::compute(b"first link target");
        let cid2 = Cid::compute(b"second link target");

        let links = vec![Link::named(cid1, "first"), Link::unnamed(cid2)];

        let meta = Some(MetaHint {
            content_type: Some("application/json".to_string()),
            encoding: None,
        });

        let original = Entry::new(payload, links, meta);

        // Encode to CBOR
        let cbor_bytes = original.to_bytes_cbor().unwrap();

        // Decode back
        let decoded = Entry::from_bytes_cbor(&cbor_bytes).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_entry_cbor_deterministic() {
        let payload = b"deterministic test".to_vec();
        let cid = Cid::compute(b"link target");
        let link = Link::named(cid, "test-link");
        let entry = Entry::new(payload, vec![link], None);

        let cbor1 = entry.to_bytes_cbor().unwrap();
        let cbor2 = entry.to_bytes_cbor().unwrap();

        assert_eq!(cbor1, cbor2, "CBOR encoding should be deterministic");
    }

    #[test]
    fn test_entry_cbor_size_limit() {
        // Create an entry that would exceed MAX_CHUNK_SIZE when encoded
        let large_payload = vec![0u8; MAX_CHUNK_SIZE];
        let entry = Entry::with_payload(large_payload);

        let result = entry.to_bytes_cbor();
        assert!(matches!(result, Err(CoreError::ChunkTooLarge { .. })));
    }

    #[test]
    fn decode_refuses_input_larger_than_one_chunk_before_parsing() {
        let oversized = vec![0_u8; MAX_CHUNK_SIZE + 1];
        assert!(matches!(
            Entry::from_bytes_cbor(&oversized),
            Err(CoreError::ChunkTooLarge {
                size,
                max_size: MAX_CHUNK_SIZE
            }) if size == MAX_CHUNK_SIZE + 1
        ));
    }

    #[test]
    fn decode_refuses_trailing_bytes_and_a_second_cbor_item() {
        let encoded = Entry::with_payload(b"one".to_vec())
            .to_bytes_cbor()
            .unwrap();

        let mut trailing_byte = encoded.clone();
        trailing_byte.push(0);
        assert!(matches!(
            Entry::from_bytes_cbor(&trailing_byte),
            Err(CoreError::Deserialization(message)) if message.contains("trailing data")
        ));

        let mut second_item = encoded.clone();
        second_item.extend_from_slice(&encoded);
        assert!(matches!(
            Entry::from_bytes_cbor(&second_item),
            Err(CoreError::Deserialization(message)) if message.contains("trailing data")
        ));
    }

    #[test]
    fn decode_refuses_unknown_duplicate_and_missing_entry_fields() {
        let base = Entry::with_payload(b"strict".to_vec());

        let mut unknown = entry_value(&base);
        map_mut(&mut unknown).push((Value::Text("surprise".into()), Value::Null));
        assert!(Entry::from_bytes_cbor(&encode_value(&unknown)).is_err());

        let mut duplicate = entry_value(&base);
        map_mut(&mut duplicate).push((Value::Text("payload".into()), Value::Array(Vec::new())));
        assert!(Entry::from_bytes_cbor(&encode_value(&duplicate)).is_err());

        for missing in [
            Value::Map(vec![(
                Value::Text("links".into()),
                Value::Array(Vec::new()),
            )]),
            Value::Map(vec![(
                Value::Text("payload".into()),
                Value::Array(Vec::new()),
            )]),
        ] {
            assert!(Entry::from_bytes_cbor(&encode_value(&missing)).is_err());
        }

        // Serde field identifiers normally accept numeric field indexes and
        // byte-string aliases. Neither is part of the frozen Rust map wire.
        let numeric_keys = Value::Map(vec![
            (Value::Integer(0.into()), Value::Array(Vec::new())),
            (Value::Integer(1.into()), Value::Array(Vec::new())),
        ]);
        assert!(Entry::from_bytes_cbor(&encode_value(&numeric_keys)).is_err());
        let byte_string_key = Value::Map(vec![
            (Value::Bytes(b"payload".to_vec()), Value::Array(Vec::new())),
            (Value::Text("links".into()), Value::Array(Vec::new())),
        ]);
        assert!(Entry::from_bytes_cbor(&encode_value(&byte_string_key)).is_err());

        let overlong_field = Value::Map(vec![(
            Value::Text("x".repeat(MAX_ENTRY_FIELD_NAME_BYTES + 1)),
            Value::Null,
        )]);
        assert!(matches!(
            Entry::from_bytes_cbor(&encode_value(&overlong_field)),
            Err(CoreError::Deserialization(message))
                if message.contains("field name exceeds schema limit")
        ));
    }

    #[test]
    fn decode_refuses_unknown_duplicate_and_missing_nested_fields() {
        let cid = Cid::compute(b"target");
        let base = Entry::new(
            Vec::new(),
            vec![Link::unnamed(cid.clone())],
            Some(MetaHint {
                content_type: Some("text/plain".into()),
                encoding: None,
            }),
        );

        let mut unknown_link = entry_value(&base);
        let entry_fields = map_mut(&mut unknown_link);
        let links = entry_fields
            .iter_mut()
            .find_map(|(key, value)| (key == &Value::Text("links".into())).then_some(value))
            .unwrap();
        let Value::Array(links) = links else {
            panic!("links was not an array")
        };
        let link_fields = map_mut(&mut links[0]);
        link_fields[0].0 = Value::Text("surprise".into());
        assert!(Entry::from_bytes_cbor(&encode_value(&unknown_link)).is_err());

        let duplicate_target = Value::Map(vec![
            (Value::Text("target".into()), entry_value_for_cid(&cid)),
            (Value::Text("target".into()), entry_value_for_cid(&cid)),
        ]);
        let duplicate_link_entry = Value::Map(vec![
            (Value::Text("payload".into()), Value::Array(Vec::new())),
            (
                Value::Text("links".into()),
                Value::Array(vec![duplicate_target]),
            ),
        ]);
        assert!(Entry::from_bytes_cbor(&encode_value(&duplicate_link_entry)).is_err());

        let missing_target = Value::Map(vec![
            (Value::Text("payload".into()), Value::Array(Vec::new())),
            (
                Value::Text("links".into()),
                Value::Array(vec![Value::Map(Vec::new())]),
            ),
        ]);
        assert!(Entry::from_bytes_cbor(&encode_value(&missing_target)).is_err());

        let mut unknown_meta = entry_value(&base);
        let entry_fields = map_mut(&mut unknown_meta);
        let meta = entry_fields
            .iter_mut()
            .find_map(|(key, value)| (key == &Value::Text("meta".into())).then_some(value))
            .unwrap();
        map_mut(meta).push((Value::Text("surprise".into()), Value::Null));
        assert!(Entry::from_bytes_cbor(&encode_value(&unknown_meta)).is_err());
    }

    fn entry_value_for_cid(cid: &Cid) -> Value {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(cid, &mut bytes).unwrap();
        ciborium::de::from_reader(bytes.as_slice()).unwrap()
    }

    #[test]
    fn decode_refuses_more_than_one_hundred_thousand_links_from_the_header() {
        // {"payload": [], "links": <array(100001)>}. No elements follow:
        // the bounded visitor must reject the declared count before trying to
        // parse or reserve storage for one of them.
        let encoded = [
            0xa2, 0x67, b'p', b'a', b'y', b'l', b'o', b'a', b'd', 0x80, 0x65, b'l', b'i', b'n',
            b'k', b's', 0x9a, 0x00, 0x01, 0x86, 0xa1,
        ];
        assert!(matches!(
            Entry::from_bytes_cbor(&encoded),
            Err(CoreError::Deserialization(message))
                if message.contains("more than 100000 links")
        ));
    }

    #[test]
    fn hostile_container_size_hints_are_rejected_without_reading_their_bodies() {
        // A map and payload array declaring usize::MAX entries, with no body.
        // Strict visitors reject their size hints immediately instead of
        // reserving attacker-selected capacities or walking to EOF.
        let huge_map = [0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert!(Entry::from_bytes_cbor(&huge_map).is_err());

        let mut huge_payload = vec![0xa2, 0x67, b'p', b'a', b'y', b'l', b'o', b'a', b'd', 0x9b];
        huge_payload.extend_from_slice(&[0xff; 8]);
        assert!(Entry::from_bytes_cbor(&huge_payload).is_err());
    }

    #[test]
    fn test_entry_empty() {
        let entry = Entry::new(Vec::new(), Vec::new(), None);

        let cbor_bytes = entry.to_bytes_cbor().unwrap();
        let decoded = Entry::from_bytes_cbor(&cbor_bytes).unwrap();

        assert_eq!(entry, decoded);
        assert!(decoded.payload.is_empty());
        assert!(decoded.links.is_empty());
        assert!(decoded.meta.is_none());
    }
}
