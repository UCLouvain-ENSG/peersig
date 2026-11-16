//! Serde helpers: bytes as unpadded URL-safe base64.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Deserializer, Serializer};

pub fn encode(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

pub fn decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('='))
}

pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&encode(b))
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(d)?;
    decode(&s).map_err(serde::de::Error::custom)
}

/// A list of byte strings.
pub mod vec {
    use super::*;
    use serde::ser::SerializeSeq;

    pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for b in v {
            seq.serialize_element(&encode(b))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        let v = Vec::<String>::deserialize(d)?;
        v.iter().map(|s| decode(s).map_err(serde::de::Error::custom)).collect()
    }
}
