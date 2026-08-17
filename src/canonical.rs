use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::Value;
use unicode_normalization::UnicodeNormalization;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalError {
    Bom,
    DuplicateKey,
    Float,
    InvalidUtf8,
    NonCanonical,
    NonNfc,
    Schema,
    Syntax,
}

pub type Result<T> = std::result::Result<T, CanonicalError>;

pub struct CanonicalJsonV1;

impl CanonicalJsonV1 {
    pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
        let value = serde_json::to_value(value).map_err(|_| CanonicalError::Schema)?;
        validate_value(&value)?;
        serde_json::to_vec(&value).map_err(|_| CanonicalError::Schema)
    }

    pub fn decode<T>(bytes: &[u8]) -> Result<T>
    where
        T: for<'de> Deserialize<'de> + Serialize,
    {
        let value = Self::decode_value(bytes)?;
        let typed: T = serde_json::from_value(value).map_err(|_| CanonicalError::Schema)?;
        let encoded = Self::encode(&typed)?;
        if constant_time_eq(bytes, &encoded) {
            Ok(typed)
        } else {
            Err(CanonicalError::NonCanonical)
        }
    }

    pub fn decode_value(bytes: &[u8]) -> Result<Value> {
        if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
            return Err(CanonicalError::Bom);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| CanonicalError::InvalidUtf8)?;
        let mut deserializer = serde_json::Deserializer::from_str(text);
        let StrictValue(value) = StrictValue::deserialize(&mut deserializer).map_err(|error| {
            if error.to_string().contains("duplicate object key") {
                CanonicalError::DuplicateKey
            } else if error.to_string().contains("floating point") {
                CanonicalError::Float
            } else {
                CanonicalError::Syntax
            }
        })?;
        deserializer.end().map_err(|_| CanonicalError::Syntax)?;
        validate_value(&value)?;
        let encoded = serde_json::to_vec(&value).map_err(|_| CanonicalError::Schema)?;
        if constant_time_eq(bytes, &encoded) {
            Ok(value)
        } else {
            Err(CanonicalError::NonCanonical)
        }
    }
}

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        let lhs = left.get(index).copied().unwrap_or(0);
        let rhs = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(lhs ^ rhs);
    }
    difference == 0
}

fn validate_value(value: &Value) -> Result<()> {
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Number(number) if number.is_i64() || number.is_u64() => Ok(()),
        Value::Number(_) => Err(CanonicalError::Float),
        Value::String(string) => validate_nfc(string),
        Value::Array(values) => values.iter().try_for_each(validate_value),
        Value::Object(values) => values.iter().try_for_each(|(key, value)| {
            validate_nfc(key)?;
            validate_value(value)
        }),
    }
}

fn validate_nfc(value: &str) -> Result<()> {
    if value.nfc().eq(value.chars()) {
        Ok(())
    } else {
        Err(CanonicalError::NonNfc)
    }
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> de::Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CanonicalJsonV1 value")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_f64<E: de::Error>(self, _value: f64) -> std::result::Result<Self::Value, E> {
        Err(E::custom("floating point numbers are forbidden"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A: de::SeqAccess<'de>>(
        self,
        mut sequence: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(StrictValue(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A: de::MapAccess<'de>>(
        self,
        mut map: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut values = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate object key"));
            }
            let StrictValue(value) = map.next_value()?;
            values.insert(key, value);
        }
        Ok(StrictValue(Value::Object(values.into_iter().collect())))
    }
}
