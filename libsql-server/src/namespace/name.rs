use std::{
    fmt,
    path::{Component, Path},
};

use bytes::Bytes;
use serde::{de::Visitor, Deserialize};

use crate::error::Error;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct NamespaceName(Bytes);

impl fmt::Debug for NamespaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl Into<libsql_sys::name::NamespaceName> for NamespaceName {
    fn into(self) -> libsql_sys::name::NamespaceName {
        libsql_sys::name::NamespaceName(self.0)
    }
}

impl Default for NamespaceName {
    fn default() -> Self {
        Self(Bytes::from_static(b"default"))
    }
}

impl AsRef<str> for NamespaceName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<&'static str> for NamespaceName {
    fn from(value: &'static str) -> Self {
        Self::from_bytes(Bytes::from_static(value.as_bytes())).unwrap()
    }
}

impl NamespaceName {
    pub fn from_string(s: String) -> crate::Result<Self> {
        Self::validate(&s)?;
        Ok(Self(Bytes::from(s)))
    }

    fn validate(s: &str) -> crate::Result<()> {
        // Names must be a single path component on both Unix and Windows.
        // Keep harmless punctuation and Unicode rather than imposing an identifier alphabet.
        let mut components = Path::new(s).components();
        if s.is_empty()
            || s.chars().any(|c| matches!(c, '/' | '\\' | '\0'))
            || (cfg!(windows) && s.contains(':'))
            || !matches!(components.next(), Some(Component::Normal(_)))
            || components.next().is_some()
        {
            tracing::warn!("invalid namespace name");
            return Err(crate::error::Error::InvalidNamespace);
        }

        Ok(())
    }

    pub fn as_str(&self) -> &str {
        // Safety: the namespace is always valid UTF8
        unsafe { std::str::from_utf8_unchecked(&self.0) }
    }

    pub fn from_bytes(bytes: Bytes) -> crate::Result<Self> {
        let s = std::str::from_utf8(&bytes).map_err(|_| Error::InvalidNamespace)?;
        Self::validate(s)?;
        Ok(Self(bytes))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_single_safe_path_components_are_names() {
        for name in [
            "",
            ".",
            "..",
            "../victim",
            "a/b",
            "a\\b",
            "/tmp/victim",
            "a\0b",
        ] {
            assert!(
                NamespaceName::from_string(name.to_owned()).is_err(),
                "{name:?}"
            );
            assert!(NamespaceName::from_bytes(Bytes::copy_from_slice(name.as_bytes())).is_err());
            assert!(serde_json::from_str::<NamespaceName>(&format!("{name:?}")).is_err());
        }
        for name in ["tenant", "a..b", "hello world", "café!", "a:b"] {
            if cfg!(windows) && name.contains(':') {
                continue;
            }
            assert_eq!(
                NamespaceName::from_string(name.to_owned())
                    .unwrap()
                    .as_str(),
                name
            );
        }
    }
}

impl fmt::Display for NamespaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl<'de> Deserialize<'de> for NamespaceName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct V;

        impl<'de> Visitor<'de> for V {
            type Value = NamespaceName;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a valid namespace name")
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                NamespaceName::from_string(v).map_err(|e| E::custom(e))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                NamespaceName::from_string(v.to_string()).map_err(|e| E::custom(e))
            }
        }

        deserializer.deserialize_string(V)
    }
}

impl serde::Serialize for NamespaceName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}
