use std::fmt;
use std::path::{Component, Path};

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
        // Names become one directory component under `dbs`, including at
        // cleanup/fork sinks. Preserve existing safe names (including spaces and
        // Unicode), but never allow path syntax on Unix or Windows. On Windows,
        // a colon can denote a drive prefix or alternate data stream.
        let mut components = Path::new(s).components();
        if s.is_empty()
            || s.chars().any(|c| matches!(c, '/' | '\\' | '\0'))
            || (cfg!(windows) && invalid_windows_component(s))
            || !matches!(components.next(), Some(Component::Normal(_)))
            || components.next().is_some()
        {
            tracing::warn!("invalid namespace name");
            return Err(Error::InvalidNamespace);
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

// Test this policy on Unix too: server tests are not run on Windows by CI.
fn invalid_windows_component(s: &str) -> bool {
    if s.ends_with(['.', ' '])
        || s.chars()
            .any(|c| c <= '\u{1f}' || matches!(c, ':' | '<' | '>' | '"' | '|' | '?' | '*'))
    {
        return true;
    }

    // Win32 treats these device names as special even when followed by an
    // extension. Superscript 1, 2 and 3 are also recognized as COM/LPT digits.
    let stem = s.split('.').next().unwrap_or("").trim_end_matches(' ');
    let stem = stem.to_ascii_uppercase();
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    if let Some(suffix) = stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"))
    {
        return matches!(
            suffix,
            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
        );
    }
    false
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

#[cfg(test)]
mod tests {
    use super::{invalid_windows_component, NamespaceName};
    use bytes::Bytes;

    #[test]
    fn accepts_single_component_names() {
        for name in [
            "default",
            "a_B-09",
            "tenant.example",
            ".hidden",
            "name..part",
            "tenant east",
            "tenant@corp",
            "a+b",
            "a~b",
            "café",
        ] {
            assert_eq!(
                NamespaceName::from_string(name.into()).unwrap().as_str(),
                name
            );
            assert_eq!(
                NamespaceName::from_bytes(Bytes::copy_from_slice(name.as_bytes()))
                    .unwrap()
                    .as_str(),
                name
            );
            assert_eq!(
                serde_json::from_str::<NamespaceName>(&format!("\"{name}\""))
                    .unwrap()
                    .as_str(),
                name
            );
        }
        #[cfg(not(windows))]
        assert!(NamespaceName::from_string("tenant:1".into()).is_ok());
    }

    #[test]
    fn windows_component_policy() {
        for name in [
            "tenant.",
            "tenant ",
            "tenant..",
            "CON",
            "con.txt",
            "prn.log",
            "AuX",
            "nul.tar.gz",
            "COM1",
            "com9.db",
            "Lpt1",
            "lpt9.txt",
            "COM¹",
            "com².txt",
            "COM³",
            "lpt¹",
            "LPT².db",
            "lpt³",
            "CONIN$",
            "conout$.txt",
            "COM1 .txt",
            "a:b",
            "a?b",
            "a*b",
            "a<b",
            "a>b",
            "a|b",
            "a\"b",
            "a\u{1f}b",
        ] {
            assert!(invalid_windows_component(name), "{name:?}");
            #[cfg(windows)]
            assert!(NamespaceName::from_string(name.into()).is_err(), "{name:?}");
        }
        for name in [
            "tenant east",
            "tenant.example",
            ".hidden",
            "name..part",
            "café",
            "COM0",
            "COM10",
            "LPT0",
            "acorn.txt",
            "community",
            "xCON.txt",
        ] {
            assert!(!invalid_windows_component(name), "{name:?}");
            assert!(NamespaceName::from_string(name.into()).is_ok(), "{name:?}");
        }
        #[cfg(not(windows))]
        for name in ["tenant.", "tenant ", "con.txt", "COM¹", "a:b"] {
            assert!(NamespaceName::from_string(name.into()).is_ok(), "{name:?}");
        }
    }

    #[test]
    fn rejects_unsafe_names_on_all_checked_constructors() {
        for name in [
            "",
            ".",
            "..",
            "../outside",
            "a/../b",
            "/absolute",
            "a\\b",
            "C:\\db",
            "a\0b",
        ] {
            assert!(NamespaceName::from_string(name.into()).is_err(), "{name:?}");
            assert!(
                NamespaceName::from_bytes(Bytes::copy_from_slice(name.as_bytes())).is_err(),
                "{name:?}"
            );
            assert!(
                serde_json::from_str::<NamespaceName>(&serde_json::to_string(name).unwrap())
                    .is_err(),
                "{name:?}"
            );
        }
        assert!(NamespaceName::from_bytes(Bytes::from_static(b"\xff")).is_err());
        #[cfg(windows)]
        for name in ["C:relative", "file:stream"] {
            assert!(NamespaceName::from_string(name.into()).is_err(), "{name:?}");
        }
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
