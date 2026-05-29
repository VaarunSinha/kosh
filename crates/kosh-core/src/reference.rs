use rand::Rng;

pub const REF_PREFIX: &str = "KOSH:";
pub const REF_PATTERN: &str = r"KOSH:[a-f0-9]{8}";

/// A Kosh reference ID — the value stored in .env
/// Format: KOSH:a3f9c2b1
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct RefId(String);

impl RefId {
    /// Generate a new cryptographically random ref ID
    pub fn generate() -> Self {
        let bytes: [u8; 4] = rand::thread_rng().gen();
        Self(format!("KOSH:{}", hex::encode(bytes)))
    }

    /// Parse a ref ID from a string (e.g. from .env file)
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.starts_with(REF_PREFIX) && s.len() == REF_PREFIX.len() + 8 {
            let hex_part = &s[REF_PREFIX.len()..];
            if hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(Self(s.to_string()));
            }
        }
        None
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The raw hex part without KOSH: prefix (used as keychain key component)
    pub fn hex(&self) -> &str {
        &self.0[REF_PREFIX.len()..]
    }
}

impl std::fmt::Display for RefId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_ref_id_format() {
        let id = RefId::generate();
        assert!(id.as_str().starts_with("KOSH:"));
        assert_eq!(id.as_str().len(), 13); // "KOSH:" + 8 hex chars
    }

    #[test]
    fn test_ref_id_parse_valid() {
        let id = RefId::parse("KOSH:a3f9c2b1").unwrap();
        assert_eq!(id.hex(), "a3f9c2b1");
    }

    #[test]
    fn test_ref_id_parse_invalid() {
        assert!(RefId::parse("KOSH:ZZZZZZZZ").is_none()); // not hex
        assert!(RefId::parse("SK-proj-xxxx").is_none()); // not a ref
        assert!(RefId::parse("KOSH:abc").is_none()); // too short
        assert!(RefId::parse("").is_none());
    }

    #[test]
    fn test_ref_id_uniqueness() {
        // 1000 generated IDs should all be unique
        let ids: HashSet<String> = (0..1000)
            .map(|_| RefId::generate().as_str().to_string())
            .collect();
        assert_eq!(ids.len(), 1000);
    }

    #[test]
    fn test_ref_id_roundtrip() {
        let id = RefId::generate();
        let parsed = RefId::parse(id.as_str()).unwrap();
        assert_eq!(id, parsed);
    }
}
