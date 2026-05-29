use crate::error::KoshError;
use crate::reference::RefId;
use serde::{Deserialize, Serialize};

/// A member's role within a workspace. Mirrors the server-side CHECK constraint
/// (owner | admin | developer | readonly | ci).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Owner,
    Admin,
    Developer,
    Readonly,
    Ci,
}

/// A validated environment name. Server rule: `^[a-z0-9-]+$`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnvName(String);

impl EnvName {
    pub fn parse(s: &str) -> Result<Self, KoshError> {
        let valid = !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if valid {
            Ok(Self(s.to_string()))
        } else {
            Err(KoshError::InvalidEnvName {
                name: s.to_string(),
            })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EnvName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A validated environment-variable key name. Rule: `^[A-Z_][A-Z0-9_]*$`
/// (uppercase letters, digits, underscores; must not start with a digit).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyName(String);

impl KeyName {
    pub fn parse(s: &str) -> Result<Self, KoshError> {
        let mut chars = s.chars();
        let first_ok = matches!(chars.next(), Some(c) if c.is_ascii_uppercase() || c == '_');
        let rest_ok = chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
        if first_ok && rest_ok {
            Ok(Self(s.to_string()))
        } else {
            Err(KoshError::InvalidKeyName {
                name: s.to_string(),
            })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for KeyName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The in-memory / persisted representation of a stored secret.
/// `encrypted_blob` is ciphertext only — plaintext never lives here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRecord {
    pub ref_id: RefId,
    pub key_name: String,
    pub env: String,
    pub workspace: String,
    pub encrypted_blob: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_name_valid() {
        assert_eq!(EnvName::parse("dev").unwrap().as_str(), "dev");
        assert_eq!(EnvName::parse("staging-2").unwrap().as_str(), "staging-2");
    }

    #[test]
    fn test_env_name_invalid() {
        assert!(EnvName::parse("Production").is_err()); // uppercase
        assert!(EnvName::parse("dev env").is_err()); // space
        assert!(EnvName::parse("").is_err()); // empty
        assert!(EnvName::parse("dev_1").is_err()); // underscore not allowed
    }

    #[test]
    fn test_key_name_valid() {
        assert_eq!(
            KeyName::parse("OPENAI_API_KEY").unwrap().as_str(),
            "OPENAI_API_KEY"
        );
        assert_eq!(KeyName::parse("_PRIVATE").unwrap().as_str(), "_PRIVATE");
        assert_eq!(KeyName::parse("PORT2").unwrap().as_str(), "PORT2");
    }

    #[test]
    fn test_key_name_invalid() {
        assert!(KeyName::parse("lowercase").is_err());
        assert!(KeyName::parse("2FACTOR").is_err()); // starts with digit
        assert!(KeyName::parse("API-KEY").is_err()); // hyphen
        assert!(KeyName::parse("").is_err());
    }

    #[test]
    fn test_role_serde_roundtrip() {
        for role in [
            Role::Owner,
            Role::Admin,
            Role::Developer,
            Role::Readonly,
            Role::Ci,
        ] {
            let json = serde_json::to_string(&role).unwrap();
            let back: Role = serde_json::from_str(&json).unwrap();
            assert_eq!(role, back);
        }
        assert_eq!(
            serde_json::to_string(&Role::Readonly).unwrap(),
            "\"readonly\""
        );
    }

    #[test]
    fn test_secret_record_serde_roundtrip() {
        let rec = SecretRecord {
            ref_id: RefId::parse("KOSH:a3f9c2b1").unwrap(),
            key_name: "OPENAI_API_KEY".into(),
            env: "dev".into(),
            workspace: "acme".into(),
            encrypted_blob: vec![1, 2, 3, 4],
        };
        let json = serde_json::to_string(&rec).unwrap();
        let back: SecretRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, back);
    }
}
