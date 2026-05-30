use crate::error::KoshError;
use crate::reference::RefId;
use keyring::{Entry, Error as KeyringError};
use std::collections::HashMap;
use std::sync::Mutex;

const DEFAULT_SERVICE: &str = "kosh";
const USER_KEY_ACCOUNT: &str = "user/private_key";
const SERVER_TOKEN_ACCOUNT: &str = "server/token";

/// Abstraction over the OS keychain (Secure Enclave / TPM / libsecret) via the
/// `keyring` crate. Secret bytes are hex-encoded for storage since keyring 2.x
/// stores string passwords.
///
/// `Entry` objects are cached per account: the keyring mock backend keeps state
/// inside the credential instance, so reusing the same `Entry` is required for
/// set→get to round-trip under test. Real OS backends are unaffected.
pub struct Keychain {
    service: String,
    entries: Mutex<HashMap<String, Entry>>,
}

impl Default for Keychain {
    fn default() -> Self {
        Self::new()
    }
}

impl Keychain {
    pub fn new() -> Self {
        Self::with_service(DEFAULT_SERVICE)
    }

    pub fn with_service(service: &str) -> Self {
        Self {
            service: service.to_string(),
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn with_entry<R>(
        &self,
        account: &str,
        f: impl FnOnce(&Entry) -> Result<R, KeyringError>,
    ) -> Result<R, KeyringError> {
        let mut map = self.entries.lock().expect("keychain mutex poisoned");
        if !map.contains_key(account) {
            let entry = Entry::new(&self.service, account)?;
            map.insert(account.to_string(), entry);
        }
        let entry = map.get(account).expect("entry just inserted");
        f(entry)
    }

    /// Store a secret's ciphertext under its ref ID.
    pub fn store_secret(&self, ref_id: &RefId, bytes: &[u8]) -> Result<(), KoshError> {
        let encoded = hex::encode(bytes);
        self.with_entry(ref_id.hex(), |e| e.set_password(&encoded))
            .map_err(|e| KoshError::KeychainWriteFailed(e.to_string()))
    }

    /// Retrieve a secret's ciphertext by ref ID. `env` is used only for the
    /// not-found error message.
    pub fn get_secret(&self, ref_id: &RefId, env: &str) -> Result<Vec<u8>, KoshError> {
        let encoded = self
            .with_entry(ref_id.hex(), |e| e.get_password())
            .map_err(|e| match e {
                KeyringError::NoEntry => KoshError::SecretNotFound {
                    ref_id: ref_id.as_str().to_string(),
                    env: env.to_string(),
                },
                other => KoshError::KeychainUnavailable(other.to_string()),
            })?;
        hex::decode(&encoded).map_err(|_| KoshError::KeychainCorrupted {
            ref_id: ref_id.as_str().to_string(),
        })
    }

    /// Delete a secret by ref ID.
    pub fn delete_secret(&self, ref_id: &RefId, env: &str) -> Result<(), KoshError> {
        self.with_entry(ref_id.hex(), |e| e.delete_password())
            .map_err(|e| match e {
                KeyringError::NoEntry => KoshError::SecretNotFound {
                    ref_id: ref_id.as_str().to_string(),
                    env: env.to_string(),
                },
                other => KoshError::KeychainWriteFailed(other.to_string()),
            })
    }

    /// Store the user's age identity (private key) string.
    pub fn store_user_key(&self, identity: &str) -> Result<(), KoshError> {
        self.with_entry(USER_KEY_ACCOUNT, |e| e.set_password(identity))
            .map_err(|e| KoshError::KeychainWriteFailed(e.to_string()))
    }

    /// Retrieve the user's age identity (private key) string.
    pub fn get_user_key(&self) -> Result<String, KoshError> {
        self.with_entry(USER_KEY_ACCOUNT, |e| e.get_password())
            .map_err(|e| KoshError::KeychainUnavailable(e.to_string()))
    }

    /// Store the access token issued by a Kosh server (for `kosh login`).
    pub fn store_server_token(&self, token: &str) -> Result<(), KoshError> {
        self.with_entry(SERVER_TOKEN_ACCOUNT, |e| e.set_password(token))
            .map_err(|e| KoshError::KeychainWriteFailed(e.to_string()))
    }

    /// Retrieve the stored server access token.
    pub fn get_server_token(&self) -> Result<String, KoshError> {
        self.with_entry(SERVER_TOKEN_ACCOUNT, |e| e.get_password())
            .map_err(|e| KoshError::KeychainUnavailable(e.to_string()))
    }

    /// Remove the stored server access token (for `kosh logout`).
    pub fn delete_server_token(&self) -> Result<(), KoshError> {
        self.with_entry(SERVER_TOKEN_ACCOUNT, |e| e.delete_password())
            .map_err(|e| KoshError::KeychainWriteFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn mock_keychain() -> Keychain {
        INIT.call_once(|| {
            keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
        });
        // Unique service per Keychain keeps tests isolated within the shared
        // process-wide mock builder.
        Keychain::with_service(&format!("kosh-test-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn test_store_get_roundtrip() {
        let kc = mock_keychain();
        let ref_id = RefId::parse("KOSH:a3f9c2b1").unwrap();
        kc.store_secret(&ref_id, b"ciphertext-bytes").unwrap();
        let got = kc.get_secret(&ref_id, "dev").unwrap();
        assert_eq!(got, b"ciphertext-bytes");
    }

    #[test]
    fn test_get_missing_is_secret_not_found() {
        let kc = mock_keychain();
        let ref_id = RefId::parse("KOSH:deadbeef").unwrap();
        let err = kc.get_secret(&ref_id, "dev").unwrap_err();
        assert!(matches!(err, KoshError::SecretNotFound { .. }));
    }

    #[test]
    fn test_delete_then_get_missing() {
        let kc = mock_keychain();
        let ref_id = RefId::parse("KOSH:c0ffee01").unwrap();
        kc.store_secret(&ref_id, b"value").unwrap();
        kc.delete_secret(&ref_id, "dev").unwrap();
        let err = kc.get_secret(&ref_id, "dev").unwrap_err();
        assert!(matches!(err, KoshError::SecretNotFound { .. }));
    }

    #[test]
    fn test_user_key_roundtrip() {
        let kc = mock_keychain();
        kc.store_user_key("AGE-SECRET-KEY-1EXAMPLE").unwrap();
        assert_eq!(kc.get_user_key().unwrap(), "AGE-SECRET-KEY-1EXAMPLE");
    }
}
