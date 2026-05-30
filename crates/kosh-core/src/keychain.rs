use crate::error::KoshError;
use crate::reference::RefId;
use keyring::{Entry, Error as KeyringError};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const DEFAULT_SERVICE: &str = "kosh";
const USER_KEY_ACCOUNT: &str = "user/private_key";
const SERVER_TOKEN_ACCOUNT: &str = "server/token";

/// Environment variable that, when set, switches the keychain to a file-backed
/// JSON store at that path instead of the OS keychain. Intended for tests and
/// headless CI: it persists across separate `kosh` process invocations (unlike
/// the in-memory mock) and is trivially isolated by pointing at a temp file.
const FILE_BACKEND_ENV: &str = "KOSH_KEYCHAIN_FILE";

/// Where credentials are actually stored.
enum Backend {
    /// Real OS keychain via the `keyring` crate (default).
    Os,
    /// A JSON map `{ "service::account": hex }` at this path.
    File(PathBuf),
}

/// Abstraction over the OS keychain (Secure Enclave / TPM / libsecret) via the
/// `keyring` crate. Secret bytes are hex-encoded for storage since keyring 2.x
/// stores string passwords.
///
/// `Entry` objects are cached per account (OS backend only): the keyring mock
/// keeps state inside the credential instance, so reusing the same `Entry` is
/// required for set→get to round-trip under test. Real OS backends are
/// unaffected. When [`FILE_BACKEND_ENV`] is set, a file-backed store is used
/// instead.
pub struct Keychain {
    service: String,
    backend: Backend,
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
        let backend = select_backend(std::env::var(FILE_BACKEND_ENV).ok().as_deref());
        Self {
            service: service.to_string(),
            backend,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Construct a file-backed keychain directly (test-only); avoids mutating
    /// the process-global [`FILE_BACKEND_ENV`], which would leak into other
    /// tests running concurrently.
    #[cfg(test)]
    fn file_backed(service: &str, path: PathBuf) -> Self {
        Self {
            service: service.to_string(),
            backend: Backend::File(path),
            entries: Mutex::new(HashMap::new()),
        }
    }

    // ---- backend primitives ----------------------------------------------

    /// Set `account` to `value`.
    fn raw_set(&self, account: &str, value: &str) -> Result<(), KoshError> {
        match &self.backend {
            Backend::Os => self
                .with_entry(account, |e| e.set_password(value))
                .map_err(|e| KoshError::KeychainWriteFailed(e.to_string())),
            Backend::File(path) => {
                let mut map = file_read(path)?;
                map.insert(self.file_key(account), value.to_string());
                file_write(path, &map)
            }
        }
    }

    /// Get `account`, returning `Ok(None)` when it is absent.
    fn raw_get(&self, account: &str) -> Result<Option<String>, KoshError> {
        match &self.backend {
            Backend::Os => match self.with_entry(account, |e| e.get_password()) {
                Ok(s) => Ok(Some(s)),
                Err(KeyringError::NoEntry) => Ok(None),
                Err(other) => Err(KoshError::KeychainUnavailable(other.to_string())),
            },
            Backend::File(path) => Ok(file_read(path)?.get(&self.file_key(account)).cloned()),
        }
    }

    /// Delete `account`, returning whether it existed.
    fn raw_delete(&self, account: &str) -> Result<bool, KoshError> {
        match &self.backend {
            Backend::Os => match self.with_entry(account, |e| e.delete_password()) {
                Ok(()) => Ok(true),
                Err(KeyringError::NoEntry) => Ok(false),
                Err(other) => Err(KoshError::KeychainWriteFailed(other.to_string())),
            },
            Backend::File(path) => {
                let mut map = file_read(path)?;
                let existed = map.remove(&self.file_key(account)).is_some();
                if existed {
                    file_write(path, &map)?;
                }
                Ok(existed)
            }
        }
    }

    /// Namespace a file-backend account by service so distinct services (used
    /// to isolate tests) never collide within one file.
    fn file_key(&self, account: &str) -> String {
        format!("{}::{}", self.service, account)
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

    // ---- secrets ----------------------------------------------------------

    /// Store a secret's ciphertext under its ref ID.
    pub fn store_secret(&self, ref_id: &RefId, bytes: &[u8]) -> Result<(), KoshError> {
        self.raw_set(ref_id.hex(), &hex::encode(bytes))
    }

    /// Retrieve a secret's ciphertext by ref ID. `env` is used only for the
    /// not-found error message.
    pub fn get_secret(&self, ref_id: &RefId, env: &str) -> Result<Vec<u8>, KoshError> {
        let encoded = self
            .raw_get(ref_id.hex())?
            .ok_or_else(|| KoshError::SecretNotFound {
                ref_id: ref_id.as_str().to_string(),
                env: env.to_string(),
            })?;
        hex::decode(&encoded).map_err(|_| KoshError::KeychainCorrupted {
            ref_id: ref_id.as_str().to_string(),
        })
    }

    /// Delete a secret by ref ID.
    pub fn delete_secret(&self, ref_id: &RefId, env: &str) -> Result<(), KoshError> {
        if self.raw_delete(ref_id.hex())? {
            Ok(())
        } else {
            Err(KoshError::SecretNotFound {
                ref_id: ref_id.as_str().to_string(),
                env: env.to_string(),
            })
        }
    }

    // ---- user key ---------------------------------------------------------

    /// Store the user's age identity (private key) string.
    pub fn store_user_key(&self, identity: &str) -> Result<(), KoshError> {
        self.raw_set(USER_KEY_ACCOUNT, identity)
    }

    /// Retrieve the user's age identity (private key) string.
    pub fn get_user_key(&self) -> Result<String, KoshError> {
        self.raw_get(USER_KEY_ACCOUNT)?
            .ok_or_else(|| KoshError::KeychainUnavailable("no Kosh user key in keychain".into()))
    }

    // ---- per-environment key ---------------------------------------------

    /// Store the age identity (private key) for one `(workspace, env)`.
    pub fn store_env_key(
        &self,
        workspace: &str,
        env: &str,
        identity: &str,
    ) -> Result<(), KoshError> {
        self.raw_set(&env_account(workspace, env), identity)
    }

    /// Retrieve the env identity for `(workspace, env)`, or `None` if absent.
    pub fn get_env_key(&self, workspace: &str, env: &str) -> Result<Option<String>, KoshError> {
        self.raw_get(&env_account(workspace, env))
    }

    // ---- server token -----------------------------------------------------

    /// Store the access token issued by a Kosh server (for `kosh login`).
    pub fn store_server_token(&self, token: &str) -> Result<(), KoshError> {
        self.raw_set(SERVER_TOKEN_ACCOUNT, token)
    }

    /// Retrieve the stored server access token.
    pub fn get_server_token(&self) -> Result<String, KoshError> {
        self.raw_get(SERVER_TOKEN_ACCOUNT)?
            .ok_or_else(|| KoshError::KeychainUnavailable("no Kosh server token".into()))
    }

    /// Remove the stored server access token (for `kosh logout`).
    pub fn delete_server_token(&self) -> Result<(), KoshError> {
        self.raw_delete(SERVER_TOKEN_ACCOUNT).map(|_| ())
    }
}

/// Choose a backend from the value of [`FILE_BACKEND_ENV`]: a non-empty path
/// selects the file backend; anything else (unset/empty) uses the OS keychain.
fn select_backend(file_var: Option<&str>) -> Backend {
    match file_var {
        Some(p) if !p.is_empty() => Backend::File(PathBuf::from(p)),
        _ => Backend::Os,
    }
}

/// Keychain account for a per-environment key.
fn env_account(workspace: &str, env: &str) -> String {
    format!("env/{workspace}/{env}")
}

/// Read the file-backend JSON map (missing/empty file → empty map).
fn file_read(path: &Path) -> Result<BTreeMap<String, String>, KoshError> {
    match std::fs::read_to_string(path) {
        Ok(s) if s.trim().is_empty() => Ok(BTreeMap::new()),
        Ok(s) => serde_json::from_str(&s)
            .map_err(|e| KoshError::KeychainUnavailable(format!("corrupted keychain file: {e}"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(KoshError::KeychainUnavailable(e.to_string())),
    }
}

/// Persist the file-backend JSON map, creating the parent directory if needed.
fn file_write(path: &Path, map: &BTreeMap<String, String>) -> Result<(), KoshError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| KoshError::KeychainWriteFailed(e.to_string()))?;
        }
    }
    let json = serde_json::to_string_pretty(map)
        .map_err(|e| KoshError::KeychainWriteFailed(e.to_string()))?;
    std::fs::write(path, json).map_err(|e| KoshError::KeychainWriteFailed(e.to_string()))
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

    #[test]
    fn test_env_key_roundtrip_and_absence() {
        let kc = mock_keychain();
        assert_eq!(kc.get_env_key("acme", "dev").unwrap(), None);
        kc.store_env_key("acme", "dev", "AGE-SECRET-KEY-1ENVKEY")
            .unwrap();
        assert_eq!(
            kc.get_env_key("acme", "dev").unwrap().as_deref(),
            Some("AGE-SECRET-KEY-1ENVKEY")
        );
        // Distinct (workspace, env) tuples do not collide.
        assert_eq!(kc.get_env_key("acme", "prod").unwrap(), None);
    }

    /// The file backend must persist across separate `Keychain` instances
    /// pointing at the same path — this is what makes the real `kosh` binary
    /// testable across multiple process invocations. We build the file backend
    /// directly rather than via `KOSH_KEYCHAIN_FILE`, since mutating that
    /// process-global env var would leak into other tests running concurrently.
    #[test]
    fn test_file_backend_persists_across_instances() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("kc.json");

        let ref_id = RefId::parse("KOSH:a1b2c3d4").unwrap();
        {
            let kc = Keychain::file_backed("kosh", path.clone());
            kc.store_user_key("AGE-SECRET-KEY-1USER").unwrap();
            kc.store_secret(&ref_id, b"blob").unwrap();
            kc.store_env_key("acme", "dev", "AGE-SECRET-KEY-1ENV")
                .unwrap();
        }
        {
            // A fresh instance (as a second process would build) sees the data.
            let kc = Keychain::file_backed("kosh", path.clone());
            assert_eq!(kc.get_user_key().unwrap(), "AGE-SECRET-KEY-1USER");
            assert_eq!(kc.get_secret(&ref_id, "dev").unwrap(), b"blob");
            assert_eq!(
                kc.get_env_key("acme", "dev").unwrap().as_deref(),
                Some("AGE-SECRET-KEY-1ENV")
            );
        }
    }

    #[test]
    fn test_file_backend_delete_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("kc.json");
        let kc = Keychain::file_backed("kosh", path);
        kc.store_server_token("jwt-token").unwrap();
        assert_eq!(kc.get_server_token().unwrap(), "jwt-token");
        kc.delete_server_token().unwrap();
        assert!(matches!(
            kc.get_server_token().unwrap_err(),
            KoshError::KeychainUnavailable(_)
        ));
    }

    #[test]
    fn test_select_backend_from_env_value() {
        assert!(matches!(
            select_backend(Some("/tmp/kc.json")),
            Backend::File(_)
        ));
        assert!(matches!(select_backend(Some("")), Backend::Os));
        assert!(matches!(select_backend(None), Backend::Os));
    }
}
