use crate::crypto::{self, SecretBytes};
use crate::env_file::EnvFile;
use crate::error::KoshError;
use crate::keychain::Keychain;
use crate::reference::RefId;
use age::x25519::{Identity, Recipient};
use std::collections::HashSet;

/// Local-first secret CRUD: ties references, crypto, the keychain, and the
/// `.env` file together. Ciphertext lives in the keychain; the `.env` holds
/// only `KOSH:` references; plaintext never persists.
pub struct Store<'a> {
    keychain: &'a Keychain,
}

impl<'a> Store<'a> {
    pub fn new(keychain: &'a Keychain) -> Self {
        Self { keychain }
    }

    /// Encrypt `plaintext` to `recipient`, store the ciphertext in the keychain,
    /// rewrite `key` in the `.env` to its new `KOSH:` reference, and save.
    /// Returns the generated reference.
    pub fn add_secret(
        &self,
        env_file: &mut EnvFile,
        key: &str,
        plaintext: &[u8],
        recipient: &Recipient,
    ) -> Result<RefId, KoshError> {
        let ref_id = Self::fresh_ref(env_file)?;
        let blob = crypto::encrypt_for_recipient(&SecretBytes::new(plaintext.to_vec()), recipient)?;
        self.keychain.store_secret(&ref_id, &blob)?;
        env_file.replace_with_ref(key, &ref_id);
        env_file.save()?;
        Ok(ref_id)
    }

    /// Fetch and decrypt a secret by reference.
    pub fn get_secret(
        &self,
        ref_id: &RefId,
        identity: &Identity,
        env: &str,
    ) -> Result<SecretBytes, KoshError> {
        let blob = self.keychain.get_secret(ref_id, env)?;
        crypto::decrypt_with_identity(&blob, identity, ref_id.as_str())
    }

    /// Delete a secret's ciphertext from the keychain.
    pub fn delete_secret(&self, ref_id: &RefId, env: &str) -> Result<(), KoshError> {
        self.keychain.delete_secret(ref_id, env)
    }

    /// All `(key, ref)` pairs in the `.env`. Never returns secret values.
    pub fn list_refs(env_file: &EnvFile) -> Vec<(String, RefId)> {
        let mut refs: Vec<(String, RefId)> = env_file.references().into_iter().collect();
        refs.sort_by(|a, b| a.0.cmp(&b.0));
        refs
    }

    /// References present in the `.env` that have no matching keychain entry
    /// (KE-305 candidates).
    pub fn detect_stale_refs(&self, env_file: &EnvFile, env: &str) -> Vec<RefId> {
        env_file
            .references()
            .into_values()
            .filter(|ref_id| {
                matches!(
                    self.keychain.get_secret(ref_id, env),
                    Err(KoshError::SecretNotFound { .. })
                )
            })
            .collect()
    }

    /// Generate a reference not already used in this `.env`.
    fn fresh_ref(env_file: &EnvFile) -> Result<RefId, KoshError> {
        let existing: HashSet<String> = env_file
            .references()
            .values()
            .map(|r| r.as_str().to_string())
            .collect();
        for _ in 0..16 {
            let candidate = RefId::generate();
            if !existing.contains(candidate.as_str()) {
                return Ok(candidate);
            }
        }
        Err(KoshError::RefCollision {
            ref_id: "<generation exhausted>".to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_keypair;
    use std::io::Write;
    use std::sync::Once;
    use tempfile::NamedTempFile;

    static INIT: Once = Once::new();

    fn mock_keychain() -> Keychain {
        INIT.call_once(|| {
            keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
        });
        Keychain::with_service(&format!("kosh-store-test-{}", uuid::Uuid::new_v4()))
    }

    fn temp_env(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn test_add_replaces_value_with_ref_in_env() {
        let kc = mock_keychain();
        let store = Store::new(&kc);
        let (_id, recipient) = generate_keypair();
        let f = temp_env("OPENAI_API_KEY=sk-proj-plain\n");
        let mut env = EnvFile::load(f.path()).unwrap();

        let ref_id = store
            .add_secret(&mut env, "OPENAI_API_KEY", b"sk-proj-plain", &recipient)
            .unwrap();

        let reloaded = EnvFile::load(f.path()).unwrap();
        let value = &reloaded.variables()["OPENAI_API_KEY"];
        assert_eq!(value, ref_id.as_str());
        assert!(!value.contains("sk-proj-plain"));
    }

    #[test]
    fn test_list_refs_shows_refs_not_values() {
        let kc = mock_keychain();
        let store = Store::new(&kc);
        let (_id, recipient) = generate_keypair();
        let f = temp_env("A=plainA\nB=plainB\n");
        let mut env = EnvFile::load(f.path()).unwrap();
        store
            .add_secret(&mut env, "A", b"plainA", &recipient)
            .unwrap();
        store
            .add_secret(&mut env, "B", b"plainB", &recipient)
            .unwrap();

        let reloaded = EnvFile::load(f.path()).unwrap();
        let refs = Store::list_refs(&reloaded);
        let keys: Vec<&str> = refs.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["A", "B"]);
        for (_, r) in &refs {
            assert!(r.as_str().starts_with("KOSH:"));
        }
    }

    #[test]
    fn test_add_get_roundtrip() {
        let kc = mock_keychain();
        let store = Store::new(&kc);
        let (identity, recipient) = generate_keypair();
        let f = temp_env("DB_URL=postgres://secret\n");
        let mut env = EnvFile::load(f.path()).unwrap();

        let ref_id = store
            .add_secret(&mut env, "DB_URL", b"postgres://secret", &recipient)
            .unwrap();

        let got = store.get_secret(&ref_id, &identity, "dev").unwrap();
        assert_eq!(got.as_bytes(), b"postgres://secret");
    }

    #[test]
    fn test_delete_removes_secret() {
        let kc = mock_keychain();
        let store = Store::new(&kc);
        let (identity, recipient) = generate_keypair();
        let f = temp_env("TOKEN=abc123\n");
        let mut env = EnvFile::load(f.path()).unwrap();
        let ref_id = store
            .add_secret(&mut env, "TOKEN", b"abc123", &recipient)
            .unwrap();

        store.delete_secret(&ref_id, "dev").unwrap();
        let err = store.get_secret(&ref_id, &identity, "dev").unwrap_err();
        assert!(matches!(err, KoshError::SecretNotFound { .. }));
    }

    #[test]
    fn test_detect_stale_refs() {
        let kc = mock_keychain();
        let store = Store::new(&kc);
        let (_id, recipient) = generate_keypair();
        // One real secret + one dangling reference with no keychain entry.
        let f = temp_env("REAL=plain\nDANGLING=KOSH:deadbeef\n");
        let mut env = EnvFile::load(f.path()).unwrap();
        store
            .add_secret(&mut env, "REAL", b"plain", &recipient)
            .unwrap();

        let reloaded = EnvFile::load(f.path()).unwrap();
        let stale = store.detect_stale_refs(&reloaded, "dev");
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].as_str(), "KOSH:deadbeef");
    }
}
