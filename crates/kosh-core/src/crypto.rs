use crate::error::KoshError;
use age::secrecy::ExposeSecret;
use age::x25519::{Identity, Recipient};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::str::FromStr;
use zeroize::ZeroizeOnDrop;

/// A secret value held in memory — zeroed on drop
#[derive(ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Generate a new age X25519 keypair for a workspace env key or user key.
/// Returns (identity = private, recipient = public).
pub fn generate_keypair() -> (Identity, Recipient) {
    let identity = Identity::generate();
    let recipient = identity.to_public();
    (identity, recipient)
}

/// Encrypt a secret value to an age X25519 recipient (public key).
/// Used for the secret-at-rest and server-sync paths — encrypts client-side.
pub fn encrypt_for_recipient(
    plaintext: &SecretBytes,
    recipient: &Recipient,
) -> Result<Vec<u8>, KoshError> {
    let encryptor = age::Encryptor::with_recipients(vec![Box::new(recipient.clone())])
        .ok_or_else(|| KoshError::EncryptionFailed("no recipients provided".to_string()))?;

    let mut ciphertext = vec![];
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|e| KoshError::EncryptionFailed(e.to_string()))?;

    use std::io::Write;
    writer
        .write_all(plaintext.as_bytes())
        .map_err(|e| KoshError::EncryptionFailed(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| KoshError::EncryptionFailed(e.to_string()))?;

    Ok(ciphertext)
}

/// Decrypt an age blob using an X25519 identity (private key).
pub fn decrypt_with_identity(
    ciphertext: &[u8],
    identity: &Identity,
    ref_id: &str,
) -> Result<SecretBytes, KoshError> {
    let decryptor = match age::Decryptor::new(ciphertext).map_err(|_| {
        KoshError::DecryptionFailed {
            ref_id: ref_id.to_string(),
        }
    })? {
        age::Decryptor::Recipients(d) => d,
        _ => {
            return Err(KoshError::DecryptionFailed {
                ref_id: ref_id.to_string(),
            })
        }
    };

    let mut reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|_| KoshError::DecryptionFailed {
            ref_id: ref_id.to_string(),
        })?;

    use std::io::Read;
    let mut plaintext = vec![];
    reader
        .read_to_end(&mut plaintext)
        .map_err(|_| KoshError::DecryptionFailed {
            ref_id: ref_id.to_string(),
        })?;

    Ok(SecretBytes::new(plaintext))
}

/// Serialize an age identity (private key) to its canonical string form
/// (`AGE-SECRET-KEY-1...`) for storage in the OS keychain.
pub fn identity_to_string(identity: &Identity) -> String {
    identity.to_string().expose_secret().to_string()
}

/// Parse an age identity from its canonical string form.
pub fn identity_from_string(s: &str) -> Result<Identity, KoshError> {
    Identity::from_str(s).map_err(|e| KoshError::KeyGenerationFailed(e.to_string()))
}

/// Serialize an age recipient (public key) to its canonical string form (`age1...`).
pub fn recipient_to_string(recipient: &Recipient) -> String {
    recipient.to_string()
}

/// Parse an age recipient from its canonical string form.
pub fn recipient_from_string(s: &str) -> Result<Recipient, KoshError> {
    Recipient::from_str(s).map_err(|e| KoshError::KeyGenerationFailed(e.to_string()))
}

/// Argon2id KDF for the passphrase-based fallback store.
/// OWASP-recommended params: memory=64MB, iterations=3, parallelism=4.
pub fn derive_key_from_passphrase(
    passphrase: &str,
    salt: &[u8; 32],
) -> Result<[u8; 32], KoshError> {
    let params = Params::new(
        64 * 1024, // 64 MB memory
        3,         // 3 iterations
        4,         // 4 parallel lanes
        Some(32),  // 32-byte output
    )
    .map_err(|e| KoshError::KeyGenerationFailed(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut output)
        .map_err(|e| KoshError::KeyGenerationFailed(e.to_string()))?;

    Ok(output)
}

/// Seal bytes under a 32-byte symmetric key with XChaCha20-Poly1305.
/// Output layout: nonce(24 bytes) || ciphertext+tag. Used by the Layer-3
/// passphrase fallback store (key from `derive_key_from_passphrase`).
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, KoshError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| KoshError::EncryptionFailed(e.to_string()))?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| KoshError::EncryptionFailed(e.to_string()))?;

    let mut out = Vec::with_capacity(nonce.len() + ct.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a blob produced by [`seal`] with the same 32-byte key.
pub fn open(key: &[u8; 32], blob: &[u8], ref_id: &str) -> Result<SecretBytes, KoshError> {
    if blob.len() < 24 {
        return Err(KoshError::DecryptionFailed {
            ref_id: ref_id.to_string(),
        });
    }
    let (nonce_bytes, ct) = blob.split_at(24);
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| {
        KoshError::DecryptionFailed {
            ref_id: ref_id.to_string(),
        }
    })?;
    let nonce = XNonce::from_slice(nonce_bytes);
    let pt = cipher
        .decrypt(nonce, ct)
        .map_err(|_| KoshError::DecryptionFailed {
            ref_id: ref_id.to_string(),
        })?;
    Ok(SecretBytes::new(pt))
}

/// BLAKE3 hash — used for ref ID deduplication and integrity checks.
pub fn hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// HKDF-SHA256 — derive a subkey from a master key and context info.
pub fn derive_subkey(master_key: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut subkey = [0u8; 32];
    hk.expand(info, &mut subkey).expect("HKDF expand failed");
    subkey
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (identity, recipient) = generate_keypair();
        let plaintext = SecretBytes::new(b"sk-proj-supersecretapikey".to_vec());

        let ciphertext = encrypt_for_recipient(&plaintext, &recipient).unwrap();

        let decrypted = decrypt_with_identity(&ciphertext, &identity, "KOSH:test0001").unwrap();

        assert_eq!(decrypted.as_bytes(), plaintext.as_bytes());
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let (_, recipient) = generate_keypair();
        let (wrong_identity, _) = generate_keypair();

        let plaintext = SecretBytes::new(b"secret".to_vec());
        let ciphertext = encrypt_for_recipient(&plaintext, &recipient).unwrap();

        let result = decrypt_with_identity(&ciphertext, &wrong_identity, "KOSH:test0001");
        assert!(result.is_err());
    }

    #[test]
    fn test_key_string_roundtrip() {
        let (identity, recipient) = generate_keypair();
        let id_str = identity_to_string(&identity);
        let rec_str = recipient_to_string(&recipient);

        let id2 = identity_from_string(&id_str).unwrap();
        // The recovered identity's public key must match the original recipient.
        assert_eq!(recipient_to_string(&id2.to_public()), rec_str);

        let rec2 = recipient_from_string(&rec_str).unwrap();
        assert_eq!(recipient_to_string(&rec2), rec_str);
    }

    #[test]
    fn test_seal_open_roundtrip() {
        let salt = [7u8; 32];
        let key = derive_key_from_passphrase("correct horse battery staple", &salt).unwrap();
        let blob = seal(&key, b"fallback-store-secret").unwrap();
        let opened = open(&key, &blob, "KOSH:test0002").unwrap();
        assert_eq!(opened.as_bytes(), b"fallback-store-secret");
    }

    #[test]
    fn test_open_wrong_key_fails() {
        let salt = [7u8; 32];
        let key = derive_key_from_passphrase("pass one", &salt).unwrap();
        let wrong = derive_key_from_passphrase("pass two", &salt).unwrap();
        let blob = seal(&key, b"data").unwrap();
        assert!(open(&wrong, &blob, "KOSH:test0003").is_err());
    }

    #[test]
    fn test_argon2id_deterministic() {
        let salt = [42u8; 32];
        let key1 = derive_key_from_passphrase("my passphrase", &salt).unwrap();
        let key2 = derive_key_from_passphrase("my passphrase", &salt).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_argon2id_different_passphrases() {
        let salt = [42u8; 32];
        let key1 = derive_key_from_passphrase("passphrase one", &salt).unwrap();
        let key2 = derive_key_from_passphrase("passphrase two", &salt).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_blake3_hash_consistency() {
        let h1 = hash(b"hello kosh");
        let h2 = hash(b"hello kosh");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hkdf_subkey_derivation() {
        let master = [1u8; 32];
        let k1 = derive_subkey(&master, b"env-key-dev");
        let k2 = derive_subkey(&master, b"env-key-staging");
        assert_ne!(k1, k2); // different contexts → different keys
    }

    #[test]
    fn test_secret_bytes_zeroized() {
        // Compile-time check: SecretBytes implements ZeroizeOnDrop
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SecretBytes>();
    }
}
