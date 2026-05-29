use thiserror::Error;

#[derive(Debug, Error)]
pub enum KoshError {
    // KE-1xx Keychain
    #[error("[KE-100] KEYCHAIN_UNAVAILABLE: {0}")]
    KeychainUnavailable(String),
    #[error("[KE-101] KEYCHAIN_LOCKED")]
    KeychainLocked,
    #[error("[KE-102] SECRET_NOT_FOUND: ref {ref_id} not found in env '{env}'")]
    SecretNotFound { ref_id: String, env: String },
    #[error("[KE-103] KEYCHAIN_WRITE_FAILED: {0}")]
    KeychainWriteFailed(String),
    #[error("[KE-104] KEYCHAIN_CORRUPTED: ref {ref_id}")]
    KeychainCorrupted { ref_id: String },

    // KE-2xx Crypto
    #[error("[KE-200] DECRYPTION_FAILED: ref {ref_id}")]
    DecryptionFailed { ref_id: String },
    #[error("[KE-201] ENCRYPTION_FAILED: {0}")]
    EncryptionFailed(String),
    #[error("[KE-202] ENV_KEY_NOT_FOUND: workspace={workspace} env={env}")]
    EnvKeyNotFound { workspace: String, env: String },
    #[error("[KE-203] ENV_KEY_MISMATCH")]
    EnvKeyMismatch,
    #[error("[KE-204] KEY_GENERATION_FAILED: {0}")]
    KeyGenerationFailed(String),

    // KE-3xx File / Env
    #[error("[KE-300] ENV_FILE_NOT_FOUND: {path}")]
    EnvFileNotFound { path: String },
    #[error("[KE-301] ENV_FILE_NOT_READABLE: {path}")]
    EnvFileNotReadable { path: String },
    #[error("[KE-302] ENV_FILE_NOT_WRITABLE: {path}")]
    EnvFileNotWritable { path: String },
    #[error("[KE-303] ENV_FILE_PARSE_ERROR: line {line}")]
    EnvFileParseError { line: usize },
    #[error("[KE-304] REF_COLLISION: ref {ref_id}")]
    RefCollision { ref_id: String },
    #[error("[KE-305] STALE_REF: ref {ref_id} in .env has no matching secret")]
    StaleRef { ref_id: String },

    // KE-4xx Process / Redactor
    #[error("[KE-400] BLOCKED_COMMAND: '{cmd}' is blocked by security policy")]
    BlockedCommand { cmd: String },
    #[error("[KE-401] REDACTOR_INIT_FAILED")]
    RedactorInitFailed,
    #[error("[KE-402] SUBPROCESS_SPAWN_FAILED: {cmd}")]
    SubprocessSpawnFailed { cmd: String },
    #[error("[KE-403] SUBPROCESS_ENV_INJECT_FAILED")]
    SubprocessEnvInjectFailed,
    #[error("[KE-404] REDACTOR_STREAM_ERROR")]
    RedactorStreamError,

    // KE-5xx Server / Sync
    #[error("[KE-500] SERVER_UNREACHABLE: {url}")]
    ServerUnreachable { url: String },
    #[error("[KE-501] SERVER_TLS_ERROR: {url}")]
    ServerTlsError { url: String },
    #[error("[KE-502] AUTH_EXPIRED")]
    AuthExpired,
    #[error("[KE-503] AUTH_INVALID")]
    AuthInvalid,
    #[error("[KE-504] FORBIDDEN: {workspace}/{env}")]
    Forbidden { workspace: String, env: String },
    #[error("[KE-505] SYNC_CONFLICT: ref {ref_id}")]
    SyncConflict { ref_id: String },
    #[error("[KE-506] SYNC_PARTIAL_FAILURE: {failed} of {total} failed")]
    SyncPartialFailure { failed: usize, total: usize },
    #[error("[KE-507] RATE_LIMITED: retry after {seconds}s")]
    RateLimited { seconds: u64 },
    #[error("[KE-508] SERVER_ERROR: HTTP {code}, request_id={request_id}")]
    ServerError { code: u16, request_id: String },
    #[error("[KE-509] WORKSPACE_NOT_FOUND: {workspace}")]
    WorkspaceNotFound { workspace: String },
    #[error("[KE-510] ENV_NOT_FOUND: {env}")]
    EnvNotFound { env: String },

    // KE-6xx Config
    #[error("[KE-600] CONFIG_NOT_FOUND")]
    ConfigNotFound,
    #[error("[KE-601] CONFIG_PARSE_ERROR: line {line}")]
    ConfigParseError { line: usize },
    #[error("[KE-602] NO_WORKSPACE_SET")]
    NoWorkspaceSet,
    #[error("[KE-603] NO_ENV_SET")]
    NoEnvSet,
    #[error("[KE-604] INVALID_ENV_NAME: {name}")]
    InvalidEnvName { name: String },
    #[error("[KE-605] INVALID_KEY_NAME: {name}")]
    InvalidKeyName { name: String },

    // KE-7xx Rotation
    #[error("[KE-700] ROTATION_SAME_VALUE")]
    RotationSameValue,
    #[error("[KE-701] ROTATION_FAILED_REMOTE: local ok, server failed")]
    RotationFailedRemote,
    #[error("[KE-702] ROTATION_FAILED_ROLLBACK: CRITICAL — manual recovery required")]
    RotationFailedRollback,
    #[error("[KE-703] SCHEDULE_INVALID: {schedule}")]
    ScheduleInvalid { schedule: String },

    // Passthrough
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl KoshError {
    /// Returns true for errors that must fail closed (never degrade gracefully)
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            KoshError::RedactorInitFailed
                | KoshError::RedactorStreamError
                | KoshError::SubprocessEnvInjectFailed
                | KoshError::RotationFailedRollback
                | KoshError::KeychainUnavailable(_)
                | KoshError::ServerTlsError { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_critical_true_cases() {
        assert!(KoshError::RedactorInitFailed.is_critical());
        assert!(KoshError::RotationFailedRollback.is_critical());
        assert!(KoshError::KeychainUnavailable("no service".into()).is_critical());
    }

    #[test]
    fn test_is_critical_false_cases() {
        assert!(!KoshError::AuthExpired.is_critical());
        assert!(!KoshError::NoWorkspaceSet.is_critical());
        assert!(!KoshError::SecretNotFound {
            ref_id: "KOSH:a3f9c2b1".into(),
            env: "dev".into()
        }
        .is_critical());
    }
}
