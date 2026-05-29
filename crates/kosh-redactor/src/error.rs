use thiserror::Error;

/// Errors raised while constructing a [`crate::redactor::Redactor`].
///
/// The redactor is deliberately independent of `kosh-core`'s `KoshError`: it is a
/// standalone scrubbing primitive. Callers (the CLI) map redactor/blocked-command
/// failures onto their own error space (e.g. `KoshError::BlockedCommand`, KE-400).
#[derive(Debug, Error)]
pub enum RedactorError {
    #[error("REDACTOR_BUILD_FAILED: {0}")]
    Build(String),
}
