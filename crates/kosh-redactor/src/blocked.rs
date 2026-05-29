/// Commands that are blocked from running under `kosh run`.
/// These can expose secrets via environment-variable dumping.
const BLOCKED_EXECUTABLES: &[&str] = &[
    "bash", "sh", "zsh", "fish", "dash", "ksh", "tcsh", "csh", "env", "printenv", "export", "set",
];

const BLOCKED_PATTERNS: &[&str] = &[
    "echo $", "echo ${", "printenv", "env |", "env|", "| env", "|env",
];

/// Returns true if `command` is blocked by the security policy.
pub fn is_blocked(command: &str) -> bool {
    let parts: Vec<&str> = command.split_whitespace().collect();
    let executable = parts
        .first()
        .map(|s| {
            // Handle paths like /usr/bin/bash → bash.
            std::path::Path::new(s)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(s)
        })
        .unwrap_or("");

    if BLOCKED_EXECUTABLES.contains(&executable) {
        return true;
    }

    BLOCKED_PATTERNS.iter().any(|p| command.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocks_bare_shells() {
        assert!(is_blocked("bash"));
        assert!(is_blocked("sh"));
        assert!(is_blocked("zsh"));
        assert!(is_blocked("fish"));
    }

    #[test]
    fn test_blocks_env_dump_commands() {
        assert!(is_blocked("env"));
        assert!(is_blocked("printenv"));
        assert!(is_blocked("echo $API_KEY"));
        assert!(is_blocked("echo ${API_KEY}"));
    }

    #[test]
    fn test_allows_safe_commands() {
        assert!(!is_blocked("next dev"));
        assert!(!is_blocked("node index.js"));
        assert!(!is_blocked("cargo test"));
        assert!(!is_blocked("pytest tests/"));
        assert!(!is_blocked("npm run dev"));
    }

    #[test]
    fn test_blocks_path_to_shell() {
        assert!(is_blocked("/usr/bin/bash"));
        assert!(is_blocked("/bin/sh -c something"));
    }
}
