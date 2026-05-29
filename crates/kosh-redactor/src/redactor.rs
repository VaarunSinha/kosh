use aho_corasick::{AhoCorasickBuilder, MatchKind};

use aho_corasick::AhoCorasick;

/// Scans a stream of bytes and replaces all known secret values
/// with their `[KOSH:ref]` placeholder. Uses Aho-Corasick for
/// multi-pattern matching in a single pass.
pub struct Redactor {
    automaton: AhoCorasick,
    replacements: Vec<String>, // parallel to patterns
}

impl Redactor {
    /// Build a Redactor from a list of `(secret_value, ref_id)` pairs.
    pub fn new(secrets: &[(String, String)]) -> Result<Self, crate::error::RedactorError> {
        if secrets.is_empty() {
            // No secrets to redact — still valid, just passes through.
            let empty: [&str; 0] = [];
            return Ok(Self {
                automaton: AhoCorasickBuilder::new()
                    .match_kind(MatchKind::LeftmostFirst)
                    .build(empty)
                    .map_err(|e| crate::error::RedactorError::Build(e.to_string()))?,
                replacements: vec![],
            });
        }

        let patterns: Vec<&str> = secrets.iter().map(|(v, _)| v.as_str()).collect();
        let replacements: Vec<String> = secrets
            .iter()
            .map(|(_, ref_id)| format!("[{}]", ref_id))
            .collect();

        let automaton = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostFirst)
            .build(patterns)
            .map_err(|e| crate::error::RedactorError::Build(e.to_string()))?;

        Ok(Self {
            automaton,
            replacements,
        })
    }

    /// Redact a line of output. Single pass, O(n) in line length.
    pub fn redact_line(&self, line: &str) -> String {
        if self.replacements.is_empty() {
            return line.to_string();
        }
        self.automaton.replace_all(line, &self.replacements)
    }

    /// Redact a chunk of bytes (for streaming use).
    pub fn redact_bytes(&self, input: &[u8]) -> Vec<u8> {
        if self.replacements.is_empty() {
            return input.to_vec();
        }
        let s = String::from_utf8_lossy(input);
        self.automaton
            .replace_all(&s, &self.replacements)
            .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_redactor(secrets: &[(&str, &str)]) -> Redactor {
        let owned: Vec<(String, String)> = secrets
            .iter()
            .map(|(v, r)| (v.to_string(), r.to_string()))
            .collect();
        Redactor::new(&owned).unwrap()
    }

    #[test]
    fn test_redacts_single_secret() {
        let r = make_redactor(&[("sk-proj-xxxxxxxxxxxx", "KOSH:a3f9c2b1")]);
        let output = r.redact_line("Connected with key sk-proj-xxxxxxxxxxxx OK");
        assert_eq!(output, "Connected with key [KOSH:a3f9c2b1] OK");
        assert!(!output.contains("sk-proj"));
    }

    #[test]
    fn test_redacts_multiple_secrets_one_pass() {
        let r = make_redactor(&[
            ("sk-proj-xxxxxxxxxxxx", "KOSH:a3f9c2b1"),
            ("sk_live_yyyyyyyyyy", "KOSH:b4d8e3c2"),
        ]);
        let line = "key1=sk-proj-xxxxxxxxxxxx key2=sk_live_yyyyyyyyyy";
        let output = r.redact_line(line);
        assert!(output.contains("[KOSH:a3f9c2b1]"));
        assert!(output.contains("[KOSH:b4d8e3c2]"));
        assert!(!output.contains("sk-proj"));
        assert!(!output.contains("sk_live"));
    }

    #[test]
    fn test_passthrough_when_no_secrets() {
        let r = make_redactor(&[]);
        let line = "normal log output nothing secret here";
        assert_eq!(r.redact_line(line), line);
    }

    #[test]
    fn test_partial_match_not_redacted() {
        let r = make_redactor(&[("sk-proj-xxxxxxxxxxxx", "KOSH:a3f9c2b1")]);
        // Partial match — should NOT be replaced (LeftmostFirst requires full match).
        let output = r.redact_line("sk-proj-xxx");
        assert_eq!(output, "sk-proj-xxx");
    }

    #[test]
    fn test_secret_appearing_multiple_times() {
        let r = make_redactor(&[("SECRET", "KOSH:a3f9c2b1")]);
        let output = r.redact_line("SECRET and SECRET again");
        assert_eq!(output, "[KOSH:a3f9c2b1] and [KOSH:a3f9c2b1] again");
    }
}
