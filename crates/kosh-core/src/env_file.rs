use crate::reference::RefId;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A parsed .env file preserving order, comments, and blank lines
#[derive(Debug, Clone)]
pub struct EnvFile {
    pub path: PathBuf,
    entries: Vec<EnvEntry>,
}

#[derive(Debug, Clone)]
enum EnvEntry {
    Comment(String),
    Blank,
    Variable {
        key: String,
        value: String,
        raw_line: String,
    },
}

impl EnvFile {
    pub fn load(path: &Path) -> Result<Self, crate::error::KoshError> {
        let content = std::fs::read_to_string(path).map_err(|_| {
            crate::error::KoshError::EnvFileNotReadable {
                path: path.display().to_string(),
            }
        })?;

        let entries = content
            .lines()
            .map(|line| {
                if line.trim().is_empty() {
                    EnvEntry::Blank
                } else if line.starts_with('#') {
                    EnvEntry::Comment(line.to_string())
                } else if let Some((key, value)) = line.split_once('=') {
                    EnvEntry::Variable {
                        key: key.trim().to_string(),
                        value: value.trim_matches('"').trim().to_string(),
                        raw_line: line.to_string(),
                    }
                } else {
                    EnvEntry::Comment(line.to_string()) // treat malformed as comment
                }
            })
            .collect();

        Ok(Self {
            path: path.to_path_buf(),
            entries,
        })
    }

    /// All key=value pairs (excludes comments and blanks)
    pub fn variables(&self) -> HashMap<String, String> {
        self.entries
            .iter()
            .filter_map(|e| {
                if let EnvEntry::Variable { key, value, .. } = e {
                    Some((key.clone(), value.clone()))
                } else {
                    None
                }
            })
            .collect()
    }

    /// All variables that are already KOSH: references
    pub fn references(&self) -> HashMap<String, RefId> {
        self.variables()
            .into_iter()
            .filter_map(|(key, value)| RefId::parse(&value).map(|ref_id| (key, ref_id)))
            .collect()
    }

    /// All variables that are NOT yet KOSH: references (plain secrets)
    pub fn plain_secrets(&self) -> HashMap<String, String> {
        self.variables()
            .into_iter()
            .filter(|(_, value)| RefId::parse(value).is_none())
            .collect()
    }

    /// Replace a plain value with a KOSH: reference
    pub fn replace_with_ref(&mut self, key: &str, ref_id: &RefId) {
        for entry in &mut self.entries {
            if let EnvEntry::Variable {
                key: k,
                value,
                raw_line,
            } = entry
            {
                if k == key {
                    *value = ref_id.as_str().to_string();
                    *raw_line = format!("{}={}", k, ref_id);
                }
            }
        }
    }

    /// Set `key` to `value`, updating the entry in place if it exists or
    /// appending a new `key=value` line otherwise. Used by `kosh add --key`
    /// to introduce a not-yet-present variable before referencing it.
    pub fn set_var(&mut self, key: &str, value: &str) {
        for entry in &mut self.entries {
            if let EnvEntry::Variable {
                key: k,
                value: v,
                raw_line,
            } = entry
            {
                if k == key {
                    *v = value.to_string();
                    *raw_line = format!("{}={}", k, value);
                    return;
                }
            }
        }
        self.entries.push(EnvEntry::Variable {
            key: key.to_string(),
            value: value.to_string(),
            raw_line: format!("{}={}", key, value),
        });
    }

    /// Remove the variable named `key`, if present. Comments and blanks are
    /// untouched. Returns true if an entry was removed.
    pub fn remove_var(&mut self, key: &str) -> bool {
        let before = self.entries.len();
        self.entries
            .retain(|e| !matches!(e, EnvEntry::Variable { key: k, .. } if k == key));
        self.entries.len() != before
    }

    /// Write the file back to disk, preserving all comments and blank lines
    pub fn save(&self) -> Result<(), crate::error::KoshError> {
        let content: String = self
            .entries
            .iter()
            .map(|e| match e {
                EnvEntry::Comment(c) => c.clone(),
                EnvEntry::Blank => String::new(),
                EnvEntry::Variable { raw_line, .. } => raw_line.clone(),
            })
            .collect::<Vec<_>>()
            .join("\n");

        std::fs::write(&self.path, content + "\n").map_err(|_| {
            crate::error::KoshError::EnvFileNotWritable {
                path: self.path.display().to_string(),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp_env(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn test_load_basic_env() {
        let f = write_temp_env("OPENAI_KEY=sk-proj-xxx\nSTRIPE=sk_live_yyy\n");
        let env = EnvFile::load(f.path()).unwrap();
        let vars = env.variables();
        assert_eq!(vars["OPENAI_KEY"], "sk-proj-xxx");
        assert_eq!(vars["STRIPE"], "sk_live_yyy");
    }

    #[test]
    fn test_preserves_comments() {
        let f = write_temp_env("# This is a comment\nKEY=value\n");
        let env = EnvFile::load(f.path()).unwrap();
        // Should have 1 variable, comment is preserved
        assert_eq!(env.variables().len(), 1);
    }

    #[test]
    fn test_detects_plain_secrets() {
        let f = write_temp_env("OPENAI=sk-proj-xxx\nNODE_ENV=development\n");
        let env = EnvFile::load(f.path()).unwrap();
        let plain = env.plain_secrets();
        assert!(plain.contains_key("OPENAI"));
        assert!(plain.contains_key("NODE_ENV"));
    }

    #[test]
    fn test_detects_references() {
        let f = write_temp_env("OPENAI=KOSH:a3f9c2b1\nPLAIN=value\n");
        let env = EnvFile::load(f.path()).unwrap();
        let refs = env.references();
        assert!(refs.contains_key("OPENAI"));
        assert!(!refs.contains_key("PLAIN"));
    }

    #[test]
    fn test_set_var_updates_existing_and_appends_new() {
        let f = write_temp_env("EXISTING=old\n");
        let mut env = EnvFile::load(f.path()).unwrap();
        env.set_var("EXISTING", "new");
        env.set_var("FRESH", "value");
        env.save().unwrap();

        let reloaded = EnvFile::load(f.path()).unwrap();
        let vars = reloaded.variables();
        assert_eq!(vars["EXISTING"], "new");
        assert_eq!(vars["FRESH"], "value");
    }

    #[test]
    fn test_remove_var() {
        let f = write_temp_env("A=1\nB=2\n");
        let mut env = EnvFile::load(f.path()).unwrap();
        assert!(env.remove_var("A"));
        assert!(!env.remove_var("MISSING"));
        env.save().unwrap();

        let reloaded = EnvFile::load(f.path()).unwrap();
        let vars = reloaded.variables();
        assert!(!vars.contains_key("A"));
        assert!(vars.contains_key("B"));
    }

    #[test]
    fn test_replace_with_ref_and_save() {
        let f = write_temp_env("OPENAI=sk-proj-xxx\n");
        let mut env = EnvFile::load(f.path()).unwrap();
        let ref_id = RefId::parse("KOSH:a3f9c2b1").unwrap();
        env.replace_with_ref("OPENAI", &ref_id);
        env.save().unwrap();

        let reloaded = EnvFile::load(f.path()).unwrap();
        assert_eq!(reloaded.variables()["OPENAI"], "KOSH:a3f9c2b1");
    }
}
