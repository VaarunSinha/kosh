use crate::error::KoshError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const CONFIG_FILE: &str = "config.toml";

/// User configuration stored at `~/.kosh/config.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub current_workspace: Option<String>,
    pub current_env: Option<String>,
    pub server_url: Option<String>,
}

impl Config {
    /// The Kosh home directory: `$KOSH_HOME` if set, else `~/.kosh`.
    pub fn kosh_home() -> Result<PathBuf, KoshError> {
        if let Ok(dir) = std::env::var("KOSH_HOME") {
            return Ok(PathBuf::from(dir));
        }
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map_err(|_| KoshError::ConfigNotFound)?;
        Ok(PathBuf::from(home).join(".kosh"))
    }

    /// Full path to the config file under [`Config::kosh_home`].
    pub fn config_path() -> Result<PathBuf, KoshError> {
        Ok(Self::kosh_home()?.join(CONFIG_FILE))
    }

    /// Load config from the default location.
    pub fn load() -> Result<Self, KoshError> {
        Self::load_from(&Self::kosh_home()?)
    }

    /// Save config to the default location.
    pub fn save(&self) -> Result<(), KoshError> {
        self.save_to(&Self::kosh_home()?)
    }

    /// Load config from `dir/config.toml`.
    pub fn load_from(dir: &Path) -> Result<Self, KoshError> {
        let path = dir.join(CONFIG_FILE);
        if !path.exists() {
            return Err(KoshError::ConfigNotFound);
        }
        let content = std::fs::read_to_string(&path)?;
        toml::from_str(&content).map_err(|e| {
            let line = e
                .span()
                .map(|s| content[..s.start.min(content.len())].lines().count())
                .unwrap_or(0);
            KoshError::ConfigParseError { line }
        })
    }

    /// Save config to `dir/config.toml`, creating `dir` if needed.
    pub fn save_to(&self, dir: &Path) -> Result<(), KoshError> {
        std::fs::create_dir_all(dir)?;
        let content =
            toml::to_string_pretty(self).map_err(|e| KoshError::Other(anyhow::anyhow!(e)))?;
        std::fs::write(dir.join(CONFIG_FILE), content)?;
        Ok(())
    }

    /// Current workspace, or `NoWorkspaceSet` if unset.
    pub fn workspace(&self) -> Result<&str, KoshError> {
        self.current_workspace
            .as_deref()
            .ok_or(KoshError::NoWorkspaceSet)
    }

    /// Current environment, or `NoEnvSet` if unset.
    pub fn env(&self) -> Result<&str, KoshError> {
        self.current_env.as_deref().ok_or(KoshError::NoEnvSet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_save_load_roundtrip() {
        let dir = TempDir::new().unwrap();
        let cfg = Config {
            current_workspace: Some("acme".into()),
            current_env: Some("dev".into()),
            server_url: Some("https://kosh.example.com".into()),
        };
        cfg.save_to(dir.path()).unwrap();
        let loaded = Config::load_from(dir.path()).unwrap();
        assert_eq!(cfg, loaded);
    }

    #[test]
    fn test_load_missing_is_config_not_found() {
        let dir = TempDir::new().unwrap();
        let err = Config::load_from(dir.path()).unwrap_err();
        assert!(matches!(err, KoshError::ConfigNotFound));
    }

    #[test]
    fn test_load_malformed_is_parse_error() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(CONFIG_FILE), "this is = = not toml\n").unwrap();
        let err = Config::load_from(dir.path()).unwrap_err();
        assert!(matches!(err, KoshError::ConfigParseError { .. }));
    }

    #[test]
    fn test_accessors_error_when_unset() {
        let cfg = Config::default();
        assert!(matches!(cfg.workspace(), Err(KoshError::NoWorkspaceSet)));
        assert!(matches!(cfg.env(), Err(KoshError::NoEnvSet)));
    }

    #[test]
    fn test_accessors_return_values_when_set() {
        let cfg = Config {
            current_workspace: Some("acme".into()),
            current_env: Some("prod".into()),
            server_url: None,
        };
        assert_eq!(cfg.workspace().unwrap(), "acme");
        assert_eq!(cfg.env().unwrap(), "prod");
    }
}
