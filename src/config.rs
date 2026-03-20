use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub backup_dir: String,
    #[serde(default = "default_checkpoint_interval")]
    pub checkpoint_interval_days: u32,
    #[serde(default = "default_keep_checkpoints")]
    pub keep_checkpoints: usize,
    pub sources: BTreeMap<String, Source>,
}

fn default_checkpoint_interval() -> u32 {
    7
}

fn default_keep_checkpoints() -> usize {
    2
}

#[derive(Debug, Deserialize)]
pub struct Source {
    pub path: Option<String>,
    pub include: Option<Vec<String>>,
    pub files: Option<Vec<String>>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content =
            std::fs::read_to_string(path).with_context(|| format!("reading config: {}", path.display()))?;
        let config: Config =
            serde_yaml::from_str(&content).with_context(|| "parsing config.yaml")?;
        Ok(config)
    }

    pub fn backup_dir(&self) -> PathBuf {
        expand_tilde(&self.backup_dir)
    }
}

pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}
