use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::config::{expand_tilde, Config};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub mtime: u64,
    pub size: u64,
}

pub type Manifest = BTreeMap<String, FileEntry>;

pub fn scan_sources(config: &Config) -> Result<Manifest> {
    let mut manifest = Manifest::new();

    for (name, source) in &config.sources {
        // Handle explicit file list
        if let Some(files) = &source.files {
            for f in files {
                let path = expand_tilde(f);
                if let Some(entry) = stat_file(&path) {
                    manifest.insert(path.to_string_lossy().to_string(), entry);
                } else {
                    eprintln!("  warn: [{}] missing: {}", name, path.display());
                }
            }
        }

        // Handle path + include glob patterns
        if let Some(base) = &source.path {
            let base_path = expand_tilde(base);
            if let Some(patterns) = &source.include {
                for pattern in patterns {
                    let full_pattern = base_path.join(pattern);
                    let full_pattern_str = full_pattern.to_string_lossy();
                    match glob::glob(&full_pattern_str) {
                        Ok(entries) => {
                            for entry in entries.flatten() {
                                if entry.is_file() {
                                    if let Some(fe) = stat_file(&entry) {
                                        manifest
                                            .insert(entry.to_string_lossy().to_string(), fe);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("  warn: [{}] bad glob {}: {}", name, full_pattern_str, e);
                        }
                    }
                }
            }
        }
    }

    Ok(manifest)
}

fn stat_file(path: &Path) -> Option<FileEntry> {
    let meta = std::fs::metadata(path).ok()?;
    let mtime = meta
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(FileEntry {
        mtime,
        size: meta.len(),
    })
}

pub fn diff_manifests(current: &Manifest, previous: &Manifest) -> Vec<PathBuf> {
    let mut changed = Vec::new();

    for (path, entry) in current {
        match previous.get(path) {
            Some(prev) => {
                if entry.mtime != prev.mtime || entry.size != prev.size {
                    changed.push(PathBuf::from(path));
                }
            }
            None => {
                changed.push(PathBuf::from(path));
            }
        }
    }

    changed.sort();
    changed
}
