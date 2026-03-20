use anyhow::{bail, Context, Result};
use rand::seq::SliceRandom;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use crate::archive::{decrypt_file, decrypt_to_bytes};
use crate::scanner::Manifest;

pub fn find_backup_chain(
    backup_dir: &Path,
    target_date: Option<&str>,
) -> Result<(PathBuf, Vec<PathBuf>)> {
    let checkpoint_dir = backup_dir.join("checkpoints");
    let delta_dir = backup_dir.join("deltas");

    // Find all checkpoints sorted by name (date-based, so alphabetical = chronological)
    let mut checkpoints = list_files(&checkpoint_dir, "_full.tar.bz2.gpg")?;
    checkpoints.sort();

    if checkpoints.is_empty() {
        bail!("no checkpoints found in {}", checkpoint_dir.display());
    }

    // Pick the checkpoint: latest before target_date, or just latest
    let checkpoint = if let Some(date) = target_date {
        checkpoints
            .iter()
            .rev()
            .find(|p| {
                file_date(p)
                    .map(|d| d.as_str() <= date)
                    .unwrap_or(false)
            })
            .cloned()
            .unwrap_or_else(|| checkpoints.last().unwrap().clone())
    } else {
        checkpoints.last().unwrap().clone()
    };

    let checkpoint_date = file_date(&checkpoint).unwrap_or_default();

    // Find applicable deltas: those after the checkpoint and before/on target_date
    let mut deltas = list_files(&delta_dir, "_delta.tar.bz2.gpg")?;
    deltas.sort();
    let deltas: Vec<PathBuf> = deltas
        .into_iter()
        .filter(|p| {
            let d = file_date(p).unwrap_or_default();
            let after_checkpoint = d > checkpoint_date;
            let before_target = target_date.map(|t| d.as_str() <= t).unwrap_or(true);
            after_checkpoint && before_target
        })
        .collect();

    Ok((checkpoint, deltas))
}

pub fn restore_chain(
    checkpoint: &Path,
    deltas: &[PathBuf],
    staging_dir: &Path,
    passphrase: &str,
) -> Result<usize> {
    std::fs::create_dir_all(staging_dir)?;
    let mut total_files = 0;

    // Restore checkpoint
    eprintln!("Restoring checkpoint: {}", checkpoint.display());
    total_files += extract_encrypted_tar(checkpoint, staging_dir, passphrase)?;

    // Apply deltas in order
    for delta in deltas {
        eprintln!("Applying delta: {}", delta.display());
        total_files += extract_encrypted_tar(delta, staging_dir, passphrase)?;
    }

    Ok(total_files)
}

fn extract_encrypted_tar(
    encrypted_path: &Path,
    output_dir: &Path,
    passphrase: &str,
) -> Result<usize> {
    let tmp = output_dir.join(".tmp_decrypt.tar.bz2");
    decrypt_file(encrypted_path, &tmp, passphrase)?;

    let file = std::fs::File::open(&tmp).context("opening decrypted tar")?;
    let decoder = bzip2::read::BzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);

    let mut count = 0;
    for entry in archive.entries().context("reading tar entries")? {
        let mut entry = entry.context("reading tar entry")?;
        entry.unpack_in(output_dir).context("extracting entry")?;
        count += 1;
    }

    let _ = std::fs::remove_file(&tmp);
    Ok(count)
}

const VERIFY_SAMPLE_SIZE: usize = 50;

pub struct VerifyResult {
    pub extracted_files: usize,
    pub manifest_entries: usize,
    pub sampled: usize,
    pub matched: usize,
    pub mismatched: Vec<String>,
    pub missing_source: Vec<String>,
}

pub fn verify_backup(backup_dir: &Path, passphrase: &str) -> Result<VerifyResult> {
    let (checkpoint, deltas) = find_backup_chain(backup_dir, None)?;

    let tmp_dir = std::env::temp_dir().join("backup-manager-verify");
    let _ = std::fs::remove_dir_all(&tmp_dir);

    let file_count = restore_chain(&checkpoint, &deltas, &tmp_dir, passphrase)?;

    // Load manifest
    let manifest_path = backup_dir.join("manifest.json.gpg");
    let manifest: Manifest = if manifest_path.exists() {
        let data = decrypt_to_bytes(&manifest_path, passphrase)?;
        serde_json::from_slice(&data).context("parsing manifest")?
    } else {
        Manifest::new()
    };

    // Collect all restored files (absolute paths in the archive are stored without leading /)
    let mut restored_files: Vec<PathBuf> = Vec::new();
    collect_files_recursive(&tmp_dir, &mut restored_files);
    // Filter out our tmp decrypt artifact
    restored_files.retain(|p| {
        p.file_name()
            .and_then(|n| n.to_str())
            .map(|n| n != ".tmp_decrypt.tar.bz2")
            .unwrap_or(true)
    });

    // Random sample
    let mut rng = rand::rng();
    let mut sample = restored_files.clone();
    sample.shuffle(&mut rng);
    let sample: Vec<PathBuf> = sample.into_iter().take(VERIFY_SAMPLE_SIZE).collect();

    let mut matched = 0;
    let mut mismatched = Vec::new();
    let mut missing_source = Vec::new();

    for restored_path in &sample {
        // Reconstruct the original absolute path
        // Archive stores paths like "Users/rajesh/..." (stripped leading /)
        let relative = restored_path.strip_prefix(&tmp_dir).unwrap_or(restored_path);
        let original = PathBuf::from("/").join(relative);

        if !original.exists() {
            missing_source.push(original.to_string_lossy().to_string());
            continue;
        }

        let hash_restored = sha256_file(restored_path)?;
        let hash_original = sha256_file(&original)?;

        if hash_restored == hash_original {
            matched += 1;
        } else {
            mismatched.push(original.to_string_lossy().to_string());
        }
    }

    let _ = std::fs::remove_dir_all(&tmp_dir);

    Ok(VerifyResult {
        extracted_files: file_count,
        manifest_entries: manifest.len(),
        sampled: sample.len(),
        matched,
        mismatched,
        missing_source,
    })
}

fn sha256_file(path: &Path) -> Result<String> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let hash = Sha256::digest(&data);
    Ok(format!("{:x}", hash))
}

fn collect_files_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_files_recursive(&path, out);
            } else {
                out.push(path);
            }
        }
    }
}

fn list_files(dir: &Path, suffix: &str) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Ok(vec![]);
    }
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.ends_with(suffix))
            .unwrap_or(false)
        {
            files.push(path);
        }
    }
    Ok(files)
}

fn file_date(path: &Path) -> Option<String> {
    path.file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.split('_').next())
        .map(|s| s.to_string())
}
