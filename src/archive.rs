use anyhow::{bail, Context, Result};
use bzip2::write::BzEncoder;
use bzip2::Compression;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub fn create_archive(files: &[PathBuf], output_path: &Path, passphrase: &str) -> Result<u64> {
    // Build tar → bzip2 in memory
    let compressed = compress_tar(files)?;

    // Encrypt with gpg
    encrypt_and_write(&compressed, output_path, passphrase)?;

    let size = std::fs::metadata(output_path)
        .map(|m| m.len())
        .unwrap_or(0);
    Ok(size)
}

fn compress_tar(files: &[PathBuf]) -> Result<Vec<u8>> {
    let buf = Vec::new();
    let encoder = BzEncoder::new(buf, Compression::best());
    let mut tar = tar::Builder::new(encoder);

    for file in files {
        if !file.exists() {
            eprintln!("  warn: skipping missing file: {}", file.display());
            continue;
        }
        // Use the absolute path as the archive name (strip leading /)
        let archive_name = file
            .to_string_lossy()
            .trim_start_matches('/')
            .to_string();
        tar.append_path_with_name(file, &archive_name)
            .with_context(|| format!("adding {} to tar", file.display()))?;
    }

    let encoder = tar.into_inner().context("finishing tar")?;
    let compressed = encoder.finish().context("finishing bzip2")?;
    Ok(compressed)
}

fn encrypt_and_write(data: &[u8], output_path: &Path, passphrase: &str) -> Result<()> {
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating directory: {}", parent.display()))?;
    }

    let out_str = output_path.to_string_lossy().to_string();
    let mut child = Command::new("gpg")
        .args([
            "--symmetric",
            "--cipher-algo",
            "AES256",
            "--batch",
            "--yes",
            "--passphrase",
            passphrase,
            "--output",
            &out_str,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning gpg")?;

    {
        let stdin = child.stdin.as_mut().context("opening gpg stdin")?;
        stdin.write_all(data).context("writing data to gpg")?;
    }

    let output = child.wait_with_output().context("waiting for gpg")?;
    if !output.status.success() {
        bail!(
            "gpg encryption failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

pub fn decrypt_file(encrypted_path: &Path, output_path: &Path, passphrase: &str) -> Result<()> {
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let output = Command::new("gpg")
        .args([
            "--decrypt",
            "--batch",
            "--yes",
            "--passphrase",
            passphrase,
            "--output",
            &output_path.to_string_lossy(),
            &encrypted_path.to_string_lossy(),
        ])
        .output()
        .context("running gpg decrypt")?;

    if !output.status.success() {
        bail!(
            "gpg decryption failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

pub fn encrypt_json(data: &[u8], output_path: &Path, passphrase: &str) -> Result<()> {
    encrypt_and_write(data, output_path, passphrase)
}

pub fn decrypt_to_bytes(encrypted_path: &Path, passphrase: &str) -> Result<Vec<u8>> {
    let output = Command::new("gpg")
        .args([
            "--decrypt",
            "--batch",
            "--yes",
            "--passphrase",
            passphrase,
            &encrypted_path.to_string_lossy(),
        ])
        .output()
        .context("running gpg decrypt")?;

    if !output.status.success() {
        bail!(
            "gpg decryption failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(output.stdout)
}
