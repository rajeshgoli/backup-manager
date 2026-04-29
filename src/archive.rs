use anyhow::{bail, Context, Result};
use bzip2::write::BzEncoder;
use bzip2::Compression;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::NamedTempFile;

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

    // Write to a local temp file first, then copy to final destination.
    // This avoids GPG writing directly to FUSE mounts (Google Drive) which
    // can fail with broken pipe or EDEADLK on cloud-only files.
    let tmp = NamedTempFile::new().context("creating temp file for gpg output")?;
    let tmp_path = tmp.path().to_string_lossy().to_string();

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
            &tmp_path,
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

    retry_on_deadlock(|| std::fs::copy(tmp.path(), output_path).map(|_| ()))
        .with_context(|| format!("copying encrypted file to {}", output_path.display()))?;

    Ok(())
}

pub fn decrypt_file(encrypted_path: &Path, output_path: &Path, passphrase: &str) -> Result<()> {
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Stage encrypted file locally first to avoid FUSE read errors
    let local_src = stage_locally(encrypted_path)?;

    let output = Command::new("gpg")
        .args([
            "--decrypt",
            "--batch",
            "--yes",
            "--passphrase",
            passphrase,
            "--output",
            &output_path.to_string_lossy(),
            &local_src.path().to_string_lossy(),
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
    // Stage encrypted file locally first to avoid FUSE read errors
    let local_src = stage_locally(encrypted_path)?;

    let output = Command::new("gpg")
        .args([
            "--decrypt",
            "--batch",
            "--yes",
            "--passphrase",
            passphrase,
            &local_src.path().to_string_lossy(),
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

/// Copy a file to a local temp file to avoid FUSE filesystem issues
/// (Google Drive FileStream returns EDEADLK on cloud-only files). Streams
/// via std::fs::copy so multi-GB archives aren't buffered into memory.
fn stage_locally(path: &Path) -> Result<NamedTempFile> {
    let tmp = NamedTempFile::new().context("creating temp file for staging")?;
    retry_on_deadlock(|| std::fs::copy(path, tmp.path()).map(|_| ()))
        .with_context(|| format!("reading {} (is Google Drive online?)", path.display()))?;
    Ok(tmp)
}

/// Retry a filesystem operation on EDEADLK (os error 11), which Google Drive
/// FileStream returns transiently on cloud-only files. Backoff: 1s, 2s, 5s, 10s, 20s.
fn retry_on_deadlock<T, F>(mut op: F) -> std::io::Result<T>
where
    F: FnMut() -> std::io::Result<T>,
{
    let delays = [1, 2, 5, 10, 20];
    for (i, delay) in delays.iter().enumerate() {
        match op() {
            Ok(v) => return Ok(v),
            // EDEADLK = 11 on macOS/Linux; Google Drive FileStream returns it transiently.
            Err(e) if e.raw_os_error() == Some(11) => {
                eprintln!(
                    "  warn: filesystem deadlock (attempt {}/{}), retrying in {}s...",
                    i + 1,
                    delays.len() + 1,
                    delay
                );
                std::thread::sleep(std::time::Duration::from_secs(*delay));
            }
            Err(e) => return Err(e),
        }
    }
    op()
}
