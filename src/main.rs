mod archive;
mod config;
mod keychain;
mod restore;
mod scanner;

use anyhow::{Context, Result};
use chrono::Local;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

use archive::{create_archive, decrypt_to_bytes, encrypt_json};
use config::Config;
use scanner::{diff_manifests, scan_sources, Manifest};

#[derive(Parser)]
#[command(name = "backup-manager", about = "Encrypted backup tool for sensitive local state")]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run backup (delta or checkpoint as needed)
    Backup {
        /// Force a full checkpoint
        #[arg(long)]
        full: bool,
    },
    /// Show backup status
    Status,
    /// Restore from backup
    Restore {
        /// Target date (YYYY-MM-DD), defaults to latest
        #[arg(long)]
        date: Option<String>,
        /// Output directory
        #[arg(long, default_value = "/tmp/backup-restore")]
        output: PathBuf,
    },
    /// Verify backup integrity
    Verify,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Resolve config path: try CWD, then relative to exe, then project root
    let config_path = resolve_config_path(&cli.config);

    let config = Config::load(&config_path)?;

    match cli.command {
        Commands::Backup { full } => cmd_backup(&config, full),
        Commands::Status => cmd_status(&config),
        Commands::Restore { date, output } => cmd_restore(&config, date.as_deref(), &output),
        Commands::Verify => cmd_verify(&config),
    }
}

fn resolve_config_path(config: &Path) -> PathBuf {
    if config.is_absolute() || config.exists() {
        return config.to_path_buf();
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            // Try next to the binary
            let candidate = dir.join(config);
            if candidate.exists() {
                return candidate;
            }
            // Try project root (../../ from target/release/)
            let project = dir.join("../..").join(config);
            if project.exists() {
                return project;
            }
        }
    }
    config.to_path_buf()
}

fn cmd_backup(config: &Config, force_full: bool) -> Result<()> {
    let backup_dir = config.backup_dir();
    let passphrase = keychain::get_passphrase()?;

    eprintln!("Scanning sources...");
    let current_manifest = scan_sources(config)?;
    eprintln!("  Found {} files", current_manifest.len());

    let needs_full = force_full || needs_checkpoint(config, &backup_dir)?;
    let today = Local::now().format("%Y-%m-%d").to_string();

    if needs_full {
        eprintln!("Creating full checkpoint...");
        let all_files: Vec<PathBuf> = current_manifest.keys().map(PathBuf::from).collect();

        let checkpoint_dir = backup_dir.join("checkpoints");
        let output = checkpoint_dir.join(format!("{}_full.tar.bz2.gpg", today));

        let size = create_archive(&all_files, &output, &passphrase)?;
        eprintln!(
            "  Checkpoint: {} ({} files, {})",
            output.display(),
            all_files.len(),
            format_size(size)
        );

        prune_old_backups(config, &backup_dir)?;
    } else {
        let previous_manifest = load_manifest(&backup_dir, &passphrase)?;
        let changed = diff_manifests(&current_manifest, &previous_manifest);

        if changed.is_empty() {
            eprintln!("  No changes detected. Nothing to back up.");
            return Ok(());
        }

        eprintln!("  {} files changed", changed.len());

        let delta_dir = backup_dir.join("deltas");
        let output = delta_dir.join(format!("{}_delta.tar.bz2.gpg", today));

        let size = create_archive(&changed, &output, &passphrase)?;
        eprintln!(
            "  Delta: {} ({} files, {})",
            output.display(),
            changed.len(),
            format_size(size)
        );
    }

    save_manifest(&current_manifest, &backup_dir, &passphrase)?;
    eprintln!("Done.");
    Ok(())
}

fn cmd_status(config: &Config) -> Result<()> {
    let backup_dir = config.backup_dir();

    println!("Backup directory: {}", backup_dir.display());
    println!();

    let checkpoint_dir = backup_dir.join("checkpoints");
    let mut checkpoints = list_backup_files(&checkpoint_dir, "_full.tar.bz2.gpg");
    checkpoints.sort();

    println!("Checkpoints ({}):", checkpoints.len());
    for cp in &checkpoints {
        let size = std::fs::metadata(cp).map(|m| m.len()).unwrap_or(0);
        println!(
            "  {} ({})",
            cp.file_name().unwrap_or_default().to_string_lossy(),
            format_size(size)
        );
    }

    let delta_dir = backup_dir.join("deltas");
    let mut deltas = list_backup_files(&delta_dir, "_delta.tar.bz2.gpg");
    deltas.sort();

    println!("\nDeltas ({}):", deltas.len());
    for d in &deltas {
        let size = std::fs::metadata(d).map(|m| m.len()).unwrap_or(0);
        println!(
            "  {} ({})",
            d.file_name().unwrap_or_default().to_string_lossy(),
            format_size(size)
        );
    }

    if let Some(latest) = checkpoints.last() {
        if let Some(date_str) = file_date(latest) {
            if let Ok(date) = chrono::NaiveDate::parse_from_str(&date_str, "%Y-%m-%d") {
                let next = date + chrono::Duration::days(config.checkpoint_interval_days as i64);
                let today = Local::now().date_naive();
                let days_until = (next - today).num_days();
                println!("\nNext checkpoint: {} ({} days)", next, days_until);
            }
        }
    }

    let manifest_path = backup_dir.join("manifest.json.gpg");
    if manifest_path.exists() {
        let passphrase = keychain::get_passphrase()?;
        let manifest = load_manifest(&backup_dir, &passphrase)?;
        let total_size: u64 = manifest.values().map(|e| e.size).sum();
        println!(
            "\nManifest: {} files tracked ({})",
            manifest.len(),
            format_size(total_size)
        );
    }

    Ok(())
}

fn cmd_restore(config: &Config, date: Option<&str>, output: &Path) -> Result<()> {
    let backup_dir = config.backup_dir();
    let passphrase = keychain::get_passphrase()?;

    let (checkpoint, deltas) = restore::find_backup_chain(&backup_dir, date)?;
    eprintln!("Restore chain: 1 checkpoint + {} deltas", deltas.len());

    let count = restore::restore_chain(&checkpoint, &deltas, output, &passphrase)?;
    eprintln!("Restored {} files to {}", count, output.display());
    Ok(())
}

fn cmd_verify(config: &Config) -> Result<()> {
    let backup_dir = config.backup_dir();
    let passphrase = keychain::get_passphrase()?;

    eprintln!("Verifying backup integrity...");
    let result = restore::verify_backup(&backup_dir, &passphrase)?;

    eprintln!("  Extracted files:  {}", result.extracted_files);
    eprintln!("  Manifest entries: {}", result.manifest_entries);
    eprintln!(
        "  Hash verification: {}/{} sampled files match",
        result.matched, result.sampled
    );

    if !result.missing_source.is_empty() {
        eprintln!(
            "  {} files no longer exist on disk (moved/deleted since backup):",
            result.missing_source.len()
        );
        for f in &result.missing_source {
            eprintln!("    {}", f);
        }
    }

    if !result.mismatched.is_empty() {
        eprintln!("  HASH MISMATCH ({} files):", result.mismatched.len());
        for f in &result.mismatched {
            eprintln!("    {}", f);
        }
    }

    if result.mismatched.is_empty() && result.sampled > 0 {
        eprintln!("  Backup integrity verified.");
    } else if !result.mismatched.is_empty() {
        eprintln!("  WARNING: some files failed hash verification!");
    }

    Ok(())
}

// --- helpers ---

fn needs_checkpoint(config: &Config, backup_dir: &Path) -> Result<bool> {
    let checkpoint_dir = backup_dir.join("checkpoints");
    let mut checkpoints = list_backup_files(&checkpoint_dir, "_full.tar.bz2.gpg");
    checkpoints.sort();

    let latest = match checkpoints.last() {
        Some(p) => p,
        None => return Ok(true),
    };

    let date_str = match file_date(latest) {
        Some(d) => d,
        None => return Ok(true),
    };

    let last_date = chrono::NaiveDate::parse_from_str(&date_str, "%Y-%m-%d")
        .context("parsing checkpoint date")?;
    let today = Local::now().date_naive();
    let age = (today - last_date).num_days();

    Ok(age >= config.checkpoint_interval_days as i64)
}

fn load_manifest(backup_dir: &Path, passphrase: &str) -> Result<Manifest> {
    let manifest_path = backup_dir.join("manifest.json.gpg");
    if !manifest_path.exists() {
        return Ok(Manifest::new());
    }
    let data = decrypt_to_bytes(&manifest_path, passphrase)?;
    let manifest: Manifest = serde_json::from_slice(&data).context("parsing manifest JSON")?;
    Ok(manifest)
}

fn save_manifest(manifest: &Manifest, backup_dir: &Path, passphrase: &str) -> Result<()> {
    let data = serde_json::to_vec_pretty(manifest).context("serializing manifest")?;
    let manifest_path = backup_dir.join("manifest.json.gpg");
    encrypt_json(&data, &manifest_path, passphrase)?;
    Ok(())
}

fn prune_old_backups(config: &Config, backup_dir: &Path) -> Result<()> {
    let checkpoint_dir = backup_dir.join("checkpoints");
    let delta_dir = backup_dir.join("deltas");

    let mut checkpoints = list_backup_files(&checkpoint_dir, "_full.tar.bz2.gpg");
    checkpoints.sort();

    if checkpoints.len() > config.keep_checkpoints {
        let cutoff = checkpoints.len() - config.keep_checkpoints;
        let oldest_kept = file_date(&checkpoints[cutoff]).unwrap_or_default();

        for cp in &checkpoints[..cutoff] {
            eprintln!("  Pruning old checkpoint: {}", cp.display());
            std::fs::remove_file(cp)?;
        }

        let deltas = list_backup_files(&delta_dir, "_delta.tar.bz2.gpg");
        for d in deltas {
            if let Some(date) = file_date(&d) {
                if date < oldest_kept {
                    eprintln!("  Pruning old delta: {}", d.display());
                    std::fs::remove_file(&d)?;
                }
            }
        }
    }

    Ok(())
}

fn list_backup_files(dir: &Path, suffix: &str) -> Vec<PathBuf> {
    if !dir.exists() {
        return vec![];
    }
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(suffix))
            {
                files.push(path);
            }
        }
    }
    files
}

fn file_date(path: &Path) -> Option<String> {
    path.file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.split('_').next())
        .map(|s| s.to_string())
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
