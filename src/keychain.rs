use anyhow::{bail, Context, Result};
use std::io::{self, Write};
use std::process::Command;

const SERVICE: &str = "backup-manager-gpg";
const ACCOUNT: &str = "backup-manager";

pub fn get_passphrase() -> Result<String> {
    match read_from_keychain() {
        Ok(pw) => Ok(pw),
        Err(_) => {
            eprintln!("No GPG passphrase found in macOS Keychain.");
            eprintln!("Enter a passphrase for encrypting backups (will be stored in Keychain):");
            eprint!("> ");
            io::stderr().flush()?;

            let pw = rpassword::read_password().context("reading passphrase")?;
            if pw.is_empty() {
                bail!("passphrase cannot be empty");
            }

            store_in_keychain(&pw)?;
            eprintln!("Passphrase stored in macOS Keychain.");
            Ok(pw)
        }
    }
}

fn read_from_keychain() -> Result<String> {
    let output = Command::new("security")
        .args(["find-generic-password", "-a", ACCOUNT, "-s", SERVICE, "-w"])
        .output()
        .context("running security find-generic-password")?;

    if !output.status.success() {
        bail!("keychain entry not found");
    }

    let pw = String::from_utf8(output.stdout)
        .context("keychain output not UTF-8")?
        .trim()
        .to_string();
    Ok(pw)
}

fn store_in_keychain(passphrase: &str) -> Result<()> {
    // Delete existing entry if present (ignore errors)
    let _ = Command::new("security")
        .args(["delete-generic-password", "-a", ACCOUNT, "-s", SERVICE])
        .output();

    let output = Command::new("security")
        .args([
            "add-generic-password",
            "-a",
            ACCOUNT,
            "-s",
            SERVICE,
            "-w",
            passphrase,
        ])
        .output()
        .context("running security add-generic-password")?;

    if !output.status.success() {
        bail!(
            "failed to store passphrase: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}
