// List Recovered Keys CLI Command

use anyhow::{Context, Result};
use std::path::PathBuf;
use temporal_planetarium_lib::utils::db::{TargetDatabase, Target};
use temporal_planetarium_lib::utils::encryption::{decrypt_private_key, EncryptedData, DEFAULT_ENCRYPTION_PASSPHRASE};
use tracing::{info, warn};
use chrono::DateTime;

pub enum OutputFormat {
    Table,
    Json,
    Csv,
}

impl std::str::FromStr for OutputFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "table" => Ok(OutputFormat::Table),
            "json" => Ok(OutputFormat::Json),
            "csv" => Ok(OutputFormat::Csv),
            _ => Err(anyhow::anyhow!("Invalid format. Use: table, json, or csv")),
        }
    }
}

pub fn run(
    db_path: PathBuf,
    passphrase: String,
    format: OutputFormat,
    show_keys: bool,
) -> Result<()> {
    info!("🔑 Listing Recovered Keys");
    info!("💾 Database: {}", db_path.display());

    // Security warning if using default passphrase
    if passphrase == DEFAULT_ENCRYPTION_PASSPHRASE {
        warn!("⚠️  WARNING: Using default encryption passphrase.");
    }

    // Critical security warning when showing keys
    if show_keys {
        eprintln!();
        eprintln!("╔══════════════════════════════════════════════════════════════════╗");
        eprintln!("║  ⚠️  SECURITY WARNING: Private keys will be displayed!           ║");
        eprintln!("║                                                                  ║");
        eprintln!("║  • Ensure no one is watching your screen                         ║");
        eprintln!("║  • Do not copy/paste keys into insecure locations                ║");
        eprintln!("║  • Clear terminal history after viewing (history -c)             ║");
        eprintln!("║  • Consider redirecting output to encrypted file instead         ║");
        eprintln!("╚══════════════════════════════════════════════════════════════════╝");
        eprintln!();
    }

    let db = TargetDatabase::new(db_path.clone())?;

    // Query all nonce_reuse targets
    let targets = db.query_by_class("nonce_reuse", 10000)?;

    if targets.is_empty() {
        println!("📭 No recovered keys found in database");
        return Ok(());
    }

    info!("Found {} recovered key(s)", targets.len());

    match format {
        OutputFormat::Table => print_table(&targets, &passphrase, show_keys, &db)?,
        OutputFormat::Json => print_json(&targets, &passphrase, show_keys, &db)?,
        OutputFormat::Csv => print_csv(&targets, &passphrase, show_keys, &db)?,
    }

    Ok(())
}

fn print_table(targets: &[Target], passphrase: &str, show_keys: bool, db: &TargetDatabase) -> Result<()> {
    println!("\n{}", "=".repeat(120));
    println!("{:<45} {:<15} {:<15} {:<20} {:<25}",
        "Address", "Status", "Access Count", "Last Accessed", "Recovery Date");
    println!("{}", "=".repeat(120));

    for target in targets {
        let last_accessed = if let Some(ts) = target.last_accessed {
            DateTime::from_timestamp(ts, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                .unwrap_or_else(|| "Invalid".to_string())
        } else {
            "Never".to_string()
        };

        // Parse metadata for recovery date
        let recovery_date = if let Some(ref metadata) = target.metadata_json {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(metadata) {
                json["recovery_date"]
                    .as_str()
                    .and_then(|s| s.get(0..16))
                    .unwrap_or("Unknown")
                    .to_string()
            } else {
                "Unknown".to_string()
            }
        } else {
            "Unknown".to_string()
        };

        println!("{:<45} {:<15} {:<15} {:<20} {:<25}",
            target.address,
            target.status,
            target.access_count,
            last_accessed,
            recovery_date
        );

        if show_keys {
            match decrypt_key(target, passphrase) {
                Ok(wif) => {
                    println!("  🔓 WIF: {}", wif);
                    // Track key access (AC3 requirement)
                    if let Err(e) = db.update_access_tracking(&target.address) {
                        warn!("  ⚠️  Failed to update access tracking: {}", e);
                    }
                }
                Err(e) => {
                    warn!("  ❌ Decryption failed for {}: {}", target.address, e);
                }
            }
        }
    }

    println!("{}", "=".repeat(120));
    println!("\n📊 Total: {} recovered key(s)", targets.len());

    if !show_keys {
        println!("\n💡 Tip: Use --show-keys flag to display decrypted private keys");
    }

    Ok(())
}

fn print_json(targets: &[Target], passphrase: &str, show_keys: bool, db: &TargetDatabase) -> Result<()> {
    let mut entries = Vec::new();

    for target in targets {
        let mut entry = serde_json::json!({
            "address": target.address,
            "vuln_class": target.vuln_class,
            "status": target.status,
            "access_count": target.access_count,
            "last_accessed": target.last_accessed,
            "metadata": target.metadata_json,
        });

        if show_keys {
            if let Ok(wif) = decrypt_key(target, passphrase) {
                entry["private_key_wif"] = serde_json::json!(wif);
                // Track key access (AC3 requirement)
                let _ = db.update_access_tracking(&target.address);
            } else {
                entry["private_key_wif"] = serde_json::json!(null);
                entry["decryption_error"] = serde_json::json!(true);
            }
        }

        entries.push(entry);
    }

    let output = serde_json::json!({
        "count": targets.len(),
        "keys": entries
    });

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn print_csv(targets: &[Target], passphrase: &str, show_keys: bool, db: &TargetDatabase) -> Result<()> {
    // CSV header
    if show_keys {
        println!("address,status,access_count,last_accessed,recovery_date,private_key_wif");
    } else {
        println!("address,status,access_count,last_accessed,recovery_date");
    }

    for target in targets {
        let last_accessed = target.last_accessed
            .map(|ts| ts.to_string())
            .unwrap_or_default();

        let recovery_date = if let Some(ref metadata) = target.metadata_json {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(metadata) {
                csv_escape(json["recovery_date"].as_str().unwrap_or(""))
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        if show_keys {
            let wif = match decrypt_key(target, passphrase) {
                Ok(w) => {
                    // Track key access (AC3 requirement)
                    let _ = db.update_access_tracking(&target.address);
                    w
                }
                Err(_) => "DECRYPTION_FAILED".to_string(),
            };

            println!("{},{},{},{},{},{}",
                csv_escape(&target.address),
                csv_escape(&target.status),
                target.access_count,
                last_accessed,
                recovery_date,
                csv_escape(&wif)
            );
        } else {
            println!("{},{},{},{},{}",
                csv_escape(&target.address),
                csv_escape(&target.status),
                target.access_count,
                last_accessed,
                recovery_date
            );
        }
    }

    Ok(())
}

/// Escape a string for CSV output (RFC 4180 compliant)
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn decrypt_key(target: &Target, passphrase: &str) -> Result<String> {
    let ciphertext = target.encrypted_private_key.as_ref()
        .context("No encrypted key")?;
    let nonce = target.encryption_nonce.as_ref()
        .context("No nonce")?;
    let salt = target.pbkdf2_salt.as_ref()
        .context("No salt")?;

    let encrypted = EncryptedData {
        ciphertext: ciphertext.clone(),
        nonce: nonce.clone(),
        salt: salt.clone(),
    };

    decrypt_private_key(&encrypted, passphrase)
}
