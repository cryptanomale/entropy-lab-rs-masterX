// Brainwallet Dictionary Import CLI Command

use anyhow::{Context, Result};
use std::path::PathBuf;
use temporal_planetarium_lib::scans::brainwallet::{run_import, AddressType, HashType};
use tracing::{info, warn};

pub fn run(
    wordlist: PathBuf,
    db_path: PathBuf,
    hash_type: String,
    address_type: String,
    dry_run: bool,
) -> Result<()> {
    info!("🔐 Brainwallet Dictionary Import");
    info!("📄 Wordlist: {}", wordlist.display());
    info!("💾 Database: {}", db_path.display());
    info!("🔨 Hash Type: {}", hash_type);
    info!("📍 Address Type: {}", address_type);

    if dry_run {
        warn!("⚠️  DRY RUN MODE - No database writes will be performed");
    }

    // Parse hash type
    let hash_type_enum = parse_hash_type(&hash_type)?;

    // Parse address type
    let address_type_enum = parse_address_type(&address_type)?;

    // Run import
    let stats = run_import(
        wordlist.to_str().context("Invalid wordlist path")?,
        Some(db_path),
        hash_type_enum,
        address_type_enum,
        dry_run,
    )?;

    // Print summary
    println!("\n{}", "=".repeat(80));
    println!("✅ Import Complete");
    println!("{}", "=".repeat(80));
    println!("Total Processed:     {}", stats.total_processed);
    println!("Stored Addresses:    {}", stats.stored_addresses);
    println!("Duplicates Skipped:  {}", stats.duplicates_skipped);
    println!("{}", "=".repeat(80));

    if dry_run {
        println!("\n💡 This was a dry run. To actually import, remove the --dry-run flag.");
    }

    Ok(())
}

fn parse_hash_type(s: &str) -> Result<HashType> {
    match s.to_lowercase().as_str() {
        "sha256-1x" | "sha256" => Ok(HashType::Sha256 { iterations: 1 }),
        "sha256-1000x" => Ok(HashType::Sha256 { iterations: 1000 }),
        "sha256-10000x" => Ok(HashType::Sha256 { iterations: 10000 }),
        "sha3-256" | "sha3" => Ok(HashType::Sha3_256),
        _ => Err(anyhow::anyhow!(
            "Invalid hash type '{}'. Supported: sha256-1x, sha256-1000x, sha256-10000x, sha3-256",
            s
        )),
    }
}

fn parse_address_type(s: &str) -> Result<AddressType> {
    match s.to_lowercase().as_str() {
        "p2pkh-uncompressed" | "p2pkh-u" => Ok(AddressType::P2pkhUncompressed),
        "p2pkh-compressed" | "p2pkh-c" | "p2pkh" => Ok(AddressType::P2pkhCompressed),
        "p2sh-p2wpkh" | "p2shwpkh" | "p2sh" => Ok(AddressType::P2shP2wpkh),
        "p2wpkh" | "bech32" => Ok(AddressType::P2wpkh),
        _ => Err(anyhow::anyhow!(
            "Invalid address type '{}'. Supported: p2pkh-uncompressed, p2pkh-compressed, p2sh-p2wpkh, p2wpkh",
            s
        )),
    }
}
