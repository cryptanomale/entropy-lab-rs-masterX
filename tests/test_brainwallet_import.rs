// Integration tests for Brainwallet Dictionary Import
//
// Tests the full pipeline:
// 1. Read passphrases from wordlist
// 2. Derive private keys
// 3. Generate addresses
// 4. Store in database with metadata

use anyhow::Result;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::File;
use std::io::Write as IoWrite;
use tempfile::TempDir;
use temporal_planetarium_lib::scans::brainwallet::{run_import, AddressType, HashType};
use temporal_planetarium_lib::utils::db::TargetDatabase;

#[test]
fn test_basic_import_to_database() -> Result<()> {
    // Create temporary directory for test files
    let temp_dir = TempDir::new()?;
    let wordlist_path = temp_dir.path().join("test_passwords.txt");
    let db_path = temp_dir.path().join("test_brainwallet.db");

    // Create test wordlist with 10 passphrases
    let mut file = File::create(&wordlist_path)?;
    writeln!(file, "password")?;
    writeln!(file, "hashcat")?;
    writeln!(file, "satoshi")?;
    writeln!(file, "bitcoin")?;
    writeln!(file, "test123")?;
    writeln!(file, "admin")?;
    writeln!(file, "wallet")?;
    writeln!(file, "secret")?;
    writeln!(file, "blockchain")?;
    writeln!(file, "nakamoto")?;
    drop(file);

    // Run import
    let stats = run_import(
        wordlist_path.to_str().unwrap(),
        Some(db_path.clone()),
        HashType::Sha256 { iterations: 1 },
        AddressType::P2pkhCompressed,
        false, // not dry_run
    )?;

    // Verify statistics
    assert_eq!(stats.total_processed, 10, "Should process 10 passphrases");
    assert_eq!(stats.stored_addresses, 10, "Should store 10 addresses");
    assert_eq!(stats.duplicates_skipped, 0, "No duplicates in test set");

    // Verify database contents
    let db = TargetDatabase::new(db_path)?;
    let targets = db.query_by_class("brainwallet", 100)?;

    assert_eq!(targets.len(), 10, "Database should contain 10 records");

    // Verify first record (password)
    let password_record = targets
        .iter()
        .find(|t| t.metadata_json.as_ref().map(|m| m.contains("password")).unwrap_or(false));

    assert!(password_record.is_some(), "Should find 'password' record");
    let record = password_record.unwrap();
    assert_eq!(record.vuln_class, "brainwallet");
    assert_eq!(record.status, "cracked");
    assert!(record.metadata_json.is_some());

    // Verify metadata contains hash_type and address_type
    let metadata = record.metadata_json.as_ref().unwrap();
    assert!(metadata.contains("hash_type"));
    assert!(metadata.contains("address_type"));
    assert!(metadata.contains("passphrase_hash"));

    Ok(())
}

#[test]
fn test_dry_run_mode() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let wordlist_path = temp_dir.path().join("test_passwords.txt");
    let db_path = temp_dir.path().join("test_dry_run.db");

    // Create test wordlist
    let mut file = File::create(&wordlist_path)?;
    writeln!(file, "password")?;
    writeln!(file, "test")?;
    drop(file);

    // Run in dry-run mode
    let stats = run_import(
        wordlist_path.to_str().unwrap(),
        Some(db_path.clone()),
        HashType::Sha256 { iterations: 1 },
        AddressType::P2pkhCompressed,
        true, // dry_run = true
    )?;

    // Verify statistics
    assert_eq!(stats.total_processed, 2);
    assert_eq!(stats.stored_addresses, 0, "Dry run should not store anything");

    // Verify database was not created
    assert!(!db_path.exists(), "Database should not be created in dry-run mode");

    Ok(())
}

#[test]
fn test_duplicate_detection() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let wordlist_path = temp_dir.path().join("test_duplicates.txt");
    let db_path = temp_dir.path().join("test_duplicates.db");

    // Create wordlist with duplicates
    let mut file = File::create(&wordlist_path)?;
    writeln!(file, "password")?;
    writeln!(file, "test")?;
    writeln!(file, "password")?; // Duplicate
    writeln!(file, "test")?; // Duplicate
    writeln!(file, "unique")?;
    drop(file);

    // Run import
    let stats = run_import(
        wordlist_path.to_str().unwrap(),
        Some(db_path.clone()),
        HashType::Sha256 { iterations: 1 },
        AddressType::P2pkhCompressed,
        false,
    )?;

    // Verify statistics
    assert_eq!(stats.total_processed, 5, "Should process all 5 lines");
    assert_eq!(stats.duplicates_skipped, 2, "Should skip 2 duplicates");
    assert_eq!(stats.stored_addresses, 3, "Should store 3 unique addresses");

    // Verify database
    let db = TargetDatabase::new(db_path)?;
    let targets = db.query_by_class("brainwallet", 100)?;
    assert_eq!(targets.len(), 3, "Database should have 3 unique records");

    Ok(())
}

#[test]
fn test_empty_lines_and_comments() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let wordlist_path = temp_dir.path().join("test_comments.txt");
    let db_path = temp_dir.path().join("test_comments.db");

    // Create wordlist with empty lines and comments
    let mut file = File::create(&wordlist_path)?;
    writeln!(file, "# This is a comment")?;
    writeln!(file, "password")?;
    writeln!(file, "")?; // Empty line
    writeln!(file, "  ")?; // Whitespace only
    writeln!(file, "test")?;
    writeln!(file, "# Another comment")?;
    writeln!(file, "valid")?;
    drop(file);

    // Run import
    let stats = run_import(
        wordlist_path.to_str().unwrap(),
        Some(db_path.clone()),
        HashType::Sha256 { iterations: 1 },
        AddressType::P2pkhCompressed,
        false,
    )?;

    // Should only process valid passphrases
    assert_eq!(stats.stored_addresses, 3, "Should store 3 valid passphrases");

    Ok(())
}

#[test]
fn test_gzip_decompression() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let wordlist_path = temp_dir.path().join("test_passwords.txt.gz");
    let db_path = temp_dir.path().join("test_gzip.db");

    // Create gzip-compressed wordlist
    let file = File::create(&wordlist_path)?;
    let mut encoder = GzEncoder::new(file, Compression::default());
    writeln!(encoder, "password")?;
    writeln!(encoder, "hashcat")?;
    writeln!(encoder, "satoshi")?;
    writeln!(encoder, "bitcoin")?;
    writeln!(encoder, "test123")?;
    encoder.finish()?;

    // Run import on gzipped file
    let stats = run_import(
        wordlist_path.to_str().unwrap(),
        Some(db_path.clone()),
        HashType::Sha256 { iterations: 1 },
        AddressType::P2pkhCompressed,
        false,
    )?;

    // Verify statistics
    assert_eq!(stats.total_processed, 5, "Should process 5 passphrases from gzipped file");
    assert_eq!(stats.stored_addresses, 5, "Should store 5 addresses");
    assert_eq!(stats.duplicates_skipped, 0, "No duplicates in test set");

    // Verify database contents
    let db = TargetDatabase::new(db_path)?;
    let targets = db.query_by_class("brainwallet", 100)?;
    assert_eq!(targets.len(), 5, "Database should contain 5 records from gzipped file");

    Ok(())
}

#[test]
fn test_sha256_1000x_hash_type() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let wordlist_path = temp_dir.path().join("test_passwords.txt");
    let db_path = temp_dir.path().join("test_sha256_1000x.db");

    // Create test wordlist
    let mut file = File::create(&wordlist_path)?;
    writeln!(file, "password")?;
    writeln!(file, "test")?;
    drop(file);

    // Run import with SHA256-1000x
    let stats = run_import(
        wordlist_path.to_str().unwrap(),
        Some(db_path.clone()),
        HashType::Sha256 { iterations: 1000 },
        AddressType::P2pkhCompressed,
        false,
    )?;

    // Verify statistics
    assert_eq!(stats.total_processed, 2);
    assert_eq!(stats.stored_addresses, 2);

    // Verify database
    let db = TargetDatabase::new(db_path)?;
    let targets = db.query_by_class("brainwallet", 100)?;
    assert_eq!(targets.len(), 2);

    // Verify metadata contains correct hash type
    let metadata = targets[0].metadata_json.as_ref().unwrap();
    assert!(metadata.contains("Sha256") && metadata.contains("1000"));

    Ok(())
}

#[test]
fn test_sha3_256_hash_type() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let wordlist_path = temp_dir.path().join("test_passwords.txt");
    let db_path = temp_dir.path().join("test_sha3.db");

    // Create test wordlist
    let mut file = File::create(&wordlist_path)?;
    writeln!(file, "password")?;
    writeln!(file, "hashcat")?;
    drop(file);

    // Run import with SHA3-256
    let stats = run_import(
        wordlist_path.to_str().unwrap(),
        Some(db_path.clone()),
        HashType::Sha3_256,
        AddressType::P2pkhCompressed,
        false,
    )?;

    // Verify statistics
    assert_eq!(stats.total_processed, 2);
    assert_eq!(stats.stored_addresses, 2);

    // Verify database
    let db = TargetDatabase::new(db_path)?;
    let targets = db.query_by_class("brainwallet", 100)?;
    assert_eq!(targets.len(), 2);

    // Verify metadata contains SHA3
    let metadata = targets[0].metadata_json.as_ref().unwrap();
    assert!(metadata.contains("Sha3_256"));

    Ok(())
}

#[test]
fn test_p2wpkh_address_type() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let wordlist_path = temp_dir.path().join("test_passwords.txt");
    let db_path = temp_dir.path().join("test_p2wpkh.db");

    // Create test wordlist
    let mut file = File::create(&wordlist_path)?;
    writeln!(file, "password")?;
    drop(file);

    // Run import with P2WPKH (bech32)
    let stats = run_import(
        wordlist_path.to_str().unwrap(),
        Some(db_path.clone()),
        HashType::Sha256 { iterations: 1 },
        AddressType::P2wpkh,
        false,
    )?;

    // Verify statistics
    assert_eq!(stats.total_processed, 1);
    assert_eq!(stats.stored_addresses, 1);

    // Verify database
    let db = TargetDatabase::new(db_path)?;
    let targets = db.query_by_class("brainwallet", 100)?;
    assert_eq!(targets.len(), 1);

    // Verify address starts with bc1q (P2WPKH bech32)
    assert!(targets[0].address.starts_with("bc1q"), "P2WPKH address should start with bc1q");

    // Verify metadata
    let metadata = targets[0].metadata_json.as_ref().unwrap();
    assert!(metadata.contains("P2wpkh"));

    Ok(())
}

#[test]
fn test_p2shwpkh_address_type() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let wordlist_path = temp_dir.path().join("test_passwords.txt");
    let db_path = temp_dir.path().join("test_p2shwpkh.db");

    // Create test wordlist
    let mut file = File::create(&wordlist_path)?;
    writeln!(file, "password")?;
    drop(file);

    // Run import with P2SH-P2WPKH
    let stats = run_import(
        wordlist_path.to_str().unwrap(),
        Some(db_path.clone()),
        HashType::Sha256 { iterations: 1 },
        AddressType::P2shP2wpkh,
        false,
    )?;

    // Verify statistics
    assert_eq!(stats.total_processed, 1);
    assert_eq!(stats.stored_addresses, 1);

    // Verify database
    let db = TargetDatabase::new(db_path)?;
    let targets = db.query_by_class("brainwallet", 100)?;
    assert_eq!(targets.len(), 1);

    // Verify address starts with 3 (P2SH)
    assert!(targets[0].address.starts_with('3'), "P2SH-P2WPKH address should start with 3");

    // Verify metadata
    let metadata = targets[0].metadata_json.as_ref().unwrap();
    assert!(metadata.contains("P2shP2wpkh"));

    Ok(())
}
