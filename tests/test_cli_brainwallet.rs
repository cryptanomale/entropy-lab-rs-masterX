// CLI Integration Tests for Brainwallet Import Command
//
// Tests the full CLI binary end-to-end

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::io::Write;
use tempfile::TempDir;
use temporal_planetarium_lib::utils::db::TargetDatabase;

#[test]
fn test_cli_brainwallet_import_help() {
    let mut cmd = Command::cargo_bin("temporal-planetarium-cli").unwrap();
    cmd.arg("brainwallet-import").arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Import brainwallet dictionary"));
}

#[test]
fn test_cli_brainwallet_import_basic() {
    let temp_dir = TempDir::new().unwrap();
    let wordlist_path = temp_dir.path().join("test_passwords.txt");
    let db_path = temp_dir.path().join("test.db");

    // Create test wordlist
    let mut file = fs::File::create(&wordlist_path).unwrap();
    writeln!(file, "password").unwrap();
    writeln!(file, "hashcat").unwrap();
    writeln!(file, "satoshi").unwrap();
    drop(file);

    // Run CLI
    let mut cmd = Command::cargo_bin("temporal-planetarium-cli").unwrap();
    cmd.arg("brainwallet-import")
        .arg("--wordlist")
        .arg(&wordlist_path)
        .arg("--db-path")
        .arg(&db_path)
        .arg("--hash-type")
        .arg("sha256")
        .arg("--address-type")
        .arg("p2pkh");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Import Complete"))
        .stdout(predicate::str::contains("Total Processed:     3"))
        .stdout(predicate::str::contains("Stored Addresses:    3"));

    // Verify database was created
    assert!(db_path.exists(), "Database file should exist");

    // Verify contents
    let db = TargetDatabase::new(db_path).unwrap();
    let targets = db.query_by_class("brainwallet", 10).unwrap();
    assert_eq!(targets.len(), 3, "Should have 3 addresses in database");
}

#[test]
fn test_cli_brainwallet_import_dry_run() {
    let temp_dir = TempDir::new().unwrap();
    let wordlist_path = temp_dir.path().join("test_passwords.txt");
    let db_path = temp_dir.path().join("test_dry_run.db");

    // Create test wordlist
    let mut file = fs::File::create(&wordlist_path).unwrap();
    writeln!(file, "password").unwrap();
    writeln!(file, "test").unwrap();
    drop(file);

    // Run CLI with --dry-run
    let mut cmd = Command::cargo_bin("temporal-planetarium-cli").unwrap();
    cmd.arg("brainwallet-import")
        .arg("--wordlist")
        .arg(&wordlist_path)
        .arg("--db-path")
        .arg(&db_path)
        .arg("--hash-type")
        .arg("sha256")
        .arg("--address-type")
        .arg("p2pkh")
        .arg("--dry-run");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("DRY RUN MODE"))
        .stdout(predicate::str::contains("This was a dry run"));

    // Verify database was NOT created
    assert!(!db_path.exists(), "Database should not exist in dry-run mode");
}

#[test]
fn test_cli_brainwallet_import_gzip() {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let temp_dir = TempDir::new().unwrap();
    let wordlist_path = temp_dir.path().join("test_passwords.txt.gz");
    let db_path = temp_dir.path().join("test.db");

    // Create gzipped wordlist with explicit flush and sync
    {
        let file = fs::File::create(&wordlist_path).unwrap();
        let mut encoder = GzEncoder::new(file, Compression::default());
        writeln!(encoder, "password").unwrap();
        writeln!(encoder, "hashcat").unwrap();
        let mut file = encoder.finish().unwrap();
        file.sync_all().unwrap(); // Ensure data is written to disk
        drop(file); // Explicitly close file
    }

    // Add small delay to ensure filesystem consistency
    std::thread::sleep(std::time::Duration::from_millis(10));

    // Run CLI
    let mut cmd = Command::cargo_bin("temporal-planetarium-cli").unwrap();
    cmd.arg("brainwallet-import")
        .arg("--wordlist")
        .arg(&wordlist_path)
        .arg("--db-path")
        .arg(&db_path)
        .arg("--hash-type")
        .arg("sha256")
        .arg("--address-type")
        .arg("p2pkh");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Total Processed:     2"))
        .stdout(predicate::str::contains("Stored Addresses:    2"));
}

#[test]
fn test_cli_brainwallet_import_invalid_hash_type() {
    let temp_dir = TempDir::new().unwrap();
    let wordlist_path = temp_dir.path().join("test.txt");
    let db_path = temp_dir.path().join("test.db");

    // Create minimal wordlist
    fs::write(&wordlist_path, "password\n").unwrap();

    // Run CLI with invalid hash type
    let mut cmd = Command::cargo_bin("temporal-planetarium-cli").unwrap();
    cmd.arg("brainwallet-import")
        .arg("--wordlist")
        .arg(&wordlist_path)
        .arg("--db-path")
        .arg(&db_path)
        .arg("--hash-type")
        .arg("invalid-hash")
        .arg("--address-type")
        .arg("p2pkh");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Invalid hash type"));
}

#[test]
fn test_cli_brainwallet_import_invalid_address_type() {
    let temp_dir = TempDir::new().unwrap();
    let wordlist_path = temp_dir.path().join("test.txt");
    let db_path = temp_dir.path().join("test.db");

    // Create minimal wordlist
    fs::write(&wordlist_path, "password\n").unwrap();

    // Run CLI with invalid address type
    let mut cmd = Command::cargo_bin("temporal-planetarium-cli").unwrap();
    cmd.arg("brainwallet-import")
        .arg("--wordlist")
        .arg(&wordlist_path)
        .arg("--db-path")
        .arg(&db_path)
        .arg("--hash-type")
        .arg("sha256")
        .arg("--address-type")
        .arg("invalid-address");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Invalid address type"));
}

#[test]
fn test_cli_brainwallet_import_missing_file() {
    let temp_dir = TempDir::new().unwrap();
    let wordlist_path = temp_dir.path().join("nonexistent.txt");
    let db_path = temp_dir.path().join("test.db");

    // Run CLI with missing file
    let mut cmd = Command::cargo_bin("temporal-planetarium-cli").unwrap();
    cmd.arg("brainwallet-import")
        .arg("--wordlist")
        .arg(&wordlist_path)
        .arg("--db-path")
        .arg(&db_path)
        .arg("--hash-type")
        .arg("sha256")
        .arg("--address-type")
        .arg("p2pkh");

    cmd.assert().failure();
}
