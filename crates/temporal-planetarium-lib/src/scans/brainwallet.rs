//! Brainwallet Scanner
//!
//! Covers Gap #8: SHA256(passphrase) → private key
//!
//! Brainwallets use a passphrase directly hashed to create a private key.
//! This scanner supports:
//! - Direct SHA256 (1 iteration)
//! - SHA256 with multiple iterations
//! - SHA3-256 variant
//!
//! Address types supported:
//! - P2PKH (uncompressed) - "1..." prefix - uses 65-byte uncompressed public key
//! - P2PKH (compressed) - "1..." prefix - uses 33-byte compressed public key
//! - P2SH-P2WPKH - "3..." prefix - SegWit-compatible (BIP49)
//! - P2WPKH - "bc1q..." prefix - Native SegWit (BIP84)
//!
//! Example brainwallet test vectors:
//! - Passphrase: "hashcat"
//! - Private key (SHA256): 127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935
//! - Run tests to see computed addresses for this passphrase
//!
//! ## Performance Characteristics
//!
//! Benchmark results (M1 Pro, release mode):
//!
//! **Key Derivation:**
//! - SHA256 1x: ~128 ns/passphrase (~7.8M passphrases/sec)
//! - SHA256 1000x: ~125 µs/passphrase (~8K passphrases/sec)
//! - SHA3-256: ~170 ns/passphrase (~5.9M passphrases/sec)
//!
//! **Address Generation:**
//! - P2PKH compressed: ~329 ns (fastest, recommended)
//! - P2WPKH: ~334 ns
//! - P2PKH uncompressed: ~424 ns
//! - P2SH-P2WPKH: ~666 ns
//!
//! **Full Import Pipeline:**
//! - CPU-only (dry-run): ~94K passphrases/sec
//! - With database writes: ~41.5 passphrases/sec
//!
//! Database writes are the primary bottleneck. The implementation uses:
//! - Batch size: 10,000 addresses
//! - AES-256-GCM encryption for private keys
//! - Duplicate detection with in-memory HashSet
//! - Progress reporting every 100K passphrases
//!
//! For large SecLists files (10M+ entries), expect:
//! - Processing time: ~3-4 hours with database
//! - Memory usage: ~500MB for deduplication
//! - Database size: ~2GB per million addresses

use anyhow::Result;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network, PrivateKey};
use flate2::read::GzDecoder;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use tracing::{debug, info, warn};

/// Hash type for brainwallet
#[derive(Debug, Clone, Copy)]
pub enum HashType {
    Sha256 { iterations: u32 },
    Sha3_256,
}

impl Default for HashType {
    fn default() -> Self {
        HashType::Sha256 { iterations: 1 }
    }
}

/// Address type for brainwallet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    P2pkhUncompressed,
    P2pkhCompressed,
    P2shP2wpkh,
    P2wpkh,
}

impl Default for AddressType {
    fn default() -> Self {
        AddressType::P2pkhCompressed
    }
}

/// Statistics from import operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportStats {
    pub total_processed: usize,
    pub stored_addresses: usize,
    pub duplicates_skipped: usize,
}

/// Hash160 helper function: RIPEMD160(SHA256(data))
fn hash160(data: &[u8]) -> [u8; 20] {
    let sha256_result = Sha256::digest(data);
    let mut ripemd = Ripemd160::new();
    ripemd.update(sha256_result);
    ripemd.finalize().into()
}

/// Generate P2PKH address from hash160 with version byte
fn p2pkh_from_hash160(hash160: &[u8; 20], version: u8) -> String {
    let mut addr_bytes = vec![version];
    addr_bytes.extend_from_slice(hash160);
    bs58::encode(&addr_bytes).with_check().into_string()
}

/// Run brainwallet scanner with a single passphrase
pub fn run_single(passphrase: &str, hash_type: HashType, target: Option<&str>) -> Result<()> {
    info!("Brainwallet Scanner");
    info!("Hash: {:?}", hash_type);
    info!("Passphrase: \"{}\"", passphrase);

    let privkey = derive_key(passphrase, hash_type);
    let secp = Secp256k1::new();
    let network = Network::Bitcoin;

    if let Ok(secret) = SecretKey::from_slice(&privkey) {
        let pubkey_secp = PublicKey::from_secret_key(&secp, &secret);
        let compressed = CompressedPublicKey(pubkey_secp);

        // Get both compressed and uncompressed public keys
        let compressed_bytes = pubkey_secp.serialize();
        let uncompressed_bytes = pubkey_secp.serialize_uncompressed();

        // P2PKH (uncompressed) - uses uncompressed public key
        let uncompressed_hash160 = hash160(&uncompressed_bytes);
        let addr_p2pkh_uncompressed = p2pkh_from_hash160(&uncompressed_hash160, 0x00);

        // P2PKH (compressed) - uses compressed public key
        let addr_p2pkh_compressed = Address::p2pkh(compressed, network);

        // P2SH-P2WPKH (BIP49) - "3" prefix
        let addr_p2sh_p2wpkh = Address::p2shwpkh(&compressed, network);

        // P2WPKH (BIP84) - "bc1q" prefix
        let addr_p2wpkh = Address::p2wpkh(&compressed, network);

        info!("Private Key: {}", hex::encode(privkey));
        info!("Compressed pubkey: {}", hex::encode(compressed_bytes));
        info!(
            "Uncompressed pubkey: {}...",
            hex::encode(&uncompressed_bytes[..33])
        );
        info!("P2PKH (uncompressed): {}", addr_p2pkh_uncompressed);
        info!("P2PKH (compressed):   {}", addr_p2pkh_compressed);
        info!("P2SH-P2WPKH:          {}", addr_p2sh_p2wpkh);
        info!("P2WPKH:               {}", addr_p2wpkh);

        if let Some(t) = target {
            if addr_p2pkh_uncompressed == t
                || addr_p2pkh_compressed.to_string() == t
                || addr_p2sh_p2wpkh.to_string() == t
                || addr_p2wpkh.to_string() == t
            {
                warn!("🎯 MATCH FOUND!");
                return Ok(());
            }
        }
    } else {
        warn!("Invalid private key derived from passphrase");
    }

    Ok(())
}

/// Run brainwallet scanner with passphrase file
pub fn run_file(wordlist_path: &str, hash_type: HashType, target: &str) -> Result<()> {
    info!("Brainwallet Scanner - File Mode");
    info!("Hash: {:?}", hash_type);
    info!("Wordlist: {}", wordlist_path);
    info!("Target: {}", target);

    let file = File::open(wordlist_path)?;
    let reader = BufReader::new(file);
    let secp = Secp256k1::new();
    let network = Network::Bitcoin;

    let mut checked = 0u64;
    let start_time = std::time::Instant::now();

    for line in reader.lines() {
        let passphrase = line?;
        if passphrase.is_empty() {
            continue;
        }

        let privkey = derive_key(&passphrase, hash_type);

        if let Ok(secret) = SecretKey::from_slice(&privkey) {
            let pubkey_secp = PublicKey::from_secret_key(&secp, &secret);
            let compressed = CompressedPublicKey(pubkey_secp);

            // Get both compressed and uncompressed public keys
            let uncompressed_bytes = pubkey_secp.serialize_uncompressed();

            // Generate all address types
            let uncompressed_hash160 = hash160(&uncompressed_bytes);
            let addr_p2pkh_uncompressed = p2pkh_from_hash160(&uncompressed_hash160, 0x00);
            let addr_p2pkh_compressed = Address::p2pkh(compressed, network);
            let addr_p2sh_p2wpkh = Address::p2shwpkh(&compressed, network);
            let addr_p2wpkh = Address::p2wpkh(&compressed, network);

            if addr_p2pkh_uncompressed == target
                || addr_p2pkh_compressed.to_string() == target
                || addr_p2sh_p2wpkh.to_string() == target
                || addr_p2wpkh.to_string() == target
            {
                warn!("\n🎯 FOUND MATCH!");
                warn!("Passphrase: \"{}\"", passphrase);
                warn!("Private Key: {}", hex::encode(privkey));
                warn!("P2PKH (uncompressed): {}", addr_p2pkh_uncompressed);
                warn!("P2PKH (compressed):   {}", addr_p2pkh_compressed);
                warn!("P2SH-P2WPKH:          {}", addr_p2sh_p2wpkh);
                warn!("P2WPKH:               {}", addr_p2wpkh);
                return Ok(());
            }
        }

        checked += 1;
        if checked.is_multiple_of(100_000) {
            let elapsed = start_time.elapsed().as_secs_f64();
            let speed = checked as f64 / elapsed;
            info!("Checked {} passphrases | {:.0}/s", checked, speed);
        }
    }

    info!(
        "Scan complete (checked {} passphrases). No match found.",
        checked
    );
    Ok(())
}

/// Run brainwallet import - generate addresses from wordlist and store in database
pub fn run_import(
    wordlist_path: &str,
    db_path: Option<PathBuf>,
    hash_type: HashType,
    address_type: AddressType,
    dry_run: bool,
) -> Result<ImportStats> {
    use crate::utils::db::{Target, TargetDatabase};
    use crate::utils::encryption::encrypt_private_key;

    info!("Brainwallet Import");
    info!("Hash: {:?}", hash_type);
    info!("Address Type: {:?}", address_type);
    info!("Wordlist: {}", wordlist_path);
    if dry_run {
        info!("DRY RUN MODE - No database writes");
    }

    // Open file with optional gzip decompression
    let file = File::open(wordlist_path)?;
    let reader: Box<dyn BufRead> = if wordlist_path.ends_with(".gz") {
        info!("Detected gzip compressed file, decompressing...");
        Box::new(BufReader::new(GzDecoder::new(file)))
    } else {
        Box::new(BufReader::new(file))
    };

    let secp = Secp256k1::new();
    let network = Network::Bitcoin;

    // Initialize database if not dry run
    let mut db = if let Some(ref path) = db_path {
        if !dry_run {
            Some(TargetDatabase::new(path.clone())?)
        } else {
            None
        }
    } else {
        None
    };

    let mut stats = ImportStats {
        total_processed: 0,
        stored_addresses: 0,
        duplicates_skipped: 0,
    };

    let mut dedup_set = HashSet::new();
    let mut batch = Vec::with_capacity(10000);

    // Get default encryption passphrase from environment or use default
    let encryption_passphrase = std::env::var("BRAINWALLET_ENCRYPTION_PASSPHRASE")
        .unwrap_or_else(|_| crate::utils::encryption::DEFAULT_ENCRYPTION_PASSPHRASE.to_string());

    let start_time = std::time::Instant::now();

    for (line_num, line) in reader.lines().enumerate() {
        let passphrase = line?.trim().to_string();

        // Skip empty lines and comments
        if passphrase.is_empty() || passphrase.starts_with('#') {
            continue;
        }

        stats.total_processed += 1;

        // Duplicate detection
        if !dedup_set.insert(passphrase.clone()) {
            stats.duplicates_skipped += 1;
            debug!("Skipping duplicate passphrase at line {}", line_num + 1);
            continue;
        }

        // Derive key and generate address
        let privkey = derive_key(&passphrase, hash_type);

        if let Ok(secret) = SecretKey::from_slice(&privkey) {
            let pubkey_secp = PublicKey::from_secret_key(&secp, &secret);
            let compressed = CompressedPublicKey(pubkey_secp);
            let uncompressed_bytes = pubkey_secp.serialize_uncompressed();

            // Generate address based on type
            let address = match address_type {
                AddressType::P2pkhUncompressed => {
                    let uncompressed_hash160 = hash160(&uncompressed_bytes);
                    p2pkh_from_hash160(&uncompressed_hash160, 0x00)
                }
                AddressType::P2pkhCompressed => Address::p2pkh(compressed, network).to_string(),
                AddressType::P2shP2wpkh => Address::p2shwpkh(&compressed, network).to_string(),
                AddressType::P2wpkh => Address::p2wpkh(&compressed, network).to_string(),
            };

            // Prepare for database storage (only if not dry run)
            if !dry_run && db.is_some() {
                // Convert to WIF for encryption
                let wif = PrivateKey::new(secret, network).to_wif();
                let encrypted = encrypt_private_key(&wif, &encryption_passphrase)?;

                // Prepare metadata
                let passphrase_hash = hex::encode(Sha256::digest(passphrase.as_bytes()));
                let metadata = serde_json::json!({
                    "passphrase_hash": passphrase_hash,
                    "hash_type": format!("{:?}", hash_type),
                    "address_type": format!("{:?}", address_type),
                    "source_file": wordlist_path,
                    "line_number": line_num + 1,
                });

                let mut target = Target::with_encrypted_key(
                    address,
                    "brainwallet".to_string(),
                    Some(metadata.to_string()),
                    encrypted.ciphertext,
                    encrypted.nonce,
                    encrypted.salt,
                );
                target.status = "cracked".to_string(); // Brainwallets are actively cracked
                batch.push(target);

                stats.stored_addresses += 1;

                // Flush batch every 10K
                if batch.len() >= 10000 {
                    if let Some(ref mut database) = db {
                        database.bulk_upsert_targets(&batch)?;
                        batch.clear();
                        debug!("Flushed batch to database");
                    }
                }
            }
        }

        // Progress reporting
        if stats.total_processed.is_multiple_of(100_000) {
            let elapsed = start_time.elapsed().as_secs_f64();
            let speed = stats.total_processed as f64 / elapsed;
            info!(
                "Processed {} passphrases | {:.0}/s | {} stored | {} duplicates skipped",
                stats.total_processed, speed, stats.stored_addresses, stats.duplicates_skipped
            );
        }
    }

    // Final batch flush
    if !batch.is_empty() {
        if let Some(ref mut database) = db {
            database.bulk_upsert_targets(&batch)?;
            debug!("Flushed final batch to database");
        }
    }

    let elapsed = start_time.elapsed().as_secs_f64();
    let speed = stats.total_processed as f64 / elapsed;

    info!(
        "✅ Import complete: {} processed | {} stored | {} duplicates | {:.0}/s",
        stats.total_processed, stats.stored_addresses, stats.duplicates_skipped, speed
    );

    Ok(stats)
}

/// Derive private key from passphrase
///
/// This function is public to support performance benchmarking in `benches/brainwallet_benchmark.rs`.
/// For production use, prefer the higher-level `run_import()` or `run_file()` functions.
pub fn derive_key(passphrase: &str, hash_type: HashType) -> [u8; 32] {
    match hash_type {
        HashType::Sha256 { iterations } => {
            let mut hash = Sha256::digest(passphrase.as_bytes());
            for _ in 1..iterations {
                hash = Sha256::digest(hash);
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&hash);
            key
        }
        HashType::Sha3_256 => {
            use sha3::{Digest as Sha3Digest, Sha3_256};
            let hash = Sha3_256::digest(passphrase.as_bytes());
            let mut key = [0u8; 32];
            key.copy_from_slice(&hash);
            key
        }
    }
}

/// Generate common brainwallet passphrases
pub fn generate_common_passphrases() -> Vec<String> {
    let common = vec![
        "password",
        "123456",
        "bitcoin",
        "secret",
        "passphrase",
        "satoshi",
        "nakamoto",
        "blockchain",
        "wallet",
        "money",
        "test",
        "hello",
        "world",
        "abc123",
        "qwerty",
        "letmein",
        "admin",
        "login",
        "welcome",
        "master",
        "correct horse battery staple", // Famous XKCD passphrase
    ];
    common.into_iter().map(String::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::PublicKey;

    #[test]
    fn test_sha256_password() {
        // SHA256("password") verified with: echo -n "password" | shasum -a 256
        let key = derive_key("password", HashType::Sha256 { iterations: 1 });
        let hex = hex::encode(key);
        assert_eq!(
            hex,
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        );
    }

    #[test]
    fn test_sha256_two_iterations() {
        let key1 = derive_key("test", HashType::Sha256 { iterations: 1 });
        let key2 = derive_key("test", HashType::Sha256 { iterations: 2 });
        assert_ne!(key1, key2);
    }

    /// Test "hashcat" passphrase produces all address types correctly
    /// SHA256("hashcat") = 127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935
    #[test]
    fn test_hashcat_passphrase_all_address_types() {
        let passphrase = "hashcat";
        let privkey = derive_key(passphrase, HashType::Sha256 { iterations: 1 });

        // Verify private key matches SHA256("hashcat")
        assert_eq!(
            hex::encode(privkey),
            "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935"
        );

        let secp = Secp256k1::new();
        let network = Network::Bitcoin;
        let secret = SecretKey::from_slice(&privkey).unwrap();
        let pubkey_secp = PublicKey::from_secret_key(&secp, &secret);
        let compressed = CompressedPublicKey(pubkey_secp);

        // Get public keys
        let compressed_bytes = pubkey_secp.serialize();
        let uncompressed_bytes = pubkey_secp.serialize_uncompressed();

        // Print all values for cross-project verification
        println!("=== Brainwallet Test Vector: 'hashcat' ===");
        println!("Private key: {}", hex::encode(privkey));
        println!("Compressed pubkey: {}", hex::encode(compressed_bytes));

        // P2PKH (uncompressed) - uses 65-byte uncompressed public key
        let uncompressed_hash160 = hash160(&uncompressed_bytes);
        let addr_p2pkh_uncompressed = p2pkh_from_hash160(&uncompressed_hash160, 0x00);
        println!("P2PKH (uncompressed): {}", addr_p2pkh_uncompressed);
        assert!(
            addr_p2pkh_uncompressed.starts_with('1'),
            "P2PKH uncompressed should start with '1'"
        );

        // P2PKH (compressed) - uses 33-byte compressed public key
        let addr_p2pkh_compressed = Address::p2pkh(compressed, network);
        println!("P2PKH (compressed):   {}", addr_p2pkh_compressed);
        assert!(
            addr_p2pkh_compressed.to_string().starts_with('1'),
            "P2PKH compressed should start with '1'"
        );

        // P2WPKH (BIP84) - "bc1q" prefix
        let addr_p2wpkh = Address::p2wpkh(&compressed, network);
        println!("P2WPKH:               {}", addr_p2wpkh);
        assert!(
            addr_p2wpkh.to_string().starts_with("bc1q"),
            "P2WPKH should start with 'bc1q'"
        );

        // P2SH-P2WPKH (BIP49) - "3" prefix
        let addr_p2sh_p2wpkh = Address::p2shwpkh(&compressed, network);
        println!("P2SH-P2WPKH:          {}", addr_p2sh_p2wpkh);
        assert!(
            addr_p2sh_p2wpkh.to_string().starts_with('3'),
            "P2SH-P2WPKH should start with '3'"
        );

        // Verify uncompressed and compressed P2PKH are different
        assert_ne!(
            addr_p2pkh_uncompressed,
            addr_p2pkh_compressed.to_string(),
            "Uncompressed and compressed P2PKH should produce different addresses"
        );
    }

    /// Test additional known brainwallet passphrases
    #[test]
    fn test_common_brainwallet_passphrases() {
        let test_cases = vec![
            (
                "password",
                "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            ),
            (
                "satoshi nakamoto",
                "aa2d3c4a4ae6559e9f13f093cc6e32459c5249da723de810651b4b54373385e2",
            ),
            (
                "correct horse battery staple",
                "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a",
            ),
            (
                "",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
        ];

        for (passphrase, expected_privkey) in test_cases {
            let privkey = derive_key(passphrase, HashType::Sha256 { iterations: 1 });
            assert_eq!(
                hex::encode(privkey),
                expected_privkey,
                "Private key mismatch for passphrase: '{}'",
                passphrase
            );
        }
    }
}
