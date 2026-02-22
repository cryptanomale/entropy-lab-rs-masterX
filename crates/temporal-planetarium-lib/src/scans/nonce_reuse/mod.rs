//! ECDSA Nonce Reuse Scanner Module
//!
//! This module provides on-chain detection of ECDSA nonce reuse vulnerabilities.
//! When two signatures share the same `r` value but different `s` values,
//! the private key can be mathematically recovered.
//!
//! ## Components
//!
//! - `NonceCrawler`: Scans blockchain blocks for R-value collisions
//! - `RValueIndex`: In-memory index for detecting duplicate R-values
//! - `RecoveryEngine`: Integrates with forensics.rs for key recovery
//!
//! ## Usage
//!
//! ```no_run
//! use temporal_planetarium_lib::scans::nonce_reuse::{NonceCrawler, CrawlerConfig};
//! use std::path::PathBuf;
//!
//! let config = CrawlerConfig::default();
//! let mut crawler = NonceCrawler::new(config)?;
//! crawler.scan_range(800000, 800100)?;
//! # Ok::<(), anyhow::Error>(())
//! ```

use anyhow::{Context, Result};
use bitcoin::{Block, Transaction};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, info, warn};

use crate::scans::randstorm::forensics::recover_privkey_from_nonce_reuse;
use crate::utils::db::{Target, TargetDatabase};
use crate::utils::encryption::{encrypt_private_key, EncryptedData, DEFAULT_ENCRYPTION_PASSPHRASE};

/// Signature data extracted from a transaction input
#[derive(Debug, Clone)]
pub struct SignatureData {
    /// The r-value (32 bytes)
    pub r: [u8; 32],
    /// The s-value (32 bytes)
    pub s: [u8; 32],
    /// Message hash (sighash) - only available if prevout is fetched
    pub z: Option<[u8; 32]>,
    /// Transaction ID containing this signature
    pub txid: String,
    /// Input index
    pub vin: usize,
    /// Derived Bitcoin address (P2PKH)
    pub address: String,
    /// Block height where this signature was found
    pub block_height: u64,
    /// Raw public key if available
    pub pubkey: Option<Vec<u8>>,
}

/// Configuration for the nonce reuse crawler
#[derive(Debug, Clone)]
pub struct CrawlerConfig {
    /// RPC host (default: 127.0.0.1)
    pub rpc_host: String,
    /// RPC port (default: 8332)
    pub rpc_port: u16,
    /// RPC username
    pub rpc_user: String,
    /// RPC password
    pub rpc_pass: String,
    /// Database path for storing findings
    pub db_path: PathBuf,
    /// Encryption passphrase for private keys
    pub passphrase: String,
    /// Enable prevout fetching for full key recovery (slower, requires txindex)
    pub fetch_prevouts: bool,
    /// Checkpoint file path for resume capability
    pub checkpoint_path: Option<PathBuf>,
    /// Number of blocks between checkpoints
    pub checkpoint_interval: u64,
    /// Rate limit delay between blocks in milliseconds (0 = no limit)
    pub rate_limit_ms: u64,
}

impl Default for CrawlerConfig {
    fn default() -> Self {
        Self {
            rpc_host: "127.0.0.1".to_string(),
            rpc_port: 8332,
            rpc_user: "user".to_string(),
            rpc_pass: "pass".to_string(),
            db_path: PathBuf::from("nonce_reuse.db"),
            passphrase: DEFAULT_ENCRYPTION_PASSPHRASE.to_string(),
            fetch_prevouts: false,
            checkpoint_path: None,
            checkpoint_interval: 100,
            rate_limit_ms: 50, // 50ms default to avoid overwhelming RPC
        }
    }
}

/// Statistics for the crawler run
#[derive(Debug, Default)]
pub struct CrawlerStats {
    /// Total blocks scanned
    pub blocks_scanned: u64,
    /// Total transactions processed
    pub transactions_processed: u64,
    /// Total signatures parsed
    pub signatures_parsed: u64,
    /// Number of R-value collisions detected
    pub collisions_detected: u64,
    /// Number of private keys recovered
    pub keys_recovered: u64,
    /// Number of errors encountered
    pub errors: u64,
}

/// In-memory index for detecting R-value collisions
struct RValueIndex {
    /// Maps r-value -> first signature with this r-value
    index: HashMap<[u8; 32], SignatureData>,
}

impl RValueIndex {
    fn new() -> Self {
        Self {
            index: HashMap::new(),
        }
    }

    /// Check if an R-value already exists and return the collision if so
    fn check_and_insert(&mut self, sig: SignatureData) -> Option<SignatureData> {
        if let Some(existing) = self.index.get(&sig.r) {
            // Collision detected! Check if it's the same signature or a real collision
            if existing.txid != sig.txid || existing.vin != sig.vin {
                // Different signature with same R-value - this is a collision!
                if existing.s != sig.s {
                    // Different s-values - we can recover the key!
                    return Some(existing.clone());
                }
            }
        }
        // No collision, insert this signature
        self.index.insert(sig.r, sig);
        None
    }

    /// Get the number of unique R-values indexed
    fn len(&self) -> usize {
        self.index.len()
    }
}

/// Main nonce reuse crawler
pub struct NonceCrawler {
    config: CrawlerConfig,
    client: Client,
    db: TargetDatabase,
    r_index: RValueIndex,
    stats: CrawlerStats,
}

impl NonceCrawler {
    /// Create a new crawler with the given configuration
    pub fn new(config: CrawlerConfig) -> Result<Self> {
        let rpc_url = format!("http://{}:{}", config.rpc_host, config.rpc_port);

        let client = Client::new(
            &rpc_url,
            Auth::UserPass(config.rpc_user.clone(), config.rpc_pass.clone()),
        )
        .context("Failed to connect to Bitcoin Core RPC")?;

        let db = TargetDatabase::new(config.db_path.clone())
            .context("Failed to initialize database")?;

        Ok(Self {
            config,
            client,
            db,
            r_index: RValueIndex::new(),
            stats: CrawlerStats::default(),
        })
    }

    /// Get blockchain info from the RPC node
    pub fn get_blockchain_info(&self) -> Result<bitcoincore_rpc::json::GetBlockchainInfoResult> {
        self.client.get_blockchain_info()
            .context("Failed to get blockchain info")
    }

    /// Scan a range of blocks for nonce reuse
    pub fn scan_range(&mut self, start_block: u64, end_block: u64) -> Result<CrawlerStats> {
        info!(
            start = start_block,
            end = end_block,
            "Starting nonce reuse scan"
        );

        let total_blocks = end_block - start_block + 1;
        let pb = ProgressBar::new(total_blocks);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} blocks ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );

        // Check for checkpoint
        let mut current_block = start_block;
        if let Some(ref checkpoint_path) = self.config.checkpoint_path {
            if let Ok(contents) = std::fs::read_to_string(checkpoint_path) {
                if let Ok(last_block) = contents.trim().parse::<u64>() {
                    if last_block >= start_block && last_block < end_block {
                        current_block = last_block + 1;
                        info!(resume_from = current_block, "Resuming from checkpoint");
                        pb.set_position(current_block - start_block);
                    }
                }
            }
        }

        for height in current_block..=end_block {
            match self.scan_block(height) {
                Ok(()) => {}
                Err(e) => {
                    warn!(height = height, error = %e, "Error scanning block");
                    self.stats.errors += 1;
                }
            }

            self.stats.blocks_scanned += 1;
            pb.inc(1);

            // Save checkpoint
            if let Some(ref checkpoint_path) = self.config.checkpoint_path {
                if height % self.config.checkpoint_interval == 0 {
                    if let Err(e) = std::fs::write(checkpoint_path, height.to_string()) {
                        warn!(error = %e, "Failed to save checkpoint");
                    }
                }
            }

            // Rate limiting to avoid overwhelming the RPC node
            if self.config.rate_limit_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(self.config.rate_limit_ms));
            }
        }

        pb.finish_with_message("Scan complete");

        info!(
            blocks = self.stats.blocks_scanned,
            txs = self.stats.transactions_processed,
            sigs = self.stats.signatures_parsed,
            collisions = self.stats.collisions_detected,
            keys_recovered = self.stats.keys_recovered,
            unique_r_values = self.r_index.len(),
            "Scan complete"
        );

        Ok(std::mem::take(&mut self.stats))
    }

    /// Scan a single block
    fn scan_block(&mut self, height: u64) -> Result<()> {
        let block_hash = self.client.get_block_hash(height)?;
        let block: Block = self.client.get_by_id(&block_hash)?;

        for tx in &block.txdata {
            self.process_transaction(tx, height)?;
        }

        Ok(())
    }

    /// Process a single transaction
    fn process_transaction(&mut self, tx: &Transaction, block_height: u64) -> Result<()> {
        self.stats.transactions_processed += 1;
        let txid = tx.compute_txid().to_string();

        for (vin, input) in tx.input.iter().enumerate() {
            let script = &input.script_sig;
            if script.is_empty() {
                continue;
            }

            // Try to parse DER signature from script_sig
            let bytes = script.as_bytes();

            // Look for DER signature prefix (0x30)
            if let Some(der_start) = bytes.iter().position(|&b| b == 0x30) {
                if bytes.len() > der_start + 2 {
                    let sig_len = bytes[der_start + 1] as usize;
                    if bytes.len() >= der_start + 2 + sig_len {
                        let der_sig = &bytes[der_start + 2..der_start + 2 + sig_len];

                        match parse_der_signature(der_sig) {
                            Ok((r, s)) => {
                                self.stats.signatures_parsed += 1;

                                // Try to extract public key (follows signature in P2PKH)
                                let pubkey = extract_pubkey_from_script_sig(bytes, der_start + 2 + sig_len);

                                let sig_data = SignatureData {
                                    r,
                                    s,
                                    z: None, // Would need prevout fetching
                                    txid: txid.clone(),
                                    vin,
                                    address: derive_address_from_pubkey(&pubkey),
                                    block_height,
                                    pubkey,
                                };

                                // Check for collision
                                if let Some(existing) = self.r_index.check_and_insert(sig_data.clone()) {
                                    self.handle_collision(existing, sig_data)?;
                                }
                            }
                            Err(e) => {
                                debug!(error = %e, "Failed to parse DER signature");
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle a detected R-value collision
    fn handle_collision(&mut self, sig1: SignatureData, sig2: SignatureData) -> Result<()> {
        self.stats.collisions_detected += 1;

        warn!(
            r_value = hex::encode(sig1.r),
            tx1 = sig1.txid,
            vin1 = sig1.vin,
            tx2 = sig2.txid,
            vin2 = sig2.vin,
            "NONCE REUSE DETECTED!"
        );

        // If we have z-values (message hashes), we can recover the private key
        if let (Some(z1), Some(z2)) = (sig1.z, sig2.z) {
            match recover_privkey_from_nonce_reuse(&z1, &z2, &sig1.r, &sig1.s, &sig2.s) {
                Ok(secret_key) => {
                    self.stats.keys_recovered += 1;

                    let wif = bitcoin::PrivateKey::new(secret_key, bitcoin::Network::Bitcoin).to_wif();
                    info!(
                        address = sig1.address,
                        "Private key recovered from nonce reuse!"
                    );

                    // Encrypt and store
                    let encrypted = encrypt_private_key(&wif, &self.config.passphrase)?;
                    self.store_recovered_key(&sig1, &sig2, encrypted)?;
                }
                Err(e) => {
                    warn!(error = %e, "Failed to recover private key");
                }
            }
        } else {
            // Store collision without recovered key (z-values not available)
            self.store_collision(&sig1, &sig2)?;
        }

        Ok(())
    }

    /// Store a recovered key in the database
    fn store_recovered_key(
        &self,
        sig1: &SignatureData,
        sig2: &SignatureData,
        encrypted: EncryptedData,
    ) -> Result<()> {
        let metadata = serde_json::json!({
            "r_value": hex::encode(sig1.r),
            "tx1": sig1.txid,
            "vin1": sig1.vin,
            "block1": sig1.block_height,
            "tx2": sig2.txid,
            "vin2": sig2.vin,
            "block2": sig2.block_height,
            "key_recovered": true,
        });

        let target = Target::with_encrypted_key(
            sig1.address.clone(),
            "nonce_reuse".to_string(),
            Some(metadata.to_string()),
            encrypted.ciphertext,
            encrypted.nonce,
            encrypted.salt,
        );

        self.db.upsert_target(&target)?;
        Ok(())
    }

    /// Store a collision without recovered key
    fn store_collision(&self, sig1: &SignatureData, sig2: &SignatureData) -> Result<()> {
        let metadata = serde_json::json!({
            "r_value": hex::encode(sig1.r),
            "tx1": sig1.txid,
            "vin1": sig1.vin,
            "block1": sig1.block_height,
            "tx2": sig2.txid,
            "vin2": sig2.vin,
            "block2": sig2.block_height,
            "key_recovered": false,
            "reason": "z-values not available (prevout not fetched)",
        });

        let target = Target {
            address: format!("collision-{}", hex::encode(&sig1.r[..8])),
            vuln_class: "nonce_reuse".to_string(),
            first_seen_timestamp: Some(chrono::Utc::now().timestamp()),
            metadata_json: Some(metadata.to_string()),
            status: "pending".to_string(),
            ..Default::default()
        };

        self.db.upsert_target(&target)?;
        Ok(())
    }

    /// Get current statistics
    pub fn stats(&self) -> &CrawlerStats {
        &self.stats
    }
}

/// Parse DER-encoded signature into r and s values
fn parse_der_signature(der: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    // DER format: 0x02 <r_len> <r_bytes> 0x02 <s_len> <s_bytes>
    if der.len() < 8 || der[0] != 0x02 {
        return Err(anyhow::anyhow!("Invalid DER signature"));
    }

    let r_len = der[1] as usize;
    let r_start = 2;

    if der.len() < r_start + r_len + 2 || der[r_start + r_len] != 0x02 {
        return Err(anyhow::anyhow!("Invalid DER R component"));
    }

    let s_len = der[r_start + r_len + 1] as usize;
    let s_start = r_start + r_len + 2;

    if der.len() < s_start + s_len {
        return Err(anyhow::anyhow!("Invalid DER S component"));
    }

    let r_bytes = &der[r_start..r_start + r_len];
    let s_bytes = &der[s_start..s_start + s_len];

    Ok((pad_to_32(r_bytes), pad_to_32(s_bytes)))
}

/// Pad or trim bytes to exactly 32 bytes
fn pad_to_32(bytes: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];

    // Skip leading zeros for values > 32 bytes
    let src_start = if bytes.len() > 32 {
        bytes.len() - 32
    } else {
        0
    };

    // Right-align in result
    let dest_start = if bytes.len() < 32 {
        32 - bytes.len()
    } else {
        0
    };

    let len = bytes.len().min(32);
    result[dest_start..dest_start + len].copy_from_slice(&bytes[src_start..src_start + len]);
    result
}

/// Extract public key from script_sig (follows signature in P2PKH)
fn extract_pubkey_from_script_sig(script: &[u8], sig_end: usize) -> Option<Vec<u8>> {
    if script.len() > sig_end + 1 {
        let remaining = &script[sig_end..];
        // Skip sighash type byte if present
        let start = if !remaining.is_empty() && remaining[0] <= 0x03 { 1 } else { 0 };

        if remaining.len() > start {
            // Next byte should be pubkey length (33 for compressed, 65 for uncompressed)
            let pubkey_len = remaining.get(start).copied().unwrap_or(0) as usize;
            if (pubkey_len == 33 || pubkey_len == 65) && remaining.len() > start + pubkey_len {
                return Some(remaining[start + 1..start + 1 + pubkey_len].to_vec());
            }
        }
    }
    None
}

/// Derive Bitcoin address from public key
fn derive_address_from_pubkey(pubkey: &Option<Vec<u8>>) -> String {
    match pubkey {
        Some(pk) if pk.len() == 33 || pk.len() == 65 => {
            // Use bitcoin library to derive address
            if let Ok(key) = bitcoin::secp256k1::PublicKey::from_slice(pk) {
                let pubkey = bitcoin::PublicKey::new(key);
                let addr = bitcoin::Address::p2pkh(&pubkey, bitcoin::Network::Bitcoin);
                return addr.to_string();
            }
            "unknown".to_string()
        }
        _ => "unknown".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_der_signature() {
        // Valid DER signature
        let der = vec![
            0x02, 0x20, // R length 32
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
            0x02, 0x20, // S length 32
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
        ];

        let result = parse_der_signature(&der);
        assert!(result.is_ok());

        let (r, s) = result.unwrap();
        assert_eq!(r[0], 0x01);
        assert_eq!(s[0], 0x21);
    }

    #[test]
    fn test_pad_to_32() {
        // Short value
        let short = vec![0x01, 0x02, 0x03];
        let padded = pad_to_32(&short);
        assert_eq!(padded[29], 0x01);
        assert_eq!(padded[30], 0x02);
        assert_eq!(padded[31], 0x03);
        assert_eq!(padded[0], 0x00);

        // Value with leading zero (33 bytes)
        let long = vec![0x00; 33];
        let trimmed = pad_to_32(&long);
        assert_eq!(trimmed.len(), 32);
    }

    #[test]
    fn test_r_value_index() {
        let mut index = RValueIndex::new();

        let sig1 = SignatureData {
            r: [1u8; 32],
            s: [2u8; 32],
            z: None,
            txid: "tx1".to_string(),
            vin: 0,
            address: "addr1".to_string(),
            block_height: 100,
            pubkey: None,
        };

        // First insert - no collision
        assert!(index.check_and_insert(sig1.clone()).is_none());

        // Same R, different S, different TX - collision!
        let sig2 = SignatureData {
            r: [1u8; 32],
            s: [3u8; 32], // Different S
            z: None,
            txid: "tx2".to_string(), // Different TX
            vin: 0,
            address: "addr1".to_string(),
            block_height: 101,
            pubkey: None,
        };

        let collision = index.check_and_insert(sig2);
        assert!(collision.is_some());
    }

    #[test]
    fn test_crawler_config_default() {
        let config = CrawlerConfig::default();
        assert_eq!(config.rpc_host, "127.0.0.1");
        assert_eq!(config.rpc_port, 8332);
        assert_eq!(config.passphrase, DEFAULT_ENCRYPTION_PASSPHRASE);
    }

    // DER parsing edge case tests (Task 2.5)
    #[test]
    fn test_parse_der_empty_input() {
        let result = parse_der_signature(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_der_missing_marker() {
        // Missing 0x02 prefix
        let der = vec![0x00, 0x20, 0x01, 0x02];
        let result = parse_der_signature(&der);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_der_truncated_r() {
        // R length says 32 but only 4 bytes provided
        let der = vec![0x02, 0x20, 0x01, 0x02, 0x03, 0x04];
        let result = parse_der_signature(&der);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_der_missing_s_marker() {
        // Valid R but missing S marker
        let mut der = vec![0x02, 0x04, 0x01, 0x02, 0x03, 0x04];
        der.push(0x00); // Wrong marker
        let result = parse_der_signature(&der);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_der_truncated_s() {
        // Valid R, S length says 32 but truncated
        let mut der = vec![
            0x02, 0x04, 0x01, 0x02, 0x03, 0x04, // R
            0x02, 0x20, 0x05, 0x06, // S truncated
        ];
        let result = parse_der_signature(&der);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_der_with_leading_zero() {
        // DER signatures often have leading zero for positive integers
        let der = vec![
            0x02, 0x21, // R length 33 (with leading zero)
            0x00, 0x81, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
            0x02, 0x20, // S length 32
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
        ];

        let result = parse_der_signature(&der);
        assert!(result.is_ok());

        let (r, s) = result.unwrap();
        // Leading zero should be stripped, 0x81 should be at position 31
        assert_eq!(r[31], 0x20);
        assert_eq!(s[0], 0x21);
    }

    #[test]
    fn test_parse_der_minimum_valid() {
        // Minimum valid DER meeting 8-byte requirement: 2-byte R, 2-byte S
        let der = vec![
            0x02, 0x02, 0x01, 0x02, // R = 2 bytes
            0x02, 0x02, 0x03, 0x04, // S = 2 bytes
        ];

        let result = parse_der_signature(&der);
        assert!(result.is_ok());

        let (r, s) = result.unwrap();
        assert_eq!(r[30], 0x01);
        assert_eq!(r[31], 0x02);
        assert_eq!(s[30], 0x03);
        assert_eq!(s[31], 0x04);
    }

    #[test]
    fn test_parse_der_too_short() {
        // Less than 8 bytes should fail
        let der = vec![0x02, 0x01, 0x01, 0x02, 0x01, 0x02]; // 6 bytes
        let result = parse_der_signature(&der);
        assert!(result.is_err());
    }
}
