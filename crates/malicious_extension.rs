#[cfg(feature = "gpu")]
use crate::scans::gpu_solver::GpuSolver;
use anyhow::Result;
#[cfg(feature = "gpu")]
use bitcoin::key::Secp256k1;
#[cfg(feature = "gpu")]
use bitcoin::secp256k1::SecretKey;
#[cfg(feature = "gpu")]
use bitcoin::{Address, Network};
#[cfg(feature = "gpu")]
use hex;
#[cfg(feature = "gpu")]
use sha2::{Digest, Sha256};
#[cfg(feature = "gpu")]
use tracing::{info, warn};

#[cfg(not(feature = "gpu"))]
pub fn run() -> Result<()> {
    anyhow::bail!("This scanner requires GPU acceleration. Please recompile with --features gpu");
}

/// Simulates a "Malicious Extension" Address Poisoning Attack (GPU Accelerated)
/// The attacker generates a "vanity" address that looks similar to the user's intended destination
/// (matching prefix/suffix) to trick them into copying the wrong address from history.
#[cfg(feature = "gpu")]
pub fn run() -> Result<()> {
    info!("Malicious Extension: Address Poisoning Attack (GPU Accelerated)");
    info!("Goal: Generate a 'poison' address that mimics a target address.");

    // Target Address (Legacy P2PKH for this demo)
    // "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" (Genesis Address)
    let target_str = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    info!("Target Address: {}", target_str);

    // We want to match the first 6 chars "1A1zP1" and maybe last 2 "Na"
    // Matching 6 chars is trivial on GPU.
    let target_prefix = "1A1zP1";
    let target_suffix = "Na";

    info!(
        "Desired Poison Address: {}...{}",
        target_prefix, target_suffix
    );
    info!("Launching GPU search for matching private key...");

    // Initialize GPU
    let solver = GpuSolver::new()?;
    info!("[GPU] Solver initialized");

    // Search parameters
    let batch_size = 10_000_000; // 10M keys per batch
    let mut seed_base = 0u64;
    let mut found = false;

    let start_time = std::time::Instant::now();

    // Run a few batches
    for i in 0..100 {
        let results = solver.compute_address_poisoning(
            seed_base,
            batch_size,
            target_prefix,
            target_suffix,
        )?;

        if !results.is_empty() {
            for &seed in &results {
                // Verify match on CPU
                let priv_key_bytes = Sha256::digest(&seed.to_le_bytes());
                let secp = Secp256k1::new();
                let secret_key = SecretKey::from_slice(&priv_key_bytes)?;
                let pubkey = secret_key.public_key(&secp);
                let address = Address::p2pkh(bitcoin::PublicKey::new(pubkey), Network::Bitcoin);
                let addr_str = address.to_string();

                if addr_str.starts_with(target_prefix) && addr_str.ends_with(target_suffix) {
                    warn!("\n[GPU] 🎯 POISON ADDRESS FOUND!");
                    warn!("  Seed: {}", seed);
                    warn!("  Private Key: {}", hex::encode(priv_key_bytes));
                    warn!("  Address:     {}", addr_str);
                    warn!("  Target:      {}", target_str);
                    warn!(
                        "  Match:       {}^^^^^...^^^^^",
                        " ".repeat(target_prefix.len())
                    );

                    found = true;
                    break;
                }
            }
        }

        if found {
            break;
        }

        seed_base += batch_size as u64;
        if i % 10 == 0 {
            // Replaced print!(".") with info update
            info!("Scanned {} seeds...", seed_base);
        }
    }

    if !found {
        info!("\nNo match found in {} iterations.", seed_base);
    } else {
        warn!("\nAttack successful! The user might mistake this address for the real one.");
    }

    info!("Time elapsed: {:.2}s", start_time.elapsed().as_secs_f64());

    Ok(())
}
