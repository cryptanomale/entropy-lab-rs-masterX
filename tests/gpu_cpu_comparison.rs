//! GPU vs CPU Address Generation Comparison Test
//!
//! This test validates that the GPU kernel generates the same Bitcoin addresses
//! as the CPU reference implementation for various test cases.
//!
//! IMPORTANT: This test requires OpenCL to be available on the system.
//! It will be skipped if GPU initialization fails.

#[cfg(feature = "gpu")]
use bip39::Mnemonic;
#[cfg(feature = "gpu")]
use bitcoin::bip32::{DerivationPath, Xpriv};
#[cfg(feature = "gpu")]
use bitcoin::secp256k1::Secp256k1;
#[cfg(feature = "gpu")]
use bitcoin::{Address, Network, PrivateKey};
#[cfg(feature = "gpu")]
use std::str::FromStr;

#[cfg(feature = "gpu")]
#[cfg(test)]
mod gpu_cpu_tests {
    use super::*;

    /// Helper function to generate Bitcoin address from entropy using CPU (reference implementation)
    fn cpu_entropy_to_address(entropy: &[u8; 16], path_str: &str) -> String {
        let mnemonic = Mnemonic::from_entropy(entropy).expect("Failed to create mnemonic");
        let seed = mnemonic.to_seed("");

        let secp = Secp256k1::new();
        let root = Xpriv::new_master(Network::Bitcoin, &seed).expect("Failed to create root key");
        let path = DerivationPath::from_str(path_str).expect("Failed to parse path");
        let derived = root
            .derive_priv(&secp, &path)
            .expect("Failed to derive key");

        let private_key = PrivateKey::new(derived.private_key, Network::Bitcoin);
        let pubkey = private_key.public_key(&secp);
        let address = Address::p2pkh(pubkey, Network::Bitcoin);

        address.to_string()
    }

    /// Helper function to convert raw address bytes to Base58Check encoded string
    fn raw_address_to_base58(raw: &[u8; 25]) -> String {
        // Use bitcoin crate for proper Base58Check encoding
        use bitcoin::base58;
        base58::encode_check(raw)
    }

    #[test]
    #[cfg(feature = "gpu")]
    fn test_gpu_cpu_match_basic_seeds() {
        println!("\n=== GPU vs CPU Address Comparison Test ===\n");
        println!("Testing 5 test seeds to validate GPU kernel byte order fix\n");

        // Initialize GPU solver
        let gpu_solver = match temporal_planetarium_lib::scans::gpu_solver::GpuSolver::new() {
            Ok(solver) => solver,
            Err(e) => {
                println!("⚠️  GPU not available ({}), skipping test", e);
                println!("   This is expected in CI environments without OpenCL");
                return;
            }
        };

        println!("✓ GPU solver initialized\n");

        // Test cases: known entropy values that should produce same addresses
        let test_cases = vec![
            // Seed 0: All zeros (produces "abandon abandon..." mnemonic)
            ("00000000000000000000000000000000", "Seed 0 (all zeros)"),
            // Seed 1: Big-endian 1
            ("00000000000000000000000000000001", "Seed 1"),
            // Seed 2: Big-endian 2
            ("00000000000000000000000000000002", "Seed 2"),
            // Seed 255: Test all bits in last byte
            ("000000000000000000000000000000ff", "Seed 255"),
            // Seed 256: Test carry to second-to-last byte
            ("00000000000000000000000000000100", "Seed 256"),
        ];

        let mut all_match = true;
        let mut match_count = 0;

        for (entropy_hex, description) in test_cases {
            let entropy_bytes = hex::decode(entropy_hex).expect("Invalid hex");
            let mut entropy = [0u8; 16];
            entropy.copy_from_slice(&entropy_bytes);

            // CPU reference: Cake Wallet uses m/0'/0/0 path
            let cpu_address = cpu_entropy_to_address(&entropy, "m/0'/0/0");

            // GPU computation: purpose=0 means Cake Wallet (m/0'/0/0)
            let gpu_results = gpu_solver
                .compute_batch(&[entropy], 0)
                .expect("GPU computation failed");
            let gpu_address = raw_address_to_base58(&gpu_results[0]);

            let matches = cpu_address == gpu_address;
            match_count += if matches { 1 } else { 0 };
            all_match &= matches;

            println!("{}: {}", description, entropy_hex);
            println!("  CPU: {}", cpu_address);
            println!("  GPU: {}", gpu_address);
            println!("  {}", if matches { "✓ MATCH" } else { "✗ MISMATCH" });
            println!();

            if !matches {
                // Show detailed hex for debugging
                println!("  Raw GPU output: {:02x?}", gpu_results[0]);
                println!();
            }
        }

        println!("Results: {}/5 seeds match", match_count);

        if all_match {
            println!("🎉 SUCCESS! All GPU addresses match CPU reference implementation!");
        } else {
            panic!("❌ GPU/CPU mismatch detected! GPU kernel byte order may be incorrect.");
        }
    }

    #[test]
    #[cfg(feature = "gpu")]
    fn test_gpu_cpu_match_random_seeds() {
        println!("\n=== GPU vs CPU Random Seeds Test ===\n");
        println!("Testing 20 random seeds for comprehensive validation\n");

        // Initialize GPU solver
        let gpu_solver = match temporal_planetarium_lib::scans::gpu_solver::GpuSolver::new() {
            Ok(solver) => solver,
            Err(e) => {
                println!("⚠️  GPU not available ({}), skipping test", e);
                return;
            }
        };

        use rand::Rng;
        let mut rng = rand::thread_rng();

        let mut all_match = true;
        let mut match_count = 0;

        for i in 0..20 {
            // Generate random 16-byte entropy
            let mut entropy = [0u8; 16];
            rng.fill(&mut entropy);

            // CPU reference
            let cpu_address = cpu_entropy_to_address(&entropy, "m/0'/0/0");

            // GPU computation
            let gpu_results = gpu_solver
                .compute_batch(&[entropy], 0)
                .expect("GPU computation failed");
            let gpu_address = raw_address_to_base58(&gpu_results[0]);

            let matches = cpu_address == gpu_address;
            match_count += if matches { 1 } else { 0 };
            all_match &= matches;

            if i < 5 || !matches {
                // Show first 5 and any mismatches
                println!("Random seed {}: {}", i, hex::encode(entropy));
                println!("  CPU: {}", cpu_address);
                println!("  GPU: {}", gpu_address);
                println!("  {}", if matches { "✓ MATCH" } else { "✗ MISMATCH" });
                println!();
            }
        }

        println!("Results: {}/20 random seeds match", match_count);

        if all_match {
            println!("🎉 SUCCESS! All random GPU addresses match CPU!");
        } else {
            panic!("❌ GPU/CPU mismatch on random seeds!");
        }
    }

    #[test]
    #[cfg(feature = "gpu")]
    fn test_gpu_batch_processing() {
        println!("\n=== GPU Batch Processing Test ===\n");

        let gpu_solver = match temporal_planetarium_lib::scans::gpu_solver::GpuSolver::new() {
            Ok(solver) => solver,
            Err(e) => {
                println!("⚠️  GPU not available ({}), skipping test", e);
                return;
            }
        };

        // Create batch of 100 sequential entropy values
        let batch_size = 100;
        let mut entropies = Vec::new();

        for i in 0..batch_size {
            let mut entropy = [0u8; 16];
            let index_bytes = (i as u32).to_be_bytes();
            entropy[12..16].copy_from_slice(&index_bytes);
            entropies.push(entropy);
        }

        println!("Testing batch of {} sequential seeds", batch_size);

        // Compute CPU reference addresses
        let cpu_addresses: Vec<String> = entropies
            .iter()
            .map(|e| cpu_entropy_to_address(e, "m/0'/0/0"))
            .collect();

        // Compute GPU addresses in batch
        let gpu_results = gpu_solver
            .compute_batch(&entropies, 0)
            .expect("GPU batch computation failed");
        let gpu_addresses: Vec<String> = gpu_results
            .iter()
            .map(|r| raw_address_to_base58(r))
            .collect();

        // Verify all match
        let mut all_match = true;
        let mut match_count = 0;

        for i in 0..batch_size {
            let matches = cpu_addresses[i] == gpu_addresses[i];
            match_count += if matches { 1 } else { 0 };
            all_match &= matches;

            if !matches {
                println!("Mismatch at index {}:", i);
                println!("  Entropy: {}", hex::encode(&entropies[i]));
                println!("  CPU: {}", cpu_addresses[i]);
                println!("  GPU: {}", gpu_addresses[i]);
                println!();
            }
        }

        println!(
            "Batch results: {}/{} addresses match",
            match_count, batch_size
        );

        assert!(
            all_match,
            "GPU batch processing produced incorrect results! {}/{} match",
            match_count, batch_size
        );

        println!("✓ All {} addresses in batch match!", batch_size);
    }
}
