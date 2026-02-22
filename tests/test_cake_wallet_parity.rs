// Cake Wallet Electrum GPU/CPU Parity Test
// Verifies that GPU produces same addresses as CPU for Electrum-style derivation

use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network};
use std::str::FromStr;

/// Generate Cake Wallet address using CPU (Electrum derivation)
fn generate_cake_wallet_cpu_address(seed_index: u32) -> (String, String, [u8; 16]) {
    let secp = Secp256k1::new();
    let network = Network::Bitcoin;

    // Create deterministic entropy from seed index (simulating 20-bit space)
    let mut entropy_bytes = [0u8; 16];
    let seed_bytes = seed_index.to_be_bytes();
    entropy_bytes[0..4].copy_from_slice(&seed_bytes);

    // BIP39 mnemonic from entropy
    let mnemonic = Mnemonic::from_entropy(&entropy_bytes).expect("Valid entropy");
    let mnemonic_str = mnemonic.to_string();

    // Electrum seed derivation
    let seed = temporal_planetarium_lib::utils::electrum::mnemonic_to_seed(&mnemonic_str);

    // Derive m/0'/0/0 path
    let root = Xpriv::new_master(network, &seed).expect("Valid master");
    let path = DerivationPath::from_str("m/0'/0/0").expect("Valid path");
    let child = root.derive_priv(&secp, &path).expect("Valid derivation");
    let pubkey = child.to_keypair(&secp).public_key();

    // Generate addresses
    let compressed_pubkey = bitcoin::CompressedPublicKey(pubkey);
    let address_segwit = Address::p2wpkh(&compressed_pubkey, network).to_string();
    let address_legacy = Address::p2pkh(compressed_pubkey, network).to_string();

    (address_segwit, address_legacy, entropy_bytes)
}

/// Extract Hash160 from P2PKH address for GPU comparison
#[allow(dead_code)]
fn extract_hash160_from_legacy(address: &str) -> Option<[u8; 20]> {
    let addr = bitcoin::Address::from_str(address).ok()?.assume_checked();
    let script = addr.script_pubkey();
    let bytes = script.as_bytes();

    // P2PKH script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if bytes.len() >= 23 {
        let mut hash160 = [0u8; 20];
        hash160.copy_from_slice(&bytes[3..23]);
        Some(hash160)
    } else {
        None
    }
}

#[test]
fn test_cake_wallet_cpu_addresses() {
    println!("\n=== Cake Wallet CPU Address Generation ===\n");

    let test_indices = vec![0u32, 1, 100, 1000, 0x12345];

    for idx in test_indices {
        let (segwit, legacy, entropy) = generate_cake_wallet_cpu_address(idx);

        println!("Seed Index: {} (0x{:08X})", idx, idx);
        println!("  Entropy: {}", hex::encode(entropy));
        println!("  Legacy:  {}", legacy);
        println!("  SegWit:  {}", segwit);
        println!();

        // Validate addresses
        assert!(legacy.starts_with("1"), "Legacy should start with 1");
        assert!(segwit.starts_with("bc1q"), "SegWit should start with bc1q");
    }

    println!("✓ CPU address generation working correctly!");
}

#[cfg(feature = "gpu")]
#[test]
fn test_cake_wallet_gpu_cpu_parity() {
    use temporal_planetarium_lib::scans::gpu_solver::GpuSolver;

    println!("\n=== Cake Wallet GPU/CPU Parity Test ===\n");

    let solver = match GpuSolver::new() {
        Ok(s) => s,
        Err(e) => {
            println!("GPU not available, skipping: {}", e);
            return;
        }
    };

    // Test with a specific seed index
    let test_idx = 12345u32;
    let (_, legacy_addr, entropy) = generate_cake_wallet_cpu_address(test_idx);

    println!("Test seed index: {}", test_idx);
    println!("CPU entropy: {}", hex::encode(&entropy));
    println!("CPU legacy address: {}", legacy_addr);

    // Extract target hash160 for GPU search
    let target_hash160 = extract_hash160_from_legacy(&legacy_addr).expect("Valid address");
    println!("Target Hash160: {}", hex::encode(&target_hash160));

    // Use GPU batch computation (purpose=0 for Cake Wallet Electrum)
    // We'll compute a batch including our test entropy
    let entropies = vec![entropy];

    match solver.compute_batch(&entropies, 0) {
        // purpose=0 = Cake Wallet Electrum
        Ok(results) => {
            if results.is_empty() {
                println!("✗ GPU returned no results");
                panic!("GPU batch returned empty");
            }

            let gpu_full = &results[0];
            println!("GPU Full (25 bytes): {}", hex::encode(gpu_full));

            // The 25-byte output is: version (1) + hash160 (20) + checksum (4)
            // Extract hash160 (bytes 1-21)
            let gpu_hash160: [u8; 20] = gpu_full[1..21].try_into().expect("slice to array");
            println!("GPU Hash160: {}", hex::encode(&gpu_hash160));

            if gpu_hash160 == target_hash160 {
                println!("\n✓ GPU/CPU MATCH for Cake Wallet Electrum derivation!");
            } else {
                println!("\n✗ MISMATCH!");
                println!("CPU Hash160: {}", hex::encode(&target_hash160));
                println!("GPU Hash160: {}", hex::encode(&gpu_hash160));
                panic!("GPU and CPU produced different Hash160 for Cake Wallet");
            }
        }
        Err(e) => {
            println!("GPU computation failed: {}", e);
            panic!("GPU batch computation failed");
        }
    }
}
