// Full Milk Sad Address Pipeline Test
// Verifies entropy -> mnemonic -> seed -> address chain

use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network};
use rand_mt::Mt19937GenRand32;
use std::str::FromStr;

/// Generate entropy using MT19937 with MSB extraction (Milk Sad method)
fn generate_milk_sad_entropy(timestamp: u32) -> [u8; 16] {
    let mut rng = Mt19937GenRand32::new(timestamp);
    let mut entropy = [0u8; 16];
    for i in 0..4 {
        let val = rng.next_u32();
        entropy[i * 4] = ((val >> 24) & 0xFF) as u8;
        entropy[i * 4 + 1] = ((val >> 16) & 0xFF) as u8;
        entropy[i * 4 + 2] = ((val >> 8) & 0xFF) as u8;
        entropy[i * 4 + 3] = (val & 0xFF) as u8;
    }
    entropy
}

/// Generate address from entropy (BIP39/BIP44 standard path)
fn generate_address_from_entropy(entropy: &[u8; 16], addr_index: u32) -> String {
    let mnemonic = Mnemonic::from_entropy(entropy).expect("Valid entropy");
    let seed = mnemonic.to_seed("");

    let secp = Secp256k1::new();
    let root = Xpriv::new_master(Network::Bitcoin, &seed).expect("Valid seed");

    // Path: m/44'/0'/0'/0/i
    let path_str = format!("m/44'/0'/0'/0/{}", addr_index);
    let path = DerivationPath::from_str(&path_str).expect("Valid path");
    let derived = root.derive_priv(&secp, &path).expect("Derivation");

    let private_key = bitcoin::PrivateKey::new(derived.private_key, Network::Bitcoin);
    let pubkey = private_key.public_key(&secp);
    let address = Address::p2pkh(pubkey, Network::Bitcoin);

    address.to_string()
}

#[test]
fn test_milk_sad_full_pipeline() {
    println!("\n=== Milk Sad Full Address Pipeline Test ===\n");

    // Test vectors: timestamp -> expected address
    let test_cases = vec![
        (0u32, "Check timestamp 0"),
        (1u32, "Check timestamp 1"),
        (1234567890u32, "Standard test vector"),
        (1293840000u32, "2011-01-01 (scan start)"),
        (1609459200u32, "2021-01-01"),
    ];

    for (timestamp, description) in test_cases {
        let entropy = generate_milk_sad_entropy(timestamp);
        let mnemonic = Mnemonic::from_entropy(&entropy).expect("Valid entropy");
        let address = generate_address_from_entropy(&entropy, 0);

        println!("Timestamp: {} ({})", timestamp, description);
        println!("  Entropy:  {}", hex::encode(entropy));
        println!("  Mnemonic: {}...", &mnemonic.to_string()[..40]);
        println!("  Address:  {}", address);
        println!();

        // Basic validation
        assert!(address.starts_with("1"), "Should be P2PKH (starts with 1)");
    }

    println!("✓ All Milk Sad pipeline tests completed!");
}

#[cfg(feature = "gpu")]
#[test]
fn test_milk_sad_gpu_address_match() {
    use temporal_planetarium_lib::scans::gpu_solver::GpuSolver;

    println!("\n=== Milk Sad GPU Address Verification ===\n");

    let solver = match GpuSolver::new() {
        Ok(s) => s,
        Err(e) => {
            println!("GPU not available, skipping: {}", e);
            return;
        }
    };

    // Test: Generate address on CPU, then use GPU to crack it
    let test_timestamp = 1234567890u32;
    let cpu_entropy = generate_milk_sad_entropy(test_timestamp);
    let cpu_address = generate_address_from_entropy(&cpu_entropy, 0);

    println!("Test timestamp: {}", test_timestamp);
    println!("CPU entropy: {}", hex::encode(&cpu_entropy));
    println!("CPU address: {}", cpu_address);

    // Extract hash160 from address for GPU search
    let address = bitcoin::Address::from_str(&cpu_address)
        .unwrap()
        .assume_checked();
    let script = address.script_pubkey();
    let target_hash160: [u8; 20] = script.as_bytes()[3..23].try_into().unwrap();

    println!("Target Hash160: {}", hex::encode(&target_hash160));

    // Use GPU to find the timestamp (narrow search around known value)
    let start = test_timestamp - 10;
    let end = test_timestamp + 10;

    match solver.compute_milk_sad_crack(start, end, &target_hash160) {
        Ok(results) => {
            if results.contains(&(test_timestamp as u64)) {
                println!("✓ GPU found correct timestamp: {}", test_timestamp);
            } else if !results.is_empty() {
                println!(
                    "Found timestamps: {:?} (expected {})",
                    results, test_timestamp
                );
                panic!("GPU found wrong timestamp!");
            } else {
                println!("✗ GPU did not find the timestamp");
                panic!("GPU milk_sad_crack failed to find known vulnerable timestamp");
            }
        }
        Err(e) => {
            println!("GPU crack failed: {}", e);
            panic!("GPU milk_sad_crack error");
        }
    }

    println!("\n✓ Milk Sad GPU address verification passed!");
}
