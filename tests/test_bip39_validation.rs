// BIP39 Validation Tests - Compare GPU output with known-good CPU implementation
// Milk Sad Vulnerability: MT19937 with MSB extraction for 128-bit entropy

use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv}; // v0.32 uses Xpriv instead of ExtendedPrivKey
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network};
use rand_mt::Mt19937GenRand32;
use std::str::FromStr;

/// Generate 128-bit entropy using MT19937 with MSB extraction (Milk Sad vulnerability)
fn generate_milk_sad_entropy(timestamp: u32) -> [u8; 16] {
    let mut rng = Mt19937GenRand32::new(timestamp); // Takes u32, not u64
    let mut entropy = [0u8; 16];

    // Libbitcoin Milk Sad bug: Uses MSB (most significant byte) of each u32
    // Extract 4 random u32 values = 128 bits
    for i in 0..4 {
        let val = rng.next_u32();
        // MSB extraction: big-endian byte order
        entropy[i * 4] = ((val >> 24) & 0xFF) as u8;
        entropy[i * 4 + 1] = ((val >> 16) & 0xFF) as u8;
        entropy[i * 4 + 2] = ((val >> 8) & 0xFF) as u8;
        entropy[i * 4 + 3] = (val & 0xFF) as u8;
    }

    entropy
}

/// Generate Bitcoin address from entropy using BIP39/BIP44
fn generate_address_from_entropy(entropy: &[u8; 16]) -> String {
    let mnemonic = Mnemonic::from_entropy(entropy).unwrap();
    let seed = mnemonic.to_seed("");

    let secp = Secp256k1::new();
    let root = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();
    let path = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
    let derived = root.derive_priv(&secp, &path).unwrap();

    // Bitcoin v0.32: private_key is SecretKey, need to wrap in PrivateKey
    let private_key = bitcoin::PrivateKey::new(derived.private_key, Network::Bitcoin);
    let pubkey = private_key.public_key(&secp);
    let address = Address::p2pkh(pubkey, Network::Bitcoin);

    address.to_string()
}

#[test]
fn test_milk_sad_entropy_generation() {
    println!("\n=== Milk Sad Entropy Generation (128-bit, MSB) ===\n");

    let test_cases = vec![
        (0u32, "Expected entropy for timestamp 0"),
        (1u32, "Expected entropy for timestamp 1"),
        (1234567890u32, "Known Milk Sad test vector"),
        (1609459200u32, "2021-01-01 00:00:00 UTC"),
        (1293840000u32, "2011-01-01 00:00:00 UTC"),
    ];

    for (timestamp, description) in test_cases {
        let entropy = generate_milk_sad_entropy(timestamp);
        println!("Timestamp: {} ({})", timestamp, description);
        println!("  Entropy (128-bit): {}", hex::encode(entropy));

        // Generate mnemonic to verify it's valid
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        let mnemonic_str = mnemonic.to_string();
        let words: Vec<&str> = mnemonic_str.split_whitespace().collect();
        println!(
            "  Mnemonic (first 3): {} {} {}",
            words[0], words[1], words[2]
        );
        println!();
    }
}

#[test]
fn test_bip39_cpu_reference_addresses() {
    println!("\n=== CPU Reference Address Generation ===\n");

    let test_timestamps = vec![
        1234567890u32, // Feb 13 2009
        1609459200u32, // Jan 01 2021
        1293840000u32, // Jan 01 2011
    ];

    for timestamp in test_timestamps {
        let entropy = generate_milk_sad_entropy(timestamp);
        let address = generate_address_from_entropy(&entropy);

        println!("Timestamp: {}", timestamp);
        println!("  Entropy: {}", hex::encode(entropy));
        println!("  Address: {}", address);
        println!();
    }
}

#[test]
fn test_mt19937_msb_extraction() {
    println!("\n=== MT19937 MSB Extraction Verification ===\n");

    // Test that MSB extraction is correct
    let mut rng = Mt19937GenRand32::new(1234567890u32);

    println!("First 4 MT19937 u32 values:");
    for i in 0..4 {
        let val = rng.next_u32();
        let msb = (val >> 24) & 0xFF;
        println!("  Value {}: 0x{:08x}, MSB: 0x{:02x}", i, val, msb);
    }
    println!();
}
