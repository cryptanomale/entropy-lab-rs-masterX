// Generate BIP39 Test Vectors for GPU Validation
// Compares CPU reference implementation against expected outputs

use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv}; // v0.32 uses Xpriv
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Network};
use rand_mt::Mt19937GenRand32;
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== GPU BIP39 Accuracy Validation ===\n");

    let test_timestamps = vec![
        1234567890u32, // 2009-02-13
        1609459200u32, // 2021-01-01
        1577836800u32, // 2020-01-01
        1293840000u32, // 2011-01-01
        1690848000u32, // 2023-08-01
    ];

    for timestamp in test_timestamps {
        println!("Test Vector for timestamp: {}", timestamp);

        // Generate entropy using MT19937
        let mut rng = Mt19937GenRand32::new(timestamp); // Takes u32
        let mut entropy = [0u8; 32];
        for i in 0..8 {
            let val = rng.next_u32();
            entropy[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
        }

        println!("  Entropy: {}", hex::encode(entropy));

        // Generate mnemonic
        let mnemonic = Mnemonic::from_entropy(&entropy)?;
        let mnemonic_str = mnemonic.to_string();
        let words: Vec<&str> = mnemonic_str.split_whitespace().collect();
        println!("  First 3 words: {} {} {}", words[0], words[1], words[2]);

        // Generate seed
        let seed = mnemonic.to_seed("");
        println!("  Seed (first 32 bytes): {}", hex::encode(&seed[..32]));

        // Derive BIP32 key m/44'/0'/0'/0/0
        let secp = Secp256k1::new();
        let root = Xpriv::new_master(Network::Bitcoin, &seed)?;
        let path = DerivationPath::from_str("m/44'/0'/0'/0/0")?;
        let derived = root.derive_priv(&secp, &path)?;

        // Generate address
        let private_key = bitcoin::PrivateKey::new(derived.private_key, Network::Bitcoin);
        let pubkey = private_key.public_key(&secp);
        let address = Address::p2pkh(pubkey, Network::Bitcoin);

        println!("  Address: {}", address);
        println!(
            "  GPU should generate THIS address for timestamp {}\n",
            timestamp
        );
    }

    println!("To test GPU implementation, run:");
    println!("./entropy-lab-rs milk-sad --target <address_from_above> --start-timestamp <ts-10> --end-timestamp <ts+10>");

    Ok(())
}
