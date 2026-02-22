// GPU BIP39 Validation Test
// Compares GPU OpenCL implementation against CPU rust-bitcoin reference

use bip39::Mnemonic;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::bip32::{Xpriv, DerivationPath};
use bitcoin::{Network, Address};
use std::str::FromStr;

#[test]
fn test_cpu_bip39_reference() {
    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║         CPU BIP39 REFERENCE GENERATION                     ║");
    println!("║  Generating known test vectors for GPU comparison          ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");
    
    let test_vectors = vec![
        (
            "00000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        ),
        (
            "80808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        ),
        (
            "ffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        ),
        (
            "68a79eaca2324873eacc50cb9c6eca8c",
            "hamster diagram private dutch cause delay private meat slide toddler razor book",
        ),
    ];
    
    let mut all_passed = true;
    
    for (i, (entropy_hex, expected_mnemonic)) in test_vectors.iter().enumerate() {
        println!("══════════════════════════════════════════════════════════");
        println!("TEST VECTOR #{}", i + 1);
        println!("══════════════════════════════════════════════════════════");
        println!("Entropy: {}", entropy_hex);
        
        // CPU Reference Implementation
        let entropy = hex::decode(entropy_hex).expect("Valid hex");
        let cpu_mnemonic = Mnemonic::from_entropy(&entropy).expect("Valid entropy");
        let cpu_mnemonic_str = cpu_mnemonic.to_string();
        
        println!("Expected:  {}", expected_mnemonic);
        println!("Generated: {}", cpu_mnemonic_str);
        
        // Verify mnemonic matches expected
        if cpu_mnemonic_str != *expected_mnemonic {
            println!("❌ FAIL: Mnemonic mismatch!");
            all_passed = false;
            continue;
        }
        println!("✓ Mnemonic correct");
        
        // Generate seed
        let cpu_seed = cpu_mnemonic.to_seed("");
        println!("Seed (hex, first 32 bytes): {}", hex::encode(&cpu_seed[..32]));
        
        // Derive address m/44'/0'/0'/0/0
        let secp = Secp256k1::new();
        let master_key = Xpriv::new_master(Network::Bitcoin, &cpu_seed).expect("Valid seed");
        let path = DerivationPath::from_str("m/44'/0'/0'/0/0").expect("Valid path");
        let derived_key = master_key.derive_priv(&secp, &path).expect("Derivation works");
        let public_key = derived_key.to_priv().public_key(&secp);
        let cpu_address = Address::p2pkh(public_key, Network::Bitcoin);
        
        println!("Address (m/44'/0'/0'/0/0): {}", cpu_address);
        println!("✓ PASS\n");
    }
    
    if all_passed {
        println!("\n╔════════════════════════════════════════════════════════════╗");
        println!("║  ✓ ALL CPU TEST VECTORS VALIDATED                         ║");
        println!("╚════════════════════════════════════════════════════════════╝\n");
    } else {
        panic!("Some test vectors failed");
    }
}

#[test]
fn generate_test_vector_file() {
    println!("\nGenerating test_vectors_bip39.txt for GPU validation...\n");
    
    use std::fs::File;
    use std::io::Write;
    
    let mut file = File::create("test_vectors_bip39.txt").expect("Create file");
    
    writeln!(file, "# BIP39 GPU Validation Test Vectors").unwrap();
    writeln!(file, "# Format: entropy_hex | mnemonic | seed_hex | address").unwrap();
    writeln!(file, "").unwrap();
    
    let test_cases = vec![
        "00000000000000000000000000000000",
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "80808080808080808080808080808080",
        "ffffffffffffffffffffffffffffffff",
        "68a79eaca2324873eacc50cb9c6eca8c",
        "0c1e24e5917779d297e14d45f14e1a1a",
        "f585c11aec520db57dd353c69554b21a",
    ];
    
    for entropy_hex in test_cases {
        let entropy = hex::decode(entropy_hex).unwrap();
        let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
        let seed = mnemonic.to_seed("");
        
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();
        let path = DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap();
        let derived = master.derive_priv(&secp, &path).unwrap();
        let pubkey = derived.to_priv().public_key(&secp);
        let address = Address::p2pkh(pubkey, Network::Bitcoin);
        
        writeln!(file, "{} | {} | {} | {}",
            entropy_hex,
            mnemonic.to_string(),
            hex::encode(&seed[..32]),
            address
        ).unwrap();
    }
    
    println!("✓ Created test_vectors_bip39.txt with {} test cases\n", test_cases.len());
}
