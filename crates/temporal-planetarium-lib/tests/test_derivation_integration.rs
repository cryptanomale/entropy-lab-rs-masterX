use temporal_planetarium_lib::scans::randstorm::derivation_batcher::{DerivationBatcher, StandardPath};
use bitcoin::Network;
use hex;

#[test]
fn test_multi_path_derivation_integration() {
    // Known seed (from BIP39 "abandon ... about")
    // Seed: 5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4
    let seed_hex = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
    let seed = hex::decode(seed_hex).expect("Failed to decode seed");

    // Initialize Batcher for Mainnet with small index range for speed
    let batcher = DerivationBatcher::new(Network::Bitcoin, 10);

    // Derive All
    let results = batcher.derive_all(&seed).expect("Derivation failed");

    // Verify Volume: 4 paths * 10 indices = 40 addresses
    assert_eq!(results.len(), 40, "Expected 40 derived addresses");

    // Verify BIP44 (Legacy)
    let bip44_addr = results.iter()
        .find(|r| r.path_type == StandardPath::Bip44 && r.index == 0)
        .expect("BIP44 index 0 missing");
    assert_eq!(bip44_addr.address, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA", "BIP44 Mismatch");

    // Verify BIP49 (SegWit Nested)
    let bip49_addr = results.iter()
        .find(|r| r.path_type == StandardPath::Bip49 && r.index == 0)
        .expect("BIP49 index 0 missing");
    assert_eq!(bip49_addr.address, "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf", "BIP49 Mismatch");

    // Verify BIP84 (Native SegWit)
    let bip84_addr = results.iter()
        .find(|r| r.path_type == StandardPath::Bip84 && r.index == 0)
        .expect("BIP84 index 0 missing");
    assert_eq!(bip84_addr.address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "BIP84 Mismatch");

    // Verify BIP86 (Taproot)
    let bip86_addr = results.iter()
        .find(|r| r.path_type == StandardPath::Bip86 && r.index == 0)
        .expect("BIP86 index 0 missing");
    // Verify it's a valid bech32m address starting with bc1p
    assert!(bip86_addr.address.starts_with("bc1p"), "BIP86 should be bc1p...");
    
    // Verify path strings are correct
    assert_eq!(bip44_addr.derivation_path, "m/44'/0'/0'/0/0");
    assert_eq!(bip86_addr.derivation_path, "m/86'/0'/0'/0/0");
    
    println!("Integration test passed: Multi-path derivation verified for all standard paths.");
}
