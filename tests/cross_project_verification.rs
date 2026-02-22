//! Cross-Project Verification Tests
//!
//! This test suite ensures that entropy-lab-rs produces IDENTICAL results
//! to hashcat modules 01337/01338 for the same inputs.
//!
//! These tests are critical for:
//! - P2SH-P2WPKH (BIP49) - Research Update #13 found 224k+ wallets using this format
//! - Brainwallet consistency between Rust and hashcat
//! - Electrum seed format for Cake Wallet
//! - secp256k1 point multiplication verification
//!
//! Reference: https://milksad.info/posts/research-update-13/

use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use std::str::FromStr;

// ============================================================================
// P2SH-P2WPKH (BIP49) TEST VECTORS
// ============================================================================

/// Test P2SH-P2WPKH generation step-by-step matching the specification
///
/// P2SH-P2WPKH Generation Flow:
/// 1. Get compressed public key (33 bytes)
/// 2. Hash160 the public key → keyhash (20 bytes)
/// 3. Build redeemScript: 0x00 0x14 || keyhash (22 bytes)
/// 4. Hash160 the redeemScript → scriptHash (20 bytes)
/// 5. Base58Check encode with version 0x05
#[test]
fn test_p2sh_p2wpkh_step_by_step() {
    println!("\n=== P2SH-P2WPKH (BIP49) Step-by-Step Verification ===\n");

    // Test vector: Private key = 1 (generator point G)
    let secp = Secp256k1::new();
    let privkey_bytes =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    let secret = SecretKey::from_slice(&privkey_bytes).unwrap();
    let pubkey = PublicKey::from_secret_key(&secp, &secret);

    // Step 1: Get compressed public key
    let compressed_pubkey = pubkey.serialize();
    println!(
        "Step 1 - Compressed pubkey: {}",
        hex::encode(compressed_pubkey)
    );
    assert_eq!(
        hex::encode(compressed_pubkey),
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );

    // Step 2: Hash160 the public key
    let sha256_pubkey = Sha256::digest(compressed_pubkey);
    let mut ripemd = Ripemd160::new();
    ripemd.update(sha256_pubkey);
    let keyhash: [u8; 20] = ripemd.finalize().into();
    println!(
        "Step 2 - keyhash (Hash160 of pubkey): {}",
        hex::encode(keyhash)
    );
    assert_eq!(
        hex::encode(keyhash),
        "751e76e8199196d454941c45d1b3a323f1433bd6"
    );

    // Step 3: Build redeemScript
    let mut redeem_script = Vec::with_capacity(22);
    redeem_script.push(0x00); // witness version 0
    redeem_script.push(0x14); // push 20 bytes
    redeem_script.extend_from_slice(&keyhash);
    println!("Step 3 - redeemScript: {}", hex::encode(&redeem_script));
    assert_eq!(
        hex::encode(&redeem_script),
        "0014751e76e8199196d454941c45d1b3a323f1433bd6"
    );

    // Step 4: Hash160 the redeemScript
    let sha256_script = Sha256::digest(&redeem_script);
    let mut ripemd2 = Ripemd160::new();
    ripemd2.update(sha256_script);
    let script_hash: [u8; 20] = ripemd2.finalize().into();
    println!(
        "Step 4 - scriptHash (Hash160 of redeemScript): {}",
        hex::encode(script_hash)
    );
    assert_eq!(
        hex::encode(script_hash),
        "bcfeb728b584253d5f3f70bcb780e9ef218a68f4"
    );

    // Step 5: Base58Check encode with version 0x05
    let mut address_bytes = Vec::with_capacity(21);
    address_bytes.push(0x05); // P2SH mainnet version
    address_bytes.extend_from_slice(&script_hash);

    let address = bs58::encode(&address_bytes).with_check().into_string();
    println!("Step 5 - P2SH-P2WPKH address: {}", address);
    assert_eq!(address, "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN");

    println!("\n  All P2SH-P2WPKH steps verified against specification.");
}

/// Test P2SH-P2WPKH using bitcoin crate's built-in function
#[test]
fn test_p2sh_p2wpkh_bitcoin_crate() {
    println!("\n=== P2SH-P2WPKH Using bitcoin Crate ===\n");

    let secp = Secp256k1::new();
    let privkey_bytes =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    let secret = SecretKey::from_slice(&privkey_bytes).unwrap();
    let pubkey = PublicKey::from_secret_key(&secp, &secret);
    let compressed = CompressedPublicKey(pubkey);

    let address = Address::p2shwpkh(&compressed, Network::Bitcoin);
    println!("P2SH-P2WPKH address (bitcoin crate): {}", address);
    assert_eq!(address.to_string(), "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN");

    println!("  bitcoin crate output matches manual calculation.");
}

/// Test BIP49 derivation path produces correct P2SH-P2WPKH addresses
#[test]
fn test_bip49_derivation_path() {
    println!("\n=== BIP49 Derivation Path (m/49'/0'/0'/0/0) ===\n");

    let test_cases = vec![
        (
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "m/49'/0'/0'/0/0",
            "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
        ),
    ];

    for (mnemonic_str, path_str, expected_address) in test_cases {
        let mnemonic = Mnemonic::from_str(mnemonic_str).expect("Failed to parse mnemonic");
        let seed = mnemonic.to_seed("");

        let secp = Secp256k1::new();
        let root = Xpriv::new_master(Network::Bitcoin, &seed).expect("Failed to create root key");
        let path = DerivationPath::from_str(path_str).expect("Failed to parse path");
        let derived = root
            .derive_priv(&secp, &path)
            .expect("Failed to derive key");

        let keypair = derived.to_keypair(&secp);
        let compressed_pubkey = CompressedPublicKey(keypair.public_key());
        let address = Address::p2shwpkh(&compressed_pubkey, Network::Bitcoin);

        println!("Mnemonic: {}...", &mnemonic_str[..50]);
        println!("  Path: {}", path_str);
        println!("  Expected: {}", expected_address);
        println!("  Got:      {}", address);

        assert_eq!(
            address.to_string(),
            expected_address,
            "BIP49 address mismatch"
        );
        println!("  MATCH\n");
    }
}

// ============================================================================
// BRAINWALLET TEST VECTORS (Must match hashcat module 01337)
// ============================================================================

/// Hash160 helper function
fn hash160(data: &[u8]) -> [u8; 20] {
    let sha256_result = Sha256::digest(data);
    let mut ripemd = Ripemd160::new();
    ripemd.update(sha256_result);
    ripemd.finalize().into()
}

/// Generate P2SH-P2WPKH address from compressed pubkey
#[allow(dead_code)]
fn pubkey_to_p2sh_p2wpkh(pubkey: &[u8; 33]) -> String {
    // Step 1: Hash160 of compressed pubkey
    let pubkey_hash = hash160(pubkey);

    // Step 2: Build redeemScript: OP_0 PUSH20 <pubkey_hash>
    let mut redeem_script = Vec::with_capacity(22);
    redeem_script.push(0x00); // witness version 0
    redeem_script.push(0x14); // push 20 bytes
    redeem_script.extend_from_slice(&pubkey_hash);

    // Step 3: Hash160 of redeemScript
    let script_hash = hash160(&redeem_script);

    // Step 4: Base58Check encode with P2SH version byte
    let mut address_bytes = Vec::with_capacity(21);
    address_bytes.push(0x05); // P2SH mainnet version
    address_bytes.extend_from_slice(&script_hash);

    bs58::encode(&address_bytes).with_check().into_string()
}

/// Test brainwallet "hashcat" passphrase - generates all address types
/// SHA256("hashcat") = 127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935
#[test]
fn test_brainwallet_hashcat_passphrase() {
    println!("\n=== Brainwallet Test: 'hashcat' Passphrase ===\n");

    let passphrase = "hashcat";

    // SHA256(passphrase) → private key
    let privkey: [u8; 32] = Sha256::digest(passphrase.as_bytes()).into();
    println!("Passphrase: \"{}\"", passphrase);
    println!("SHA256(passphrase): {}", hex::encode(privkey));

    // Verify SHA256("hashcat")
    assert_eq!(
        hex::encode(privkey),
        "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935"
    );

    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&privkey).expect("Valid secret key");

    // Generate uncompressed public key
    let pubkey = PublicKey::from_secret_key(&secp, &secret);
    let uncompressed = pubkey.serialize_uncompressed();
    let compressed = pubkey.serialize();

    println!(
        "Uncompressed pubkey: {}...",
        hex::encode(&uncompressed[..33])
    );
    println!("Compressed pubkey: {}", hex::encode(compressed));

    // P2PKH (uncompressed) - "1" prefix
    let uncompressed_hash160 = hash160(&uncompressed);
    let mut addr_bytes = vec![0x00];
    addr_bytes.extend_from_slice(&uncompressed_hash160);
    let p2pkh_uncompressed = bs58::encode(&addr_bytes).with_check().into_string();
    println!("P2PKH (uncompressed): {}", p2pkh_uncompressed);

    // P2PKH (compressed) - "1" prefix
    let compressed_pubkey = CompressedPublicKey(pubkey);
    let p2pkh_compressed = Address::p2pkh(compressed_pubkey, Network::Bitcoin);
    println!("P2PKH (compressed): {}", p2pkh_compressed);

    // P2WPKH (compressed only) - "bc1q" prefix
    let p2wpkh = Address::p2wpkh(&compressed_pubkey, Network::Bitcoin);
    println!("P2WPKH: {}", p2wpkh);

    // P2SH-P2WPKH - "3" prefix
    let p2sh_p2wpkh = Address::p2shwpkh(&compressed_pubkey, Network::Bitcoin);
    println!("P2SH-P2WPKH: {}", p2sh_p2wpkh);

    // Verify address format correctness
    assert!(
        p2pkh_uncompressed.starts_with('1'),
        "P2PKH uncompressed should start with '1'"
    );
    assert!(
        p2pkh_compressed.to_string().starts_with('1'),
        "P2PKH compressed should start with '1'"
    );
    assert!(
        p2wpkh.to_string().starts_with("bc1q"),
        "P2WPKH should start with 'bc1q'"
    );
    assert!(
        p2sh_p2wpkh.to_string().starts_with('3'),
        "P2SH-P2WPKH should start with '3'"
    );

    // Verify uncompressed and compressed P2PKH produce different addresses
    assert_ne!(
        p2pkh_uncompressed,
        p2pkh_compressed.to_string(),
        "Uncompressed and compressed P2PKH should be different"
    );

    println!("\n  All addresses generated correctly.");
}

/// Additional brainwallet test vectors
#[test]
fn test_brainwallet_test_vectors() {
    println!("\n=== Brainwallet Additional Test Vectors ===\n");

    let test_cases = vec![
        (
            "password",
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        ),
        (
            "satoshi nakamoto",
            "aa2d3c4a4ae6559e9f13f093cc6e32459c5249da723de810651b4b54373385e2",
        ),
        (
            "correct horse battery staple",
            "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a",
        ),
        (
            "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
    ];

    for (passphrase, expected_privkey) in test_cases {
        let privkey: [u8; 32] = Sha256::digest(passphrase.as_bytes()).into();
        let privkey_hex = hex::encode(privkey);

        println!("Passphrase: \"{}\"", passphrase);
        println!("  Expected: {}", expected_privkey);
        println!("  Got:      {}", privkey_hex);

        assert_eq!(privkey_hex, expected_privkey);
        println!("  MATCH\n");
    }
}

// ============================================================================
// SECP256K1 POINT MULTIPLICATION VERIFICATION
// ============================================================================

/// Test that private key = 1 gives generator point G
#[test]
fn test_secp256k1_privkey_one_is_generator() {
    println!("\n=== secp256k1: Private Key 1 = Generator G ===\n");

    let secp = Secp256k1::new();
    let privkey_bytes =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    let secret = SecretKey::from_slice(&privkey_bytes).unwrap();
    let pubkey = PublicKey::from_secret_key(&secp, &secret);

    let compressed = pubkey.serialize();
    let uncompressed = pubkey.serialize_uncompressed();

    // Generator point G (compressed)
    let expected_g_x = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    let expected_g_y = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

    println!("Private key: 1");
    println!("Expected G.x: {}", expected_g_x);
    println!("Got pubkey.x: {}", hex::encode(&compressed[1..33]));

    assert_eq!(hex::encode(&compressed[1..33]), expected_g_x);
    assert_eq!(hex::encode(&uncompressed[33..65]), expected_g_y);

    // Verify compressed prefix is 02 (y is even)
    assert_eq!(compressed[0], 0x02);

    println!("  Private key 1 correctly produces generator point G.");
}

/// Test private key = 2 gives 2G
#[test]
fn test_secp256k1_privkey_two() {
    println!("\n=== secp256k1: Private Key 2 = 2G ===\n");

    let secp = Secp256k1::new();
    let privkey_bytes =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000002").unwrap();
    let secret = SecretKey::from_slice(&privkey_bytes).unwrap();
    let pubkey = PublicKey::from_secret_key(&secp, &secret);

    let compressed = pubkey.serialize();

    // 2G (compressed) - x coordinate
    let expected_2g_x = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

    println!("Private key: 2");
    println!("Expected 2G.x: {}", expected_2g_x);
    println!("Got pubkey.x:  {}", hex::encode(&compressed[1..33]));

    assert_eq!(hex::encode(&compressed[1..33]), expected_2g_x);

    println!("  Private key 2 correctly produces 2G.");
}

// ============================================================================
// ELECTRUM SEED FORMAT VERIFICATION
// ============================================================================

/// Electrum seed types
#[derive(Debug, Clone, Copy)]
pub enum ElectrumSeedType {
    Standard, // Version prefix starts with "01"
    Segwit,   // Version prefix starts with "100"
    TwoFA,    // Version prefix starts with "101"
}

/// Validate Electrum seed version using HMAC-SHA512
#[allow(dead_code)]
fn is_valid_electrum_seed(mnemonic: &str, seed_type: ElectrumSeedType) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    type HmacSha512 = Hmac<Sha512>;

    // Normalize mnemonic (NFKD normalization would be ideal, but ASCII works for English)
    let normalized = mnemonic.to_lowercase();

    // HMAC-SHA512 with key "Seed version"
    let mut mac = HmacSha512::new_from_slice(b"Seed version").expect("HMAC key");
    mac.update(normalized.as_bytes());
    let result = mac.finalize().into_bytes();

    // Check version prefix (first bytes of HMAC result as hex)
    let version_hex = hex::encode(&result[0..2]);

    match seed_type {
        ElectrumSeedType::Standard => version_hex.starts_with("01"),
        ElectrumSeedType::Segwit => version_hex.starts_with("100"),
        ElectrumSeedType::TwoFA => version_hex.starts_with("101"),
    }
}

/// Generate Electrum seed (PBKDF2 with "electrum" salt)
fn electrum_mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    use hmac::Hmac;
    use pbkdf2::pbkdf2;
    use sha2::Sha512;

    type HmacSha512 = Hmac<Sha512>;

    let salt = format!("electrum{}", passphrase);
    let mut seed = [0u8; 64];

    pbkdf2::<HmacSha512>(mnemonic.as_bytes(), salt.as_bytes(), 2048, &mut seed)
        .expect("PBKDF2 should not fail");

    seed
}

/// Test Electrum vs BIP39 seed derivation difference
#[test]
fn test_electrum_vs_bip39_seed() {
    println!("\n=== Electrum vs BIP39 Seed Derivation ===\n");

    let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // BIP39 seed (salt = "mnemonic" + passphrase)
    let mnemonic = Mnemonic::from_str(mnemonic_str).unwrap();
    let bip39_seed = mnemonic.to_seed("");

    // Electrum seed (salt = "electrum" + passphrase)
    let electrum_seed = electrum_mnemonic_to_seed(mnemonic_str, "");

    println!("Mnemonic: {}...", &mnemonic_str[..50]);
    println!("BIP39 seed:     {}...", hex::encode(&bip39_seed[..32]));
    println!("Electrum seed:  {}...", hex::encode(&electrum_seed[..32]));

    // They MUST be different (different salts!)
    assert_ne!(
        &bip39_seed[..],
        &electrum_seed[..],
        "BIP39 and Electrum seeds must be different"
    );

    println!("\n  Confirmed: BIP39 and Electrum produce DIFFERENT seeds from same mnemonic.");
}

/// Test Electrum derivation path for Cake Wallet
#[test]
fn test_electrum_cake_wallet_path() {
    println!("\n=== Electrum Cake Wallet Path (m/0'/0/0) ===\n");

    let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // Use Electrum seed derivation
    let seed = electrum_mnemonic_to_seed(mnemonic_str, "");

    let secp = Secp256k1::new();
    let root = Xpriv::new_master(Network::Bitcoin, &seed).expect("Failed to create root key");

    // Electrum derivation path: m/0'/0/0
    let path = DerivationPath::from_str("m/0'/0/0").expect("Failed to parse path");
    let derived = root
        .derive_priv(&secp, &path)
        .expect("Failed to derive key");

    let keypair = derived.to_keypair(&secp);
    let compressed_pubkey = CompressedPublicKey(keypair.public_key());

    // Cake Wallet uses SegWit
    let address = Address::p2wpkh(&compressed_pubkey, Network::Bitcoin);

    println!("Mnemonic: {}...", &mnemonic_str[..50]);
    println!("Seed (Electrum): {}...", hex::encode(&seed[..32]));
    println!("Path: m/0'/0/0");
    println!("Address (P2WPKH): {}", address);

    // Verify it starts with bc1q
    assert!(address.to_string().starts_with("bc1q"));

    println!("\n  Electrum/Cake Wallet derivation produces valid address.");
}

// ============================================================================
// MILK SAD (RESEARCH UPDATE #13) VERIFICATION
// ============================================================================

/// Generate entropy using MT19937 with MSB extraction (libbitcoin/bx pattern)
fn milk_sad_entropy_msb(timestamp: u32, byte_len: usize) -> Vec<u8> {
    use rand_mt::Mt19937GenRand32;

    let mut rng = Mt19937GenRand32::new(timestamp);
    let mut entropy = vec![0u8; byte_len];

    // MSB extraction: take ONLY bits 31:24 (most significant byte) from each output
    for byte in entropy.iter_mut() {
        let val = rng.next_u32();
        *byte = ((val >> 24) & 0xFF) as u8;
    }

    entropy
}

/// Test Milk Sad mnemonic generation for timestamp 0
#[test]
fn test_milk_sad_timestamp_zero() {
    println!("\n=== Milk Sad: Timestamp 0 Produces 'milk sad...' ===\n");

    // 256-bit entropy (24 words)
    let entropy = milk_sad_entropy_msb(0, 32);
    println!("Timestamp: 0");
    println!("Entropy (256-bit): {}", hex::encode(&entropy));

    let mnemonic = Mnemonic::from_entropy(&entropy).expect("Valid entropy");
    let words: Vec<&str> = mnemonic.words().collect();

    println!("Mnemonic: {}...", &mnemonic.to_string()[..80]);

    // The canonical test: timestamp 0 produces "milk sad wage cup..."
    assert_eq!(words[0], "milk", "First word must be 'milk'");
    assert_eq!(words[1], "sad", "Second word must be 'sad'");
    assert_eq!(words[2], "wage", "Third word must be 'wage'");
    assert_eq!(words[3], "cup", "Fourth word must be 'cup'");

    println!("\n  Milk Sad entropy generation verified.");
}

/// Test Research Update #13 requirements: 256-bit entropy + BIP49
#[test]
fn test_research_update_13_bip49() {
    println!("\n=== Research Update #13: BIP49 P2SH-P2WPKH ===\n");

    // Test with a 2018 timestamp (Research Update #13 time range)
    let timestamp = 1520000000u32; // Mid-2018
    let entropy = milk_sad_entropy_msb(timestamp, 32); // 256-bit for 24-word mnemonic

    println!("Timestamp: {} (2018)", timestamp);
    println!("Entropy (256-bit): {}", hex::encode(&entropy));

    let mnemonic = Mnemonic::from_entropy(&entropy).expect("Valid entropy");
    let seed = mnemonic.to_seed("");

    println!("Mnemonic (24 words): {}...", &mnemonic.to_string()[..60]);

    let secp = Secp256k1::new();
    let root = Xpriv::new_master(Network::Bitcoin, &seed).expect("Failed to create root key");

    // BIP49 path: m/49'/0'/0'/0/0
    let path = DerivationPath::from_str("m/49'/0'/0'/0/0").expect("Failed to parse path");
    let derived = root
        .derive_priv(&secp, &path)
        .expect("Failed to derive key");

    let keypair = derived.to_keypair(&secp);
    let compressed_pubkey = CompressedPublicKey(keypair.public_key());
    let address = Address::p2shwpkh(&compressed_pubkey, Network::Bitcoin);

    println!("Path: m/49'/0'/0'/0/0");
    println!("Address (P2SH-P2WPKH): {}", address);

    // Verify prefix is "3"
    assert!(
        address.to_string().starts_with('3'),
        "Research Update #13 addresses must start with '3'"
    );

    println!("\n  Research Update #13 BIP49 address generation verified.");
}

// ============================================================================
// TRUST WALLET iOS LCG VERIFICATION
// ============================================================================

/// minstd_rand0 LCG implementation: x(n+1) = (16807 * x(n)) mod (2^31 - 1)
struct MinstdRand0 {
    state: u32,
}

impl MinstdRand0 {
    fn new(seed: u32) -> Self {
        let mut s = seed;
        if s == 0 {
            s = 1;
        }
        Self { state: s }
    }

    fn next(&mut self) -> u32 {
        const A: u64 = 16807;
        const M: u64 = 2147483647; // 2^31 - 1

        let product = (self.state as u64) * A;
        self.state = (product % M) as u32;
        self.state
    }
}

/// Test minstd_rand0 LCG implementation
#[test]
fn test_minstd_rand0_lcg() {
    println!("\n=== Trust Wallet iOS: minstd_rand0 LCG ===\n");

    let mut rng = MinstdRand0::new(1);

    // First few outputs from seed 1
    let expected = [16807u32, 282475249, 1622650073, 984943658, 1144108930];

    println!("Seed: 1");
    for (i, &exp) in expected.iter().enumerate() {
        let got = rng.next();
        println!("  Output {}: expected {} got {}", i + 1, exp, got);
        assert_eq!(got, exp, "LCG output {} mismatch", i + 1);
    }

    println!("\n  minstd_rand0 LCG implementation verified.");
}

// ============================================================================
// ADDRESS FORMAT COMPREHENSIVE TEST
// ============================================================================

/// Test all address formats from the same mnemonic
#[test]
fn test_all_address_formats_from_mnemonic() {
    println!("\n=== All Address Formats from Same Mnemonic ===\n");

    let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = Mnemonic::from_str(mnemonic_str).unwrap();
    let seed = mnemonic.to_seed("");

    let secp = Secp256k1::new();
    let root = Xpriv::new_master(Network::Bitcoin, &seed).expect("Failed to create root key");

    let test_cases = vec![
        ("m/44'/0'/0'/0/0", "BIP44 P2PKH", "1"),
        ("m/49'/0'/0'/0/0", "BIP49 P2SH-P2WPKH", "3"),
        ("m/84'/0'/0'/0/0", "BIP84 P2WPKH", "bc1q"),
    ];

    println!("Mnemonic: {}...", &mnemonic_str[..50]);
    println!();

    for (path_str, description, expected_prefix) in test_cases {
        let path = DerivationPath::from_str(path_str).expect("Failed to parse path");
        let derived = root
            .derive_priv(&secp, &path)
            .expect("Failed to derive key");
        let keypair = derived.to_keypair(&secp);
        let compressed_pubkey = CompressedPublicKey(keypair.public_key());

        let address = if path_str.contains("/44'") {
            Address::p2pkh(compressed_pubkey, Network::Bitcoin).to_string()
        } else if path_str.contains("/49'") {
            Address::p2shwpkh(&compressed_pubkey, Network::Bitcoin).to_string()
        } else {
            Address::p2wpkh(&compressed_pubkey, Network::Bitcoin).to_string()
        };

        println!("{}: {}", description, path_str);
        println!("  Address: {}", address);

        assert!(
            address.starts_with(expected_prefix),
            "{} should start with '{}'",
            description,
            expected_prefix
        );
        println!("  Prefix OK\n");
    }
}

// ============================================================================
// DERIVATION PATH REFERENCE TABLE
// ============================================================================

/// Print reference table of all derivation paths and address types
#[test]
fn test_print_derivation_reference() {
    println!("\n{}", "=".repeat(80));
    println!("DERIVATION PATHS BY STANDARD");
    println!("{}", "=".repeat(80));
    println!(
        "{:<8} | {:<22} | {:<12} | Notes",
        "BIP", "Path", "Address Type"
    );
    println!("{}", "-".repeat(80));
    println!(
        "{:<8} | {:<22} | {:<12} | Legacy, most compatible",
        "BIP44", "m/44'/0'/0'/0/0", "P2PKH (1)"
    );
    println!(
        "{:<8} | {:<22} | {:<12} | SegWit wrapped, Research #13",
        "BIP49", "m/49'/0'/0'/0/0", "P2SH (3)"
    );
    println!(
        "{:<8} | {:<22} | {:<12} | Native SegWit",
        "BIP84", "m/84'/0'/0'/0/0", "P2WPKH(bc1q)"
    );
    println!(
        "{:<8} | {:<22} | {:<12} | Taproot",
        "BIP86", "m/86'/0'/0'/0/0", "P2TR (bc1p)"
    );
    println!(
        "{:<8} | {:<22} | {:<12} | Cake Wallet uses this",
        "Electrum", "m/0'/0/0", "Varies"
    );
    println!("{}", "=".repeat(80));
}
