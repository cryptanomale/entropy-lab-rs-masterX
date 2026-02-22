//! Test Vectors for "hashcat" Passphrase
//!
//! This test module specifically verifies the "hashcat" passphrase mentioned
//! in the hashcat module prompt. This is a reference test case for:
//! - Module 01337 (uncompressed brainwallet)
//! - Module 01338 (compressed brainwallet)
//!
//! Test vectors should be manually verified at https://www.bitaddress.org
//! using the "Brain Wallet" tab.

use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// Hash160 helper function: RIPEMD160(SHA256(data))
fn hash160(data: &[u8]) -> [u8; 20] {
    let sha256_result = Sha256::digest(data);
    let mut ripemd = Ripemd160::new();
    ripemd.update(sha256_result);
    ripemd.finalize().into()
}

/// Generate P2PKH address from hash160 with version byte
fn p2pkh_from_hash160(hash160: &[u8; 20], version: u8) -> String {
    let mut addr_bytes = vec![version];
    addr_bytes.extend_from_slice(hash160);
    bs58::encode(&addr_bytes).with_check().into_string()
}

/// Helper function to convert secp256k1 compressed public key to bitcoin::PublicKey
fn to_bitcoin_pubkey(compressed_bytes: &[u8]) -> bitcoin::PublicKey {
    bitcoin::PublicKey::from_slice(compressed_bytes)
        .expect("Failed to convert to bitcoin::PublicKey")
}

#[test]
fn test_hashcat_passphrase_sha256() {
    println!("\n=== Test: SHA256('hashcat') ===\n");

    let passphrase = "hashcat";
    let expected_privkey = "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935";

    let privkey_bytes = Sha256::digest(passphrase.as_bytes());
    let privkey_hex = hex::encode(privkey_bytes);

    println!("  Passphrase: \"{}\"", passphrase);
    println!("  Expected private key: {}", expected_privkey);
    println!("  Got private key:      {}", privkey_hex);

    assert_eq!(
        privkey_hex, expected_privkey,
        "SHA256('hashcat') private key mismatch"
    );

    println!("  ✅ SHA256 verification passed\n");
}

#[test]
fn test_hashcat_passphrase_uncompressed() {
    println!("\n=== Test: Brainwallet 'hashcat' (Uncompressed) ===\n");

    let passphrase = "hashcat";
    let secp = Secp256k1::new();

    // Step 1: SHA256(passphrase) -> private key
    let privkey_bytes = Sha256::digest(passphrase.as_bytes());
    let privkey_hex = hex::encode(privkey_bytes);
    println!("  1. Private key (SHA256): {}", privkey_hex);

    // Expected from the prompt
    assert_eq!(
        privkey_hex,
        "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935"
    );

    // Step 2: secp256k1 point multiplication
    let secret_key = SecretKey::from_slice(&privkey_bytes).expect("Invalid private key");
    let public_key_secp = secret_key.public_key(&secp);

    // Step 3: Uncompressed public key (65 bytes: 0x04 || x || y)
    let uncompressed_bytes = public_key_secp.serialize_uncompressed();
    let pubkey_hex = hex::encode(uncompressed_bytes);

    println!("  2. Public key (uncompressed):");
    println!("     Length: {} bytes", uncompressed_bytes.len());
    println!("     Prefix: 0x{:02x}", uncompressed_bytes[0]);
    println!("     Full hex: {}", pubkey_hex);

    assert_eq!(
        uncompressed_bytes.len(),
        65,
        "Uncompressed pubkey should be 65 bytes"
    );
    assert_eq!(
        uncompressed_bytes[0], 0x04,
        "Uncompressed pubkey should start with 0x04"
    );

    // Step 4: Hash160 = RIPEMD160(SHA256(pubkey))
    let hash160_value = hash160(&uncompressed_bytes);
    let hash160_hex = hex::encode(hash160_value);
    println!("  3. Hash160: {}", hash160_hex);

    // Step 5: Generate P2PKH address (uncompressed)
    let address_uncompressed = p2pkh_from_hash160(&hash160_value, 0x00);
    println!(
        "  4. P2PKH Address (uncompressed): {}",
        address_uncompressed
    );

    // Verify address format
    assert!(
        address_uncompressed.starts_with('1'),
        "P2PKH address should start with '1'"
    );
    assert!(
        address_uncompressed.len() >= 25 && address_uncompressed.len() <= 34,
        "P2PKH address should be 25-34 characters"
    );

    println!("\n  ⚠️  MANUAL VERIFICATION REQUIRED:");
    println!("     1. Go to https://www.bitaddress.org");
    println!("     2. Click 'Brain Wallet' tab");
    println!("     3. Uncheck 'Use Compressed Public Keys'");
    println!("     4. Enter passphrase: \"{}\"", passphrase);
    println!("     5. Verify address matches: {}", address_uncompressed);
    println!("     6. Verify private key matches: {}", privkey_hex);
    println!("     7. Verify public key matches: {}", pubkey_hex);
    println!("\n  ✅ Uncompressed derivation complete\n");
}

#[test]
fn test_hashcat_passphrase_compressed() {
    println!("\n=== Test: Brainwallet 'hashcat' (Compressed) ===\n");

    let passphrase = "hashcat";
    let secp = Secp256k1::new();
    let network = Network::Bitcoin;

    // Step 1: SHA256(passphrase) -> private key
    let privkey_bytes = Sha256::digest(passphrase.as_bytes());
    let privkey_hex = hex::encode(privkey_bytes);
    println!("  1. Private key (SHA256): {}", privkey_hex);

    // Expected from the prompt
    assert_eq!(
        privkey_hex,
        "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935"
    );

    // Step 2: secp256k1 point multiplication
    let secret_key = SecretKey::from_slice(&privkey_bytes).expect("Invalid private key");
    let public_key_secp = secret_key.public_key(&secp);
    let compressed = CompressedPublicKey(public_key_secp);

    // Step 3: Compressed public key (33 bytes: 0x02/0x03 || x)
    let compressed_bytes = compressed.to_bytes();
    let pubkey_hex = hex::encode(compressed_bytes);

    println!("  2. Public key (compressed):");
    println!("     Length: {} bytes", compressed_bytes.len());
    println!("     Prefix: 0x{:02x}", compressed_bytes[0]);
    println!("     Full hex: {}", pubkey_hex);

    assert_eq!(
        compressed_bytes.len(),
        33,
        "Compressed pubkey should be 33 bytes"
    );
    assert!(
        compressed_bytes[0] == 0x02 || compressed_bytes[0] == 0x03,
        "Compressed pubkey should start with 0x02 or 0x03"
    );

    // Step 4: Hash160 = RIPEMD160(SHA256(pubkey))
    let hash160_value = hash160(&compressed_bytes);
    let hash160_hex = hex::encode(hash160_value);
    println!("  3. Hash160: {}", hash160_hex);

    // Step 5: Generate addresses
    let bitcoin_public_key = to_bitcoin_pubkey(&compressed_bytes);
    let address_p2pkh = Address::p2pkh(bitcoin_public_key, network);
    let address_p2wpkh = Address::p2wpkh(&compressed, network);

    println!("  4. P2PKH Address (compressed):  {}", address_p2pkh);
    println!("  5. P2WPKH Address (SegWit):     {}", address_p2wpkh);

    // Verify address formats
    assert!(
        address_p2pkh.to_string().starts_with('1'),
        "P2PKH address should start with '1'"
    );
    assert!(
        address_p2wpkh.to_string().starts_with("bc1q"),
        "P2WPKH address should start with 'bc1q'"
    );

    println!("\n  ⚠️  MANUAL VERIFICATION REQUIRED:");
    println!("     1. Go to https://www.bitaddress.org");
    println!("     2. Click 'Brain Wallet' tab");
    println!("     3. Check 'Use Compressed Public Keys'");
    println!("     4. Enter passphrase: \"{}\"", passphrase);
    println!("     5. Verify P2PKH address matches: {}", address_p2pkh);
    println!("     6. Verify private key matches: {}", privkey_hex);
    println!("     7. Verify public key matches: {}", pubkey_hex);
    println!("\n  Note: P2WPKH address uses same hash160, different encoding");
    println!("        P2WPKH: {}", address_p2wpkh);
    println!("\n  ✅ Compressed derivation complete\n");
}

#[test]
fn test_hashcat_passphrase_all_formats() {
    println!("\n=== Test: 'hashcat' All Address Formats Summary ===\n");

    let passphrase = "hashcat";
    let secp = Secp256k1::new();
    let network = Network::Bitcoin;

    // Derive private key
    let privkey_bytes = Sha256::digest(passphrase.as_bytes());
    let privkey_hex = hex::encode(privkey_bytes);

    // Generate keys
    let secret_key = SecretKey::from_slice(&privkey_bytes).expect("Invalid private key");
    let public_key_secp = secret_key.public_key(&secp);

    // Uncompressed
    let uncompressed_bytes = public_key_secp.serialize_uncompressed();
    let uncompressed_hash160 = hash160(&uncompressed_bytes);
    let address_uncompressed = p2pkh_from_hash160(&uncompressed_hash160, 0x00);

    // Compressed
    let compressed = CompressedPublicKey(public_key_secp);
    let compressed_bytes = compressed.to_bytes();
    let bitcoin_public_key = to_bitcoin_pubkey(&compressed_bytes);
    let address_p2pkh_compressed = Address::p2pkh(bitcoin_public_key, network);
    let address_p2wpkh = Address::p2wpkh(&compressed, network);
    let address_p2sh_p2wpkh = Address::p2shwpkh(&compressed, network);

    println!("=== Brainwallet Test Vector: 'hashcat' ===");
    println!();
    println!("Private Key:");
    println!("  SHA256('hashcat'): {}", privkey_hex);
    println!();
    println!("Public Keys:");
    println!("  Uncompressed (65): {}", hex::encode(uncompressed_bytes));
    println!("  Compressed   (33): {}", hex::encode(compressed_bytes));
    println!();
    println!("Addresses:");
    println!("  P2PKH (uncompressed):  {}", address_uncompressed);
    println!("  P2PKH (compressed):    {}", address_p2pkh_compressed);
    println!("  P2SH-P2WPKH:           {}", address_p2sh_p2wpkh);
    println!("  P2WPKH:                {}", address_p2wpkh);
    println!();
    println!("Hash160 Values:");
    println!("  Uncompressed: {}", hex::encode(uncompressed_hash160));
    println!(
        "  Compressed:   {}",
        hex::encode(hash160(&compressed_bytes))
    );
    println!();
    // Hashcat Module Test Vectors:
    // Module 01337 uses $bitcoin$ prefix for uncompressed public keys
    // Module 01338 uses $bitcoin-compressed$ prefix for compressed public keys
    println!("Hashcat Module Test Vectors:");
    println!(
        "  Module 01337 (uncompressed): $bitcoin${}",
        address_uncompressed
    );
    println!(
        "  Module 01338 (compressed):   $bitcoin-compressed${}",
        address_p2pkh_compressed
    );
    println!();
    println!("Manual Verification:");
    println!("  https://www.bitaddress.org (Brain Wallet tab)");
    println!();

    // All assertions
    assert_eq!(
        privkey_hex,
        "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935"
    );
    assert_eq!(uncompressed_bytes.len(), 65);
    assert_eq!(compressed_bytes.len(), 33);
    assert!(address_uncompressed.starts_with('1'));
    assert!(address_p2pkh_compressed.to_string().starts_with('1'));
    assert!(address_p2wpkh.to_string().starts_with("bc1q"));
    assert!(address_p2sh_p2wpkh.to_string().starts_with('3'));

    // Verify compressed and uncompressed produce different addresses
    assert_ne!(
        address_uncompressed,
        address_p2pkh_compressed.to_string(),
        "Compressed and uncompressed should produce different P2PKH addresses"
    );

    println!("  ✅ All test vectors generated and verified\n");
}

/// Test additional brainwallet passphrases mentioned in the prompt
#[test]
fn test_additional_brainwallet_passphrases() {
    println!("\n=== Test: Additional Brainwallet Passphrases ===\n");

    let secp = Secp256k1::new();
    let network = Network::Bitcoin;

    let test_cases = vec![
        "satoshi",
        "satoshi nakamoto",
        "correct horse battery staple",
        "bitcoin",
    ];

    for passphrase in test_cases {
        println!("Passphrase: \"{}\"", passphrase);

        // Derive
        let privkey_bytes = Sha256::digest(passphrase.as_bytes());
        let privkey_hex = hex::encode(privkey_bytes);

        let secret_key =
            SecretKey::from_slice(&privkey_bytes).expect("Invalid private key from passphrase");
        let public_key_secp = secret_key.public_key(&secp);
        let compressed = CompressedPublicKey(public_key_secp);

        let compressed_bytes = compressed.to_bytes();
        let bitcoin_public_key = to_bitcoin_pubkey(&compressed_bytes);
        let address_p2pkh = Address::p2pkh(bitcoin_public_key, network);
        let address_p2wpkh = Address::p2wpkh(&compressed, network);

        println!("  Private key: {}", privkey_hex);
        println!("  Compressed pubkey: {}", hex::encode(compressed_bytes));
        println!("  P2PKH:  {}", address_p2pkh);
        println!("  P2WPKH: {}", address_p2wpkh);
        println!();
    }

    println!("  ✅ All additional passphrases processed\n");
}
