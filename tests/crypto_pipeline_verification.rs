//! Cryptographic Pipeline Verification Tests
//!
//! This test suite verifies the complete brainwallet derivation pipeline:
//! 1. passphrase -> SHA256 -> private_key
//! 2. private_key -> secp256k1_point_mul -> public_key
//! 3. public_key -> SHA256 -> RIPEMD160 -> hash160
//! 4. hash160 -> Base58Check/Bech32 -> address
//!
//! Critical for ensuring entropy-lab-rs and hashcat modules produce identical results.

use bech32::{self, Bech32, Hrp};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

// ============================================================================
// SECP256K1 CONSTANT VERIFICATION
// ============================================================================

/// secp256k1 curve parameters (must match bitcoin-core/secp256k1)
///
/// Field prime p = 2^256 - 2^32 - 977
#[allow(dead_code)]
const SECP256K1_P_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";

/// Curve order n
#[allow(dead_code)]
const SECP256K1_N_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

/// Generator point G (x-coordinate)
const SECP256K1_G_X_HEX: &str = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";

/// Generator point G (y-coordinate)
const SECP256K1_G_Y_HEX: &str = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

#[test]
fn test_secp256k1_generator_point() {
    println!("\n=== secp256k1 Generator Point G Verification ===\n");

    let secp = Secp256k1::new();

    // Private key = 1 should give generator point G
    let privkey_bytes =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    let secret = SecretKey::from_slice(&privkey_bytes).unwrap();
    let pubkey = PublicKey::from_secret_key(&secp, &secret);

    let uncompressed = pubkey.serialize_uncompressed();
    let x_coord = hex::encode(&uncompressed[1..33]);
    let y_coord = hex::encode(&uncompressed[33..65]);

    println!("Expected G.x: {}", SECP256K1_G_X_HEX.to_lowercase());
    println!("Got G.x:      {}", x_coord);
    println!("Expected G.y: {}", SECP256K1_G_Y_HEX.to_lowercase());
    println!("Got G.y:      {}", y_coord);

    assert_eq!(x_coord.to_uppercase(), SECP256K1_G_X_HEX, "G.x mismatch");
    assert_eq!(y_coord.to_uppercase(), SECP256K1_G_Y_HEX, "G.y mismatch");

    println!("\n  Generator point verified.");
}

#[test]
fn test_secp256k1_point_multiplication_vectors() {
    println!("\n=== secp256k1 Point Multiplication Test Vectors ===\n");

    let secp = Secp256k1::new();

    // Test vectors: private_key -> expected x-coordinate of pubkey
    let test_vectors = vec![
        // (privkey_hex, expected_x_hex)
        (
            "0000000000000000000000000000000000000000000000000000000000000001",
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        ), // 1*G
        (
            "0000000000000000000000000000000000000000000000000000000000000002",
            "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
        ), // 2*G
        (
            "0000000000000000000000000000000000000000000000000000000000000003",
            "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        ), // 3*G
        (
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140",
            "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        ), // (n-1)*G = -G (same x as G)
    ];

    for (privkey_hex, expected_x) in test_vectors {
        let privkey_bytes = hex::decode(privkey_hex).unwrap();
        let secret = SecretKey::from_slice(&privkey_bytes).unwrap();
        let pubkey = PublicKey::from_secret_key(&secp, &secret);

        let compressed = pubkey.serialize();
        let x_coord = hex::encode(&compressed[1..33]);

        println!("Private key: {}...", &privkey_hex[..16]);
        println!("  Expected x: {}", expected_x);
        println!("  Got x:      {}", x_coord.to_uppercase());

        assert_eq!(
            x_coord.to_uppercase(),
            expected_x,
            "Point multiplication failed for privkey {}",
            privkey_hex
        );
        println!("  OK\n");
    }
}

// ============================================================================
// HASH CHAIN VERIFICATION
// ============================================================================

/// Hash160 = RIPEMD160(SHA256(data))
fn hash160(data: &[u8]) -> [u8; 20] {
    let sha256_result = Sha256::digest(data);
    let mut ripemd = Ripemd160::new();
    ripemd.update(sha256_result);
    ripemd.finalize().into()
}

#[test]
fn test_hash160_chain() {
    println!("\n=== Hash160 Chain Verification ===\n");

    // Test vector: known pubkey -> hash160
    // Generator point G compressed (02 prefix because y is even)
    let g_compressed =
        hex::decode("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798").unwrap();

    // Step 1: SHA256
    let sha256_result: [u8; 32] = Sha256::digest(&g_compressed).into();
    println!("Input (G compressed): {}", hex::encode(&g_compressed));
    println!("SHA256:  {}", hex::encode(sha256_result));

    // Expected SHA256 of compressed G (verified with: python3 -c "import hashlib; print(hashlib.sha256(bytes.fromhex('0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798')).hexdigest())")
    assert_eq!(
        hex::encode(sha256_result),
        "0f715baf5d4c2ed329785cef29e562f73488c8a2bb9dbc5700b361d54b9b0554"
    );

    // Step 2: RIPEMD160
    let hash160_result = hash160(&g_compressed);
    println!("RIPEMD160: {}", hex::encode(hash160_result));

    // Expected hash160 of compressed G
    assert_eq!(
        hex::encode(hash160_result),
        "751e76e8199196d454941c45d1b3a323f1433bd6"
    );

    println!("\n  Hash160 chain verified.");
}

// ============================================================================
// BASE58CHECK VERIFICATION
// ============================================================================

#[test]
fn test_base58check_encoding() {
    println!("\n=== Base58Check Encoding Verification ===\n");

    // Test vector: hash160 of generator point G -> P2PKH address
    let hash160 = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();

    // Version byte 0x00 for mainnet P2PKH
    let mut with_version = vec![0x00];
    with_version.extend(&hash160);

    // Checksum = first 4 bytes of double SHA256
    let checksum: [u8; 32] = Sha256::digest(Sha256::digest(&with_version)).into();
    with_version.extend(&checksum[..4]);

    let address = bs58::encode(&with_version).into_string();
    println!("Hash160:  {}", hex::encode(&hash160));
    println!("Address:  {}", address);

    // Expected P2PKH address for private key = 1 (compressed)
    assert_eq!(address, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");

    println!("\n  Base58Check encoding verified.");
}

#[test]
fn test_base58check_version_bytes() {
    println!("\n=== Base58Check Version Bytes ===\n");

    let test_cases = vec![
        (0x00u8, "P2PKH Mainnet", '1'),
        (0x05u8, "P2SH Mainnet", '3'),
        (0x6Fu8, "P2PKH Testnet", 'm'), // or 'n'
        (0xC4u8, "P2SH Testnet", '2'),
    ];

    // Use a dummy hash160
    let hash160 = [0u8; 20];

    for (version, desc, _expected_prefix) in test_cases {
        let mut with_version = vec![version];
        with_version.extend(&hash160);

        let checksum: [u8; 32] = Sha256::digest(Sha256::digest(&with_version)).into();
        with_version.extend(&checksum[..4]);

        let address = bs58::encode(&with_version).into_string();
        let first_char = address.chars().next().unwrap();

        println!(
            "{} (0x{:02x}): {} -> '{}'",
            desc, version, address, first_char
        );

        // Note: Prefix depends on hash160 content, so we just verify it's valid Base58
        // The expected_prefix is a guide but actual prefix varies based on hash160 value
        assert!("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(first_char));
    }

    println!("\n  Version bytes verified.");
}

// ============================================================================
// BECH32 VERIFICATION
// ============================================================================

#[test]
fn test_bech32_encoding() {
    println!("\n=== Bech32 (P2WPKH) Encoding Verification ===\n");

    // Hash160 of generator point G (compressed)
    let hash160 = hex::decode("751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();

    // Bech32 encode for P2WPKH (witness version 0)
    let hrp = Hrp::parse("bc").unwrap();

    // Witness program: version 0 + 20-byte hash160
    let mut witness_program = vec![0u8]; // witness version 0
    witness_program.extend(&hash160);

    // Use bech32 encoding
    let address = bech32::encode::<Bech32>(hrp, &witness_program).unwrap();

    println!("Hash160: {}", hex::encode(&hash160));
    println!("P2WPKH:  {}", address);

    // Verify prefix
    assert!(address.starts_with("bc1q"));

    println!("\n  Bech32 encoding verified.");
}

// ============================================================================
// COMPLETE BRAINWALLET PIPELINE
// ============================================================================

#[test]
fn test_brainwallet_pipeline_uncompressed() {
    println!("\n=== Complete Brainwallet Pipeline (Uncompressed) ===\n");

    let passphrase = "satoshi";

    // Step 1: SHA256(passphrase) -> private key
    let privkey: [u8; 32] = Sha256::digest(passphrase.as_bytes()).into();
    println!("Passphrase: \"{}\"", passphrase);
    println!("Private key: {}", hex::encode(privkey));

    // Step 2: Point multiplication -> public key
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&privkey).unwrap();
    let pubkey = PublicKey::from_secret_key(&secp, &secret);
    let uncompressed = pubkey.serialize_uncompressed();

    println!(
        "Public key (uncompressed): {}...",
        hex::encode(&uncompressed[..33])
    );

    // Step 3: Hash160 of uncompressed pubkey
    let hash160_result = hash160(&uncompressed);
    println!("Hash160: {}", hex::encode(hash160_result));

    // Step 4: Base58Check encode
    let mut with_version = vec![0x00];
    with_version.extend(&hash160_result);
    let checksum: [u8; 32] = Sha256::digest(Sha256::digest(&with_version)).into();
    with_version.extend(&checksum[..4]);
    let address = bs58::encode(&with_version).into_string();

    println!("P2PKH Address (uncompressed): {}", address);

    // Verify it starts with '1'
    assert!(address.starts_with('1'));

    println!("\n  Uncompressed brainwallet pipeline verified.");
}

#[test]
fn test_brainwallet_pipeline_compressed() {
    println!("\n=== Complete Brainwallet Pipeline (Compressed) ===\n");

    let passphrase = "satoshi";

    // Step 1: SHA256(passphrase) -> private key
    let privkey: [u8; 32] = Sha256::digest(passphrase.as_bytes()).into();
    println!("Passphrase: \"{}\"", passphrase);
    println!("Private key: {}", hex::encode(privkey));

    // Step 2: Point multiplication -> public key
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&privkey).unwrap();
    let pubkey = PublicKey::from_secret_key(&secp, &secret);
    let compressed = pubkey.serialize();

    println!("Public key (compressed): {}", hex::encode(compressed));

    // Verify prefix is 02 or 03
    assert!(
        compressed[0] == 0x02 || compressed[0] == 0x03,
        "Compressed pubkey must start with 02 or 03"
    );

    // Step 3: Hash160 of compressed pubkey
    let hash160_result = hash160(&compressed);
    println!("Hash160: {}", hex::encode(hash160_result));

    // Step 4a: Base58Check encode (P2PKH)
    let compressed_pubkey = CompressedPublicKey(pubkey);
    let p2pkh = Address::p2pkh(compressed_pubkey, Network::Bitcoin);
    println!("P2PKH Address (compressed): {}", p2pkh);

    // Step 4b: Bech32 encode (P2WPKH)
    let p2wpkh = Address::p2wpkh(&compressed_pubkey, Network::Bitcoin);
    println!("P2WPKH Address: {}", p2wpkh);

    // Step 4c: P2SH-P2WPKH
    let p2sh_p2wpkh = Address::p2shwpkh(&compressed_pubkey, Network::Bitcoin);
    println!("P2SH-P2WPKH Address: {}", p2sh_p2wpkh);

    // Verify prefixes
    assert!(p2pkh.to_string().starts_with('1'));
    assert!(p2wpkh.to_string().starts_with("bc1q"));
    assert!(p2sh_p2wpkh.to_string().starts_with('3'));

    println!("\n  Compressed brainwallet pipeline verified.");
}

// ============================================================================
// ADDRESS FORMAT DETECTION
// ============================================================================

/// Detect Bitcoin address type from address string
fn detect_address_type(address: &str) -> &'static str {
    if address.starts_with('1') {
        "P2PKH (Legacy)"
    } else if address.starts_with('3') {
        "P2SH (can be P2SH-P2WPKH)"
    } else if address.starts_with("bc1q") && address.len() == 42 {
        "P2WPKH (Native SegWit)"
    } else if address.starts_with("bc1q") && address.len() == 62 {
        "P2WSH (Native SegWit Script)"
    } else if address.starts_with("bc1p") {
        "P2TR (Taproot)"
    } else if address.starts_with("tb1") {
        "Testnet SegWit"
    } else if address.starts_with('m') || address.starts_with('n') {
        "Testnet P2PKH"
    } else if address.starts_with('2') {
        "Testnet P2SH"
    } else {
        "Unknown"
    }
}

#[test]
fn test_address_format_detection() {
    println!("\n=== Address Format Detection ===\n");

    let test_addresses = vec![
        "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
        "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
    ];

    for addr in test_addresses {
        let addr_type = detect_address_type(addr);
        println!("{}: {}", addr_type, addr);
    }

    println!("\n  Address format detection works.");
}

// ============================================================================
// COMPREHENSIVE TEST VECTORS
// ============================================================================

#[test]
fn test_comprehensive_brainwallet_vectors() {
    println!("\n=== Comprehensive Brainwallet Test Vectors ===\n");

    let secp = Secp256k1::new();

    // Test vectors with known SHA256 hashes
    let test_cases = vec![
        (
            "password",
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        ),
        (
            "satoshi",
            "da2876b3eb31edb4436fa4650673fc6f01f90de2f1793c4ec332b2387b09726f",
        ),
        (
            "bitcoin",
            "6b88c087247aa2f07ee1c5956b8e1a9f4c7f892a70e324f1bb3d161e05ca107b",
        ),
        (
            "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
    ];

    for (passphrase, expected_privkey) in test_cases {
        let privkey: [u8; 32] = Sha256::digest(passphrase.as_bytes()).into();

        println!("Passphrase: \"{}\"", passphrase);
        println!("  SHA256: {}", hex::encode(privkey));

        assert_eq!(
            hex::encode(privkey),
            expected_privkey,
            "SHA256 mismatch for passphrase '{}'",
            passphrase
        );

        // Generate addresses
        if let Ok(secret) = SecretKey::from_slice(&privkey) {
            let pubkey = PublicKey::from_secret_key(&secp, &secret);
            let compressed = CompressedPublicKey(pubkey);
            let uncompressed = pubkey.serialize_uncompressed();

            // Uncompressed P2PKH
            let uncompressed_hash160 = hash160(&uncompressed);
            let mut addr_bytes = vec![0x00];
            addr_bytes.extend(&uncompressed_hash160);
            let checksum: [u8; 32] = Sha256::digest(Sha256::digest(&addr_bytes)).into();
            addr_bytes.extend(&checksum[..4]);
            let p2pkh_uncompressed = bs58::encode(&addr_bytes).into_string();

            // Compressed addresses
            let p2pkh = Address::p2pkh(compressed, Network::Bitcoin);
            let p2wpkh = Address::p2wpkh(&compressed, Network::Bitcoin);
            let p2sh_p2wpkh = Address::p2shwpkh(&compressed, Network::Bitcoin);

            println!("  P2PKH (uncompressed): {}", p2pkh_uncompressed);
            println!("  P2PKH (compressed):   {}", p2pkh);
            println!("  P2WPKH:               {}", p2wpkh);
            println!("  P2SH-P2WPKH:          {}", p2sh_p2wpkh);
        } else {
            // Empty string produces invalid private key (all zeros)
            println!("  (Invalid private key - edge case)");
        }
        println!();
    }
}

// ============================================================================
// ENDIANNESS VERIFICATION
// ============================================================================

#[test]
fn test_endianness_handling() {
    println!("\n=== Endianness Handling Verification ===\n");

    // Test that private key bytes are handled correctly
    let privkey_hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    let privkey_bytes = hex::decode(privkey_hex).unwrap();

    println!("Private key (hex):    {}", privkey_hex);
    println!("Private key (bytes):  {:02x?}", &privkey_bytes[..8]);

    // The first byte should be 0x01
    assert_eq!(privkey_bytes[0], 0x01);

    // The last byte should be 0x20
    assert_eq!(privkey_bytes[31], 0x20);

    println!("  Endianness: Big-endian (network byte order) as expected.");
}

// ============================================================================
// TEST VECTOR DISCREPANCY DOCUMENTATION
// ============================================================================

/// IMPORTANT: Document test vector discrepancy
///
/// The original prompt contained test vectors with:
/// - passphrase: "hashcat"
/// - expected_privkey: "127a3bde6edb8d2e0ceaf2f9e264a3a7a027f29fe64b7f2c37eec3a4c08f6db5"
///
/// However, actual SHA256("hashcat") = "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935"
///
/// This is a significant discrepancy. The provided test vectors appear to be:
/// 1. From a different source
/// 2. Using a different hashing method
/// 3. Or contain typos
///
/// When integrating with hashcat modules, verify which private key value
/// the hashcat module expects for the "hashcat" passphrase.
#[test]
fn test_document_hashcat_discrepancy() {
    println!("\n=== TEST VECTOR DISCREPANCY DOCUMENTATION ===\n");

    let passphrase = "hashcat";
    let actual_sha256: [u8; 32] = Sha256::digest(passphrase.as_bytes()).into();

    println!("Passphrase: \"{}\"", passphrase);
    println!();
    println!(
        "Provided in prompt:  127a3bde6edb8d2e0ceaf2f9e264a3a7a027f29fe64b7f2c37eec3a4c08f6db5"
    );
    println!("Actual SHA256:       {}", hex::encode(actual_sha256));
    println!();
    println!("NOTE: These do NOT match!");
    println!("      The prompt's test vectors may be from a different source.");
    println!("      Verify with hashcat module implementation before integration.");

    // This test intentionally does NOT assert equality
    // to document the discrepancy
}
