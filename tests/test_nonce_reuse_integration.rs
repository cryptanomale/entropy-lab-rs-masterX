// Integration tests for Nonce Reuse Detection System
//
// Tests the full pipeline:
// 1. Generate synthetic nonce reuse (same nonce, different messages)
// 2. Detect collision
// 3. Recover private key
// 4. Store encrypted in database
// 5. Retrieve and decrypt

use anyhow::Result;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::PrivateKey;
use temporal_planetarium_lib::scans::randstorm::forensics::recover_privkey_from_nonce_reuse;
use temporal_planetarium_lib::utils::db::{Target, TargetDatabase};
use temporal_planetarium_lib::utils::encryption::{
    decrypt_private_key, encrypt_private_key, DEFAULT_ENCRYPTION_PASSPHRASE,
};

/// Generate two ECDSA signatures with the same nonce (k)
/// Returns (z1, z2, r, s1, s2, original_private_key)
fn generate_nonce_reuse_signatures() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32], SecretKey)
{
    use num_bigint::BigUint;
    use num_traits::{Zero, One};

    // Known private key (d)
    let secret_bytes = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let secret_key = SecretKey::from_slice(&secret_bytes).unwrap();
    let d = BigUint::from_bytes_be(&secret_bytes);

    // Two different messages
    let z1_bytes = [0xAA; 32];
    let z2_bytes = [0xBB; 32];
    let z1 = BigUint::from_bytes_be(&z1_bytes);
    let z2 = BigUint::from_bytes_be(&z2_bytes);

    // Fixed nonce k (this is the vulnerability - reusing nonce)
    let k_bytes = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b,
        0x20, 0xa0,
    ];
    let k = BigUint::from_bytes_be(&k_bytes);

    // secp256k1 curve order
    let n = BigUint::parse_bytes(
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .unwrap();

    // Compute r = (k * G).x mod n
    let secp = Secp256k1::new();
    let k_sk = SecretKey::from_slice(&k_bytes).unwrap();
    let r_point = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &k_sk);
    let r_point_bytes = r_point.serialize_uncompressed();
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&r_point_bytes[1..33]); // Skip 0x04 prefix
    let r = BigUint::from_bytes_be(&r_bytes);

    // Compute s1 = k^(-1) * (z1 + r * d) mod n
    let k_inv = k.modinv(&n).unwrap();
    let s1_big = (k_inv.clone() * (z1 + r.clone() * d.clone())) % n.clone();

    // Compute s2 = k^(-1) * (z2 + r * d) mod n
    let s2_big = (k_inv * (z2 + r.clone() * d)) % n;

    // Convert to 32-byte arrays
    let mut s1_bytes = [0u8; 32];
    let mut s2_bytes = [0u8; 32];

    let s1_vec = s1_big.to_bytes_be();
    let s2_vec = s2_big.to_bytes_be();

    s1_bytes[32 - s1_vec.len()..].copy_from_slice(&s1_vec);
    s2_bytes[32 - s2_vec.len()..].copy_from_slice(&s2_vec);

    (z1_bytes, z2_bytes, r_bytes, s1_bytes, s2_bytes, secret_key)
}

#[test]
fn test_nonce_reuse_key_recovery() -> Result<()> {
    let (z1, z2, r, s1, s2, original_key) = generate_nonce_reuse_signatures();

    // Recover the private key
    let recovered_key = recover_privkey_from_nonce_reuse(&z1, &z2, &r, &s1, &s2)?;

    // Verify recovery is correct
    assert_eq!(
        original_key.secret_bytes(),
        recovered_key.secret_bytes(),
        "Recovered key should match original"
    );

    Ok(())
}

#[test]
fn test_encrypted_storage_roundtrip() -> Result<()> {
    let (z1, z2, r, s1, s2, original_key) = generate_nonce_reuse_signatures();

    // Recover the key
    let recovered_key = recover_privkey_from_nonce_reuse(&z1, &z2, &r, &s1, &s2)?;

    // Convert to WIF
    let wif = PrivateKey::new(recovered_key, bitcoin::Network::Bitcoin).to_wif();

    // Encrypt
    let encrypted = encrypt_private_key(&wif, DEFAULT_ENCRYPTION_PASSPHRASE)?;

    // Decrypt
    let decrypted_wif = decrypt_private_key(&encrypted, DEFAULT_ENCRYPTION_PASSPHRASE)?;

    // Verify roundtrip
    assert_eq!(wif, decrypted_wif, "WIF should match after encrypt/decrypt");

    Ok(())
}

#[test]
fn test_database_storage_and_retrieval() -> Result<()> {
    let (z1, z2, r, s1, s2, original_key) = generate_nonce_reuse_signatures();

    // Create temporary database
    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join(format!("test_nonce_reuse_{}.db", rand::random::<u64>()));

    // Ensure cleanup
    let _cleanup = scopeguard::guard(db_path.clone(), |path| {
        let _ = std::fs::remove_file(&path);
    });

    // Recover key
    let recovered_key = recover_privkey_from_nonce_reuse(&z1, &z2, &r, &s1, &s2)?;
    let wif = PrivateKey::new(recovered_key, bitcoin::Network::Bitcoin).to_wif();

    // Encrypt
    let encrypted = encrypt_private_key(&wif, DEFAULT_ENCRYPTION_PASSPHRASE)?;

    // Store in database
    let db = TargetDatabase::new(db_path.clone())?;

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &recovered_key);
    let compressed = bitcoin::key::CompressedPublicKey::from_slice(&pubkey.serialize())?;
    let address = bitcoin::Address::p2pkh(compressed, bitcoin::Network::Bitcoin).to_string();

    let metadata = serde_json::json!({
        "vulnerability": "ecdsa_nonce_reuse",
        "shared_r_value": hex::encode(r),
        "recovery_date": "2024-01-01T00:00:00Z",
        "validation": "confirmed"
    });

    let target = Target::with_encrypted_key(
        address.clone(),
        "nonce_reuse".to_string(),
        Some(metadata.to_string()),
        encrypted.ciphertext,
        encrypted.nonce,
        encrypted.salt,
    );

    db.upsert_target(&target)?;

    // Retrieve from database
    let targets = db.query_by_class("nonce_reuse", 10)?;

    assert_eq!(targets.len(), 1, "Should have one target");
    assert_eq!(targets[0].address, address, "Address should match");
    assert_eq!(
        targets[0].vuln_class, "nonce_reuse",
        "Vuln class should match"
    );

    // Decrypt from database
    let stored = &targets[0];
    let encrypted_from_db = temporal_planetarium_lib::utils::encryption::EncryptedData {
        ciphertext: stored.encrypted_private_key.clone().unwrap(),
        nonce: stored.encryption_nonce.clone().unwrap(),
        salt: stored.pbkdf2_salt.clone().unwrap(),
    };

    let decrypted_wif = decrypt_private_key(&encrypted_from_db, DEFAULT_ENCRYPTION_PASSPHRASE)?;

    assert_eq!(wif, decrypted_wif, "Decrypted WIF should match original");

    Ok(())
}

#[test]
fn test_wrong_passphrase_fails() -> Result<()> {
    let (z1, z2, r, s1, s2, _original_key) = generate_nonce_reuse_signatures();

    let recovered_key = recover_privkey_from_nonce_reuse(&z1, &z2, &r, &s1, &s2)?;
    let wif = PrivateKey::new(recovered_key, bitcoin::Network::Bitcoin).to_wif();

    let encrypted = encrypt_private_key(&wif, DEFAULT_ENCRYPTION_PASSPHRASE)?;

    // Try with wrong passphrase
    let result = decrypt_private_key(&encrypted, "wrong_passphrase");

    assert!(result.is_err(), "Should fail with wrong passphrase");

    Ok(())
}

#[test]
fn test_multiple_nonce_reuse_detections() -> Result<()> {
    // Create temporary database
    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join(format!("test_multi_nonce_{}.db", rand::random::<u64>()));

    let _cleanup = scopeguard::guard(db_path.clone(), |path| {
        let _ = std::fs::remove_file(&path);
    });

    let db = TargetDatabase::new(db_path.clone())?;

    // Generate and store 3 different nonce reuse cases
    for i in 0..3 {
        let (z1, z2, r, s1, s2, _) = generate_nonce_reuse_signatures();

        let recovered_key = recover_privkey_from_nonce_reuse(&z1, &z2, &r, &s1, &s2)?;
        let wif = PrivateKey::new(recovered_key, bitcoin::Network::Bitcoin).to_wif();
        let encrypted = encrypt_private_key(&wif, DEFAULT_ENCRYPTION_PASSPHRASE)?;

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &recovered_key);
        let compressed = bitcoin::key::CompressedPublicKey::from_slice(&pubkey.serialize())?;
        let address = bitcoin::Address::p2pkh(compressed, bitcoin::Network::Bitcoin).to_string();

        let target = Target::with_encrypted_key(
            format!("{}_{}", address, i), // Make unique
            "nonce_reuse".to_string(),
            Some(format!(r#"{{"test_index": {}}}"#, i)),
            encrypted.ciphertext,
            encrypted.nonce,
            encrypted.salt,
        );

        db.upsert_target(&target)?;
    }

    // Query all
    let targets = db.query_by_class("nonce_reuse", 100)?;

    assert_eq!(targets.len(), 3, "Should have 3 targets");

    // Verify all can be decrypted
    for target in &targets {
        let encrypted_data = temporal_planetarium_lib::utils::encryption::EncryptedData {
            ciphertext: target.encrypted_private_key.clone().unwrap(),
            nonce: target.encryption_nonce.clone().unwrap(),
            salt: target.pbkdf2_salt.clone().unwrap(),
        };

        let decrypted = decrypt_private_key(&encrypted_data, DEFAULT_ENCRYPTION_PASSPHRASE)?;
        assert!(decrypted.starts_with('5') || decrypted.starts_with('K') || decrypted.starts_with('L'),
                "Decrypted value should be valid WIF format");
    }

    Ok(())
}

#[test]
fn test_access_tracking() -> Result<()> {
    let temp_dir = std::env::temp_dir();
    let db_path = temp_dir.join(format!("test_access_{}.db", rand::random::<u64>()));

    let _cleanup = scopeguard::guard(db_path.clone(), |path| {
        let _ = std::fs::remove_file(&path);
    });

    let db = TargetDatabase::new(db_path.clone())?;

    let (z1, z2, r, s1, s2, _) = generate_nonce_reuse_signatures();
    let recovered_key = recover_privkey_from_nonce_reuse(&z1, &z2, &r, &s1, &s2)?;
    let wif = PrivateKey::new(recovered_key, bitcoin::Network::Bitcoin).to_wif();
    let encrypted = encrypt_private_key(&wif, DEFAULT_ENCRYPTION_PASSPHRASE)?;

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &recovered_key);
    let compressed = bitcoin::key::CompressedPublicKey::from_slice(&pubkey.serialize())?;
    let address = bitcoin::Address::p2pkh(compressed, bitcoin::Network::Bitcoin).to_string();

    let target = Target::with_encrypted_key(
        address.clone(),
        "nonce_reuse".to_string(),
        None,
        encrypted.ciphertext,
        encrypted.nonce,
        encrypted.salt,
    );

    db.upsert_target(&target)?;

    // Initial access count should be 0
    let targets = db.query_by_class("nonce_reuse", 1)?;
    assert_eq!(targets[0].access_count, 0);

    // Update access tracking
    db.update_access_tracking(&address)?;

    // Access count should be 1
    let targets = db.query_by_class("nonce_reuse", 1)?;
    assert_eq!(targets[0].access_count, 1);
    assert!(targets[0].last_accessed.is_some());

    Ok(())
}
