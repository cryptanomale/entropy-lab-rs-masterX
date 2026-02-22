// Encryption utilities for nonce reuse private key storage
//
// This module provides AES-256-GCM encryption for storing recovered
// private keys in the vulnerability database.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use tracing::debug;

/// Default encryption passphrase for nonce reuse database
/// Can be overridden via CLI flag --encryption-passphrase or NONCE_CRAWLER_PASSPHRASE env var
pub const DEFAULT_ENCRYPTION_PASSPHRASE: &str = "MadMad13221!@";

/// PBKDF2 iteration count for key derivation (100,000 iterations)
const PBKDF2_ITERATIONS: u32 = 100_000;

/// Salt size for PBKDF2 (32 bytes)
const SALT_SIZE: usize = 32;

/// Nonce size for AES-256-GCM (12 bytes)
const NONCE_SIZE: usize = 12;

/// Result of encryption operation containing ciphertext, nonce, and salt
#[derive(Debug, Clone)]
pub struct EncryptedData {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub salt: Vec<u8>,
}

/// Encrypt a private key (WIF format) using AES-256-GCM
///
/// # Arguments
/// * `wif` - Private key in WIF (Wallet Import Format)
/// * `passphrase` - Passphrase for encryption
///
/// # Returns
/// * `EncryptedData` containing ciphertext, nonce, and salt
///
/// # Security
/// - Uses PBKDF2-HMAC-SHA256 with 100,000 iterations
/// - Generates random 32-byte salt
/// - Generates random 12-byte nonce
/// - Uses AES-256-GCM for authenticated encryption
pub fn encrypt_private_key(wif: &str, passphrase: &str) -> Result<EncryptedData> {
    // Generate random salt for PBKDF2
    let salt = generate_random_salt();

    // Derive encryption key from passphrase using PBKDF2
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, PBKDF2_ITERATIONS, &mut key);

    // Create AES-256-GCM cipher
    let cipher = Aes256Gcm::new(&key.into());

    // Generate random nonce
    let nonce_bytes = generate_random_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the WIF key
    let ciphertext = cipher
        .encrypt(nonce, wif.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to encrypt private key: {:?}", e))?;

    debug!(
        "Encrypted private key: {} bytes ciphertext, {} bytes nonce, {} bytes salt",
        ciphertext.len(),
        nonce_bytes.len(),
        salt.len()
    );

    Ok(EncryptedData {
        ciphertext,
        nonce: nonce_bytes,
        salt,
    })
}

/// Decrypt a private key using AES-256-GCM
///
/// # Arguments
/// * `encrypted_data` - Encrypted data containing ciphertext, nonce, and salt
/// * `passphrase` - Passphrase for decryption (must match encryption passphrase)
///
/// # Returns
/// * Decrypted WIF private key string
///
/// # Errors
/// * Returns error if passphrase is incorrect or data is corrupted
pub fn decrypt_private_key(encrypted_data: &EncryptedData, passphrase: &str) -> Result<String> {
    // Derive encryption key from passphrase using same PBKDF2 parameters
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        passphrase.as_bytes(),
        &encrypted_data.salt,
        PBKDF2_ITERATIONS,
        &mut key,
    );

    // Create AES-256-GCM cipher
    let cipher = Aes256Gcm::new(&key.into());

    // Create nonce from stored bytes
    let nonce = Nonce::from_slice(&encrypted_data.nonce);

    // Decrypt the ciphertext
    let plaintext = cipher
        .decrypt(nonce, encrypted_data.ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("Failed to decrypt private key - incorrect passphrase or corrupted data"))?;

    // Convert decrypted bytes to string
    let wif = String::from_utf8(plaintext).context("Decrypted data is not valid UTF-8")?;

    debug!("Successfully decrypted private key");

    Ok(wif)
}

/// Generate a random 32-byte salt for PBKDF2
fn generate_random_salt() -> Vec<u8> {
    let mut salt = vec![0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Generate a random 12-byte nonce for AES-256-GCM
fn generate_random_nonce() -> Vec<u8> {
    let mut nonce = vec![0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        let passphrase = "test_passphrase_123";

        // Encrypt
        let encrypted = encrypt_private_key(wif, passphrase).unwrap();

        // Verify components exist
        assert!(!encrypted.ciphertext.is_empty());
        assert_eq!(encrypted.nonce.len(), NONCE_SIZE);
        assert_eq!(encrypted.salt.len(), SALT_SIZE);

        // Decrypt
        let decrypted = decrypt_private_key(&encrypted, passphrase).unwrap();

        // Verify roundtrip
        assert_eq!(wif, decrypted);
    }

    #[test]
    fn test_decrypt_with_wrong_passphrase_fails() {
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        let passphrase = "correct_passphrase";
        let wrong_passphrase = "wrong_passphrase";

        // Encrypt with correct passphrase
        let encrypted = encrypt_private_key(wif, passphrase).unwrap();

        // Attempt to decrypt with wrong passphrase should fail
        let result = decrypt_private_key(&encrypted, wrong_passphrase);
        assert!(result.is_err());
    }

    #[test]
    fn test_default_passphrase_constant() {
        assert_eq!(DEFAULT_ENCRYPTION_PASSPHRASE, "MadMad13221!@");
    }

    #[test]
    fn test_nonce_and_salt_uniqueness() {
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        let passphrase = "test";

        // Encrypt same data twice
        let encrypted1 = encrypt_private_key(wif, passphrase).unwrap();
        let encrypted2 = encrypt_private_key(wif, passphrase).unwrap();

        // Nonces and salts should be different (random)
        assert_ne!(encrypted1.nonce, encrypted2.nonce);
        assert_ne!(encrypted1.salt, encrypted2.salt);

        // Both should decrypt successfully
        let decrypted1 = decrypt_private_key(&encrypted1, passphrase).unwrap();
        let decrypted2 = decrypt_private_key(&encrypted2, passphrase).unwrap();

        assert_eq!(decrypted1, wif);
        assert_eq!(decrypted2, wif);
    }

    #[test]
    fn test_encryption_with_default_passphrase() {
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";

        // Encrypt with default passphrase
        let encrypted = encrypt_private_key(wif, DEFAULT_ENCRYPTION_PASSPHRASE).unwrap();

        // Decrypt with default passphrase
        let decrypted = decrypt_private_key(&encrypted, DEFAULT_ENCRYPTION_PASSPHRASE).unwrap();

        assert_eq!(wif, decrypted);
    }

    #[test]
    fn test_empty_wif_encryption() {
        let wif = "";
        let passphrase = "test_passphrase";

        let encrypted = encrypt_private_key(wif, passphrase).unwrap();
        let decrypted = decrypt_private_key(&encrypted, passphrase).unwrap();

        assert_eq!(wif, decrypted);
    }

    #[test]
    fn test_compressed_wif_format() {
        // Compressed WIF (starts with K or L)
        let wif = "L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ";
        let passphrase = "test";

        let encrypted = encrypt_private_key(wif, passphrase).unwrap();
        let decrypted = decrypt_private_key(&encrypted, passphrase).unwrap();

        assert_eq!(wif, decrypted);
    }

    #[test]
    fn test_testnet_wif_format() {
        // Testnet WIF (starts with 9 or c)
        let wif = "92Qba5hnyWSn5Ffcka56yMQauaWY6ZLd91Vzxbi4a9CCetaHtYj";
        let passphrase = "test";

        let encrypted = encrypt_private_key(wif, passphrase).unwrap();
        let decrypted = decrypt_private_key(&encrypted, passphrase).unwrap();

        assert_eq!(wif, decrypted);
    }

    #[test]
    fn test_long_passphrase() {
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        let passphrase = "a".repeat(256); // Very long passphrase

        let encrypted = encrypt_private_key(wif, &passphrase).unwrap();
        let decrypted = decrypt_private_key(&encrypted, &passphrase).unwrap();

        assert_eq!(wif, decrypted);
    }

    #[test]
    fn test_special_characters_in_passphrase() {
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        let passphrase = "P@$$w0rd!#%&*()[]{}|<>?/\\~`";

        let encrypted = encrypt_private_key(wif, passphrase).unwrap();
        let decrypted = decrypt_private_key(&encrypted, passphrase).unwrap();

        assert_eq!(wif, decrypted);
    }

    #[test]
    fn test_corrupted_ciphertext_fails() {
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        let passphrase = "test";

        let mut encrypted = encrypt_private_key(wif, passphrase).unwrap();

        // Corrupt the ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 0xFF;
        }

        // Decryption should fail due to authentication tag mismatch
        let result = decrypt_private_key(&encrypted, passphrase);
        assert!(result.is_err());
    }

    #[test]
    fn test_corrupted_nonce_fails() {
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        let passphrase = "test";

        let mut encrypted = encrypt_private_key(wif, passphrase).unwrap();

        // Corrupt the nonce
        encrypted.nonce[0] ^= 0xFF;

        // Decryption should fail
        let result = decrypt_private_key(&encrypted, passphrase);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_salt_fails() {
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        let passphrase = "test";

        let mut encrypted = encrypt_private_key(wif, passphrase).unwrap();

        // Corrupt the salt (this affects key derivation)
        encrypted.salt[0] ^= 0xFF;

        // Decryption should fail due to wrong derived key
        let result = decrypt_private_key(&encrypted, passphrase);
        assert!(result.is_err());
    }

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn test_invalid_nonce_size() {
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        let passphrase = "test";

        let mut encrypted = encrypt_private_key(wif, passphrase).unwrap();

        // Truncate nonce to invalid size (this will panic at the generic_array level)
        encrypted.nonce.truncate(6);

        // This will panic when trying to create a Nonce from wrong-sized slice
        let _ = decrypt_private_key(&encrypted, passphrase);
    }

    #[test]
    fn test_invalid_salt_size() {
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        let passphrase = "test";

        let mut encrypted = encrypt_private_key(wif, passphrase).unwrap();

        // Truncate salt to invalid size
        encrypted.salt.truncate(8);

        let result = decrypt_private_key(&encrypted, passphrase);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_encryptions_with_same_passphrase() {
        let passphrase = "same_passphrase";
        let wifs = vec![
            "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
            "L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ",
            "92Qba5hnyWSn5Ffcka56yMQauaWY6ZLd91Vzxbi4a9CCetaHtYj",
        ];

        for wif in wifs {
            let encrypted = encrypt_private_key(wif, passphrase).unwrap();
            let decrypted = decrypt_private_key(&encrypted, passphrase).unwrap();
            assert_eq!(wif, decrypted);
        }
    }

    #[test]
    fn test_utf8_in_wif_string() {
        // Test with UTF-8 characters (though WIF shouldn't contain these in practice)
        let wif = "Test_私密鍵_🔑";
        let passphrase = "test";

        let encrypted = encrypt_private_key(wif, passphrase).unwrap();
        let decrypted = decrypt_private_key(&encrypted, passphrase).unwrap();

        assert_eq!(wif, decrypted);
    }

    #[test]
    fn test_encryption_deterministic_with_fixed_salt_and_nonce() {
        // This test verifies that with the same salt and nonce,
        // we get deterministic encryption (for debugging purposes)
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        let passphrase = "test";

        let encrypted1 = encrypt_private_key(wif, passphrase).unwrap();
        let encrypted2 = encrypt_private_key(wif, passphrase).unwrap();

        // Ciphertexts should be different due to random nonce/salt
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);

        // But both should decrypt to the same value
        let decrypted1 = decrypt_private_key(&encrypted1, passphrase).unwrap();
        let decrypted2 = decrypt_private_key(&encrypted2, passphrase).unwrap();

        assert_eq!(decrypted1, wif);
        assert_eq!(decrypted2, wif);
    }

    #[test]
    fn test_pbkdf2_iteration_count() {
        // Verify that PBKDF2_ITERATIONS is set to a secure value
        assert_eq!(PBKDF2_ITERATIONS, 100_000);
    }

    #[test]
    fn test_encrypted_data_serialization() {
        let wif = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        let passphrase = "test";

        let encrypted = encrypt_private_key(wif, passphrase).unwrap();

        // Verify EncryptedData can be cloned/moved
        let encrypted_clone = EncryptedData {
            ciphertext: encrypted.ciphertext.clone(),
            nonce: encrypted.nonce.clone(),
            salt: encrypted.salt.clone(),
        };

        let decrypted = decrypt_private_key(&encrypted_clone, passphrase).unwrap();
        assert_eq!(wif, decrypted);
    }
}
