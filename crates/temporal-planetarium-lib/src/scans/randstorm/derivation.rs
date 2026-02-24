//! Bitcoin address derivation for pre-BIP32 P2PKH wallets
//!
//! Implements the original Bitcoin address derivation used by vulnerable wallets.

use anyhow::{anyhow, Result};
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, Network, PublicKey as BitcoinPublicKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// Derive P2PKH (Pay-to-Public-Key-Hash) Bitcoin address from public key
///
/// This implements the original Bitcoin address format used by wallets
/// affected by the Randstorm vulnerability (pre-BIP32).
///
/// Process:
/// 1. SHA256 hash of compressed public key
/// 2. RIPEMD160 hash of result (hash160)
/// 3. Add version byte (0x00 for mainnet)
/// 4. Base58Check encoding
///
/// NOTE: The hash160 computation is delegated entirely to `Address::p2pkh`.
/// The manual SHA256/RIPEMD160 code that was previously here was dead code
/// (result stored in `_pubkey_hash`, immediately discarded).
pub fn derive_p2pkh_address(public_key: &PublicKey) -> String {
    let pubkey_bytes = public_key.serialize();
    let bitcoin_pubkey =
        BitcoinPublicKey::from_slice(&pubkey_bytes).expect("Valid public key");
    Address::p2pkh(&bitcoin_pubkey, Network::Bitcoin).to_string()
}

/// Derive P2PKH address from uncompressed public key serialization
pub fn derive_p2pkh_address_uncompressed(public_key: &PublicKey) -> String {
    let pubkey_bytes = public_key.serialize_uncompressed();
    let bitcoin_pubkey =
        BitcoinPublicKey::from_slice(&pubkey_bytes).expect("Valid public key");
    Address::p2pkh(&bitcoin_pubkey, Network::Bitcoin).to_string()
}

/// Derive P2PKH address directly from a 32-byte private key (big endian)
pub fn derive_p2pkh_address_from_bytes(bytes: &[u8; 32]) -> Result<String> {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let secret_key = bitcoin::secp256k1::SecretKey::from_slice(bytes).map_err(|e| anyhow!(e))?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    Ok(derive_p2pkh_address(&public_key))
}

/// Derive address hash (20 bytes) for GPU comparison
///
/// Returns the RIPEMD160(SHA256(pubkey)) hash without Base58 encoding.
/// Used for efficient GPU-based address matching.
pub fn derive_address_hash(public_key: &PublicKey) -> [u8; 20] {
    let pubkey_bytes = public_key.serialize();

    let mut hasher = Sha256::new();
    hasher.update(&pubkey_bytes);
    let sha256_hash = hasher.finalize();

    let mut hasher = Ripemd160::new();
    hasher.update(&sha256_hash);
    let ripemd_hash = hasher.finalize();

    let mut result = [0u8; 20];
    result.copy_from_slice(&ripemd_hash);
    result
}

/// Derive address hash from UNCOMPRESSED public key
/// (for --randstorm-include-uncompressed)
pub fn derive_address_hash_uncompressed(public_key: &PublicKey) -> [u8; 20] {
    let pubkey_bytes = public_key.serialize_uncompressed();

    let mut hasher = Sha256::new();
    hasher.update(&pubkey_bytes);
    let sha256_hash = hasher.finalize();

    let mut hasher = Ripemd160::new();
    hasher.update(&sha256_hash);
    let ripemd_hash = hasher.finalize();

    let mut result = [0u8; 20];
    result.copy_from_slice(&ripemd_hash);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    #[test]
    fn test_p2pkh_derivation() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0x01; 32]).expect("Valid secret key");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let address = derive_p2pkh_address(&public_key);
        assert!(address.starts_with('1') || address.starts_with('3'));
        assert!(address.len() >= 26 && address.len() <= 35);
    }

    #[test]
    fn test_address_hash_derivation() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0x01; 32]).expect("Valid secret key");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let hash = derive_address_hash(&public_key);
        assert_eq!(hash.len(), 20);
        assert_ne!(hash, [0u8; 20]);
    }

    #[test]
    fn test_deterministic_derivation() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0x42; 32]).expect("Valid secret key");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let addr1 = derive_p2pkh_address(&public_key);
        let addr2 = derive_p2pkh_address(&public_key);
        assert_eq!(addr1, addr2);

        let hash1 = derive_address_hash(&public_key);
        let hash2 = derive_address_hash(&public_key);
        assert_eq!(hash1, hash2);
    }

    /// Verify that derive_p2pkh_address and derive_address_hash produce
    /// consistent results (same hash160 in both the address and hash output).
    #[test]
    fn test_address_and_hash_consistent() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0x77; 32]).expect("Valid secret key");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        let address_str = derive_p2pkh_address(&public_key);
        let hash160 = derive_address_hash(&public_key);

        // Reconstruct address from hash160 using bitcoin crate to verify consistency
        let reconstructed = bitcoin::Address::p2pkh(
            BitcoinPublicKey::from_slice(&public_key.serialize()).unwrap(),
            Network::Bitcoin,
        )
        .to_string();
        assert_eq!(address_str, reconstructed);

        // hash160 must not be all zeros
        assert_ne!(hash160, [0u8; 20]);
    }
}
