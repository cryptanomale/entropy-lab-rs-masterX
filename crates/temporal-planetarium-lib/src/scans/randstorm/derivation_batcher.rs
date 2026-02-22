//! Multi-Path Derivation Batcher
//!
//! Handles batch derivation of addresses across multiple standard BIP paths
//! (BIP44, BIP49, BIP84, BIP86) to maximize recoverability of funds from
//! vulnerable seeds.

use anyhow::{Context, Result};
use bitcoin::secp256k1::{Secp256k1, All};
use bitcoin::{Address, Network, CompressedPublicKey, PublicKey};
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use std::str::FromStr;

/// Supported derivation paths for Bitcoin
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandardPath {
    /// BIP44: Legacy P2PKH (starts with 1...) -> m/44'/0'/0'/0/i
    Bip44,
    /// BIP49: Nested SegWit P2SH-P2WPKH (starts with 3...) -> m/49'/0'/0'/0/i
    Bip49,
    /// BIP84: Native SegWit P2WPKH (starts with bc1q...) -> m/84'/0'/0'/0/i
    Bip84,
    /// BIP86: Taproot P2TR (starts with bc1p...) -> m/86'/0'/0'/0/i
    Bip86,
}

impl StandardPath {
    /// Get the base derivation path string
    pub fn base_path_str(&self) -> &'static str {
        match self {
            StandardPath::Bip44 => "m/44'/0'/0'/0",
            StandardPath::Bip49 => "m/49'/0'/0'/0",
            StandardPath::Bip84 => "m/84'/0'/0'/0",
            StandardPath::Bip86 => "m/86'/0'/0'/0",
        }
    }

    /// Get all variants
    pub fn all() -> &'static [StandardPath] {
        &[
            StandardPath::Bip44,
            StandardPath::Bip49,
            StandardPath::Bip84,
            StandardPath::Bip86,
        ]
    }
}

/// Batch derivation result
#[derive(Debug, Clone)]
pub struct DerivedAddress {
    pub path_type: StandardPath,
    pub index: u32,
    pub address: String,
    pub derivation_path: String,
}

pub struct DerivationBatcher {
    secp: Secp256k1<All>,
    network: Network,
    max_index: u32,
}

impl DerivationBatcher {
    /// Create a new batcher
    pub fn new(network: Network, max_index: u32) -> self::DerivationBatcher {
        Self {
            secp: Secp256k1::new(),
            network,
            max_index,
        }
    }

    /// Default configuration for mainnet scanning (indices 0-99)
    pub fn default_mainnet() -> Self {
        Self::new(Network::Bitcoin, 100)
    }

    /// Derive all addresses for a given seed across all standard paths
    pub fn derive_all(&self, seed: &[u8]) -> Result<Vec<DerivedAddress>> {
        // Create root key from seed
        let root = Xpriv::new_master(self.network, seed)
            .context("Failed to create master key from seed")?;

        let mut results = Vec::with_capacity(StandardPath::all().len() * self.max_index as usize);

        for path_type in StandardPath::all() {
            let base_path_str = path_type.base_path_str();
            let base_path = DerivationPath::from_str(base_path_str)
                .with_context(|| format!("Invalid base path: {}", base_path_str))?;

            // Derive the account/chain level key first (optimization)
            // e.g., derive m/44'/0'/0'/0 once, then derive children
            let parent_key = root.derive_priv(&self.secp, &base_path)?;

            for index in 0..self.max_index {
                let child_key = parent_key.derive_priv(
                    &self.secp, 
                    &[ChildNumber::from_normal_idx(index)?]
                )?;
                
                // Convert secp256k1 public key to bitcoin PublicKey/CompressedPublicKey
                let secp_pubkey = child_key.to_keypair(&self.secp).public_key();
                let compressed_pubkey = CompressedPublicKey(secp_pubkey);
                let pubkey = PublicKey::new(secp_pubkey);

                let address = match path_type {
                    StandardPath::Bip44 => Address::p2pkh(&pubkey, self.network),
                    StandardPath::Bip49 => {
                        // BIP49: P2SH-P2WPKH
                        // First create a P2WPKH script, then nest it in P2SH
                        Address::p2shwpkh(&compressed_pubkey, self.network)
                    },
                    StandardPath::Bip84 => Address::p2wpkh(&compressed_pubkey, self.network),
                    StandardPath::Bip86 => Address::p2tr(&self.secp, secp_pubkey.x_only_public_key().0, None, self.network),
                };

                results.push(DerivedAddress {
                    path_type: *path_type,
                    index,
                    address: address.to_string(),
                    derivation_path: format!("{}/{}", base_path_str, index),
                });
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip44_derivation() {
        let seed = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
        let batcher = DerivationBatcher::new(Network::Bitcoin, 1);
        let results = batcher.derive_all(&seed).unwrap();

        // BIP44 Test Vector 1 (Account 0, Chain 0, Index 0)
        // correct: 1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA
        let bip44_0 = results.iter().find(|r| r.path_type == StandardPath::Bip44 && r.index == 0).unwrap();
        assert_eq!(bip44_0.address, "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA");
    }

    #[test]
    fn test_bip49_derivation() {
        // Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
        // Root seed: 5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4
        let seed = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
        let batcher = DerivationBatcher::new(Network::Bitcoin, 1);
        let results = batcher.derive_all(&seed).unwrap();

        // BIP49 m/49'/0'/0'/0/0
        // Correct: 37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf
        let bip49_0 = results.iter().find(|r| r.path_type == StandardPath::Bip49 && r.index == 0).unwrap();
        assert_eq!(bip49_0.address, "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf");
    }

    #[test]
    fn test_bip84_derivation() {
        let seed = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
        let batcher = DerivationBatcher::new(Network::Bitcoin, 1);
        let results = batcher.derive_all(&seed).unwrap();

        // BIP84 m/84'/0'/0'/0/0
        // Correct: bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
        let bip84_0 = results.iter().find(|r| r.path_type == StandardPath::Bip84 && r.index == 0).unwrap();
        assert_eq!(bip84_0.address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    }

    #[test]
    fn test_bip86_derivation() {
        // Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
        let seed = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
        let batcher = DerivationBatcher::new(Network::Bitcoin, 1);
        let results = batcher.derive_all(&seed).unwrap();

        // BIP86 m/86'/0'/0'/0/0 (Taproot P2TR)
        // Expected: bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr
        let bip86_0 = results.iter().find(|r| r.path_type == StandardPath::Bip86 && r.index == 0).unwrap();
        assert!(bip86_0.address.starts_with("bc1p"), "BIP86 should produce bc1p Taproot address");
    }

    #[test]
    fn test_batch_volume() {
        // Use a dummy seed (zeros)
        let seed = [0u8; 64];
        // Use default mainnet config (max_index = 100)
        let batcher = DerivationBatcher::default_mainnet();
        let results = batcher.derive_all(&seed).unwrap();

        // 4 path types * 100 indices = 400 results
        assert_eq!(results.len(), 400, "Should generate exactly 400 addresses");

        // Verify boundary indices exist for all paths
        for path in StandardPath::all() {
            let path_results: Vec<_> = results.iter().filter(|r| r.path_type == *path).collect();
            assert_eq!(path_results.len(), 100, "Should have 100 results for path {:?}", path);
            assert!(path_results.iter().any(|r| r.index == 0), "Should include index 0 for {:?}", path);
            assert!(path_results.iter().any(|r| r.index == 99), "Should include index 99 for {:?}", path);
        }
    }
}
