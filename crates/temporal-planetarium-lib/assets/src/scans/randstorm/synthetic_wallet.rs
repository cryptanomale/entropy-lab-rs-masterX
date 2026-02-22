//! Synthetic Vulnerable Wallet Generator
//!
//! Generates known-weak Bitcoin wallets for scanner validation.
//! These wallets are created using the same weak PRNG mechanisms as
//! the original vulnerable BitcoinJS implementations.
//!
//! **Purpose:** Self-validation - if scanner can't detect wallets we generate,
//! it won't detect real vulnerable wallets either.
//!
//! **Usage:**
//! ```rust
//! use entropy_lab_rs::scans::randstorm::synthetic_wallet::SyntheticWalletGenerator;
//!
//! let generator = SyntheticWalletGenerator::new();
//! let wallet = generator.generate_wallet_v8(1389781850000);
//! println!("Address: {}", wallet.address);
//! ```

use super::derivation::derive_p2pkh_address_from_bytes;
use super::prng::{BitcoinJsV013Prng, MathRandomEngine};
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// A synthetic vulnerable wallet with all metadata for validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyntheticWallet {
    /// Generated Bitcoin address (P2PKH)
    pub address: String,

    /// Private key bytes (for internal validation only - never expose!)
    #[serde(skip_serializing)]
    pub private_key: [u8; 32],

    /// Timestamp used to seed the PRNG (milliseconds since epoch)
    pub timestamp_ms: u64,

    /// Browser engine used
    pub engine: String,

    /// Entropy pool first 32 bytes (for debugging)
    pub pool_hash: String,

    /// Description of this test case
    pub description: String,
}

/// Generates synthetic vulnerable wallets for validation
pub struct SyntheticWalletGenerator {
    /// Pre-generated test cases for different scenarios
    predefined_timestamps: Vec<(u64, &'static str)>,
}

impl Default for SyntheticWalletGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl SyntheticWalletGenerator {
    pub fn new() -> Self {
        Self {
            predefined_timestamps: vec![
                (1325376000000, "2012-01-01 00:00:00 UTC"),
                (1356998400000, "2013-01-01 00:00:00 UTC"),
                (1365000000000, "2013-04-03 12:40:00 UTC"),
                (1389781850000, "2014-01-15 12:30:50 UTC"), // Known test timestamp
                (1420070400000, "2015-01-01 00:00:00 UTC"),
            ],
        }
    }

    /// Generate a vulnerable wallet using Chrome V8 MWC1616 PRNG
    pub fn generate_wallet_v8(&self, timestamp_ms: u64) -> Result<SyntheticWallet> {
        self.generate_wallet(timestamp_ms, MathRandomEngine::V8Mwc1616, None)
    }

    /// Generate a vulnerable wallet using Firefox/IE Java LCG
    pub fn generate_wallet_firefox(&self, timestamp_ms: u64) -> Result<SyntheticWallet> {
        self.generate_wallet(timestamp_ms, MathRandomEngine::SpiderMonkeyLcg, None)
    }

    /// Generate a vulnerable wallet using IE Chakra (same as Firefox)
    pub fn generate_wallet_ie(&self, timestamp_ms: u64) -> Result<SyntheticWallet> {
        self.generate_wallet(timestamp_ms, MathRandomEngine::IeChakraLcg, None)
    }

    /// Generate a vulnerable wallet using Safari Windows MSVC CRT
    pub fn generate_wallet_safari_windows(&self, timestamp_ms: u64) -> Result<SyntheticWallet> {
        self.generate_wallet(timestamp_ms, MathRandomEngine::SafariWindowsCrt, None)
    }

    /// Generate a vulnerable wallet with specific parameters
    pub fn generate_wallet(
        &self,
        timestamp_ms: u64,
        engine: MathRandomEngine,
        seed_override: Option<u64>,
    ) -> Result<SyntheticWallet> {
        // Generate private key using vulnerable PRNG chain
        let private_key =
            BitcoinJsV013Prng::generate_privkey_bytes(timestamp_ms, engine, seed_override);

        // Derive P2PKH address from private key
        let address = derive_p2pkh_address_from_bytes(&private_key)?;

        // Generate pool hash for debugging
        let pool =
            BitcoinJsV013Prng::generate_entropy_pool_with_engine(timestamp_ms, engine, seed_override);
        let pool_hash = hex::encode(&pool[..32]);

        let engine_name = format!("{:?}", engine);

        Ok(SyntheticWallet {
            address,
            private_key,
            timestamp_ms,
            engine: engine_name,
            pool_hash,
            description: format!(
                "Synthetic wallet generated with {} at timestamp {}",
                format!("{:?}", engine),
                timestamp_ms
            ),
        })
    }

    /// Generate a complete test suite of wallets across all engines
    pub fn generate_test_suite(&self) -> Result<Vec<SyntheticWallet>> {
        let mut wallets = Vec::new();

        for (timestamp, _desc) in &self.predefined_timestamps {
            // Chrome V8
            wallets.push(self.generate_wallet_v8(*timestamp)?);

            // Firefox
            wallets.push(self.generate_wallet_firefox(*timestamp)?);

            // IE (same algo as Firefox, different engine name)
            wallets.push(self.generate_wallet_ie(*timestamp)?);

            // Safari Windows
            wallets.push(self.generate_wallet_safari_windows(*timestamp)?);
        }

        Ok(wallets)
    }

    /// Generate and export test suite to JSON
    pub fn export_test_suite_json(&self) -> Result<String> {
        let wallets = self.generate_test_suite()?;
        let json = serde_json::to_string_pretty(&wallets)?;
        Ok(json)
    }

    /// Validate that a scanner correctly detects a synthetic wallet
    pub fn validate_detection(
        &self,
        wallet: &SyntheticWallet,
        detected_address: &str,
    ) -> ValidationResult {
        if wallet.address == detected_address {
            ValidationResult::Match
        } else {
            ValidationResult::Mismatch {
                expected: wallet.address.clone(),
                actual: detected_address.to_string(),
            }
        }
    }
}

/// Result of scanner validation against synthetic wallet
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationResult {
    Match,
    Mismatch { expected: String, actual: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_wallet_v8() {
        let generator = SyntheticWalletGenerator::new();
        let wallet = generator.generate_wallet_v8(1389781850000).unwrap();

        // Address should be valid P2PKH
        assert!(wallet.address.starts_with('1'));
        assert!(wallet.address.len() >= 26);
        assert!(wallet.address.len() <= 35);

        // Pool hash should match known value
        assert_eq!(
            wallet.pool_hash,
            "c31bd379e0304e75edd7eb3075cc421024b66e2259f36e99c27262bba0cf8007"
        );
    }

    #[test]
    fn test_generate_wallet_firefox() {
        let generator = SyntheticWalletGenerator::new();
        let wallet = generator.generate_wallet_firefox(1389781850000).unwrap();

        assert!(wallet.address.starts_with('1'));
        assert!(wallet.engine.contains("SpiderMonkey"));
    }

    #[test]
    fn test_generate_wallet_ie() {
        let generator = SyntheticWalletGenerator::new();
        let wallet = generator.generate_wallet_ie(1389781850000).unwrap();

        assert!(wallet.address.starts_with('1'));
        assert!(wallet.engine.contains("IeChakra"));
    }

    #[test]
    fn test_generate_wallet_safari_windows() {
        let generator = SyntheticWalletGenerator::new();
        let wallet = generator.generate_wallet_safari_windows(1389781850000).unwrap();

        assert!(wallet.address.starts_with('1'));
        assert!(wallet.engine.contains("SafariWindows"));
    }

    #[test]
    fn test_deterministic_generation() {
        let generator = SyntheticWalletGenerator::new();

        // Same timestamp should produce same wallet
        let wallet1 = generator.generate_wallet_v8(1389781850000).unwrap();
        let wallet2 = generator.generate_wallet_v8(1389781850000).unwrap();

        assert_eq!(wallet1.address, wallet2.address);
        assert_eq!(wallet1.private_key, wallet2.private_key);
    }

    #[test]
    fn test_different_timestamps_different_wallets() {
        let generator = SyntheticWalletGenerator::new();

        let wallet1 = generator.generate_wallet_v8(1389781850000).unwrap();
        let wallet2 = generator.generate_wallet_v8(1389781860000).unwrap();

        assert_ne!(wallet1.address, wallet2.address);
    }

    #[test]
    fn test_generate_test_suite() {
        let generator = SyntheticWalletGenerator::new();
        let wallets = generator.generate_test_suite().unwrap();

        // 5 timestamps × 4 engines = 20 wallets
        assert_eq!(wallets.len(), 20);

        // All addresses should be unique (except V8/Firefox may rarely collide)
        let addresses: Vec<&str> = wallets.iter().map(|w| w.address.as_str()).collect();
        let unique_count = addresses
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert!(unique_count >= 15); // Firefox (SpiderMonkey) and IE (Chakra) use same LCG → same addresses
    }

    #[test]
    fn test_validation() {
        let generator = SyntheticWalletGenerator::new();
        let wallet = generator.generate_wallet_v8(1389781850000).unwrap();

        // Correct detection
        let result = generator.validate_detection(&wallet, &wallet.address);
        assert_eq!(result, ValidationResult::Match);

        // Wrong detection
        let result = generator.validate_detection(&wallet, "1wrongAddress");
        assert!(matches!(result, ValidationResult::Mismatch { .. }));
    }

    #[test]
    fn test_json_export() {
        let generator = SyntheticWalletGenerator::new();
        let json = generator.export_test_suite_json().unwrap();

        // Should be valid JSON
        assert!(json.starts_with('['));
        assert!(json.contains("address"));
        assert!(json.contains("timestamp_ms"));

        // Private keys should NOT be in JSON output
        assert!(!json.contains("private_key"));
    }
}
