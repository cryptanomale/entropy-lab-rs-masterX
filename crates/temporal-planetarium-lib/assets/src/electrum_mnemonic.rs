/// Electrum mnemonic generation and seed derivation
/// Based on Electrum wallet's mnemonic format (different from BIP39)
use bip39::Mnemonic;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;

// Unused imports for the disabled ElectrumMnemonic code
// use anyhow::{anyhow, Result};
// use hmac::{Hmac, Mac};
// use std::fmt;
// type HmacSha512 = Hmac<Sha512>;

// Electrum wordlist support is disabled - it's not needed for the current implementation
// which only converts BIP39 mnemonics to Electrum seeds using the correct PBKDF2 salt.
// If full Electrum mnemonic generation is needed in the future, uncomment this section.
//
// /// Electrum wordlist (same as BIP39 English wordlist)
// /// Note: This wordlist is the same as BIP39, but Electrum uses it differently
// /// with version checking via HMAC-SHA512. Currently only used for reference.
// const WORDLIST: &[&str] = &include!("data/electrum_wordlist.txt");
//
// /// Version prefixes for different Electrum wallet types
// pub const SEGWIT_PREFIX: &str = "100";
// pub const LEGACY_PREFIX: &str = "01";
// pub const STANDARD_PREFIX: &str = "01";

// The following ElectrumMnemonic struct and related functions are currently unused
// and disabled because they require the wordlist file. They can be re-enabled
// if full Electrum mnemonic generation is needed in the future.
/*
#[derive(Debug, Clone)]
pub struct ElectrumMnemonic {
    words: Vec<String>,
}

impl ElectrumMnemonic {
    /// Create an Electrum mnemonic from entropy bytes
    /// The entropy is encoded into words using base-2048 encoding
    pub fn from_entropy(entropy: &[u8], prefix: &str) -> Result<Self> {
        // Try multiple nonces to find a valid mnemonic that matches the version prefix
        for nonce in 0u32..1000000 {
            let mut entropy_with_nonce = entropy.to_vec();
            // Append nonce bytes
            entropy_with_nonce.extend_from_slice(&nonce.to_le_bytes());

            let words = encode_entropy(&entropy_with_nonce)?;
            let mnemonic_str = words.join(" ");

            if check_version_prefix(&mnemonic_str, prefix)? {
                return Ok(ElectrumMnemonic { words });
            }
        }

        Err(anyhow!("Failed to generate valid Electrum mnemonic with prefix {}", prefix))
    }

    /// Create from a mnemonic string
    pub fn from_string(mnemonic: &str) -> Result<Self> {
        let words: Vec<String> = mnemonic.split_whitespace().map(|s| s.to_string()).collect();

        // Validate words are in the wordlist
        for word in &words {
            if !WORDLIST.contains(&word.as_str()) {
                return Err(anyhow!("Invalid word in mnemonic: {}", word));
            }
        }

        Ok(ElectrumMnemonic { words })
    }

    /// Check if this mnemonic matches a specific version prefix
    pub fn check_prefix(&self, prefix: &str) -> Result<bool> {
        check_version_prefix(&self.to_string(), prefix)
    }

    /// Convert mnemonic to seed bytes using PBKDF2-HMAC-SHA512
    /// Salt is "electrum" + optional passphrase
    pub fn to_seed(&self, passphrase: &str) -> [u8; 64] {
        let mnemonic_str = self.to_string();
        let salt = if passphrase.is_empty() {
            "electrum".to_string()
        } else {
            format!("electrum{}", passphrase)
        };

        let mut seed = [0u8; 64];
        pbkdf2_hmac::<Sha512>(
            mnemonic_str.as_bytes(),
            salt.as_bytes(),
            2048,
            &mut seed,
        );
        seed
    }
}

impl fmt::Display for ElectrumMnemonic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.words.join(" "))
    }
}

/// Encode entropy bytes into Electrum mnemonic words
fn encode_entropy(entropy: &[u8]) -> Result<Vec<String>> {
    if entropy.is_empty() {
        return Err(anyhow!("Entropy cannot be empty"));
    }

    // Convert entropy to binary string
    let mut bin = String::new();
    for byte in entropy {
        bin.push_str(&format!("{:08b}", byte));
    }

    // Split into 11-bit chunks (log2(2048) = 11)
    let mut words = Vec::new();
    let word_bit_len = 11;
    let word_count = bin.len() / word_bit_len;

    for i in 0..word_count {
        let start = i * word_bit_len;
        let end = (i + 1) * word_bit_len;
        if end > bin.len() {
            break;
        }

        let word_bits = &bin[start..end];
        let word_index = usize::from_str_radix(word_bits, 2)
            .map_err(|e| anyhow!("Failed to parse word bits: {}", e))?;

        if word_index >= WORDLIST.len() {
            return Err(anyhow!("Word index {} out of range", word_index));
        }

        words.push(WORDLIST[word_index].to_string());
    }

    Ok(words)
}

/// Check if a mnemonic matches the expected version prefix
/// Uses HMAC-SHA512 with key "Seed version"
fn check_version_prefix(mnemonic: &str, expected_prefix: &str) -> Result<bool> {
    let normalized = normalize_text(mnemonic);

    let mut mac = HmacSha512::new_from_slice(b"Seed version")
        .map_err(|e| anyhow!("Failed to create HMAC: {}", e))?;
    mac.update(normalized.as_bytes());
    let result = mac.finalize();
    let hash_hex = hex::encode(result.into_bytes());

    Ok(hash_hex.starts_with(&expected_prefix.to_lowercase()))
}

/// Normalize text for Electrum (NFKD normalization)
fn normalize_text(text: &str) -> String {
    // TODO: Implement proper Unicode NFKD normalization for full Electrum compatibility
    // For now, just use basic trimming and lowercasing which works for ASCII mnemonics
    text.trim().to_lowercase()
}
*/

/// Generate Electrum-style seed from BIP39 mnemonic
/// This uses the same word phrase but derives the seed using Electrum's method
/// (PBKDF2 with salt "electrum" instead of "mnemonic")
pub fn mnemonic_to_electrum_seed(mnemonic: &Mnemonic, passphrase: &str) -> [u8; 64] {
    let mnemonic_str = mnemonic.to_string();
    let salt = if passphrase.is_empty() {
        "electrum".to_string()
    } else {
        format!("electrum{}", passphrase)
    };

    let mut seed = [0u8; 64];
    pbkdf2_hmac::<Sha512>(mnemonic_str.as_bytes(), salt.as_bytes(), 2048, &mut seed);
    seed
}

// Tests for the unused ElectrumMnemonic code are also disabled
/*
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_electrum_mnemonic_generation() {
        // Test with known entropy
        let entropy = [0u8; 16];
        let result = ElectrumMnemonic::from_entropy(&entropy, SEGWIT_PREFIX);

        // Should eventually find a valid mnemonic
        match result {
            Ok(mnemonic) => {
                println!("Generated mnemonic: {}", mnemonic);
                assert!(mnemonic.words.len() > 0);
            }
            Err(e) => {
                println!("Note: Electrum mnemonic generation may take time: {}", e);
            }
        }
    }

    #[test]
    fn test_electrum_seed_derivation() {
        // Test seed derivation
        let mnemonic = ElectrumMnemonic::from_string("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let seed = mnemonic.to_seed("");

        // Seed should be 64 bytes
        assert_eq!(seed.len(), 64);
        // Should be deterministic
        let seed2 = mnemonic.to_seed("");
        assert_eq!(seed, seed2);
    }
}
*/
