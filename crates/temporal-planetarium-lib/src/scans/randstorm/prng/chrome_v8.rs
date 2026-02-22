//! Chrome V8 MWC1616 PRNG Implementation
//!
//! Chrome versions 14-45 (2011-2015) used the MWC1616 (Multiply-With-Carry)
//! algorithm for Math.random(). This PRNG had insufficient entropy for
//! cryptographic key generation.
//!
//! # Algorithm: MWC1616
//!
//! ```text
//! s1 = 18000 * (s1 & 0xFFFF) + (s1 >> 16)
//! s2 = 30903 * (s2 & 0xFFFF) + (s2 >> 16)
//! result = (s1 << 16) + s2
//! ```
//!
//! Period: 2^32 (~4 billion states)
//!
//! # References
//!
//! - V8 source: https://github.com/v8/v8/blob/3.14.5.9/src/math.cc
//! - Randstorm disclosure: Section 2.1

#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]
#![deny(clippy::float_cmp_const)]

use super::{BrowserVersion, PrngEngine, PrngState, SeedComponents};
use crate::scans::randstorm::core_types::ChromeV8State;
use crate::scans::randstorm::engines::V8Reference;
use sha2::{Digest, Sha256};

pub struct ChromeV8Prng {
    applicable_versions: Vec<BrowserVersion>,
}

impl ChromeV8Prng {
    pub fn new() -> Self {
        Self {
            applicable_versions: vec![BrowserVersion::new("Chrome", 14..=45)],
        }
    }

    /// Generate seed value from fingerprint components
    fn generate_seed(components: &SeedComponents) -> u64 {
        let mut hasher = Sha256::new();

        // Hash all fingerprint components
        hasher.update(components.user_agent.as_bytes());
        hasher.update(components.screen_width.to_le_bytes());
        hasher.update(components.screen_height.to_le_bytes());
        hasher.update(&[components.color_depth]);
        hasher.update(components.timezone_offset.to_le_bytes());
        hasher.update(components.language.as_bytes());
        hasher.update(components.platform.as_bytes());

        let hash = hasher.finalize();

        // XOR timestamp with hash to create seed
        let hash_u64 = u64::from_le_bytes(hash[0..8].try_into().unwrap());
        components.timestamp_ms ^ hash_u64
    }
}

impl Default for ChromeV8Prng {
    fn default() -> Self {
        Self::new()
    }
}

impl PrngEngine for ChromeV8Prng {
    fn generate_state(&self, seed: &SeedComponents) -> PrngState {
        let seed_value = Self::generate_seed(seed);

        // Split 64-bit seed into two 32-bit values for MWC1616
        let s1 = (seed_value >> 32) as u32;
        let s2 = (seed_value & 0xFFFFFFFF) as u32;

        PrngState { s1, s2 }
    }

    fn generate_bytes(&self, state: &PrngState, count: usize) -> Vec<u8> {
        // Delegate to V8Reference (Golden Reference) for MWC1616 step
        // This ensures all callers use the same bit-perfect implementation.
        let mut chrome_state = ChromeV8State {
            s1: state.s1,
            s2: state.s2,
        };
        let mut result = Vec::with_capacity(count);

        // Generate bytes using MWC1616 algorithm via Golden Reference
        for _ in 0..(count / 4) {
            // MWC1616 step via V8Reference (Integer Isolation Law compliant)
            let value = V8Reference::next_state(&mut chrome_state);

            // Extract 4 bytes (little-endian)
            result.extend_from_slice(&value.to_le_bytes());
        }

        // Handle remaining bytes
        let remainder = count % 4;
        if remainder > 0 {
            let value = V8Reference::next_state(&mut chrome_state);
            let bytes = value.to_le_bytes();
            result.extend_from_slice(&bytes[0..remainder]);
        }

        result
    }

    fn applicable_to(&self) -> &[BrowserVersion] {
        &self.applicable_versions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mwc1616_deterministic() {
        let prng = ChromeV8Prng::new();

        let seed = SeedComponents {
            timestamp_ms: 1234567890000,
            user_agent: "Mozilla/5.0 (Windows NT 6.1) Chrome/25.0".to_string(),
            screen_width: 1366,
            screen_height: 768,
            color_depth: 24,
            timezone_offset: -300,
            language: "en-US".to_string(),
            platform: "Win32".to_string(),
        };

        let state1 = prng.generate_state(&seed);
        let bytes1 = prng.generate_bytes(&state1, 32);

        let state2 = prng.generate_state(&seed);
        let bytes2 = prng.generate_bytes(&state2, 32);

        // Same seed should produce identical output
        assert_eq!(bytes1, bytes2);
        assert_eq!(bytes1.len(), 32);
    }

    #[test]
    fn test_mwc1616_different_seeds() {
        let prng = ChromeV8Prng::new();

        let seed1 = SeedComponents {
            timestamp_ms: 1234567890000,
            user_agent: "Mozilla/5.0 (Windows NT 6.1) Chrome/25.0".to_string(),
            screen_width: 1366,
            screen_height: 768,
            color_depth: 24,
            timezone_offset: -300,
            language: "en-US".to_string(),
            platform: "Win32".to_string(),
        };

        let seed2 = SeedComponents {
            timestamp_ms: 1234567890001, // Different timestamp
            ..seed1.clone()
        };

        let bytes1 = prng.generate_bytes(&prng.generate_state(&seed1), 32);
        let bytes2 = prng.generate_bytes(&prng.generate_state(&seed2), 32);

        // Different seeds should produce different output
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_applicable_versions() {
        let prng = ChromeV8Prng::new();
        let versions = prng.applicable_to();

        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].name, "Chrome");
        assert_eq!(versions[0].version_min, 14);
        assert_eq!(versions[0].version_max, 45);
    }
}
