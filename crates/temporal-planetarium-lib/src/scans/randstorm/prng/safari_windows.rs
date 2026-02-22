//! Safari Windows MSVC CRT rand() Implementation
//!
//! This module implements the Math.random() PRNG used by Safari on Windows
//! during the 2009-2012 vulnerable period (Safari 4.0.2-4.0.5, 5.0-5.0.2).
//!
//! Safari Windows used Microsoft Visual C++ CRT rand() function
//! combined in a specific way to produce 30-bit random values.
//!
//! Algorithm: Two 15-bit values from MSVC rand() combined
//! MSVC rand() LCG: X[n+1] = (214013 * X[n] + 2531011) mod 2^32
//!   - Output: bits 16-30 of state (15 bits)
//!
//! Research Sources:
//! - securitygalore.com Safari Math.random documentation
//! - WebKit revision 40968 analysis
//! - MSVC CRT source code

use super::{BrowserVersion, PrngEngine, PrngState, SeedComponents};

/// MSVC CRT rand() LCG constants (from Visual C++ runtime)
const MSVC_MULTIPLIER: u32 = 214013;
const MSVC_ADDEND: u32 = 2531011;

/// Safari Windows MSVC CRT-based PRNG
///
/// This PRNG affects Safari versions 4.0.2-4.0.5 and 5.0-5.0.2 on Windows.
/// It uses the Microsoft Visual C++ CRT rand() function internally.
#[derive(Debug, Clone)]
pub struct SafariWindowsCrt {
    applicable_versions: Vec<BrowserVersion>,
}

impl Default for SafariWindowsCrt {
    fn default() -> Self {
        Self::new()
    }
}

impl SafariWindowsCrt {
    pub fn new() -> Self {
        Self {
            applicable_versions: vec![
                BrowserVersion::new("Safari", 4..=5), // Safari 4.x-5.x on Windows
            ],
        }
    }

    /// MSVC CRT rand() implementation
    /// Returns 15-bit value (0-32767)
    #[inline]
    pub fn msvc_rand(state: &mut u32) -> u32 {
        *state = state.wrapping_mul(MSVC_MULTIPLIER).wrapping_add(MSVC_ADDEND);
        (*state >> 16) & 0x7FFF
    }

    /// Safari Windows Math.random() implementation
    /// Combines two 15-bit values into a 30-bit value, then scales to [0, 1)
    #[inline]
    pub fn math_random(state: &mut u32) -> f64 {
        let r1 = Self::msvc_rand(state);
        let r2 = Self::msvc_rand(state);
        let combined = (r1 << 15) | r2; // 30-bit value
        combined as f64 / 1073741824.0 // 2^30
    }

    /// Generate a single random byte (for entropy pool filling)
    #[inline]
    pub fn random_byte(state: &mut u32) -> u8 {
        let r = Self::msvc_rand(state);
        (r & 0xFF) as u8
    }

    /// Seed from timestamp (MSVC srand behavior)
    pub fn seed_from_timestamp(timestamp_ms: u64) -> u32 {
        // MSVC srand takes a 32-bit unsigned int
        (timestamp_ms & 0xFFFFFFFF) as u32
    }

    /// Seed from fingerprint components
    pub fn seed_from_fingerprint(seed_components: &SeedComponents) -> u32 {
        let fingerprint_hash = Self::hash_fingerprint(seed_components);
        let combined = seed_components.timestamp_ms ^ fingerprint_hash;
        Self::seed_from_timestamp(combined)
    }

    /// Simple hash of fingerprint components
    fn hash_fingerprint(seed: &SeedComponents) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        seed.user_agent.hash(&mut hasher);
        seed.screen_width.hash(&mut hasher);
        seed.screen_height.hash(&mut hasher);
        seed.timezone_offset.hash(&mut hasher);
        hasher.finish()
    }
}

impl PrngEngine for SafariWindowsCrt {
    fn generate_state(&self, seed: &SeedComponents) -> PrngState {
        let state = Self::seed_from_fingerprint(seed);

        // Store 32-bit state in s1, s2 unused
        PrngState {
            s1: state,
            s2: 0, // Not used for MSVC CRT
        }
    }

    fn generate_bytes(&self, state: &PrngState, count: usize) -> Vec<u8> {
        let mut current_state = state.s1;
        let mut result = Vec::with_capacity(count);

        for _ in 0..count {
            result.push(Self::random_byte(&mut current_state));
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
    fn test_msvc_constants() {
        assert_eq!(MSVC_MULTIPLIER, 214013);
        assert_eq!(MSVC_ADDEND, 2531011);
    }

    #[test]
    fn test_msvc_rand_range() {
        // Test that MSVC rand() produces 15-bit values
        let mut state: u32 = 12345;
        for _ in 0..1000 {
            let r = SafariWindowsCrt::msvc_rand(&mut state);
            assert!(r <= 0x7FFF, "rand() should be <= 32767");
        }
    }

    #[test]
    fn test_math_random_range() {
        // Test that Math.random() is in [0, 1)
        let mut state: u32 = 12345;
        for _ in 0..100 {
            let r = SafariWindowsCrt::math_random(&mut state);
            assert!(r >= 0.0, "Math.random() should be >= 0");
            assert!(r < 1.0, "Math.random() should be < 1");
        }
    }

    #[test]
    fn test_deterministic() {
        let prng = SafariWindowsCrt::new();

        let seed = SeedComponents {
            timestamp_ms: 1283299200000, // September 1, 2010
            user_agent: "Mozilla/5.0 (Windows; U; Windows NT 6.1) AppleWebKit/533.16 (KHTML, like Gecko) Version/5.0 Safari/533.16".to_string(),
            screen_width: 1366,
            screen_height: 768,
            color_depth: 32,
            timezone_offset: -300,
            language: "en-US".to_string(),
            platform: "Win32".to_string(),
        };

        let state = prng.generate_state(&seed);
        let bytes1 = prng.generate_bytes(&state, 32);
        let bytes2 = prng.generate_bytes(&state, 32);

        assert_eq!(bytes1, bytes2, "PRNG must be deterministic");
    }

    #[test]
    fn test_applicable_browsers() {
        let prng = SafariWindowsCrt::new();
        let versions = prng.applicable_to();

        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].name, "Safari");
        assert_eq!(versions[0].version_min, 4);
        assert_eq!(versions[0].version_max, 5);
    }

    #[test]
    fn test_known_msvc_sequence() {
        // Verify against known MSVC rand() sequence
        // When seeded with 1, first call returns 41
        let mut state: u32 = 1;
        let result = SafariWindowsCrt::msvc_rand(&mut state);
        assert_eq!(result, 41, "MSVC rand() with seed 1 should return 41");
    }
}
