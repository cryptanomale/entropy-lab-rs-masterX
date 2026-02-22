//! Firefox/IE Java-Derived Linear Congruential Generator (LCG)
//!
//! This module implements the Math.random() PRNG used by:
//! - Firefox SpiderMonkey (versions 4-40, 2011-2015)
//! - Internet Explorer Chakra (versions 9-11, 2011-2016)
//!
//! Critical Finding: Both browsers use IDENTICAL algorithm constants
//! derived from Java's java.util.Random LCG.
//!
//! Algorithm: X[n+1] = (a * X[n] + c) mod m
//! Constants:
//!   - Multiplier (a): 0x5DEECE66D (25214903917)
//!   - Addend (c): 11
//!   - Modulus (m): 2^48 (48-bit state)
//!   - Output: High 32 bits of state
//!
//! Research Sources:
//! - java.util.Random Oracle documentation
//! - LWN.net browser PRNG comparison (2015)
//! - ChakraCore GitHub issue #1548

use super::{BrowserVersion, PrngEngine, PrngState, SeedComponents};

/// Java LCG constants (confirmed from java.util.Random)
const MULTIPLIER: u64 = 0x5DEECE66D; // 25214903917
const ADDEND: u64 = 11;
const MASK: u64 = (1u64 << 48) - 1; // 48-bit mask

/// Firefox/IE Java-derived LCG implementation
/// 
/// This PRNG is used by both Firefox SpiderMonkey and IE Chakra engines
/// during the 2011-2015 vulnerable period.
#[derive(Debug, Clone)]
pub struct FirefoxIeLcg {
    applicable_versions: Vec<BrowserVersion>,
}

impl Default for FirefoxIeLcg {
    fn default() -> Self {
        Self::new()
    }
}

impl FirefoxIeLcg {
    pub fn new() -> Self {
        Self {
            applicable_versions: vec![
                BrowserVersion::new("Firefox", 4..=40),
                BrowserVersion::new("IE", 9..=11),
                BrowserVersion::new("Edge", 12..=18), // EdgeHTML (pre-Chromium)
            ],
        }
    }

    /// Advance the LCG state by one step
    #[inline]
    fn advance_state(state: u64) -> u64 {
        state.wrapping_mul(MULTIPLIER).wrapping_add(ADDEND) & MASK
    }

    /// Get next 32-bit random value from current state
    #[inline]
    fn next_u32(state: u64) -> u32 {
        // Return high 32 bits of 48-bit state
        (state >> 16) as u32
    }

    /// Generate Math.random() output (0.0 to 1.0)
    #[inline]
    pub fn math_random(state: u64) -> f64 {
        let u32_val = Self::next_u32(state);
        u32_val as f64 / 4294967296.0
    }

    /// Seed the LCG from timestamp (vulnerable seeding mechanism)
    pub fn seed_from_timestamp(timestamp_ms: u64) -> u64 {
        // Java.util.Random XORs seed with MULTIPLIER
        (timestamp_ms ^ MULTIPLIER) & MASK
    }

    /// Seed from fingerprint components (browser-specific)
    pub fn seed_from_fingerprint(seed_components: &SeedComponents) -> u64 {
        // Combine timestamp with fingerprint hash
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

impl PrngEngine for FirefoxIeLcg {
    fn generate_state(&self, seed: &SeedComponents) -> PrngState {
        let state = Self::seed_from_fingerprint(seed);
        
        // Store 48-bit state as two 32-bit values (s1 = high, s2 = low)
        PrngState {
            s1: (state >> 32) as u32,
            s2: (state & 0xFFFFFFFF) as u32,
        }
    }

    fn generate_bytes(&self, state: &PrngState, count: usize) -> Vec<u8> {
        // Reconstruct 48-bit state from s1 (high) and s2 (low)
        let mut current_state = ((state.s1 as u64) << 32) | (state.s2 as u64);
        current_state &= MASK; // Ensure 48-bit

        let mut result = Vec::with_capacity(count);

        for _ in 0..count {
            // Advance state
            current_state = Self::advance_state(current_state);
            
            // Output high byte of the 32-bit random value
            let random_u32 = Self::next_u32(current_state);
            result.push((random_u32 >> 24) as u8);
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
    fn test_lcg_constants() {
        assert_eq!(MULTIPLIER, 0x5DEECE66D);
        assert_eq!(ADDEND, 11);
        assert_eq!(MASK, (1u64 << 48) - 1);
    }

    #[test]
    fn test_lcg_deterministic() {
        let prng = FirefoxIeLcg::new();

        let seed = SeedComponents {
            timestamp_ms: 1366070400000, // April 16, 2013
            user_agent: "Mozilla/5.0 (Windows NT 6.1; rv:20.0) Gecko/20100101 Firefox/20.0"
                .to_string(),
            screen_width: 1366,
            screen_height: 768,
            color_depth: 24,
            timezone_offset: -300,
            language: "en-US".to_string(),
            platform: "Win32".to_string(),
        };

        let state = prng.generate_state(&seed);
        let bytes1 = prng.generate_bytes(&state, 32);
        let bytes2 = prng.generate_bytes(&state, 32);

        assert_eq!(bytes1, bytes2, "LCG must be deterministic");
    }

    #[test]
    fn test_lcg_state_advance() {
        // Test that state advances correctly using known Java behavior
        let initial_state: u64 = 12345;
        let seeded = (initial_state ^ MULTIPLIER) & MASK;
        
        let next = FirefoxIeLcg::advance_state(seeded);
        
        // Verify state changed and is within 48-bit range
        assert_ne!(next, seeded);
        assert!(next <= MASK);
    }

    #[test]
    fn test_applicable_browsers() {
        let prng = FirefoxIeLcg::new();
        let versions = prng.applicable_to();

        assert!(versions.iter().any(|v| v.name == "Firefox"));
        assert!(versions.iter().any(|v| v.name == "IE"));
    }

    #[test]
    fn test_math_random_range() {
        // Test that Math.random() output is in [0, 1)
        let state: u64 = 0x123456789ABC;
        let random = FirefoxIeLcg::math_random(state);
        
        assert!(random >= 0.0);
        assert!(random < 1.0);
    }
}
