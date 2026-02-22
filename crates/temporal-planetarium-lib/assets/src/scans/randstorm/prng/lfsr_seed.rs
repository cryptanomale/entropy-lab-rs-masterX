//! LFSR Seed Generation Model for V8 PRNG
//!
//! Models the internal entropy state transitions in Chrome V8 that contribute 
//! to Math.random() seeding uncertainty.

use std::num::Wrapping;

/// V8 internal LFSR state (32-bit)
pub struct V8Lfsr {
    state: u32,
}

impl V8Lfsr {
    /// Create new LFSR with initial seed
    pub fn new(seed: u32) -> Self {
        Self { state: seed }
    }

    /// Advance LFSR and return next state
    /// 
    /// Historical V8 used a variation of a Linear Feedback Shift Register
    /// for internal entropy management.
    pub fn next(&mut self) -> u32 {
        let mut x = Wrapping(self.state);
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.state = x.0;
        self.state
    }

    /// Model the MWC1616 seed combination
    /// 
    /// v8::internal::MathRandom::Initialize() used timestamp XORed with 
    /// internal entropy.
    pub fn generate_mwc_seed(timestamp_ms: u64, entropy: u32) -> (u32, u32) {
        let s1 = (timestamp_ms & 0xFFFFFFFF) as u32 ^ entropy;
        let s2 = (timestamp_ms >> 32) as u32 ^ (entropy.rotate_left(13));
        
        // Ensure non-zero
        let s1 = if s1 == 0 { 1 } else { s1 };
        let s2 = if s2 == 0 { 1 } else { s2 };
        
        (s1, s2)
    }
}

/// Candidate seed generator for Randstorm scanning
pub struct SeedCandidateGenerator {
    base_timestamp: u64,
    entropy_bits: u32,
    current_offset: u32,
}

impl SeedCandidateGenerator {
    pub fn new(base_timestamp: u64, entropy_bits: u32) -> Self {
        Self {
            base_timestamp,
            entropy_bits,
            current_offset: 0,
        }
    }
}

impl Iterator for SeedCandidateGenerator {
    type Item = (u32, u32);

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_offset >= (1 << self.entropy_bits) {
            return None;
        }

        let seed = V8Lfsr::generate_mwc_seed(self.base_timestamp, self.current_offset);
        self.current_offset += 1;
        Some(seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lfsr_evolution() {
        let mut lfsr = V8Lfsr::new(0xACE1);
        let s1 = lfsr.next();
        let s2 = lfsr.next();
        assert_ne!(s1, s2);
        assert_ne!(s1, 0xACE1);
    }

    #[test]
    fn test_seed_generation() {
        let (s1, s2) = V8Lfsr::generate_mwc_seed(1365000000000, 0x12345678);
        assert!(s1 != 0);
        assert!(s2 != 0);
    }
}
