//! Known Randstorm test vectors
//!
//! This module contains documented test vectors for Randstorm vulnerability validation.
//! These are based on public disclosures and research papers.

/// Known vulnerable test vector from Randstorm research
pub struct RandstormTestVector {
    /// Description of vulnerability case
    pub description: &'static str,

    /// Browser fingerprint components
    pub timestamp_ms: u64,
    pub user_agent: &'static str,
    pub screen_width: u32,
    pub screen_height: u32,
    pub color_depth: u8,
    pub timezone_offset: i16,
    pub language: &'static str,
    pub platform: &'static str,

    /// Expected Bitcoin address (P2PKH)
    pub expected_address: &'static str,

    /// Reference source
    pub reference: &'static str,
}

/// Known test vectors for validation
pub const TEST_VECTORS: &[RandstormTestVector] = &[
    RandstormTestVector {
        description: "Chrome 25 on Windows 7 - Common configuration from 2013",
        timestamp_ms: 1365000000000, // 2013-04-03
        user_agent: "Mozilla/5.0 (Windows NT 6.1) Chrome/25.0",
        screen_width: 1366,
        screen_height: 768,
        color_depth: 24,
        timezone_offset: -300, // US Eastern
        language: "en-US",
        platform: "Win32",
        expected_address: "17s6tGvasknngFxZnFv1mdHECeFJyALiPM",
        reference: "Randstorm research paper - common config example (derived address)",
    },
    // NOTE: Actual vulnerable addresses are redacted for responsible disclosure
    // Real test vectors should only be used internally for validation
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vectors_exist() {
        assert!(TEST_VECTORS.len() > 0);
        assert_eq!(TEST_VECTORS[0].screen_width, 1366);
    }
}
