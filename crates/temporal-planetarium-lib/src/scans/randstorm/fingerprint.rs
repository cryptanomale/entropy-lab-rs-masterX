//! Browser fingerprint representation

use super::fingerprints::BrowserConfig;
use serde::{Deserialize, Serialize};

/// Represents a browser environment fingerprint for PRNG state reconstruction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct BrowserFingerprint {
    /// Timestamp when wallet was generated (milliseconds since Unix epoch)
    pub timestamp_ms: u64,

    /// Screen width in pixels
    pub screen_width: u32,

    /// Screen height in pixels  
    pub screen_height: u32,

    /// Color depth in bits (typically 24 or 32)
    pub color_depth: u8,

    /// Timezone offset in minutes
    pub timezone_offset: i32,

    /// Browser language (e.g., "en-US")
    pub language: String,

    /// Platform identifier (e.g., "Win32", "MacIntel")
    pub platform: String,

    /// User agent string
    pub user_agent: String,
}

impl BrowserFingerprint {
    /// Create fingerprint from known parameters
    pub fn new(
        timestamp_ms: u64,
        screen_width: u32,
        screen_height: u32,
        color_depth: u8,
        timezone_offset: i32,
        language: String,
        platform: String,
        user_agent: String,
    ) -> Self {
        Self {
            timestamp_ms,
            screen_width,
            screen_height,
            color_depth,
            timezone_offset,
            language,
            platform,
            user_agent,
        }
    }

    /// Create fingerprint with common defaults (1920x1080, 24-bit color, en-US, Windows)
    pub fn with_timestamp(timestamp_ms: u64) -> Self {
        Self {
            timestamp_ms,
            screen_width: 1920,
            screen_height: 1080,
            color_depth: 24,
            timezone_offset: -420, // US Pacific Time
            language: "en-US".to_string(),
            platform: "Win32".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
        }
    }

    /// Create fingerprint from BrowserConfig and timestamp
    pub fn from_config_and_timestamp(config: &BrowserConfig, timestamp_ms: u64) -> Self {
        Self {
            timestamp_ms,
            screen_width: config.screen_width,
            screen_height: config.screen_height,
            color_depth: config.color_depth,
            timezone_offset: config.timezone_offset as i32,
            language: config.language.clone(),
            platform: config.platform.clone(),
            user_agent: config.user_agent.clone(),
        }
    }

    /// Get a unique identifier for this fingerprint
    pub fn fingerprint_id(&self) -> String {
        format!(
            "{}_{}_{}x{}",
            self.timestamp_ms, self.platform, self.screen_width, self.screen_height
        )
    }
}

impl Default for BrowserFingerprint {
    fn default() -> Self {
        Self::with_timestamp(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_creation() {
        let fp = BrowserFingerprint::new(
            1633024800000,
            1920,
            1080,
            24,
            -420,
            "en-US".to_string(),
            "Win32".to_string(),
            "Mozilla/5.0".to_string(),
        );

        assert_eq!(fp.timestamp_ms, 1633024800000);
        assert_eq!(fp.screen_width, 1920);
        assert_eq!(fp.screen_height, 1080);
    }

    #[test]
    fn test_with_timestamp() {
        let fp = BrowserFingerprint::with_timestamp(1234567890000);
        assert_eq!(fp.timestamp_ms, 1234567890000);
        assert_eq!(fp.screen_width, 1920);
        assert_eq!(fp.language, "en-US");
    }

    #[test]
    fn test_fingerprint_id() {
        let fp = BrowserFingerprint::with_timestamp(1633024800000);
        let id = fp.fingerprint_id();
        assert!(id.contains("1633024800000"));
        assert!(id.contains("Win32"));
        assert!(id.contains("1920x1080"));
    }

    // TEST-ID: 1.9-UNIT-005
    // AC: AC-3 (Fingerprint with Timestamp)
    // PRIORITY: P0
    #[test]
    fn test_fingerprint_with_timestamp() {
        use super::super::fingerprints::BrowserConfig;

        let config = BrowserConfig {
            priority: 1,
            user_agent: "Chrome/42".to_string(),
            screen_width: 1366,
            screen_height: 768,
            color_depth: 24,
            timezone_offset: -300,
            language: "en-US".to_string(),
            platform: "Win32".to_string(),
            market_share_estimate: 0.5,
            year_min: 2011,
            year_max: 2015,
        };

        let timestamp = 1293840000000; // 2011-01-01
        let fp = BrowserFingerprint::from_config_and_timestamp(&config, timestamp);

        assert_eq!(fp.timestamp_ms, timestamp);
        assert_eq!(fp.screen_width, 1366);
        assert_eq!(fp.screen_height, 768);
        assert_eq!(fp.user_agent, "Chrome/42");
        assert_eq!(fp.timezone_offset, -300);
    }
}
