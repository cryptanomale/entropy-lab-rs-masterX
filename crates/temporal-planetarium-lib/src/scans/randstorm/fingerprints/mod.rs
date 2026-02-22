/// Browser fingerprint database
///
/// Curated database of browser configurations from 2011-2015 ranked by
/// estimated market share. Used to prioritize scanning of most common
/// wallet generation scenarios.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Iterator for generating timestamps
pub trait TimestampIterator: Iterator<Item = u64> {
    fn reset(&mut self);
}

/// Linear iterator (start -> end)
pub struct LinearTimestampGenerator {
    pub(crate) start_ms: u64,
    pub(crate) end_ms: u64,
    pub(crate) interval_ms: u64,
    current_ms: u64,
}

impl LinearTimestampGenerator {
    pub fn new(start_ms: u64, end_ms: u64, interval_ms: u64) -> Self {
        Self {
            start_ms,
            end_ms,
            interval_ms,
            current_ms: start_ms,
        }
    }
    pub fn len(&self) -> u64 {
        if self.end_ms <= self.start_ms {
            return 0;
        }
        (self.end_ms - self.start_ms) / self.interval_ms
    }
}

impl TimestampIterator for LinearTimestampGenerator {
    fn reset(&mut self) {
        self.current_ms = self.start_ms;
    }
}

impl Iterator for LinearTimestampGenerator {
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        if self.current_ms >= self.end_ms {
            return None;
        }
        let ts = self.current_ms;
        self.current_ms += self.interval_ms;
        Some(ts)
    }
}

/// Spiral iterator (center -> outwards)
/// Prioritizes timestamps closest to the estimated creation time
pub struct SpiralTimestampGenerator {
    center_ms: u64,
    radius_ms: u64,
    interval_ms: u64,
    step: i64,
    done: bool,
}

impl SpiralTimestampGenerator {
    pub fn new(center_ms: u64, radius_ms: u64, interval_ms: u64) -> Self {
        Self {
            center_ms,
            radius_ms,
            interval_ms,
            step: 0,
            done: false,
        }
    }

    pub fn len(&self) -> u64 {
        // Approximate count based on radius (radius is one-way, so diameter is 2*radius)
        (2 * self.radius_ms) / self.interval_ms
    }
}

impl TimestampIterator for SpiralTimestampGenerator {
    fn reset(&mut self) {
        self.step = 0;
        self.done = false;
    }
}

impl Iterator for SpiralTimestampGenerator {
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        if self.done {
            return None;
        }

        // Logic: 0, -1, +1, -2, +2, ...
        let offset_units = if self.step == 0 {
            0
        } else if self.step % 2 != 0 {
            -(self.step + 1) / 2
        } else {
            self.step / 2
        };

        let offset_ms = offset_units * self.interval_ms as i64;
        
        if offset_ms.abs() as u64 > self.radius_ms {
            self.done = true;
            return None;
        }

        self.step += 1;
        let ts = (self.center_ms as i64 + offset_ms) as u64;
        Some(ts)
    }
}

/// Unified timestamp generator enum
pub enum TimestampGenerator {
    Linear(LinearTimestampGenerator),
    Spiral(SpiralTimestampGenerator),
}

impl TimestampGenerator {
    /// Create new linear generator
    pub fn new(start_ms: u64, end_ms: u64, interval_ms: u64) -> Self {
        Self::Linear(LinearTimestampGenerator::new(start_ms, end_ms, interval_ms))
    }

    /// Create new spiral generator
    pub fn new_spiral(center_ms: u64, radius_ms: u64, interval_ms: u64) -> Self {
        Self::Spiral(SpiralTimestampGenerator::new(center_ms, radius_ms, interval_ms))
    }

    pub fn reset(&mut self) {
        match self {
            Self::Linear(g) => g.reset(),
            Self::Spiral(g) => g.reset(),
        }
    }

    pub fn len(&self) -> u64 {
        match self {
            Self::Linear(g) => g.len(),
            Self::Spiral(g) => g.len(),
        }
    }
}

impl Iterator for TimestampGenerator {
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        match self {
            Self::Linear(g) => g.next(),
            Self::Spiral(g) => g.next(),
        }
    }
}

impl TimestampIterator for TimestampGenerator {
    fn reset(&mut self) {
        self.reset();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserConfig {
    pub priority: u32,
    pub user_agent: String,
    pub screen_width: u32,
    pub screen_height: u32,
    pub color_depth: u8,
    pub timezone_offset: i16,
    pub language: String,
    pub platform: String,
    pub market_share_estimate: f64,
    pub year_min: u16,
    pub year_max: u16,
}

impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            priority: 0,
            user_agent: String::new(),
            screen_width: 1024,
            screen_height: 768,
            color_depth: 24,
            timezone_offset: 0,
            language: String::from("en-US"),
            platform: String::new(),
            market_share_estimate: 0.0,
            year_min: 2011,
            year_max: 2015,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    One,   // Top 100 configs
    Two,   // Top 500 configs
    Three, // All configs + probabilistic
}

pub struct FingerprintDatabase {
    configs: Vec<BrowserConfig>,
}

impl FingerprintDatabase {
    /// Load fingerprint database from embedded data (100 configs)
    pub fn load() -> Result<Self> {
        const EMBEDDED_CSV: &str = include_str!("data/phase1_top100.csv");

        let mut reader = csv::Reader::from_reader(EMBEDDED_CSV.as_bytes());
        let mut configs = Vec::new();

        for result in reader.deserialize() {
            let config: BrowserConfig =
                result.context("Failed to parse embedded browser config")?;
            configs.push(config);
        }

        // Already sorted by priority in the CSV
        Ok(Self { configs })
    }

    /// Load comprehensive database from embedded data (246 configs)
    pub fn load_comprehensive() -> Result<Self> {
        const EMBEDDED_CSV: &str = include_str!("data/comprehensive.csv");

        let mut reader = csv::Reader::from_reader(EMBEDDED_CSV.as_bytes());
        let mut configs = Vec::new();

        for result in reader.deserialize() {
            let config: BrowserConfig =
                result.context("Failed to parse comprehensive browser config")?;
            configs.push(config);
        }

        Ok(Self { configs })
    }

    /// Load from custom CSV file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut reader =
            csv::Reader::from_path(path).context("Failed to open fingerprint database CSV")?;

        let mut configs = Vec::new();
        for result in reader.deserialize() {
            let config: BrowserConfig =
                result.context("Failed to parse browser config from CSV")?;
            configs.push(config);
        }

        // Sort by market share descending
        configs.sort_by(|a, b| {
            b.market_share_estimate
                .partial_cmp(&a.market_share_estimate)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(Self { configs })
    }

    /// Get configurations for specified phase
    pub fn get_configs_for_phase(&self, phase: Phase) -> &[BrowserConfig] {
        match phase {
            Phase::One => &self.configs[0..self.configs.len().min(100)],
            Phase::Two => &self.configs[0..self.configs.len().min(500)],
            Phase::Three => &self.configs,
        }
    }

    /// Get total number of configurations
    pub fn len(&self) -> usize {
        self.configs.len()
    }

    /// Check if database is empty
    pub fn is_empty(&self) -> bool {
        self.configs.is_empty()
    }

    /// Get fingerprints for specified phase (converts BrowserConfig to BrowserFingerprint)
    pub fn get_fingerprints_for_phase(
        &self,
        phase: Phase,
    ) -> Vec<super::fingerprint::BrowserFingerprint> {
        let configs = self.get_configs_for_phase(phase);
        configs
            .iter()
            .map(|config| {
                super::fingerprint::BrowserFingerprint {
                    timestamp_ms: 1420070400000, // Jan 1, 2015 - midpoint of vulnerable period
                    screen_width: config.screen_width,
                    screen_height: config.screen_height,
                    color_depth: config.color_depth,
                    timezone_offset: config.timezone_offset as i32,
                    language: config.language.clone(),
                    platform: config.platform.clone(),
                    user_agent: config.user_agent.clone(),
                }
            })
            .collect()
    }

    /// Get cumulative market share for top N configs
    pub fn cumulative_market_share(&self, n: usize) -> f64 {
        self.configs
            .iter()
            .take(n)
            .map(|c| c.market_share_estimate)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TEST-ID: 1.9-UNIT-001
    // AC: AC-1 (Timestamp Permutation Engine)
    // PRIORITY: P0
    #[test]
    fn test_timestamp_generator_iteration() {
        let start_ms = 1306886400000; // June 1, 2011 00:00:00 UTC
        let end_ms = 1306972800000; // June 2, 2011 00:00:00 UTC (24 hours later)
        let interval_ms = 3600000; // 1 hour

        let gen = TimestampGenerator::new(start_ms, end_ms, interval_ms);
        let timestamps: Vec<u64> = gen.collect();

        assert_eq!(timestamps.len(), 24, "24 hours = 24 timestamps");
        assert_eq!(timestamps[0], start_ms);
        assert_eq!(timestamps[23], start_ms + 23 * interval_ms);
    }

    // TEST-ID: 1.9-UNIT-002
    // AC: AC-1 (Timestamp Permutation Engine)
    // PRIORITY: P0
    #[test]
    fn test_vulnerable_window_coverage() {
        let start_ms = 1306886400000; // June 1, 2011
        let end_ms = 1435708799000; // June 30, 2015
        let interval_ms = 3600000; // 1 hour

        let gen = TimestampGenerator::new(start_ms, end_ms, interval_ms);
        let count = gen.count();

        // ~4 years × 365.25 days × 24 hours = 35,064 hours
        assert!(count > 35000, "Should have ~35K hourly timestamps");
        assert!(count < 36000, "Sanity check: not more than 36K");
    }

    #[test]
    fn test_database_loads() {
        let db = FingerprintDatabase::load();
        match &db {
            Ok(database) => {
                assert!(!database.is_empty());
                assert_eq!(database.len(), 100);
            }
            Err(e) => panic!("Database failed to load: {}", e),
        }
    }

    #[test]
    fn test_phase_limits() {
        let base = BrowserConfig {
            priority: 1,
            user_agent: "Test".to_string(),
            screen_width: 1366,
            screen_height: 768,
            color_depth: 24,
            timezone_offset: -300,
            language: "en-US".to_string(),
            platform: "Win32".to_string(),
            market_share_estimate: 0.1,
            year_min: 2011,
            year_max: 2015,
        };

        // Build a list of 150 configs to exercise the slicing logic
        let configs = vec![base; 150];

        let db = FingerprintDatabase { configs };

        assert_eq!(db.get_configs_for_phase(Phase::One).len(), 100);
        assert_eq!(db.get_configs_for_phase(Phase::Two).len(), 150);
        assert_eq!(db.get_configs_for_phase(Phase::Three).len(), 150);
    }

    // TEST-ID: 1.9-UNIT-006
    // AC: AC-2 (Comprehensive Database)
    // PRIORITY: P0
    #[test]
    fn test_comprehensive_database_loads() {
        let db =
            FingerprintDatabase::load_comprehensive().expect("Failed to load comprehensive DB");
        assert_eq!(db.len(), 246, "Expected 246 configs");
    }

    // TEST-ID: 1.9-UNIT-007
    // AC: AC-2 (Language Coverage)
    // PRIORITY: P1
    #[test]
    fn test_language_coverage() {
        let db = FingerprintDatabase::load_comprehensive().unwrap();

        // Check for diverse languages
        let has_chinese = db.configs.iter().any(|c| c.language == "zh-CN");
        let has_japanese = db.configs.iter().any(|c| c.language == "ja-JP");
        let has_german = db.configs.iter().any(|c| c.language == "de-DE");
        let has_spanish = db.configs.iter().any(|c| c.language == "es-ES");

        assert!(has_chinese, "Should have Chinese configs");
        assert!(has_japanese, "Should have Japanese configs");
        assert!(has_german, "Should have German configs");
        assert!(has_spanish, "Should have Spanish configs");
    }

    // TEST-ID: 1.9-UNIT-008
    // AC: AC-2 (Platform Coverage)
    // PRIORITY: P1
    #[test]
    fn test_platform_coverage() {
        let db = FingerprintDatabase::load_comprehensive().unwrap();

        // Check for Linux
        let has_linux = db.configs.iter().any(|c| c.platform.contains("Linux"));

        // Check for mobile
        let has_mobile_ua = db.configs.iter().any(|c| c.user_agent.contains("Mobile"));

        assert!(has_linux, "Should have Linux configs");
        assert!(has_mobile_ua, "Should have mobile configs");
    }

    // TEST-ID: 1.9-UNIT-009
    // AC: AC-5 (Spiral Timestamp Generator)
    // PRIORITY: P0
    #[test]
    fn test_spiral_generator() {
        let center = 1000;
        let radius = 50;
        let interval = 10;
        
        let gen = TimestampGenerator::new_spiral(center, radius, interval);
        let timestamps: Vec<u64> = gen.collect();

        assert_eq!(timestamps[0], 1000); // 0
        assert_eq!(timestamps[1], 990);  // -10
        assert_eq!(timestamps[2], 1010); // +10
        assert_eq!(timestamps[3], 980);  // -20
        assert_eq!(timestamps[4], 1020); // +20
        assert_eq!(timestamps.len(), 11); // 0, +/-10, +/-20, +/-30, +/-40, +/-50 = 1+10 = 11
        
        // Ensure bounds respected
        for ts in timestamps {
            assert!(ts >= center - radius);
            assert!(ts <= center + radius);
        }
    }
}
