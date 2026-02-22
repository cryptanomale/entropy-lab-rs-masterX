//! Checkpoint and resume logic for long-running scans

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Checkpoint state for resumable scans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCheckpoint {
    /// Current config index
    pub config_idx: usize,

    /// Current timestamp in milliseconds
    pub timestamp_ms: u64,

    /// Total fingerprints scanned so far
    pub fingerprints_scanned: u64,

    /// Findings count
    pub findings_count: usize,

    /// Scan mode
    pub scan_mode: String,

    /// Checkpoint timestamp
    pub checkpoint_time: u64,
}

impl ScanCheckpoint {
    /// Create new checkpoint
    pub fn new(
        config_idx: usize,
        timestamp_ms: u64,
        fingerprints_scanned: u64,
        findings_count: usize,
        scan_mode: String,
    ) -> Self {
        Self {
            config_idx,
            timestamp_ms,
            fingerprints_scanned,
            findings_count,
            scan_mode,
            checkpoint_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Save checkpoint to file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(self).context("Failed to serialize checkpoint")?;

        fs::write(path, json).context("Failed to write checkpoint file")?;

        Ok(())
    }

    /// Load checkpoint from file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let json = fs::read_to_string(path).context("Failed to read checkpoint file")?;

        let checkpoint: ScanCheckpoint =
            serde_json::from_str(&json).context("Failed to parse checkpoint JSON")?;

        Ok(checkpoint)
    }

    /// Check if checkpoint exists
    pub fn exists<P: AsRef<Path>>(path: P) -> bool {
        path.as_ref().exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    // TEST-ID: 1.9-UNIT-010
    // AC: AC-5 (Checkpoint Save/Load)
    // PRIORITY: P1
    #[test]
    fn test_checkpoint_save_load() {
        let temp_file = NamedTempFile::new().unwrap();
        let checkpoint_path = temp_file.path();

        // Create checkpoint
        let checkpoint = ScanCheckpoint::new(42, 1293840000000, 100_000, 5, "Standard".to_string());

        // Save
        checkpoint
            .save(checkpoint_path)
            .expect("Failed to save checkpoint");

        // Load
        let loaded = ScanCheckpoint::load(checkpoint_path).expect("Failed to load checkpoint");

        assert_eq!(loaded.config_idx, 42);
        assert_eq!(loaded.timestamp_ms, 1293840000000);
        assert_eq!(loaded.fingerprints_scanned, 100_000);
        assert_eq!(loaded.findings_count, 5);
        assert_eq!(loaded.scan_mode, "Standard");
    }

    // TEST-ID: 1.9-UNIT-011
    // AC: AC-5 (Resume from Checkpoint)
    // PRIORITY: P1
    #[test]
    fn test_resume_from_checkpoint() {
        let temp_file = NamedTempFile::new().unwrap();
        let checkpoint_path = temp_file.path();

        // Save checkpoint mid-scan
        let checkpoint = ScanCheckpoint::new(10, 1293926400000, 50_000, 2, "Deep".to_string());
        checkpoint.save(checkpoint_path).unwrap();

        // Verify we can resume
        let resumed = ScanCheckpoint::load(checkpoint_path).unwrap();
        assert_eq!(resumed.config_idx, 10);
        assert_eq!(resumed.fingerprints_scanned, 50_000);

        // Should be able to continue from here
        assert!(resumed.config_idx < 246); // Haven't finished all configs
    }

    #[test]
    fn test_checkpoint_exists() {
        let temp_file = NamedTempFile::new().unwrap();
        let temp_path = temp_file.into_temp_path();
        let checkpoint_path = temp_path.to_path_buf();

        // Delete the temp file so it doesn't exist
        drop(temp_path);

        assert!(!ScanCheckpoint::exists(&checkpoint_path));

        let checkpoint = ScanCheckpoint::new(0, 0, 0, 0, "Quick".to_string());
        checkpoint.save(&checkpoint_path).unwrap();

        assert!(ScanCheckpoint::exists(&checkpoint_path));
    }
}
