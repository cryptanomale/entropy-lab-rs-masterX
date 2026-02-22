use anyhow::Result;
use std::sync::mpsc::Sender;
use crate::scans::randstorm::core_types::{ScanProgress, SeedComponents};

/// Core trait for Randstorm scanners.
///
/// Every scanner engine (CPU, GPU, etc.) MUST implement this trait to ensure
/// consistent progress reporting and result handling.
pub trait Scanner {
    /// Name of the scanner engine (e.g., "CPU Golden Reference", "WGPU Optimized").
    fn name(&self) -> &str;

    /// Run the scan across a range of seeds or a specific fingerprint.
    /// Reports progress via an UnboundedSender.
    fn scan(
        &self,
        target_addresses: &[String],
        components: &SeedComponents,
        progress_tx: Option<Sender<ScanProgress>>,
    ) -> Result<Vec<VulnerabilityFinding>>;
}

/// A finding discovered by the scanner.
#[derive(Debug, Clone)]
pub struct VulnerabilityFinding {
    pub address: String,
    pub timestamp: u64,
    pub engine: String,
    pub confidence: String,
}
