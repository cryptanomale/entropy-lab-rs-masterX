use serde::{Deserialize, Serialize};

/// Shared core types for Randstorm PRNG reconstruction.
///
/// These types are designed to be bit-identical across CPU and GPU hardware.
/// All structs are #[repr(C)] for stable memory layout.

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(C)]
pub struct ChromeV8State {
    pub s1: u32,
    pub s2: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(C)]
pub struct SpiderMonkeyState {
    pub multiplier: u64,
    pub addend: u64,
    pub mask: u64,
    pub current_seed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedComponents {
    pub timestamp_ms: u64,
    pub user_agent: String,
    pub screen_width: u32,
    pub screen_height: u32,
    pub color_depth: u8,
    pub timezone_offset: i16,
    pub language: String,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub range_start: u64,
    pub range_end: u64,
    pub current: u64,
    pub hits: u64,
    pub eta_seconds: Option<u64>,
}
