pub mod attack_estimator;
pub mod checkpoint;
pub mod cli;
pub mod config;
pub mod cpu;
pub mod derivation;
pub mod derivation_batcher;
pub mod engines;
pub mod core_types;
pub mod scanner_trait;
pub mod fingerprint;
pub mod fingerprints;
pub mod forensics;
pub mod gpu_integration;
#[cfg(feature = "wgpu")]
pub mod wgpu_integration;
pub mod heuristics;
pub mod integration;
pub mod validator;

pub use core_types::{ChromeV8State, ScanProgress, SeedComponents, SpiderMonkeyState};
pub use engines::{V8Reference, SpiderMonkeyReference};
pub use scanner_trait::Scanner;

#[cfg(feature = "z3-solver")]
pub mod z3_solver;
/// Randstorm/BitcoinJS Scanner
///
/// This module implements detection of vulnerable Bitcoin wallets affected by the
/// Randstorm vulnerability (CVE-2018-6798 and related). The vulnerability affects
/// wallets generated using JavaScript in browsers from 2011-2015 due to insufficient
/// PRNG entropy in browser implementations.
///
/// # Phases
///
/// - **Phase 1** (Week 1): Chrome V8 PRNG, top 100 browser configs, 60-70% coverage
/// - **Phase 2** (Week 2): All browser PRNGs, 500 configs, 85-90% coverage
/// - **Phase 3** (Week 3+): Probabilistic search, multi-GPU, 95%+ coverage
///
/// # Security & Ethics
///
/// This scanner is designed for **white-hat security research only**:
/// - Private keys are NEVER exported from GPU memory
/// - No fund transfer capabilities
/// - Responsible disclosure framework built-in
/// - 90-day disclosure window before public release
///
/// # References
///
/// - Randstorm Disclosure: https://www.unciphered.com/randstorm
/// - CVE-2018-6798: Chrome V8 PRNG vulnerability
pub mod prng;
pub mod progress;
pub mod synthetic_wallet;
pub mod test_vectors;

pub use checkpoint::ScanCheckpoint;
pub use config::ScanConfig;
pub use fingerprint::BrowserFingerprint;
pub use fingerprints::FingerprintDatabase;
pub use gpu_integration::GpuScanner;
pub use integration::RandstormScanner;
pub use prng::{MathRandomEngine, PrngEngine};
pub use progress::ProgressTracker;

#[cfg(test)]
mod tests {

    #[test]
    fn test_module_compiles() {
        // Basic compilation test
        assert!(true);
    }
}
