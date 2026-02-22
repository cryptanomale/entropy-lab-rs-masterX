//! Attack Complexity Estimator for Randstorm Scanner
//!
//! Provides statistical estimates of search space and time requirements 
//! for various Randstorm scanning scenarios.

use std::time::Duration;
use super::prng::MathRandomEngine;

/// Detailed breakdown of attack complexity
#[derive(Debug, Clone)]
pub struct AttackComplexity {
    /// Total number of keys in the search space
    pub total_keys: u128,
    /// Number of browser configurations considered
    pub num_configs: u64,
    /// Time window duration (milliseconds)
    pub window_ms: u64,
    /// Estimated time on GPU (30,000 keys/sec target)
    pub est_gpu_time: Duration,
    /// Estimated time on CPU (5,000 keys/sec target)
    pub est_cpu_time: Duration,
}

impl AttackComplexity {
    /// Estimate complexity for a given scanning window and browser count
    pub fn estimate(
        window_ms: u64,
        num_configs: u64,
        engines: &[MathRandomEngine],
    ) -> Self {
        let num_engines = engines.len() as u128;
        // Total keys = (Timestamps in window) * configs * engines
        // Assuming 1ms resolution (typical for historical Date.getTime())
        let total_keys = (window_ms as u128) * (num_configs as u128) * num_engines;
        
        // Base throughput estimates
        let gpu_rate = 30_000u128; // keys/sec
        let cpu_rate = 5_000u128;  // keys/sec
        
        let gpu_secs = (total_keys / gpu_rate) as u64;
        let cpu_secs = (total_keys / cpu_rate) as u64;
        
        Self {
            total_keys,
            num_configs,
            window_ms,
            est_gpu_time: Duration::from_secs(gpu_secs),
            est_cpu_time: Duration::from_secs(cpu_secs),
        }
    }

    /// Format total keys for human readability (e.g., 2^32 or 1.2 quadrillion)
    pub fn format_keys(&self) -> String {
        if self.total_keys < 1000 {
            format!("{}", self.total_keys)
        } else if self.total_keys < 1_000_000 {
            format!("{:.2} thousand", self.total_keys as f64 / 1_000.0)
        } else if self.total_keys < 1_000_000_000 {
            format!("{:.2} million", self.total_keys as f64 / 1_000_000.0)
        } else if self.total_keys < 1_000_000_000_000 {
            format!("{:.2} billion", self.total_keys as f64 / 1_000_000_000.0)
        } else {
            // Power of 2 representation is often more useful for crypto
            format!("2^{:.2}", (self.total_keys as f64).log2())
        }
    }

    /// Return if the attack is considered "feasible" (< 1 week on GPU)
    pub fn is_feasible(&self) -> bool {
        self.est_gpu_time < Duration::from_secs(7 * 24 * 3600)
    }
}

/// Helper for CLI to print a beautiful summary
pub fn print_complexity_report(report: &AttackComplexity) {
    println!("📊 Randstorm Attack Complexity Report");
    println!("--------------------------------------");
    println!("Total Search Space: {}", report.format_keys());
    println!("Time Window:        {} days", report.window_ms / (1000 * 3600 * 24));
    println!("Configurations:     {}", report.num_configs);
    println!("");
    println!("Estimated GPU Time: {:?}", report.est_gpu_time);
    println!("Estimated CPU Time: {:?}", report.est_cpu_time);
    println!("--------------------------------------");
    
    if report.is_feasible() {
        println!("✅ Status: FEASIBLE with current hardware.");
    } else {
        println!("⚠️  Status: MASSIVE SEARCH SPACE - target narrowing recommended.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_complexity_estimation() {
        let one_month_ms = 30 * 24 * 3600 * 1000;
        let report = AttackComplexity::estimate(one_month_ms, 10, &[MathRandomEngine::V8Mwc1616]);
        
        assert!(report.total_keys > 1_000_000_000);
        assert!(report.est_gpu_time.as_secs() > 3600);
    }
}
