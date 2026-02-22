//! Progress tracking and reporting for Randstorm scanner
//!
//! Provides real-time progress updates following the patterns from gpu_solver.rs

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Progress tracker for scanning operations
pub struct ProgressTracker {
    total_fingerprints: u64,
    processed: Arc<AtomicU64>,
    matches: Arc<AtomicU64>,
    start_time: Instant,
    last_update: Instant,
}

impl ProgressTracker {
    /// Create new progress tracker
    pub fn new(total_fingerprints: u64) -> Self {
        Self {
            total_fingerprints,
            processed: Arc::new(AtomicU64::new(0)),
            matches: Arc::new(AtomicU64::new(0)),
            start_time: Instant::now(),
            last_update: Instant::now(),
        }
    }

    /// Update progress with batch results
    pub fn update(&mut self, processed: u64, matches: u64) {
        self.processed.fetch_add(processed, Ordering::Relaxed);
        self.matches.fetch_add(matches, Ordering::Relaxed);
        self.last_update = Instant::now();
    }

    /// Get current progress percentage
    pub fn progress_percent(&self) -> f64 {
        let processed = self.processed.load(Ordering::Relaxed);
        if self.total_fingerprints == 0 {
            return 0.0;
        }
        (processed as f64 / self.total_fingerprints as f64) * 100.0
    }

    /// Calculate current processing rate (keys/sec)
    pub fn rate(&self) -> f64 {
        let processed = self.processed.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed < 0.001 {
            return 0.0;
        }
        processed as f64 / elapsed
    }

    /// Estimate time remaining
    pub fn eta(&self) -> Duration {
        let processed = self.processed.load(Ordering::Relaxed);
        let remaining = self.total_fingerprints.saturating_sub(processed);
        let rate = self.rate();

        if rate < 0.001 {
            return Duration::from_secs(0);
        }

        Duration::from_secs_f64(remaining as f64 / rate)
    }

    /// Get total processed count
    pub fn processed(&self) -> u64 {
        self.processed.load(Ordering::Relaxed)
    }

    /// Get total matches found
    pub fn matches(&self) -> u64 {
        self.matches.load(Ordering::Relaxed)
    }

    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Print progress update (following gpu_solver.rs style)
    pub fn print_update(&self) {
        let processed = self.processed();
        let matches = self.matches();
        let progress = self.progress_percent();
        let rate = self.rate();
        let eta = self.eta();

        println!(
            "⚡ Progress: {:.2}% | Processed: {} | Matches: {} | Rate: {:.2} keys/sec | ETA: {}",
            progress,
            format_number(processed),
            matches,
            rate,
            format_duration(eta)
        );
    }

    /// Create a shareable clone for multi-threaded tracking
    pub fn clone_handle(&self) -> ProgressHandle {
        ProgressHandle {
            processed: Arc::clone(&self.processed),
            matches: Arc::clone(&self.matches),
        }
    }
}

/// Shareable handle for updating progress from multiple threads
#[derive(Clone)]
pub struct ProgressHandle {
    processed: Arc<AtomicU64>,
    matches: Arc<AtomicU64>,
}

impl ProgressHandle {
    pub fn add_processed(&self, count: u64) {
        self.processed.fetch_add(count, Ordering::Relaxed);
    }

    pub fn add_match(&self) {
        self.matches.fetch_add(1, Ordering::Relaxed);
    }

    pub fn processed(&self) -> u64 {
        self.processed.load(Ordering::Relaxed)
    }

    pub fn matches(&self) -> u64 {
        self.matches.load(Ordering::Relaxed)
    }
}

/// Format large numbers with thousand separators
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    let chars: Vec<char> = s.chars().collect();

    for (i, c) in chars.iter().enumerate() {
        if i > 0 && (chars.len() - i) % 3 == 0 {
            result.push(',');
        }
        result.push(*c);
    }

    result
}

/// Format duration in human-readable form
fn format_duration(d: Duration) -> String {
    let total_secs = d.as_secs();

    if total_secs < 60 {
        return format!("{}s", total_secs);
    }

    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else {
        format!("{}m {}s", minutes, seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration as StdDuration;

    #[test]
    fn test_progress_tracking() {
        let mut tracker = ProgressTracker::new(1000);

        assert_eq!(tracker.processed(), 0);
        assert_eq!(tracker.matches(), 0);
        assert_eq!(tracker.progress_percent(), 0.0);

        tracker.update(100, 5);
        assert_eq!(tracker.processed(), 100);
        assert_eq!(tracker.matches(), 5);
        assert_eq!(tracker.progress_percent(), 10.0);

        tracker.update(400, 20);
        assert_eq!(tracker.processed(), 500);
        assert_eq!(tracker.matches(), 25);
        assert_eq!(tracker.progress_percent(), 50.0);
    }

    #[test]
    fn test_rate_calculation() {
        let mut tracker = ProgressTracker::new(1000);
        thread::sleep(StdDuration::from_millis(100));

        tracker.update(100, 0);
        let rate = tracker.rate();

        // Should process at least some keys per second
        assert!(rate > 0.0);
    }

    #[test]
    fn test_progress_handle() {
        let tracker = ProgressTracker::new(1000);
        let handle = tracker.clone_handle();

        handle.add_processed(50);
        handle.add_match();
        handle.add_match();

        assert_eq!(handle.processed(), 50);
        assert_eq!(handle.matches(), 2);
    }

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(123), "123");
        assert_eq!(format_number(1234), "1,234");
        assert_eq!(format_number(1234567), "1,234,567");
        assert_eq!(format_number(1000000000), "1,000,000,000");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(30)), "30s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h 1m 1s");
    }
}
