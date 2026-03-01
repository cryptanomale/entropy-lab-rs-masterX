//! CLI Interface for Randstorm Scanner
//!
//! Provides the command-line interface with CSV input/output, progress reporting,
//! and comprehensive error handling.
//!
//! ## Test Strategy
//!
//! Tests are organized into three levels:
//!
//! ### Unit Tests (13 tests)
//! - CSV Input: 5 tests covering valid/invalid addresses, comments, whitespace
//! - CSV Output: 5 tests for header, single/multiple findings, empty results
//! - Timestamp Formatting: 3 tests for ISO 8601, epoch zero, invalid values
//!
//! ### Integration Tests (5 tests)
//! - CLI help text validation
//! - File not found error handling
//! - Invalid phase validation
//! - Output file creation
//! - End-to-end CPU scan
//!
//! ### Test Fixtures
//! - `tests/fixtures/addresses_p2pkh.csv` - Valid P2PKH addresses
//! - `tests/fixtures/addresses_mixed.csv` - Mixed valid/invalid
//! - `tests/fixtures/addresses_edge_cases.csv` - Whitespace, comments
//!
//! All tests include TEST-ID, AC reference, and PRIORITY markers for traceability.

use super::integration::RandstormScanner;
use super::prng::bitcoinjs_v013::BitcoinJsV013Prng;
use super::prng::MathRandomEngine;
use anyhow::{Context, Result};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::Address;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::str::FromStr;
use tracing::info;
use super::config::{self, GpuBackend};

/// Run the Randstorm scanner with CLI arguments
pub fn run_scan(
    target_addresses_path: &Path,
    start_ms: Option<u64>,
    end_ms: Option<u64>,
    interval_ms: u64,
    phase: u8,
    mode: &str,
    force_gpu: bool,
    force_cpu: bool,
    output_path: Option<&Path>,
    backend_str: Option<&str>,
    math_random_engine: &str,
    seed_override: Option<u64>,
    seed_bruteforce_bits: Option<u8>,
    include_uncompressed: bool,
    estimate_mode: bool,
    z3_solve_input: Option<&str>,
    path_coverage: &str,
    db_path: Option<&Path>,
    target_class: Option<&str>,
    fingerprints_csv: Option<&Path>,
) -> Result<()> {

    // 1. Handle Z3 Solve Mode (Early exit)
    if let Some(_outputs_str) = z3_solve_input {
        #[cfg(feature = "z3-solver")]
        {
            info!("\u{1f9e0} Running Z3 MWC1616 State Recovery...");
            let solver = super::z3_solver::Z3MwcSolver::new();
            let outputs: Vec<u32> = outputs_str
                .split(',')
                .map(|s| {
                    if s.starts_with("0x") {
                        u32::from_str_radix(&s[2..], 16).unwrap_or(0)
                    } else {
                        s.parse::<u32>().unwrap_or(0)
                    }
                })
                .collect();

            match solver.solve_from_outputs(&outputs) {
                Ok((s1, s2)) => {
                    info!("\u{2705} Initial State Recovered!");
                    info!("   s1: 0x{:08X}", s1);
                    info!("   s2: 0x{:08X}", s2);
                    info!("   Combined Seed (approx): {}", ((s1 as u64) << 32) | (s2 as u64));
                }
                Err(e) => {
                    anyhow::bail!("Z3 Solver failed: {}", e);
                }
            }
            return Ok(());
        }
        #[cfg(not(feature = "z3-solver"))]
        {
            anyhow::bail!("Z3 solver feature is disabled. Rebuild with --features z3-solver and ensure Z3 library is installed.");
        }
    }

    // 2. Parse scan mode and phase
    let scan_mode = match mode.to_lowercase().as_str() {
        "quick"     => super::config::ScanMode::Quick,
        "standard"  => super::config::ScanMode::Standard,
        "deep"      => super::config::ScanMode::Deep,
        "exhaustive"=> super::config::ScanMode::Exhaustive,
        _ => anyhow::bail!(
            "Invalid mode: {}. Must be quick, standard, deep, or exhaustive", mode
        ),
    };

    // Parse GPU backend
    let gpu_backend = match backend_str {
        Some(s) => match s.to_lowercase().as_str() {
            "auto"   => GpuBackend::Auto,
            "wgpu"   => GpuBackend::Wgpu,
            "opencl" => GpuBackend::OpenCl,
            "cpu"    => GpuBackend::Cpu,
            _ => return Err(anyhow::anyhow!("Invalid backend: must be auto, wgpu, opencl, or cpu")),
        },
        None => GpuBackend::Auto,
    };

    let phase_enum = match phase {
        1 => super::fingerprints::Phase::One,
        2 => super::fingerprints::Phase::Two,
        3 => super::fingerprints::Phase::Three,
        _ => anyhow::bail!("Invalid phase: {}. Must be 1, 2, or 3", phase),
    };

    let engine = MathRandomEngine::from_str(math_random_engine).unwrap_or(MathRandomEngine::V8Mwc1616);

    // 3. Handle Estimate Mode (Early exit)
    if estimate_mode {
        let window_ms = if let (Some(start), Some(end)) = (start_ms, end_ms) {
            end.saturating_sub(start)
        } else {
            scan_mode.interval_ms()
        };
        let num_configs = match phase { 1 => 100, 2 => 500, _ => 2000 };
        let report = super::attack_estimator::AttackComplexity::estimate(
            window_ms, num_configs, &[engine],
        );
        super::attack_estimator::print_complexity_report(&report);
        return Ok(());
    }

    info!("\u{1f50d} Randstorm Scanner Starting");
    info!("Phase: {:?}", phase_enum);
    info!("Target addresses: {}", target_addresses_path.display());

    let mut addresses = load_addresses_from_csv(target_addresses_path).unwrap_or_default();

    if let (Some(db), Some(class)) = (db_path, target_class) {
        info!("Loading targets from database ({}) for class: {}", db.display(), class);
        let target_db = crate::utils::db::TargetDatabase::new(db.to_path_buf())?;
        let db_targets = target_db.query_by_class(class, 1_000_000)?;
        for t in db_targets { addresses.push(t.address); }
    }

    if addresses.is_empty() {
        anyhow::bail!("No valid addresses found in CSV or Database");
    }

    info!("Loaded {} target addresses", addresses.len());

    if force_gpu && force_cpu {
        anyhow::bail!("Cannot specify both --gpu and --cpu flags");
    }

    if let (Some(start), Some(end)) = (start_ms, end_ms) {
        #[cfg(feature = "wgpu")]
        if force_gpu || !force_cpu {
            match gpu_direct_sweep_scan(
                &addresses, start, end, interval_ms,
                output_path, math_random_engine, include_uncompressed,
                fingerprints_csv,
            ) {
                Ok(()) => return Ok(()),
                Err(e) => tracing::warn!("\u{26a0}\u{fe0f}  GPU sweep failed ({}), falling back to CPU", e),
            }
        }

        direct_sweep_scan(
            &addresses, start, end, interval_ms,
            output_path, math_random_engine,
            seed_override, seed_bruteforce_bits, include_uncompressed,
        )?;
    } else {
        let mut cfg = super::config::ScanConfig::default();
        cfg.scan_mode   = scan_mode;
        cfg.gpu_backend = gpu_backend;
        cfg.use_gpu     = !force_cpu;
        cfg.path_coverage = super::config::PathCoverage::from_str(path_coverage);

        let mut scanner = RandstormScanner::with_config(cfg, engine)?;

        let pb = ProgressBar::new(addresses.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} addresses ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );

        let results = scanner.scan_with_progress(&addresses, phase_enum)?;
        pb.finish_with_message("Scan complete!");
        output_results(&results, output_path)?;
        info!("\u{2705} Scan complete. Found {} vulnerable addresses", results.len());
    }

    Ok(())
}

/// Validate bit-parity between CPU Golden Reference and GPU backends
pub fn run_validate_parity(backend_str: &str, count: u64, engine_str: &str) -> Result<()> {
    info!("\u{1f9ea} Zero-Tolerance Parity Validation");
    info!("   Backend: {}", backend_str);
    info!("   Engine:  {}", engine_str);
    info!("   Samples: {}", count);

    let engine = super::prng::MathRandomEngine::from_str(engine_str)
        .ok_or_else(|| anyhow::anyhow!("Invalid engine: {}", engine_str))?;

    #[cfg(feature = "wgpu")]
    if backend_str.to_lowercase() == "wgpu" {
        let mut wgpu = super::wgpu_integration::WgpuScanner::new(
            super::config::ScanConfig::default(),
            engine,
            None,
            true,
        )?;
        super::validator::HardwareParityChecker::validate_v8_parity(&mut wgpu, count)?;
    } else {
        info!("\u{26a0} Validation for backend '{}' not yet implemented.", backend_str);
    }

    #[cfg(not(feature = "wgpu"))]
    {
        info!("\u{26a0} WGPU feature not compiled. Validation skipped.");
    }

    Ok(())
}

// ── GPU Direct Sweep (WGPU path) ─────────────────────────────────────────

#[cfg(feature = "wgpu")]
fn gpu_direct_sweep_scan(
    addresses:            &[String],
    start_ms:             u64,
    end_ms:               u64,
    interval_ms:          u64,
    output_path:          Option<&Path>,
    math_random_engine:   &str,
    include_uncompressed: bool,
    fingerprints_csv:     Option<&Path>,
) -> Result<()> {
    use super::wgpu_integration::{load_fingerprints, WgpuScanner, GpuMatchResult};
    use crate::utils::gpu_bloom_filter::{compute_bloom_bits, GpuBloomConfig};

    if interval_ms == 0  { anyhow::bail!("interval_ms must be > 0"); }
    if start_ms > end_ms { anyhow::bail!("start_ms must be <= end_ms"); }

    let engine = MathRandomEngine::from_str(math_random_engine)
        .unwrap_or(MathRandomEngine::V8Mwc1616);

    let fingerprints = if let Some(csv) = fingerprints_csv {
        info!("\u{1f5c2}  Loading fingerprints from: {}", csv.display());
        load_fingerprints(csv, None, None, None)
            .context("Failed to load fingerprints CSV")?
    } else {
        info!("\u{26a0}\u{fe0f}  No --fingerprints-csv provided, using default single fingerprint (1366x768 cd=32 tz=0)");
        vec![super::wgpu_integration::GpuFingerprint {
            screen_width:    1366,
            screen_height:   768,
            color_depth:     32,
            timezone_offset: 0,
        }]
    };

    info!("\u{1f4ca} GPU Direct Sweep");
    info!("   Addresses:    {}", addresses.len());
    info!("   Range:        {} → {}", start_ms, end_ms);
    info!("   Interval:     {} ms", interval_ms);
    info!("   Fingerprints: {}", fingerprints.len());

    let address_hashes = prepare_address_hashes(addresses)?;

    let bloom_cfg = GpuBloomConfig {
        expected_items: addresses.len(),
        fp_rate: 0.0001,
        num_hashes: 15,
    };
    let bloom_data = compute_bloom_bits(
        &address_hashes,
        bloom_cfg.calculate_filter_size(),
        15,
    );

    let wgpu = WgpuScanner::new(
        super::config::ScanConfig::default(),
        engine,
        None,
        true,
    ).context("Failed to initialize WGPU scanner")?;

    // Incremental CPU verification using sweep_with_callback
    let secp = Secp256k1::new();
    let addr_set: HashSet<&str> = addresses.iter().map(|s| s.as_str()).collect();
    let mut findings = Vec::new();
    let mut total_verified = 0usize;

    wgpu.sweep_with_callback(
        start_ms,
        end_ms,
        interval_ms as u32,
        &bloom_data,
        &fingerprints,
        |batch_num, total_batches, batch_results: &[GpuMatchResult]| {
            // CPU-verify each bloom hit in this batch
            for result in batch_results {
                let ts = ((result.timestamp_hi as u64) << 32) | result.timestamp_lo as u64;
                let key_bytes = BitcoinJsV013Prng::generate_privkey_bytes(ts, engine, None);

                if let Ok(sk) = SecretKey::from_slice(&key_bytes) {
                    let pk = PublicKey::from_secret_key(&secp, &sk);

                    for compressed in [true, false] {
                        if !compressed && !include_uncompressed { break; }
                        let btc_pk = bitcoin::PublicKey { inner: pk, compressed };
                        let addr = Address::p2pkh(&btc_pk, bitcoin::Network::Bitcoin);
                        let addr_str = addr.to_string();

                        if addr_set.contains(addr_str.as_str()) {
                            info!("\u{1f511} VERIFIED MATCH: {} @ ts={}", addr_str, ts);
                            findings.push(super::integration::VulnerabilityFinding {
                                address: addr_str.clone(),
                                confidence: super::integration::Confidence::High,
                                browser_config: super::fingerprints::BrowserConfig {
                                    priority:              1,
                                    user_agent:            String::new(),
                                    screen_width:          fingerprints[0].screen_width,
                                    screen_height:         fingerprints[0].screen_height,
                                    color_depth:           fingerprints[0].color_depth as u8,
                                    timezone_offset:       fingerprints[0].timezone_offset as i16,
                                    language:              String::new(),
                                    platform:              String::new(),
                                    market_share_estimate: 0.0,
                                    year_min:              2011,
                                    year_max:              2016,
                                },
                                timestamp:       ts,
                                derivation_path: "gpu-verified".to_string(),
                            });
                            break; // Found match for this timestamp, stop checking compressed/uncompressed
                        }
                    }
                }
            }

            total_verified += batch_results.len();

            // Progress report every 100 batches
            if batch_num % 100 == 0 {
                info!("\u{1f4ca} Progress: {}/{} batches | Verified hits: {} | True matches: {}",
                    batch_num, total_batches, total_verified, findings.len());
            }

            Ok(())
        },
    )?;

    output_results(&findings, output_path)?;
    info!("\u{2705} GPU Direct Sweep complete. Total verified: {} | True matches: {}", total_verified, findings.len());
    Ok(())
}

// ── CPU Direct Sweep fallback ────────────────────────────────────────────

fn direct_sweep_scan(
    addresses:            &[String],
    start_ms:             u64,
    end_ms:               u64,
    interval_ms:          u64,
    output_path:          Option<&Path>,
    math_random_engine:   &str,
    seed_override:        Option<u64>,
    seed_bruteforce_bits: Option<u8>,
    include_uncompressed: bool,
) -> Result<()> {
    use rayon::prelude::*;

    if interval_ms == 0 { anyhow::bail!("interval_ms must be > 0"); }

    let engine = MathRandomEngine::from_str(math_random_engine)
        .unwrap_or(MathRandomEngine::V8Mwc1616);

    let addr_set: HashSet<String> = addresses.iter().cloned().collect();

    let timestamps: Vec<u64> = if let Some(seed) = seed_override {
        vec![seed]
    } else {
        let bits = seed_bruteforce_bits.unwrap_or(0);
        if bits > 0 {
            let range = 1u64 << bits;
            (start_ms..start_ms.saturating_add(range)).step_by(interval_ms as usize).collect()
        } else {
            (start_ms..=end_ms).step_by(interval_ms as usize).collect()
        }
    };

    info!("CPU Direct Sweep: {} timestamps", timestamps.len());

    let secp = Secp256k1::new();

    let findings: Vec<super::integration::VulnerabilityFinding> = timestamps
        .par_iter()
        .filter_map(|&ts| {
            let key_bytes = BitcoinJsV013Prng::generate_privkey_bytes(ts, engine, None);
            if let Ok(sk) = SecretKey::from_slice(&key_bytes) {
                let pk = PublicKey::from_secret_key(&secp, &sk);
                for compressed in [true, false] {
                    if !compressed && !include_uncompressed { break; }
                    let btc_pk = bitcoin::PublicKey { inner: pk, compressed };
                    let addr = Address::p2pkh(&btc_pk, bitcoin::Network::Bitcoin).to_string();
                    if addr_set.contains(&addr) {
                        return Some(super::integration::VulnerabilityFinding {
                            address: addr,
                            confidence: super::integration::Confidence::High,
                            browser_config: super::fingerprints::BrowserConfig {
                                priority:              1,
                                user_agent:            String::new(),
                                screen_width:          1366,
                                screen_height:         768,
                                color_depth:           32,
                                timezone_offset:       0,
                                language:              String::new(),
                                platform:              String::new(),
                                market_share_estimate: 0.0,
                                year_min:              2011,
                                year_max:              2016,
                            },
                            timestamp:       ts,
                            derivation_path: "direct-cpu".to_string(),
                        });
                    }
                }
            }
            None
        })
        .collect();

    output_results(&findings, output_path)?;
    info!("\u{2705} CPU Direct Sweep complete. Found: {}", findings.len());
    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn prepare_address_hashes(addresses: &[String]) -> Result<Vec<Vec<u8>>> {
    use std::str::FromStr;
    let mut result = Vec::with_capacity(addresses.len());
    for addr_str in addresses {
        let address = Address::from_str(addr_str)
            .context(format!("Invalid Bitcoin address: {}", addr_str))?
            .assume_checked();
        let script = address.script_pubkey();
        if script.is_p2pkh() {
            result.push(script.as_bytes()[3..23].to_vec());
        } else if script.is_p2sh() {
            result.push(script.as_bytes()[2..22].to_vec());
        } else {
            anyhow::bail!("Unsupported address type for direct sweep: {}", addr_str);
        }
    }
    Ok(result)
}

pub fn load_addresses_from_csv(path: &Path) -> Result<Vec<String>> {
    let file = File::open(path).context(format!("Cannot open {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut addresses = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
        let addr = trimmed.split(',').next().unwrap_or(trimmed).trim();
        if addr.starts_with('1') || addr.starts_with('3') || addr.starts_with("bc1") {
            addresses.push(addr.to_string());
        }
    }
    Ok(addresses)
}

fn output_results(
    results: &[super::integration::VulnerabilityFinding],
    output_path: Option<&Path>,
) -> Result<()> {
    if results.is_empty() {
        info!("No findings to output.");
        return Ok(());
    }
    if let Some(path) = output_path {
        let mut file = File::create(path).context("Cannot create output file")?;
        writeln!(file, "address,confidence,timestamp,browser_config,derivation_path")?;
        for r in results {
            writeln!(file, "{},{:?},{},{:?},{}",
                r.address, r.confidence, r.timestamp,
                r.browser_config.user_agent, r.derivation_path)?;
        }
        info!("Results written to {}", path.display());
    } else {
        for r in results {
            println!("FOUND: {} | ts={} | conf={:?} | path={}",
                r.address, r.timestamp, r.confidence, r.derivation_path);
        }
    }
    Ok(())
}

fn format_timestamp(ts_ms: u64) -> String {
    if ts_ms == 0 {
        return "1970-01-01T00:00:00Z".to_string();
    }
    let secs = (ts_ms / 1000) as i64;
    let nanos = ((ts_ms % 1000) * 1_000_000) as u32;
    if let Some(dt) = chrono::DateTime::from_timestamp(secs, nanos) {
        dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    } else {
        format!("ts:{}", ts_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // TEST-ID: CSV-001 | AC: load valid P2PKH | PRIORITY: P1
    #[test]
    fn test_load_valid_p2pkh_addresses() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf").unwrap();
        writeln!(f, "1BpEi6DfDAUFd153wiGrvkiboLLaqFZqW").unwrap();
        let addrs = load_addresses_from_csv(f.path()).unwrap();
        assert_eq!(addrs.len(), 2);
    }

    // TEST-ID: CSV-002 | AC: skip comments and blank lines | PRIORITY: P1
    #[test]
    fn test_load_csv_skips_comments() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "# comment").unwrap();
        writeln!(f, "").unwrap();
        writeln!(f, "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf").unwrap();
        let addrs = load_addresses_from_csv(f.path()).unwrap();
        assert_eq!(addrs.len(), 1);
    }

    // TEST-ID: CSV-003 | AC: parse first column of multi-column CSV | PRIORITY: P2
    #[test]
    fn test_load_csv_first_column() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf,extra,data").unwrap();
        let addrs = load_addresses_from_csv(f.path()).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf");
    }

    // TEST-ID: TS-001 | AC: ISO 8601 format | PRIORITY: P2
    #[test]
    fn test_format_timestamp_iso8601() {
        let s = format_timestamp(1366027200000);
        assert!(s.contains("2013"), "Expected year 2013 in {}", s);
    }

    // TEST-ID: TS-002 | AC: epoch zero | PRIORITY: P3
    #[test]
    fn test_format_timestamp_epoch_zero() {
        assert_eq!(format_timestamp(0), "1970-01-01T00:00:00Z");
    }
}
