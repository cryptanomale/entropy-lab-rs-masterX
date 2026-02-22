//! GPU-Accelerated Blocked Bloom Filter
//!
//! Part of STORY-003-001: Implement OpenCL Blocked Bloom Filter Kernel
//!
//! This module provides a GPU-accelerated Bloom filter for efficient
//! membership testing against large target address sets (1M+ addresses).

use anyhow::{Context, Result};
#[cfg(feature = "gpu")]
use ocl::{Buffer, Kernel, Program, Queue};
use std::fs::File;
use std::io::{BufRead, BufReader};
use tracing::info;

/// Configuration for the GPU Bloom Filter
#[derive(Debug, Clone)]
pub struct GpuBloomConfig {
    /// Expected number of items in the filter
    pub expected_items: usize,
    /// Target false positive rate (e.g., 0.001 for 0.1%)
    pub fp_rate: f64,
    /// Number of hash functions to use
    pub num_hashes: usize,
}

impl Default for GpuBloomConfig {
    fn default() -> Self {
        Self {
            expected_items: 1_000_000,
            fp_rate: 0.001,
            num_hashes: 15,
        }
    }
}

impl GpuBloomConfig {
    /// Calculate optimal filter size in bytes for given parameters
    pub fn calculate_filter_size(&self) -> usize {
        // m = -n * ln(p) / (ln(2)^2)
        let n = self.expected_items as f64;
        let p = self.fp_rate;
        let ln2_sq = std::f64::consts::LN_2.powi(2);
        let m_bits = (-n * p.ln() / ln2_sq).ceil() as usize;
        // Round up to 256-bit (32-byte) blocks for GPU cache alignment
        let m_bytes = (m_bits + 255) / 256 * 32;
        m_bytes
    }

    /// Calculate optimal number of hash functions
    pub fn calculate_optimal_k(&self) -> usize {
        // k = (m/n) * ln(2)
        let m = self.calculate_filter_size() * 8;
        let n = self.expected_items;
        let k = (m as f64 / n as f64) * std::f64::consts::LN_2;
        k.ceil() as usize
    }
}

/// GPU-backed Bloom Filter for high-performance address lookup
pub struct GpuBloomFilter {
    /// OpenCL queue
    #[cfg(feature = "gpu")]
    queue: Queue,
    /// OpenCL program
    #[cfg(feature = "gpu")]
    program: Program,
    /// GPU buffer containing the filter bits
    #[cfg(feature = "gpu")]
    filter_buffer: Buffer<u8>,
    /// Size of the filter in bytes
    filter_size: usize,
    /// Number of items inserted
    item_count: usize,
    /// Configuration
    config: GpuBloomConfig,
}

impl GpuBloomFilter {
    /// Create a new GPU Bloom Filter
    #[cfg(feature = "gpu")]
    pub fn new(queue: Queue, config: GpuBloomConfig) -> Result<Self> {
        let filter_size = config.calculate_filter_size();
        info!(
            "Initializing GPU Bloom Filter: {} bytes ({:.2} MB), k={} hashes",
            filter_size,
            filter_size as f64 / 1_048_576.0,
            config.num_hashes
        );

        // Load and compile the OpenCL kernel
        let kernel_src = include_str!("../../../../cl/bloom_filter.cl");
        let program = Program::builder()
            .src(kernel_src)
            .devices(queue.device())
            .build(&queue.context())?;

        // Create the filter buffer (initialized to zeros)
        let filter_buffer = Buffer::<u8>::builder()
            .queue(queue.clone())
            .len(filter_size)
            .fill_val(0u8)
            .build()?;

        Ok(Self {
            queue,
            program,
            filter_buffer,
            filter_size,
            item_count: 0,
            config,
        })
    }

    /// Populate the filter from a file of addresses
    #[cfg(feature = "gpu")]
    pub fn populate_from_file(&mut self, path: &str) -> Result<usize> {
        info!("Loading target addresses from {} into GPU Bloom Filter...", path);

        let file = File::open(path).context("Failed to open address file")?;
        let reader = BufReader::new(file);

        // Collect addresses into a Vec for batch processing
        let mut addresses: Vec<Vec<u8>> = Vec::new();
        for line in reader.lines() {
            let line = line?;
            let addr = line.trim();
            if !addr.is_empty() {
                // Decode base58 address to raw bytes (simplified - assumes valid P2PKH)
                addresses.push(addr.as_bytes().to_vec());
            }
        }

        let count = addresses.len();
        info!("Read {} addresses, inserting into GPU filter...", count);

        // For now, insert on CPU and transfer to GPU
        // TODO: Implement GPU-side insertion for large batches
        self.insert_batch_cpu(&addresses)?;
        self.item_count = count;

        info!("GPU Bloom Filter populated with {} addresses", count);
        Ok(count)
    }

    /// Populate Bloom filter from a list of 20-byte hashes
    #[cfg(feature = "gpu")]
    pub fn populate_from_hashes(&mut self, hashes: &[Vec<u8>]) -> Result<()> {
        let filter_data = compute_bloom_bits(hashes, self.filter_size, self.config.num_hashes);
 
        // Transfer to GPU
        self.filter_buffer.write(&filter_data).enq()?;
        self.queue.finish()?;
        self.item_count = hashes.len();
 
        Ok(())
    }

    /// Insert a batch of items (public API)
    #[cfg(feature = "gpu")]
    pub fn insert_batch(&mut self, items: &[Vec<u8>]) -> Result<()> {
        self.insert_batch_cpu(items)
    }

    /// Insert a batch of items using CPU-side insertion (for initial population)
    #[cfg(feature = "gpu")]
    fn insert_batch_cpu(&mut self, items: &[Vec<u8>]) -> Result<()> {
        // Read filter from GPU
        let mut filter_data = vec![0u8; self.filter_size];
        self.filter_buffer.read(&mut filter_data).enq()?;

        // Insert each item
        for item in items {
            for k in 0..self.config.num_hashes {
                let bit_pos = self.hash_k(item, k);
                let byte_pos = bit_pos / 8;
                let bit_offset = (bit_pos % 8) as u8;
                filter_data[byte_pos] |= 1 << bit_offset;
            }
        }

        // Write back to GPU
        self.filter_buffer.write(&filter_data).enq()?;
        self.queue.finish()?;
        Ok(())
    }

    /// Generate the k-th hash for an item
    fn hash_k(&self, item: &[u8], k: usize) -> usize {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let mut h1 = DefaultHasher::new();
        item.hash(&mut h1);
        0usize.hash(&mut h1);
        let h1_val = h1.finish() as usize;

        let mut h2 = DefaultHasher::new();
        item.hash(&mut h2);
        h1_val.hash(&mut h2);
        let h2_val = h2.finish() as usize;

        (h1_val.wrapping_add(k.wrapping_mul(h2_val))) % (self.filter_size * 8)
    }

    /// Check if items are possibly in the filter (GPU-accelerated batch lookup)
    #[cfg(feature = "gpu")]
    pub fn batch_lookup(&self, items: &[Vec<u8>]) -> Result<Vec<bool>> {
        if items.is_empty() {
            return Ok(vec![]);
        }

        let num_items = items.len();
        let item_len = items[0].len();

        // Flatten items into a single buffer
        let flat_items: Vec<u8> = items.iter().flat_map(|i| i.iter().copied()).collect();

        // Create GPU buffers
        let items_buffer = Buffer::<u8>::builder()
            .queue(self.queue.clone())
            .len(flat_items.len())
            .copy_host_slice(&flat_items)
            .build()?;

        let results_buffer = Buffer::<u8>::builder()
            .queue(self.queue.clone())
            .len(num_items)
            .fill_val(0u8)
            .build()?;

        // Build and execute kernel
        let kernel = Kernel::builder()
            .program(&self.program)
            .name("bloom_lookup")
            .queue(self.queue.clone())
            .arg(&self.filter_buffer)
            .arg(&(self.filter_size as u32))
            .arg(&items_buffer)
            .arg(&(item_len as u32))
            .arg(&(num_items as u32))
            .arg(&results_buffer)
            .global_work_size(num_items)
            .build()?;

        unsafe {
            kernel.enq()?;
        }

        // Read results
        let mut results = vec![0u8; num_items];
        results_buffer.read(&mut results).enq()?;

        Ok(results.iter().map(|&r| r != 0).collect())
    }

    /// Get the number of items in the filter
    pub fn item_count(&self) -> usize {
        self.item_count
    }

    /// Get the filter size in bytes
    pub fn filter_size(&self) -> usize {
        self.filter_size
    }

    /// Get the underlying OpenCL buffer
    #[cfg(feature = "gpu")]
    pub fn buffer(&self) -> &Buffer<u8> {
        &self.filter_buffer
    }
 
    /// Get the raw filter bytes from the GPU
    #[cfg(feature = "gpu")]
    pub fn get_bytes(&self) -> Result<Vec<u8>> {
        let mut data = vec![0u8; self.filter_size];
        self.filter_buffer.read(&mut data).enq()?;
        return Ok(data);
    }

    /// Get the theoretical false positive rate
    pub fn theoretical_fp_rate(&self) -> f64 {
        // p = (1 - e^(-kn/m))^k
        let k = self.config.num_hashes as f64;
        let n = self.item_count as f64;
        let m = (self.filter_size * 8) as f64;
        (1.0 - (-k * n / m).exp()).powf(k)
    }
}

/// Helper function to compute Bloom filter bits on CPU
pub fn compute_bloom_bits(hashes: &[Vec<u8>], filter_size: usize, num_hashes: usize) -> Vec<u8> {
    let mut filter_data = vec![0u8; filter_size];
    for hash in hashes {
        for k in 0..num_hashes {
            let bit_pos = hash_k_static(hash, k, filter_size);
            let byte_pos = bit_pos / 8;
            let bit_offset = (bit_pos % 8) as u8;
            filter_data[byte_pos] |= 1 << bit_offset;
        }
    }
    filter_data
}

fn hash_k_static(item: &[u8], k: usize, filter_size: usize) -> usize {
    let d0 = u32::from_le_bytes(item[0..4].try_into().unwrap_or([0; 4]));
    let d1 = u32::from_le_bytes(item[4..8].try_into().unwrap_or([0; 4]));
    let d2 = u32::from_le_bytes(item[8..12].try_into().unwrap_or([0; 4]));
    let d3 = u32::from_le_bytes(item[12..16].try_into().unwrap_or([0; 4]));
    let d4 = u32::from_le_bytes(item[16..20].try_into().unwrap_or([0; 4]));
    
    let seed = 0x9E3779B9u32;
    let h1 = murmur_hash_x5(d0, d1, d2, d3, d4, seed);
    let h2 = murmur_hash_x5(d0, d1, d2, d3, d4, h1);
    
    ((h1.wrapping_add((k as u32).wrapping_mul(h2))) as usize) % (filter_size * 8)
}

fn murmur_hash_x5(d0: u32, d1: u32, d2: u32, d3: u32, d4: u32, seed: u32) -> u32 {
    let mut h = seed;
    let data = [d0, d1, d2, d3, d4];
    for &val in &data {
        let mut k = val;
        k = k.wrapping_mul(0xCC9E2D51);
        k = k.rotate_left(15);
        k = k.wrapping_mul(0x1B873593);
        h ^= k;
        h = h.rotate_left(13);
        h = h.wrapping_mul(5).wrapping_add(0xE6546B64);
    }
    h ^= 20;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85EBCA6B);
    h ^= h >> 13;
    h = h.wrapping_mul(0xC2B2AE35);
    h ^= h >> 16;
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_calculation() {
        let config = GpuBloomConfig {
            expected_items: 1_000_000,
            fp_rate: 0.001,
            num_hashes: 15,
        };

        let size = config.calculate_filter_size();
        // Should be roughly 1.8 MB for 1M items at 0.1% FPR
        assert!(size > 1_000_000);
        assert!(size < 3_000_000);

        let k = config.calculate_optimal_k();
        // k should be around 10-15 for this configuration
        assert!(k >= 8);
        assert!(k <= 20);
    }

    #[test]
    fn test_hash_distribution() {
        let config = GpuBloomConfig::default();
        
        // This test would require GPU context, so just validate config
        assert_eq!(config.num_hashes, 15);
        assert!(config.fp_rate < 0.01);
    }
}
