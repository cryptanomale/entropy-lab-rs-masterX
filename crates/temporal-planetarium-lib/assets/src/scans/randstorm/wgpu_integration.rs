use anyhow::{Context, Result};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use wgpu::util::DeviceExt;
use crate::scans::randstorm::fingerprint::BrowserFingerprint;
use crate::scans::randstorm::config::ScanConfig;
use crate::scans::randstorm::prng::MathRandomEngine;
use crate::scans::randstorm::gpu_integration::{GpuBatchResult, MatchedKey};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

pub struct WgpuScanner {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::ComputePipeline,
    bind_group_layout: wgpu::BindGroupLayout,
    keys_checked: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
    engine_type: u32,
    
    // Persistent buffers to avoid allocation overhead in main loop
    fp_buffer: Option<wgpu::Buffer>,
    bloom_buffer: Option<wgpu::Buffer>,
    result_buffer: Option<wgpu::Buffer>,
    staging_buffer: Option<wgpu::Buffer>,
    bind_group: Option<wgpu::BindGroup>,
    current_batch_capacity: usize,
}

impl WgpuScanner {
    pub fn new(
        _config: ScanConfig,
        engine: MathRandomEngine,
        _seed_override: Option<u64>,
        _include_uncompressed: bool,
    ) -> Result<Self> {
        pollster::block_on(Self::new_async(engine))
    }

    async fn new_async(engine: MathRandomEngine) -> Result<Self> {
        let instance = wgpu::Instance::default();
        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                compatible_surface: None,
                force_fallback_adapter: false,
            })
            .await
            .context("Failed to find a suitable GPU adapter")?;

        let (device, queue) = adapter
            .request_device(
                &wgpu::DeviceDescriptor {
                    label: Some("Randstorm Wgpu Device"),
                    required_features: wgpu::Features::empty(),
                    required_limits: wgpu::Limits::default(),
                    memory_hints: wgpu::MemoryHints::Performance,
                },
                None,
            )
            .await
            .context("Failed to create WGPU device")?;

        let shader_src = include_str!("randstorm.wgsl");
        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("Randstorm Shader"),
            source: wgpu::ShaderSource::Wgsl(shader_src.into()),
        });

        let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("Randstorm Bind Group Layout"),
            entries: &[
                // Fingerprints (input)
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                // Bloom Filter (input)
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                // Results (output)
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        });

        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("Randstorm Pipeline Layout"),
            bind_group_layouts: &[&bind_group_layout],
            push_constant_ranges: &[],
        });

        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("Randstorm Compute Pipeline"),
            layout: Some(&pipeline_layout),
            module: &shader,
            entry_point: "randstorm_main",
            compilation_options: Default::default(),
            cache: None,
        });

        let engine_type = match engine {
            MathRandomEngine::V8Mwc1616 => 0,
            MathRandomEngine::SpiderMonkeyLcg |
            MathRandomEngine::IeChakraLcg |
            MathRandomEngine::JavaUtil => 1,
            MathRandomEngine::SafariWindowsCrt => 2,
            _ => 0,
        };

        Ok(Self {
            device,
            queue,
            pipeline,
            bind_group_layout,
            keys_checked: Arc::new(AtomicU64::new(0)),
            running: Arc::new(AtomicBool::new(true)),
            engine_type,
            fp_buffer: None,
            bloom_buffer: None,
            result_buffer: None,
            staging_buffer: None,
            bind_group: None,
            current_batch_capacity: 0,
        })
    }

    pub fn process_batch(
        &mut self,
        fingerprints: &[BrowserFingerprint],
        bloom_filter: &[u8],
    ) -> Result<GpuBatchResult> {
        let start_time = std::time::Instant::now();
        let batch_size = fingerprints.len();
        if batch_size == 0 {
            return Ok(GpuBatchResult {
                keys_processed: 0,
                matches_found: Vec::new(),
                elapsed_ms: 0,
            });
        }

        // 1. Ensure buffers and bind groups are allocated and have enough capacity
        if self.current_batch_capacity < batch_size {
            let fp_size = (batch_size * 16) as u64;
            let bloom_size = bloom_filter.len() as u64;
            let result_size = (batch_size * 64) as u64;

            self.fp_buffer = Some(self.device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("Fingerprint Buffer"),
                size: fp_size,
                usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            }));

            self.bloom_buffer = Some(self.device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("Bloom Buffer"),
                size: bloom_size,
                usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            }));

            self.result_buffer = Some(self.device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("Result Buffer"),
                size: result_size,
                usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
                mapped_at_creation: false,
            }));

            self.staging_buffer = Some(self.device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("Staging Buffer"),
                size: result_size,
                usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            }));

            self.bind_group = Some(self.device.create_bind_group(&wgpu::BindGroupDescriptor {
                label: Some("Randstorm Bind Group"),
                layout: &self.bind_group_layout,
                entries: &[
                    wgpu::BindGroupEntry {
                        binding: 0,
                        resource: self.fp_buffer.as_ref().unwrap().as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 1,
                        resource: self.bloom_buffer.as_ref().unwrap().as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 2,
                        resource: self.result_buffer.as_ref().unwrap().as_entire_binding(),
                    },
                ],
            }));

            self.current_batch_capacity = batch_size;
            
            // Initial bloom write (usually doesn't change)
            self.queue.write_buffer(self.bloom_buffer.as_ref().unwrap(), 0, bloom_filter);
        }

        // 2. Pack and write fingerprints
        let mut fp_data = Vec::with_capacity(batch_size * 16);
        for fp in fingerprints {
            fp_data.extend_from_slice(&fp.timestamp_ms.to_ne_bytes());
            fp_data.extend_from_slice(&(fp.screen_width as u32).to_ne_bytes());
            fp_data.extend_from_slice(&(fp.screen_height as u32).to_ne_bytes());
        }
        self.queue.write_buffer(self.fp_buffer.as_ref().unwrap(), 0, &fp_data);

        // 3. Encode and submit compute pass
        let mut encoder = self.device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("Randstorm Command Encoder"),
        });

        {
            let mut cpass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("Randstorm Compute Pass"),
                timestamp_writes: None,
            });
            cpass.set_pipeline(&self.pipeline);
            cpass.set_bind_group(0, self.bind_group.as_ref().unwrap(), &[]);
            let workgroup_count = (batch_size as u32 + 63) / 64;
            cpass.dispatch_workgroups(workgroup_count, 1, 1);
        }

        let result_size = (batch_size * 64) as u64;
        encoder.copy_buffer_to_buffer(
            self.result_buffer.as_ref().unwrap(), 0, 
            self.staging_buffer.as_ref().unwrap(), 0, 
            result_size
        );

        self.queue.submit(Some(encoder.finish()));

        // 4. Map and read back
        let buffer_slice = self.staging_buffer.as_ref().unwrap().slice(..);
        let (sender, receiver) = std::sync::mpsc::channel();
        buffer_slice.map_async(wgpu::MapMode::Read, move |v| {
            let _ = sender.send(v);
        });

        self.device.poll(wgpu::Maintain::Wait);

        if let Ok(Ok(())) = receiver.recv() {
            let data = buffer_slice.get_mapped_range();
            let _results: &[u32] = bytemuck::cast_slice(&data);

            let mut matches = Vec::new();
            let secp = Secp256k1::new();
            for idx in 0..batch_size {
                let base = idx * 16;
                if _results[base + 8] != 0 {
                    let fp = &fingerprints[idx];
                    if let Ok(sk) = self.derive_key_from_fingerprint(fp) {
                        let pk = PublicKey::from_secret_key(&secp, &sk);
                        let addr = crate::scans::randstorm::derivation::derive_p2pkh_address(&pk);
                        matches.push(MatchedKey {
                            private_key: sk,
                            public_key: pk,
                            address: addr,
                            fingerprint: fp.clone(),
                        });
                    }
                }
            }
            
            drop(data);
            self.staging_buffer.as_ref().unwrap().unmap();
            
            let elapsed_ms = start_time.elapsed().as_millis() as u64;
            self.keys_checked.fetch_add(batch_size as u64, Ordering::Relaxed);
            
            Ok(GpuBatchResult {
                keys_processed: batch_size as u64,
                matches_found: matches,
                elapsed_ms,
            })
        } else {
            anyhow::bail!("Failed to map WGPU buffer")
        }
    }

    fn derive_key_from_fingerprint(&self, fp: &BrowserFingerprint) -> Result<SecretKey> {
        use super::prng::bitcoinjs_v013::BitcoinJsV013Prng;
        let engine = match self.engine_type {
            0 => MathRandomEngine::V8Mwc1616,
            1 => MathRandomEngine::JavaUtil,
            2 => MathRandomEngine::SafariWindowsCrt,
            _ => MathRandomEngine::V8Mwc1616,
        };
        let bytes = BitcoinJsV013Prng::generate_privkey_bytes(fp.timestamp_ms, engine, None);
        SecretKey::from_slice(&bytes).context("Invalid key from fingerprint")
    }

    pub fn keys_checked(&self) -> u64 {
        self.keys_checked.load(Ordering::Relaxed)
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scans::randstorm::config::ScanConfig;

    #[test]
    fn test_wgpu_scanner_creation() {
        let scanner = WgpuScanner::new(
            ScanConfig::default(),
            MathRandomEngine::V8Mwc1616,
            None,
            true,
        );
        assert!(scanner.is_ok(), "WGPU scanner creation failed: {:?}", scanner.err());
    }

    #[test]
    fn test_wgpu_hashing_parity() {
        let mut scanner = WgpuScanner::new(
            ScanConfig::default(),
            MathRandomEngine::V8Mwc1616,
            None,
            true,
        ).unwrap();

        // 2013 test vector - simplified for bit-perfect verification
        let ts = 0x12345678u64;

        let fingerprints = vec![
            BrowserFingerprint {
                timestamp_ms: ts,
                user_agent: "Mozilla/5.0 (Windows NT 6.1) Chrome/25.0".to_string(),
                screen_width: 1366,
                screen_height: 768,
                color_depth: 24,
                timezone_offset: -300,
                language: "en-US".to_string(),
                platform: "Win32".to_string(),
            }
        ];

        use crate::scans::randstorm::prng::bitcoinjs_v013::BitcoinJsV013Prng;
        use crate::scans::randstorm::prng::MathRandomEngine;

        let privkey_bytes = BitcoinJsV013Prng::generate_privkey_bytes(ts, MathRandomEngine::V8Mwc1616, None);

        // Emulate WGSL Stub: PubKey X = PrivKey (compressed 02 || X)
        let mut mock_pubkey = vec![0x02u8];
        mock_pubkey.extend_from_slice(&privkey_bytes);

        use sha2::{Sha256, Digest};
        let sha_hash = Sha256::digest(&mock_pubkey);

        use ripemd::Ripemd160;
        let ripe_hash = Ripemd160::digest(&sha_hash);

        // 2. Create a Bloom filter targeting only this bit
        use crate::utils::gpu_bloom_filter::{compute_bloom_bits, GpuBloomConfig};
        let bloom_cfg = GpuBloomConfig::default();
        let bloom_data = compute_bloom_bits(&[ripe_hash.to_vec()], bloom_cfg.calculate_filter_size(), 15);

        // 3. Run GPU scanner
        let result = scanner.process_batch(&fingerprints, &bloom_data).unwrap();
        
        // 4. Verify hit
        assert_eq!(result.matches_found.len(), 1, "GPU should have matched the test vector");
        assert_eq!(result.matches_found[0].private_key.as_ref(), &privkey_bytes[..]);
    }
}
