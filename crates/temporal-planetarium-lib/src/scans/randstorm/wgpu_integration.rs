// wgpu_integration.rs - Fingerprint-Aware Randstorm GPU Scanner
// FIX: count_buf reset to 0 before each batch + per-batch readback

use std::path::Path;
use bytemuck::{Pod, Zeroable};
use wgpu::util::DeviceExt;
use tracing::info;
use crate::scans::randstorm::core_types::SeedComponents;
pub use self::scanner::WgpuScanner;

#[repr(C)]
#[derive(Copy, Clone, Pod, Zeroable, Debug)]
pub struct GpuParams {
    pub start_ms_lo:  u32,
    pub start_ms_hi:  u32,
    pub interval_ms:  u32,
    pub fp_count:     u32,
    pub bloom_size:   u32,
    pub _pad0:        u32,
    pub _pad1:        u32,
    pub _pad2:        u32,
}

#[repr(C)]
#[derive(Copy, Clone, Pod, Zeroable, Debug)]
pub struct GpuFingerprint {
    pub screen_width:    u32,
    pub screen_height:   u32,
    pub color_depth:     u32,
    pub timezone_offset: i32,
}

#[repr(C)]
#[derive(Copy, Clone, Pod, Zeroable, Debug)]
pub struct GpuMatchResult {
    pub timestamp_lo: u32,
    pub timestamp_hi: u32,
    pub fp_index:     u32,
    pub _pad:         u32,
    pub address:      [u32; 5],
}

pub fn load_fingerprints(
    csv_path: &Path,
    year_min: Option<u32>,
    year_max: Option<u32>,
    max_count: Option<usize>,
) -> anyhow::Result<Vec<GpuFingerprint>> {
    let mut rdr = csv::Reader::from_path(csv_path)?;
    let mut fps: Vec<GpuFingerprint> = Vec::new();
    for result in rdr.records() {
        let record = result?;
        if record.len() < 11 { continue; }
        let screen_width:    u32 = record[2].parse().unwrap_or(1366);
        let screen_height:   u32 = record[3].parse().unwrap_or(768);
        let color_depth:     u32 = record[4].parse().unwrap_or(32);
        let timezone_offset: i32 = record[5].parse().unwrap_or(0);
        let fp_year_min:     u32 = record[9].parse().unwrap_or(2011);
        let fp_year_max:     u32 = record[10].parse().unwrap_or(2015);
        if let Some(y) = year_min { if fp_year_max < y { continue; } }
        if let Some(y) = year_max { if fp_year_min > y { continue; } }
        fps.push(GpuFingerprint { screen_width, screen_height, color_depth, timezone_offset });
        if let Some(max) = max_count { if fps.len() >= max { break; } }
    }
    info!("Loaded {} fingerprints from {}", fps.len(), csv_path.display());
    Ok(fps)
}

mod scanner {
    use super::*;
    use crate::scans::randstorm::core_types::SeedComponents;
    use crate::scans::randstorm::config::ScanConfig;
    use crate::scans::randstorm::prng::MathRandomEngine;

    pub struct WgpuScanner {
        fingerprints:      Vec<GpuFingerprint>,
        device:            wgpu::Device,
        queue:             wgpu::Queue,
        pipeline:          wgpu::ComputePipeline,
        bind_group_layout: wgpu::BindGroupLayout,
    }

    impl WgpuScanner {
        pub fn new(
            _config: ScanConfig, _engine: MathRandomEngine,
            fingerprints_csv: Option<&Path>, _use_gpu: bool,
        ) -> anyhow::Result<Self> {
            let fingerprints = if let Some(csv) = fingerprints_csv {
                load_fingerprints(csv, None, None, None)?
            } else {
                vec![GpuFingerprint { screen_width: 1366, screen_height: 768, color_depth: 32, timezone_offset: 0 }]
            };
            let (device, queue, pipeline, bind_group_layout) = pollster::block_on(init_gpu())?;
            Ok(Self { fingerprints, device, queue, pipeline, bind_group_layout })
        }

        pub fn sweep(
            &self, start_ms: u64, end_ms: u64, interval_ms: u32, bloom_bytes: &[u8],
        ) -> anyhow::Result<Vec<SeedComponents>> {
            self.sweep_with_fingerprints(start_ms, end_ms, interval_ms, bloom_bytes, &self.fingerprints)
        }

        pub fn sweep_with_fingerprints(
            &self,
            start_ms:     u64,
            end_ms:       u64,
            interval_ms:  u32,
            bloom_bytes:  &[u8],
            fingerprints: &[GpuFingerprint],
        ) -> anyhow::Result<Vec<SeedComponents>> {
            if interval_ms == 0        { anyhow::bail!("interval_ms must be > 0"); }
            if end_ms < start_ms       { anyhow::bail!("end_ms must be >= start_ms"); }
            if fingerprints.is_empty() { anyhow::bail!("fingerprints must be non-empty"); }

            let padded_len = (bloom_bytes.len() + 3) & !3;
            let mut padded = bloom_bytes.to_vec();
            padded.resize(padded_len, 0u8);
            let bloom_u32: Vec<u32> = padded.chunks_exact(4)
                .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();

            let ts_count: u64 = (end_ms - start_ms) / interval_ms as u64 + 1;
            let fp_count: u32 = fingerprints.len() as u32;
            info!("GPU Sweep: {} timestamps x {} fingerprints = {} combinations",
                ts_count, fp_count, ts_count * fp_count as u64);

            let params_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("params"),
                size: std::mem::size_of::<GpuParams>() as u64,
                usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });
            let fp_buf = self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
                label: Some("fingerprints"), contents: bytemuck::cast_slice(fingerprints),
                usage: wgpu::BufferUsages::STORAGE,
            });
            let bloom_buf = self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
                label: Some("bloom"), contents: bytemuck::cast_slice(&bloom_u32),
                usage: wgpu::BufferUsages::STORAGE,
            });

            const MAX_PER_BATCH: u32 = 65536;
            let stride = std::mem::size_of::<GpuMatchResult>();
            let results_size = stride * MAX_PER_BATCH as usize;

            let results_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("results"), size: results_size as u64,
                usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
                mapped_at_creation: false,
            });

            // FIX: COPY_DST on count_buf -> reset to 0 at start of every batch.
            // Bug was: count accumulated cross-batch => batch2 hit 65536 (MAX)
            // => all results from batch3..N were silently dropped.
            let count_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("count"), size: 4,
                usage: wgpu::BufferUsages::STORAGE
                     | wgpu::BufferUsages::COPY_SRC
                     | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });
            let count_stg = self.device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("count_stg"), size: 4,
                usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });
            let results_stg = self.device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("results_stg"), size: results_size as u64,
                usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });

            let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
                label: Some("bg"), layout: &self.bind_group_layout,
                entries: &[
                    wgpu::BindGroupEntry { binding: 0, resource: params_buf.as_entire_binding() },
                    wgpu::BindGroupEntry { binding: 1, resource: fp_buf.as_entire_binding() },
                    wgpu::BindGroupEntry { binding: 2, resource: bloom_buf.as_entire_binding() },
                    wgpu::BindGroupEntry { binding: 3, resource: results_buf.as_entire_binding() },
                    wgpu::BindGroupEntry { binding: 4, resource: count_buf.as_entire_binding() },
                ],
            });

            const BATCH_TS: u64 = 65536;
            let total_batches = ts_count.div_ceil(BATCH_TS);
            let mut offset: u64 = 0;
            let mut all_results: Vec<GpuMatchResult> = Vec::new();

            while offset < ts_count {
                let batch = (ts_count - offset).min(BATCH_TS) as u32;
                let batch_start = start_ms + offset * interval_ms as u64;

                let params = GpuParams {
                    start_ms_lo: (batch_start & 0xFFFF_FFFF) as u32,
                    start_ms_hi: (batch_start >> 32) as u32,
                    interval_ms, fp_count,
                    bloom_size: bloom_u32.len() as u32,
                    _pad0: 0, _pad1: 0, _pad2: 0,
                };
                self.queue.write_buffer(&params_buf, 0, bytemuck::bytes_of(&params));

                // === RESET count to 0 before dispatch ===
                self.queue.write_buffer(&count_buf, 0, bytemuck::bytes_of(&0u32));

                let mut enc = self.device.create_command_encoder(
                    &wgpu::CommandEncoderDescriptor { label: Some("sweep") });
                {
                    let mut cp = enc.begin_compute_pass(&wgpu::ComputePassDescriptor {
                        label: Some("cp"), timestamp_writes: None });
                    cp.set_pipeline(&self.pipeline);
                    cp.set_bind_group(0, &bind_group, &[]);
                    cp.dispatch_workgroups(batch.div_ceil(64), fp_count, 1);
                }
                self.queue.submit(std::iter::once(enc.finish()));
                self.device.poll(wgpu::Maintain::Wait);

                // Readback this batch
                let mut enc2 = self.device.create_command_encoder(
                    &wgpu::CommandEncoderDescriptor { label: Some("rb") });
                enc2.copy_buffer_to_buffer(&count_buf, 0, &count_stg, 0, 4);
                enc2.copy_buffer_to_buffer(&results_buf, 0, &results_stg, 0, results_size as u64);
                self.queue.submit(std::iter::once(enc2.finish()));
                count_stg.slice(..).map_async(wgpu::MapMode::Read, |_| {});
                results_stg.slice(..).map_async(wgpu::MapMode::Read, |_| {});
                self.device.poll(wgpu::Maintain::Wait);

                let n = {
                    let d = count_stg.slice(..).get_mapped_range();
                    u32::from_le_bytes([d[0], d[1], d[2], d[3]])
                };
                count_stg.unmap();

                let batch_res: Vec<GpuMatchResult> = {
                    let d = results_stg.slice(..).get_mapped_range();
                    let s: &[GpuMatchResult] = bytemuck::cast_slice(&d);
                    s[..n.min(MAX_PER_BATCH) as usize].to_vec()
                };
                results_stg.unmap();

                if n > 0 {
                    info!("Batch {}/{}: {} hits (ts_offset={})",
                        offset / BATCH_TS + 1, total_batches, n, offset);
                }
                all_results.extend_from_slice(&batch_res);
                offset += batch as u64;
            }

            info!("GPU sweep complete. Total matches: {}", all_results.len());

            let seeds = all_results.iter().map(|r| {
                let ts = ((r.timestamp_hi as u64) << 32) | r.timestamp_lo as u64;
                let idx = (r.fp_index as usize).min(fingerprints.len().saturating_sub(1));
                let fp = &fingerprints[idx];
                SeedComponents {
                    timestamp_ms:    ts,
                    screen_width:    fp.screen_width,
                    screen_height:   fp.screen_height,
                    color_depth:     fp.color_depth as u8,
                    timezone_offset: fp.timezone_offset as i16,
                    hash160:         Some(r.address),
                    ..Default::default()
                }
            }).collect();

            Ok(seeds)
        }

        pub fn queue(&self) -> &wgpu::Queue { &self.queue }
    }

    async fn init_gpu() -> anyhow::Result<(
        wgpu::Device, wgpu::Queue, wgpu::ComputePipeline, wgpu::BindGroupLayout,
    )> {
        let instance = wgpu::Instance::default();
        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                ..Default::default()
            })
            .await
            .ok_or_else(|| anyhow::anyhow!("No GPU adapter found"))?;
        let (device, queue) = adapter
            .request_device(&wgpu::DeviceDescriptor::default(), None)
            .await?;
        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("Randstorm"),
            source: wgpu::ShaderSource::Wgsl(include_str!("randstorm_fingerprint.wgsl").into()),
        });
        let bgl = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("bgl"),
            entries: &[
                wgpu::BindGroupLayoutEntry { binding: 0, visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer { ty: wgpu::BufferBindingType::Uniform,
                        has_dynamic_offset: false, min_binding_size: None }, count: None },
                wgpu::BindGroupLayoutEntry { binding: 1, visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer { ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false, min_binding_size: None }, count: None },
                wgpu::BindGroupLayoutEntry { binding: 2, visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer { ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false, min_binding_size: None }, count: None },
                wgpu::BindGroupLayoutEntry { binding: 3, visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer { ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false, min_binding_size: None }, count: None },
                wgpu::BindGroupLayoutEntry { binding: 4, visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer { ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false, min_binding_size: None }, count: None },
            ],
        });
        let pl = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: None, bind_group_layouts: &[&bgl], push_constant_ranges: &[],
        });
        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("randstorm"), layout: Some(&pl), module: &shader,
            entry_point: "randstorm_main",
            compilation_options: Default::default(), cache: None,
        });
        Ok((device, queue, pipeline, bgl))
    }
}
