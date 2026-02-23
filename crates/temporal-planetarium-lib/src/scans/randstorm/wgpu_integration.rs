
//! wgpu_integration.rs — Fingerprint-Aware Randstorm GPU Scanner
//!
//! Экспортирует `WgpuScanner` (имя сохранено для совместимости с cli.rs,
//! validator.rs и integration.rs).

use std::path::Path;
use bytemuck::{Pod, Zeroable};
use wgpu::util::DeviceExt;
use tracing::info;

use crate::scans::randstorm::core_types::SeedComponents;

// ── Публичные re-exports для совместимости ───────────────────────────────────
pub use self::scanner::WgpuScanner;

// ── GPU-совместимые структуры ─────────────────────────────────────────────────

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

/// Fingerprint — точно совпадает со структурой в WGSL (16 байт)
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
    pub address:      [u32; 5],   // hash160
}

// ── Загрузка fingerprints из CSV ──────────────────────────────────────────────

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
        // priority,user_agent,screen_width,screen_height,color_depth,
        // timezone_offset,language,platform,market_share_estimate,year_min,year_max
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

// ── Внутренний модуль со структурой WgpuScanner ───────────────────────────────
mod scanner {
    use super::*;
    use crate::scans::randstorm::core_types::{RandstormConfig, ScanEngine, SeedComponents};

    pub struct WgpuScanner {
        config:       RandstormConfig,
        engine:       ScanEngine,
        fingerprints: Vec<GpuFingerprint>,
        device:       wgpu::Device,
        queue:        wgpu::Queue,
        pipeline:     wgpu::ComputePipeline,
        bind_group_layout: wgpu::BindGroupLayout,
    }

    impl WgpuScanner {
        /// Конструктор — совместим с существующими вызовами:
        ///   WgpuScanner::new(config, engine, fingerprints_csv, use_gpu)
        pub fn new(
            config: RandstormConfig,
            engine: ScanEngine,
            fingerprints_csv: Option<&Path>,
            _use_gpu: bool,
        ) -> anyhow::Result<Self> {
            // Загружаем fingerprints если CSV передан
            let fingerprints = if let Some(csv) = fingerprints_csv {
                load_fingerprints(csv, None, None, None)?
            } else {
                // Дефолтный fingerprint — самый популярный из comprehensive.csv
                // 1366×768, colorDepth=32, tz=0 (priority=1)
                vec![GpuFingerprint {
                    screen_width: 1366,
                    screen_height: 768,
                    color_depth: 32,
                    timezone_offset: 0,
                }]
            };

            // Инициализируем wgpu синхронно через pollster
            let (device, queue, pipeline, bind_group_layout) =
                pollster::block_on(init_gpu())?;

            Ok(Self { config, engine, fingerprints, device, queue, pipeline, bind_group_layout })
        }

        /// Запуск sweep по диапазону timestamp'ов с fingerprints
        pub fn sweep(
            &self,
            start_ms:    u64,
            end_ms:      u64,
            interval_ms: u32,
            bloom:       &[u32],
            bloom_entries: usize,
        ) -> anyhow::Result<Vec<SeedComponents>> {
            let ts_count   = ((end_ms - start_ms) / interval_ms as u64 + 1) as u32;
            let fp_count   = self.fingerprints.len() as u32;

            info!(
                "GPU Sweep: {} timestamps × {} fingerprints = {} combinations",
                ts_count, fp_count,
                ts_count as u64 * fp_count as u64
            );

            let params = GpuParams {
                start_ms_lo:  (start_ms & 0xFFFFFFFF) as u32,
                start_ms_hi:  (start_ms >> 32) as u32,
                interval_ms,
                fp_count,
                bloom_size:   bloom.len() as u32,
                _pad0: 0, _pad1: 0, _pad2: 0,
            };

            let params_buf = self.device.create_buffer_init(
                &wgpu::util::BufferInitDescriptor {
                    label:    Some("params"),
                    contents: bytemuck::bytes_of(&params),
                    usage:    wgpu::BufferUsages::UNIFORM,
                }
            );
            let fp_buf = self.device.create_buffer_init(
                &wgpu::util::BufferInitDescriptor {
                    label:    Some("fingerprints"),
                    contents: bytemuck::cast_slice(&self.fingerprints),
                    usage:    wgpu::BufferUsages::STORAGE,
                }
            );
            let bloom_buf = self.device.create_buffer_init(
                &wgpu::util::BufferInitDescriptor {
                    label:    Some("bloom"),
                    contents: bytemuck::cast_slice(bloom),
                    usage:    wgpu::BufferUsages::STORAGE,
                }
            );

            const MAX_RESULTS: u32 = 65536;
            let result_stride = std::mem::size_of::<GpuMatchResult>();
            let results_size  = result_stride * MAX_RESULTS as usize;

            let results_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
                label:               Some("results"),
                size:                results_size as u64,
                usage:               wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
                mapped_at_creation:  false,
            });
            let count_buf = self.device.create_buffer_init(
                &wgpu::util::BufferInitDescriptor {
                    label:    Some("count"),
                    contents: bytemuck::bytes_of(&[0u32]),
                    usage:    wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
                }
            );

            let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
                label:  Some("randstorm_bg"),
                layout: &self.bind_group_layout,
                entries: &[
                    wgpu::BindGroupEntry { binding: 0, resource: params_buf.as_entire_binding() },
                    wgpu::BindGroupEntry { binding: 1, resource: fp_buf.as_entire_binding() },
                    wgpu::BindGroupEntry { binding: 2, resource: bloom_buf.as_entire_binding() },
                    wgpu::BindGroupEntry { binding: 3, resource: results_buf.as_entire_binding() },
                    wgpu::BindGroupEntry { binding: 4, resource: count_buf.as_entire_binding() },
                ],
            });

            // Dispatch батчами по 65536 timestamps
            const BATCH_TS: u32 = 65536;
            let mut offset = 0u32;
            while offset < ts_count {
                let batch   = (ts_count - offset).min(BATCH_TS);
                let x_groups = batch.div_ceil(64);
                let y_groups = fp_count;

                let mut encoder = self.device.create_command_encoder(
                    &wgpu::CommandEncoderDescriptor { label: Some("sweep") }
                );
                {
                    let mut cpass = encoder.begin_compute_pass(
                        &wgpu::ComputePassDescriptor {
                            label: Some("sweep_pass"),
                            timestamp_writes: None,
                        }
                    );
                    cpass.set_pipeline(&self.pipeline);
                    cpass.set_bind_group(0, &bind_group, &[]);
                    cpass.dispatch_workgroups(x_groups, y_groups, 1);
                }
                self.queue.submit(std::iter::once(encoder.finish()));
                self.device.poll(wgpu::Maintain::Wait);
                offset += batch;
            }

            // Читаем результаты
            let count_staging = self.device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("count_staging"), size: 4,
                usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });
            let results_staging = self.device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("results_staging"), size: results_size as u64,
                usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });

            let mut encoder = self.device.create_command_encoder(
                &wgpu::CommandEncoderDescriptor { label: Some("readback") }
            );
            encoder.copy_buffer_to_buffer(&count_buf, 0, &count_staging, 0, 4);
            encoder.copy_buffer_to_buffer(
                &results_buf, 0, &results_staging, 0, results_size as u64
            );
            self.queue.submit(std::iter::once(encoder.finish()));

            count_staging.slice(..).map_async(wgpu::MapMode::Read, |_| {});
            results_staging.slice(..).map_async(wgpu::MapMode::Read, |_| {});
            self.device.poll(wgpu::Maintain::Wait);

            let count = {
                let data = count_staging.slice(..).get_mapped_range();
                u32::from_le_bytes([data[0], data[1], data[2], data[3]])
            };

            let found_results: Vec<GpuMatchResult> = {
                let data = results_staging.slice(..).get_mapped_range();
                let all: &[GpuMatchResult] = bytemuck::cast_slice(&data);
                all[..count.min(MAX_RESULTS) as usize].to_vec()
            };

            info!("GPU sweep complete. Matches: {}", found_results.len());

            // Конвертируем GpuMatchResult → SeedComponents
            let seeds = found_results.iter().map(|r| {
                let ts = ((r.timestamp_hi as u64) << 32) | r.timestamp_lo as u64;
                let fp = &self.fingerprints[r.fp_index.min(self.fingerprints.len() as u32 - 1) as usize];
                SeedComponents {
                    timestamp_ms: ts,
                    screen_width:  Some(fp.screen_width),
                    screen_height: Some(fp.screen_height),
                    color_depth:   Some(fp.color_depth),
                    timezone_offset: Some(fp.timezone_offset),
                    hash160: Some(r.address),
                    ..Default::default()
                }
            }).collect();

            Ok(seeds)
        }
    }

    // ── GPU инициализация ────────────────────────────────────────────────────
    async fn init_gpu() -> anyhow::Result<(
        wgpu::Device,
        wgpu::Queue,
        wgpu::ComputePipeline,
        wgpu::BindGroupLayout,
    )> {
        let instance = wgpu::Instance::default();
        let adapter  = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::HighPerformance,
                ..Default::default()
            })
            .await
            .ok_or_else(|| anyhow::anyhow!("No GPU adapter found"))?;

        let (device, queue) = adapter
            .request_device(&wgpu::DeviceDescriptor::default(), None)
            .await?;

        let shader_src = include_str!("randstorm_fingerprint.wgsl");
        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label:  Some("Randstorm Fingerprint Shader"),
            source: wgpu::ShaderSource::Wgsl(shader_src.into()),
        });

        let bind_group_layout = device.create_bind_group_layout(
            &wgpu::BindGroupLayoutDescriptor {
                label: Some("randstorm_bgl"),
                entries: &[
                    // binding 0: GpuParams uniform
                    wgpu::BindGroupLayoutEntry {
                        binding: 0, visibility: wgpu::ShaderStages::COMPUTE,
                        ty: wgpu::BindingType::Buffer {
                            ty: wgpu::BufferBindingType::Uniform,
                            has_dynamic_offset: false, min_binding_size: None,
                        }, count: None,
                    },
                    // binding 1: fingerprints storage read
                    wgpu::BindGroupLayoutEntry {
                        binding: 1, visibility: wgpu::ShaderStages::COMPUTE,
                        ty: wgpu::BindingType::Buffer {
                            ty: wgpu::BufferBindingType::Storage { read_only: true },
                            has_dynamic_offset: false, min_binding_size: None,
                        }, count: None,
                    },
                    // binding 2: bloom storage read
                    wgpu::BindGroupLayoutEntry {
                        binding: 2, visibility: wgpu::ShaderStages::COMPUTE,
                        ty: wgpu::BindingType::Buffer {
                            ty: wgpu::BufferBindingType::Storage { read_only: true },
                            has_dynamic_offset: false, min_binding_size: None,
                        }, count: None,
                    },
                    // binding 3: results storage read_write
                    wgpu::BindGroupLayoutEntry {
                        binding: 3, visibility: wgpu::ShaderStages::COMPUTE,
                        ty: wgpu::BindingType::Buffer {
                            ty: wgpu::BufferBindingType::Storage { read_only: false },
                            has_dynamic_offset: false, min_binding_size: None,
                        }, count: None,
                    },
                    // binding 4: result_count atomic
                    wgpu::BindGroupLayoutEntry {
                        binding: 4, visibility: wgpu::ShaderStages::COMPUTE,
                        ty: wgpu::BindingType::Buffer {
                            ty: wgpu::BufferBindingType::Storage { read_only: false },
                            has_dynamic_offset: false, min_binding_size: None,
                        }, count: None,
                    },
                ],
            }
        );

        let pipeline_layout = device.create_pipeline_layout(
            &wgpu::PipelineLayoutDescriptor {
                label: Some("randstorm_pl"),
                bind_group_layouts: &[&bind_group_layout],
                push_constant_ranges: &[],
            }
        );

        let pipeline = device.create_compute_pipeline(
            &wgpu::ComputePipelineDescriptor {
                label:  Some("randstorm_pipeline"),
                layout: Some(&pipeline_layout),
                module: &shader,
                entry_point: "randstorm_main",   // &str, не Option — исправлено
                compilation_options: Default::default(),
                cache: None,
            }
        );

        Ok((device, queue, pipeline, bind_group_layout))
    }
}
