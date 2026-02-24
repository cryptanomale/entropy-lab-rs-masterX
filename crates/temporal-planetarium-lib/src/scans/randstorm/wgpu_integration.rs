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
        /// Конструктор — совместим с существующими вызовами:
        ///   WgpuScanner::new(config, engine, fingerprints_csv, use_gpu)
        pub fn new(
            _config: ScanConfig,
            _engine: MathRandomEngine,
            fingerprints_csv: Option<&Path>,
            _use_gpu: bool,
        ) -> anyhow::Result<Self> {
            let fingerprints = if let Some(csv) = fingerprints_csv {
                load_fingerprints(csv, None, None, None)?
            } else {
                // Дефолтный fingerprint — 1366×768, colorDepth=32, tz=0
                vec![GpuFingerprint {
                    screen_width:    1366,
                    screen_height:   768,
                    color_depth:     32,
                    timezone_offset: 0,
                }]
            };

            let (device, queue, pipeline, bind_group_layout) =
                pollster::block_on(init_gpu())?;

            Ok(Self { fingerprints, device, queue, pipeline, bind_group_layout })
        }

        /// Backward-compat wrapper: sweep с self.fingerprints.
        /// Исправлена в части батчинга (см. sweep_with_fingerprints).
        pub fn sweep(
            &self,
            start_ms:    u64,
            end_ms:      u64,
            interval_ms: u32,
            bloom_bytes: &[u8],
        ) -> anyhow::Result<Vec<SeedComponents>> {
            self.sweep_with_fingerprints(start_ms, end_ms, interval_ms, bloom_bytes, &self.fingerprints)
        }

        /// Главный метод: sweep с явно переданными fingerprints.
        ///
        /// Исправляет два бага оригинального sweep():
        ///   1. ts_count переполнял u32 на диапазонах > ~49 дней.
        ///      Теперь ts_count: u64.
        ///   2. offset не менял start_ms в params — каждый dispatch гонял
        ///      одни и те же timestamps снова (gid.x всегда начинался с 0).
        ///      Теперь start_ms обновляется через queue.write_buffer на каждый батч.
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
            if fingerprints.is_empty() { anyhow::bail!("fingerprints slice must be non-empty"); }

            // Конвертируем &[u8] → Vec<u32> (little-endian, padding до кратности 4)
            let padded_len = (bloom_bytes.len() + 3) & !3;
            let mut padded = bloom_bytes.to_vec();
            padded.resize(padded_len, 0u8);
            let bloom_u32: Vec<u32> = padded
                .chunks_exact(4)
                .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect();

            // ИСПРАВЛЕНИЕ 1: ts_count как u64, иначе overflow при диапазоне > 49 дней
            let ts_count: u64 = (end_ms - start_ms) / interval_ms as u64 + 1;
            let fp_count: u32 = fingerprints.len() as u32;

            info!(
                "GPU Sweep: {} timestamps × {} fingerprints = {} combinations",
                ts_count, fp_count,
                ts_count * fp_count as u64
            );

            // ИСПРАВЛЕНИЕ 2: params_buf с COPY_DST — обновляем start_ms на каждый батч
            let params_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
                label:              Some("params"),
                size:               std::mem::size_of::<GpuParams>() as u64,
                usage:              wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });
            let fp_buf = self.device.create_buffer_init(
                &wgpu::util::BufferInitDescriptor {
                    label:    Some("fingerprints"),
                    contents: bytemuck::cast_slice(fingerprints), // внешние fps
                    usage:    wgpu::BufferUsages::STORAGE,
                }
            );
            let bloom_buf = self.device.create_buffer_init(
                &wgpu::util::BufferInitDescriptor {
                    label:    Some("bloom"),
                    contents: bytemuck::cast_slice(&bloom_u32),
                    usage:    wgpu::BufferUsages::STORAGE,
                }
            );

            const MAX_RESULTS: u32 = 65536;
            let result_stride = std::mem::size_of::<GpuMatchResult>();
            let results_size  = result_stride * MAX_RESULTS as usize;

            let results_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
                label:              Some("results"),
                size:               results_size as u64,
                usage:              wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
                mapped_at_creation: false,
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

            // Dispatch батчами по 65536 timestamps.
            // На каждый батч двигаем start_ms в GpuParams через write_buffer,
            // т.к. gid.x в шейдере всегда начинается с 0 внутри каждого dispatch.
            const BATCH_TS: u64 = 65536;
            let mut offset: u64 = 0;
            while offset < ts_count {
                let batch: u32 = (ts_count - offset).min(BATCH_TS) as u32;
                let x_groups  = batch.div_ceil(64);
                let y_groups  = fp_count;

                let batch_start_ms = start_ms + offset * interval_ms as u64;
                let params = GpuParams {
                    start_ms_lo: (batch_start_ms & 0xFFFF_FFFF) as u32,
                    start_ms_hi: (batch_start_ms >> 32) as u32,
                    interval_ms,
                    fp_count,
                    bloom_size: bloom_u32.len() as u32,
                    _pad0: 0, _pad1: 0, _pad2: 0,
                };
                self.queue.write_buffer(&params_buf, 0, bytemuck::bytes_of(&params));

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
                offset += batch as u64;
            }

            // Читаем результаты обратно
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
            // fp_idx индексирует переданные fingerprints, не self.fingerprints
            let seeds = found_results.iter().map(|r| {
                let ts = ((r.timestamp_hi as u64) << 32) | r.timestamp_lo as u64;
                let fp_idx = (r.fp_index as usize).min(fingerprints.len().saturating_sub(1));
                let fp = &fingerprints[fp_idx];
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

        /// Accessor for queue (used by validator.rs)
        pub fn queue(&self) -> &wgpu::Queue {
            &self.queue
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
                    wgpu::BindGroupLayoutEntry {
                        binding: 0, visibility: wgpu::ShaderStages::COMPUTE,
                        ty: wgpu::BindingType::Buffer {
                            ty: wgpu::BufferBindingType::Uniform,
                            has_dynamic_offset: false, min_binding_size: None,
                        }, count: None,
                    },
                    wgpu::BindGroupLayoutEntry {
                        binding: 1, visibility: wgpu::ShaderStages::COMPUTE,
                        ty: wgpu::BindingType::Buffer {
                            ty: wgpu::BufferBindingType::Storage { read_only: true },
                            has_dynamic_offset: false, min_binding_size: None,
                        }, count: None,
                    },
                    wgpu::BindGroupLayoutEntry {
                        binding: 2, visibility: wgpu::ShaderStages::COMPUTE,
                        ty: wgpu::BindingType::Buffer {
                            ty: wgpu::BufferBindingType::Storage { read_only: true },
                            has_dynamic_offset: false, min_binding_size: None,
                        }, count: None,
                    },
                    wgpu::BindGroupLayoutEntry {
                        binding: 3, visibility: wgpu::ShaderStages::COMPUTE,
                        ty: wgpu::BindingType::Buffer {
                            ty: wgpu::BufferBindingType::Storage { read_only: false },
                            has_dynamic_offset: false, min_binding_size: None,
                        }, count: None,
                    },
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
                entry_point: "randstorm_main",
                compilation_options: Default::default(),
                cache: None,
            }
        );

        Ok((device, queue, pipeline, bind_group_layout))
    }
}
