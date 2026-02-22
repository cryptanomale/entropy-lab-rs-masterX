use criterion::{black_box, criterion_group, criterion_main, Criterion};
use temporal_planetarium_lib::scans::randstorm::{
    config::{GpuBackend, ScanConfig, ScanMode},
    integration::RandstormScanner,
    prng::MathRandomEngine,
    fingerprints::Phase,
};

fn wgpu_scan_benchmark(c: &mut Criterion) {
    // Only run if wgpu feature is enabled and system supports it
    let config = ScanConfig {
        use_gpu: true,
        gpu_backend: GpuBackend::Wgpu,
        scan_mode: ScanMode::Quick, // Use quick mode for benchmark (~1000 timestamps)
        ..Default::default()
    };

    // Attempt init to check availability
    if let Ok(mut scanner) = RandstormScanner::with_config(config.clone(), MathRandomEngine::V8Mwc1616) {
        if scanner.active_backend() == GpuBackend::Wgpu {
            let mut group = c.benchmark_group("wgpu_performance");
            group.sample_size(10); // Reduce sample size for heavy GPU ops

            let dummy_addresses = vec!["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string()];

            group.bench_function("scan_1000_timestamps_wgpu", |b| {
                b.iter(|| {
                    let _ = scanner.scan_with_progress(black_box(&dummy_addresses), Phase::One);
                })
            });
            group.finish();
        } else {
            println!("WGPU initialization failed or fell back to CPU. Skipping benchmark.");
        }
    } else {
        println!("Scanner initialization failed. Skipping benchmark.");
    }
}

criterion_group!(benches, wgpu_scan_benchmark);
criterion_main!(benches);
