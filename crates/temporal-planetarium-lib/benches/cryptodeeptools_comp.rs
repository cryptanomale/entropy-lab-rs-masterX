//! CryptoDeepTools Performance Comparison Benchmark
//!
//! Measures performance of Randstorm address derivation across different
//! implementations (CPU vs GPU vs Python-style).
//!
//! Run with: cargo bench --bench cryptodeeptools_comp

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use temporal_planetarium_lib::scans::randstorm::{
    prng::bitcoinjs_v013::BitcoinJsV013Prng,
    prng::MathRandomEngine,
};

fn benchmark_rust_cpu(c: &mut Criterion) {
    let mut group = c.benchmark_group("randstorm_comparison_cpu");
    let batch_size = 10_000u64;
    group.throughput(Throughput::Elements(batch_size));
    
    group.bench_function("rust_cpu_v8", |b| {
        b.iter(|| {
            for i in 0..batch_size {
                let _ = BitcoinJsV013Prng::generate_privkey_bytes(
                    black_box(1366027200000 + i),
                    MathRandomEngine::V8Mwc1616,
                    None
                );
            }
        });
    group.finish();
}

#[cfg(feature = "gpu")]
fn benchmark_rust_gpu(c: &mut Criterion) {
    use temporal_planetarium_lib::scans::randstorm::gpu_integration::GpuScanner;
    use temporal_planetarium_lib::scans::randstorm::config::ScanConfig;
    use temporal_planetarium_lib::scans::randstorm::fingerprint::BrowserFingerprint;
    
    let engine = MathRandomEngine::V8Mwc1616;
    let scanner = GpuScanner::new(ScanConfig::default(), engine, None, true).expect("GPU Init");
    
    let mut group = c.benchmark_group("randstorm_comparison_gpu");
    let batch_size = 100_000u64;
    group.throughput(Throughput::Elements(batch_size));
    
    // Simulate fingerprints
    let fingerprints: Vec<_> = (0..batch_size).map(|i| BrowserFingerprint {
        timestamp_ms: 1366027200000 + i,
        ..Default::default()
    }).collect();
    
    // Target hashes for verification (dummy)
    let targets = vec![vec![0u8; 20]];
    
    group.bench_function("rust_gpu_v8", |b| {
        let mut scanner = GpuScanner::new(ScanConfig::default(), engine, None, true).expect("GPU Init");
        b.iter(|| {
            let _ = scanner.process_batch(black_box(&fingerprints), &targets, 1);
        });
    });
    group.finish();
}

#[cfg(feature = "gpu")]
criterion_group!(benches, benchmark_rust_cpu, benchmark_rust_gpu);
#[cfg(not(feature = "gpu"))]
criterion_group!(benches, benchmark_rust_cpu);

criterion_main!(benches);
