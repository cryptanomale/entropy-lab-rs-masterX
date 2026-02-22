//! Trust Wallet Brute-force Performance Benchmark
//!
//! Measures the throughput of the MT19937 LSB extraction and address derivation kernel.
//!
//! Run with: cargo bench --features gpu --bench trust_wallet_benchmark

#[cfg(feature = "gpu")]
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

#[cfg(feature = "gpu")]
use temporal_planetarium_lib::scans::gpu_solver::GpuSolver;

#[cfg(feature = "gpu")]
fn benchmark_trust_wallet_crack(c: &mut Criterion) {
    let solver = GpuSolver::new().expect("Failed to initialize GPU solver");
    
    let mut group = c.benchmark_group("trust_wallet_bruteforce");
    group.sample_size(10);
    
    // Target H160 (random but valid structure)
    let target_h160 = [0x42u8; 20];
    
    // Test with different scan ranges
    for range_size in [100_000, 1_000_000].iter() {
        group.throughput(Throughput::Elements(*range_size as u64));
        group.bench_with_input(
            criterion::BenchmarkId::from_parameter(range_size),
            range_size,
            |b, &range| {
                b.iter(|| {
                    let start = 1668470400;
                    let end = start + range as u32;
                    solver
                        .compute_trust_wallet_crack(
                            black_box(start),
                            black_box(end),
                            black_box(&target_h160),
                        )
                        .expect("Trust Wallet crack failed")
                });
            },
        );
    }
    
    group.finish();
}

#[cfg(feature = "gpu")]
criterion_group!(benches, benchmark_trust_wallet_crack);
#[cfg(feature = "gpu")]
criterion_main!(benches);

#[cfg(not(feature = "gpu"))]
fn main() {
    println!("Trust Wallet benchmarks require the 'gpu' feature flag");
}
