//! GPU Optimization Benchmarks
//!
//! This benchmark suite measures the performance improvements from GPU optimizations
//! including local memory usage, vector operations, and work group tuning.
//!
//! Run with: cargo bench --features gpu --bench gpu_optimization_benchmark
//!
//! Requirements:
//! - OpenCL runtime installed
//! - GPU with OpenCL support
//! - Sufficient local memory (32KB+ recommended)

#[cfg(feature = "gpu")]
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

#[cfg(feature = "gpu")]
use temporal_planetarium_lib::scans::gpu_solver::GpuSolver;

#[cfg(feature = "gpu")]
fn benchmark_standard_kernel(c: &mut Criterion) {
    let solver = GpuSolver::new().expect("Failed to initialize GPU solver");

    let mut group = c.benchmark_group("standard_kernel");
    group.sample_size(10);

    for batch_size in [64, 512, 1024, 10240].iter() {
        // Generate test entropies
        let mut test_entropies = Vec::new();
        for i in 0..*batch_size {
            let mut entropy = [0u8; 16];
            for j in 0..16 {
                entropy[j] = ((i * 16 + j) % 256) as u8;
            }
            test_entropies.push(entropy);
        }

        group.throughput(Throughput::Elements(*batch_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            batch_size,
            |b, _| {
                b.iter(|| {
                    solver
                        .compute_batch(black_box(&test_entropies), black_box(44))
                        .expect("Batch computation failed")
                });
            },
        );
    }

    group.finish();
}

#[cfg(feature = "gpu")]
fn benchmark_optimized_kernel(c: &mut Criterion) {
    let solver = GpuSolver::new().expect("Failed to initialize GPU solver");

    let mut group = c.benchmark_group("optimized_kernel");
    group.sample_size(10);

    for batch_size in [64, 512, 1024, 10240].iter() {
        // Generate test entropies
        let mut test_entropies = Vec::new();
        for i in 0..*batch_size {
            let mut entropy = [0u8; 16];
            for j in 0..16 {
                entropy[j] = ((i * 16 + j) % 256) as u8;
            }
            test_entropies.push(entropy);
        }

        group.throughput(Throughput::Elements(*batch_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            batch_size,
            |b, _| {
                b.iter(|| {
                    solver
                        .compute_batch_optimized(black_box(&test_entropies), black_box(44))
                        .expect("Batch computation failed")
                });
            },
        );
    }

    group.finish();
}

#[cfg(feature = "gpu")]
fn benchmark_comparison(c: &mut Criterion) {
    let solver = GpuSolver::new().expect("Failed to initialize GPU solver");

    let batch_size = 512;
    let mut test_entropies = Vec::new();
    for i in 0..batch_size {
        let mut entropy = [0u8; 16];
        for j in 0..16 {
            entropy[j] = ((i * 16 + j) % 256) as u8;
        }
        test_entropies.push(entropy);
    }

    let mut group = c.benchmark_group("kernel_comparison");
    group.throughput(Throughput::Elements(batch_size as u64));

    group.bench_function("standard", |b| {
        b.iter(|| {
            solver
                .compute_batch(black_box(&test_entropies), black_box(44))
                .expect("Batch computation failed")
        });
    });

    group.bench_function("optimized", |b| {
        b.iter(|| {
            solver
                .compute_batch_optimized(black_box(&test_entropies), black_box(44))
                .expect("Batch computation failed")
        });
    });

    group.finish();
}

#[cfg(feature = "gpu")]
fn benchmark_pbkdf2_iterations(c: &mut Criterion) {
    let solver = GpuSolver::new().expect("Failed to initialize GPU solver");

    // Single entropy to isolate PBKDF2 performance
    let test_entropy = vec![[0x42u8; 16]];

    let mut group = c.benchmark_group("pbkdf2_performance");
    group.throughput(Throughput::Elements(2048)); // 2048 PBKDF2 iterations

    group.bench_function("standard_kernel", |b| {
        b.iter(|| {
            solver
                .compute_batch(black_box(&test_entropy), black_box(44))
                .expect("Batch computation failed")
        });
    });

    group.bench_function("optimized_kernel", |b| {
        b.iter(|| {
            solver
                .compute_batch_optimized(black_box(&test_entropy), black_box(44))
                .expect("Batch computation failed")
        });
    });

    group.finish();
}

#[cfg(feature = "gpu")]
criterion_group!(
    benches,
    benchmark_standard_kernel,
    benchmark_optimized_kernel,
    benchmark_comparison,
    benchmark_pbkdf2_iterations
);

#[cfg(feature = "gpu")]
criterion_main!(benches);

// Dummy main for when GPU feature is not enabled
#[cfg(not(feature = "gpu"))]
fn main() {
    println!("GPU benchmarks require the 'gpu' feature flag");
    println!("Run with: cargo bench --features gpu --bench gpu_optimization_benchmark");
}
