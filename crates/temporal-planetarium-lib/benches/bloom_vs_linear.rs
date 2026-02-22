//! Benchmark Bloom Filter vs. Linear Scan
//!
//! Part of STORY-003-002: Benchmark Bloom Filter vs. Linear Scan

#[cfg(feature = "gpu")]
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
#[cfg(feature = "gpu")]
use temporal_planetarium_lib::utils::gpu_bloom_filter::{GpuBloomConfig, GpuBloomFilter};
#[cfg(feature = "gpu")]
use ocl::{Buffer, Kernel, Platform, Device, Context, Queue, Program};

#[cfg(feature = "gpu")]
fn benchmark_lookup_comparison(c: &mut Criterion) {
    let platform = Platform::default();
    let device = Device::first(platform).expect("No GPU found");
    let context = Context::builder().platform(platform).devices(device).build().expect("Failed to create context");
    let queue = Queue::new(&context, device, None).expect("Failed to create queue");

    let mut group = c.benchmark_group("lookup_comparison");
    group.sample_size(10);

    // Test with different target set sizes
    let target_sizes = [1000, 10000, 100000];
    let probe_count = 1000; // Total probes per bench iteration
    let item_len = 20; // 20-byte hash160

    // Prepare probe data (random-ish)
    let mut probe_data = Vec::with_capacity(probe_count * item_len);
    for i in 0..probe_count {
        for j in 0..item_len {
            probe_data.push(((i + j) % 256) as u8);
        }
    }
    let probe_items: Vec<Vec<u8>> = probe_data.chunks(item_len).map(|c| c.to_vec()).collect();

    // Load Linear Kernel
    let linear_src = include_str!("../../../cl/bench_linear.cl");
    let linear_program = Program::builder()
        .src(linear_src)
        .devices(device)
        .build(&context)
        .expect("Failed to build linear program");

    for &num_targets in &target_sizes {
        group.throughput(Throughput::Elements(probe_count as u64));

        // 1. Benchmark GPU Linear Scan
        let target_data = vec![0u8; num_targets * item_len];
        let targets_buffer = Buffer::<u8>::builder()
            .queue(queue.clone())
            .len(num_targets * item_len)
            .copy_host_slice(&target_data)
            .build()
            .unwrap();

        let items_buffer = Buffer::<u8>::builder()
            .queue(queue.clone())
            .len(probe_data.len())
            .copy_host_slice(&probe_data)
            .build()
            .unwrap();

        let results_buffer = Buffer::<u8>::builder()
            .queue(queue.clone())
            .len(probe_count)
            .fill_val(0u8)
            .build()
            .unwrap();

        let linear_kernel = Kernel::builder()
            .program(&linear_program)
            .name("linear_lookup")
            .queue(queue.clone())
            .arg(&targets_buffer)
            .arg(num_targets as u32)
            .arg(&items_buffer)
            .arg(item_len as u32)
            .arg(probe_count as u32)
            .arg(&results_buffer)
            .global_work_size(probe_count)
            .build()
            .unwrap();

        group.bench_with_input(
            BenchmarkId::new("GPU_Linear", num_targets),
            &num_targets,
            |b, _| {
                b.iter(|| unsafe {
                    linear_kernel.enq().unwrap();
                    queue.finish().unwrap();
                });
            },
        );

        // 2. Benchmark GPU Bloom Filter
        let config = GpuBloomConfig {
            expected_items: num_targets,
            fp_rate: 0.001,
            num_hashes: 15,
        };
        let mut bloom = GpuBloomFilter::new(queue.clone(), config).unwrap();
        // (Insertion not timed here, only lookup)

        group.bench_with_input(
            BenchmarkId::new("GPU_Bloom", num_targets),
            &num_targets,
            |b, _| {
                b.iter(|| {
                    black_box(bloom.batch_lookup(&probe_items).unwrap());
                    queue.finish().unwrap();
                });
            },
        );
    }

    group.finish();
}

#[cfg(feature = "gpu")]
criterion_group!(benches, benchmark_lookup_comparison);
#[cfg(feature = "gpu")]
criterion_main!(benches);

#[cfg(not(feature = "gpu"))]
fn main() {
    println!("GPU benchmarks require the 'gpu' feature flag");
}
