// GPU Performance Benchmarking Utility
// This file demonstrates how to benchmark the optimized GPU kernels

#[cfg(feature = "gpu")]
use temporal_planetarium_lib::scans::gpu_solver::GpuSolver;
#[cfg(feature = "gpu")]
use std::time::Instant;

#[cfg(feature = "gpu")]
fn benchmark_batch_address() {
    println!("=== Batch Address Generation Benchmark ===\n");

    let solver = match GpuSolver::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to initialize GPU: {}", e);
            return;
        }
    };

    let batch_sizes = vec![1000, 10000, 100000, 1000000];

    for batch_size in batch_sizes {
        println!("Batch size: {}", batch_size);

        // Generate test entropies
        let mut entropies = Vec::with_capacity(batch_size);
        for i in 0..batch_size {
            let mut entropy = [0u8; 16];
            let bytes = (i as u128).to_le_bytes();
            entropy.copy_from_slice(&bytes);
            entropies.push(entropy);
        }

        // Warmup run
        let _ = solver.compute_batch(&entropies, 44);

        // Benchmark run
        let start = Instant::now();
        let results = solver.compute_batch(&entropies, 44).unwrap();
        let duration = start.elapsed();

        let throughput = batch_size as f64 / duration.as_secs_f64();

        println!("  Time: {:.3}s", duration.as_secs_f64());
        println!("  Throughput: {:.0} addresses/sec", throughput);
        println!(
            "  Per address: {:.3}ms\n",
            duration.as_secs_f64() * 1000.0 / batch_size as f64
        );

        assert_eq!(results.len(), batch_size);
    }
}

#[cfg(feature = "gpu")]
fn benchmark_cake_hash() {
    println!("=== Cake Hash Search Benchmark ===\n");

    let solver = match GpuSolver::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to initialize GPU: {}", e);
            return;
        }
    };

    let batch_sizes = vec![10000, 100000, 1000000];

    // Create dummy target hashes
    let target_count = 100;
    let mut target_hashes = vec![0u8; target_count * 32];
    for i in 0..target_count {
        target_hashes[i * 32] = (i % 256) as u8;
    }

    for batch_size in batch_sizes {
        println!("Batch size: {}", batch_size);

        // Generate test timestamps
        let timestamps: Vec<u64> = (0..batch_size).map(|i| i as u64).collect();

        // Warmup
        let _ = solver.compute_cake_hash(&timestamps[..100], &target_hashes);

        // Benchmark
        let start = Instant::now();
        let results = solver
            .compute_cake_hash(&timestamps, &target_hashes)
            .unwrap();
        let duration = start.elapsed();

        let throughput = batch_size as f64 / duration.as_secs_f64();

        println!("  Time: {:.3}s", duration.as_secs_f64());
        println!("  Throughput: {:.0} hashes/sec", throughput);
        println!("  Matches found: {}\n", results.len());
    }
}

#[cfg(feature = "gpu")]
fn benchmark_mobile_sensor() {
    println!("=== Mobile Sensor Hash Benchmark ===\n");

    let solver = match GpuSolver::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to initialize GPU: {}", e);
            return;
        }
    };

    let batch_sizes = vec![1000, 10000, 100000];

    for batch_size in batch_sizes {
        println!("Batch size: {}", batch_size);

        let indices: Vec<u64> = (0..batch_size).map(|i| i as u64).collect();

        // Warmup
        let _ = solver.compute_mobile_hash(&indices[..100]);

        // Benchmark
        let start = Instant::now();
        let results = solver.compute_mobile_hash(&indices).unwrap();
        let duration = start.elapsed();

        let throughput = batch_size as f64 / duration.as_secs_f64();

        println!("  Time: {:.3}s", duration.as_secs_f64());
        println!("  Throughput: {:.0} hashes/sec", throughput);
        println!("  Hashes computed: {}\n", results.len());

        assert_eq!(results.len(), batch_size);
    }
}

#[cfg(feature = "gpu")]
fn benchmark_profanity() {
    println!("=== Profanity Address Search Benchmark ===\n");

    let solver = match GpuSolver::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to initialize GPU: {}", e);
            return;
        }
    };

    let search_spaces = vec![100000, 1000000, 10000000];
    let target_addr = vec![0u8; 20]; // Dummy target

    for search_space in search_spaces {
        println!("Search space: {}", search_space);

        let start = Instant::now();
        let results = solver
            .compute_profanity(search_space, &target_addr)
            .unwrap();
        let duration = start.elapsed();

        let throughput = search_space as f64 / duration.as_secs_f64();

        println!("  Time: {:.3}s", duration.as_secs_f64());
        println!("  Throughput: {:.0} attempts/sec", throughput);
        println!("  Matches found: {}\n", results.len());
    }
}

fn main() {
    #[cfg(feature = "gpu")]
    main_gpu();
    #[cfg(not(feature = "gpu"))]
    println!("This benchmark requires the 'gpu' feature. Run with --features gpu");
}

#[cfg(feature = "gpu")]
fn main_gpu() {
    println!("\n╔═══════════════════════════════════════════════════╗");
    println!("║   Entropy Lab RS - GPU Performance Benchmark     ║");
    println!("╚═══════════════════════════════════════════════════╝\n");

    benchmark_batch_address();
    benchmark_cake_hash();
    benchmark_mobile_sensor();
    benchmark_profanity();

    println!("\n╔═══════════════════════════════════════════════════╗");
    println!("║   Benchmark Complete                              ║");
    println!("╚═══════════════════════════════════════════════════╝\n");

    println!(
        "Note: These benchmarks measure GPU kernel performance.\n\
              Actual application performance depends on:\n\
                - Data transfer overhead\n\
                - CPU preprocessing\n\
                - Network I/O (for RPC operations)\n\
                - Disk I/O (for large datasets)"
    );
}
