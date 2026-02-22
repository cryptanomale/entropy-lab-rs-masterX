// MT19937 Reference Test Vectors
// Generated using rand_mt::Mt19937GenRand32 with MSB extraction

use rand_mt::Mt19937GenRand32;

#[test]
fn test_mt19937_reference_vectors() {
    println!("\n=== MT19937 Reference Vectors ===\n");

    let test_vectors = vec![
        (0u32, "Test vector for timestamp 0"),
        (1u32, "Test vector for timestamp 1"),
        (1234567890u32, "Milk Sad known test vector"),
        (1609459200u32, "2021-01-01 00:00:00 UTC"),
        (1293840000u32, "2011-01-01 00:00:00 UTC (scan range start)"),
    ];

    for (seed, description) in test_vectors {
        let mut rng = Mt19937GenRand32::new(seed);
        let mut entropy = [0u8; 16];

        // Extract 4 u32 values with MSB extraction
        for i in 0..4 {
            let val = rng.next_u32();
            entropy[i * 4] = ((val >> 24) & 0xFF) as u8;
            entropy[i * 4 + 1] = ((val >> 16) & 0xFF) as u8;
            entropy[i * 4 + 2] = ((val >> 8) & 0xFF) as u8;
            entropy[i * 4 + 3] = (val & 0xFF) as u8;
        }

        println!("Timestamp: {} ({})", seed, description);
        println!("  Entropy: {}", hex::encode(entropy));
    }

    println!("\nThese values should match GPU test_mt19937 kernel output");
}

#[cfg(feature = "gpu")]
#[test]
fn test_gpu_mt19937_if_available() {
    // This test requires GPU - skip if not available
    use temporal_planetarium_lib::scans::gpu_solver::GpuSolver;

    let solver = match GpuSolver::new() {
        Ok(s) => s,
        Err(e) => {
            println!("GPU not available, skipping test: {}", e);
            return;
        }
    };

    let test_seeds = vec![0u32, 1u32, 1234567890u32];

    match solver.test_mt19937(&test_seeds) {
        Ok(gpu_results) => {
            println!("\n=== GPU vs CPU MT19937 Comparison ===\n");

            for (i, seed) in test_seeds.iter().enumerate() {
                // Generate CPU reference
                let mut rng = Mt19937GenRand32::new(*seed);
                let mut cpu_entropy = [0u8; 16];

                for j in 0..4 {
                    let val = rng.next_u32();
                    cpu_entropy[j * 4] = ((val >> 24) & 0xFF) as u8;
                    cpu_entropy[j * 4 + 1] = ((val >> 16) & 0xFF) as u8;
                    cpu_entropy[j * 4 + 2] = ((val >> 8) & 0xFF) as u8;
                    cpu_entropy[j * 4 + 3] = (val & 0xFF) as u8;
                }

                println!("Seed: {}", seed);
                println!("  CPU: {}", hex::encode(&cpu_entropy));
                println!("  GPU: {}", hex::encode(&gpu_results[i]));

                if cpu_entropy == gpu_results[i] {
                    println!("  ✓ MATCH\n");
                } else {
                    println!("  ✗ MISMATCH\n");
                    panic!("GPU MT19937 output does not match CPU for seed {}", seed);
                }
            }

            println!("✓ All MT19937 GPU tests passed!");
        }
        Err(e) => {
            println!("GPU test failed: {}", e);
            panic!("MT19937 GPU test failed");
        }
    }
}
