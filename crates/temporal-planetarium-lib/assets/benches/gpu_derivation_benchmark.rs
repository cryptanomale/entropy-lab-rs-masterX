use criterion::{black_box, criterion_group, criterion_main, Criterion};
use temporal_planetarium_lib::scans::randstorm::derivation_batcher::DerivationBatcher;
use temporal_planetarium_lib::scans::randstorm::gpu_integration::GpuDerivationBatcher;
use bitcoin::Network;

fn bench_derivation(c: &mut Criterion) {
    let seed = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
    let max_index = 10; // Use small index for quick benchmark, 100 for real test

    let mut group = c.benchmark_group("Derivation Batching");

    group.bench_function("CPU Derivation (Batch=10)", |b| {
        let batcher = DerivationBatcher::new(Network::Bitcoin, max_index);
        b.iter(|| {
            batcher.derive_all(black_box(&seed)).unwrap();
        })
    });

    #[cfg(feature = "gpu")]
    group.bench_function("GPU Derivation (Batch=10)", |b| {
        // Initialize GPU batcher once
        if let Ok(mut batcher) = GpuDerivationBatcher::new(max_index) {
             let seeds = vec![seed.clone()];
             b.iter(|| {
                 batcher.derive_batch(black_box(&seeds)).unwrap();
             });
        }
    });

    group.finish();
}

criterion_group!(benches, bench_derivation);
criterion_main!(benches);
