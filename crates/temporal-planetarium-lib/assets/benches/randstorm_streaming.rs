use criterion::{black_box, criterion_group, criterion_main, Criterion};
use temporal_planetarium_lib::scans::randstorm::{
    config::ScanMode, fingerprints::FingerprintDatabase, integration::StreamingScan, Phase,
};

fn streaming_throughput(c: &mut Criterion) {
    // Use a small subset of configs to keep bench lightweight while exercising streaming
    let db = FingerprintDatabase::load_comprehensive().expect("load comprehensive DB");
    let configs: Vec<_> = db
        .get_configs_for_phase(Phase::One)
        .iter()
        .take(4)
        .cloned()
        .collect();

    c.bench_function("randstorm_streaming_hourly", |b| {
        b.iter(|| {
            let mut scan = StreamingScan::new(configs.clone(), ScanMode::Standard);
            let mut count = 0u64;
            // Iterate a fixed number of fingerprints to estimate throughput
            while count < 50_000 {
                if scan.next_fingerprint().is_none() {
                    break;
                }
                count += 1;
            }
            black_box(count);
        });
    });
}

criterion_group!(benches, streaming_throughput);
criterion_main!(benches);
