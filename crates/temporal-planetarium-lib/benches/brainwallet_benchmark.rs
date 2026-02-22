// Brainwallet Performance Benchmark
//
// Measures:
// 1. Key derivation throughput (SHA256 hashing)
// 2. Address generation throughput
// 3. Full import pipeline performance

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use std::fs::File;
use std::io::Write;
use tempfile::TempDir;
use temporal_planetarium_lib::scans::brainwallet::{derive_key, run_import, AddressType, HashType};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Address, CompressedPublicKey, Network};

fn bench_derive_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("brainwallet_derive_key");

    // Test different hash types
    let passphrases = vec![
        "password",
        "hashcat",
        "satoshi nakamoto",
        "correct horse battery staple",
        "the quick brown fox jumps over the lazy dog",
    ];

    for passphrase in passphrases {
        // SHA256 1x
        group.bench_with_input(
            BenchmarkId::new("sha256_1x", passphrase),
            passphrase,
            |b, p| b.iter(|| derive_key(black_box(p), HashType::Sha256 { iterations: 1 }))
        );

        // SHA256 1000x
        group.bench_with_input(
            BenchmarkId::new("sha256_1000x", passphrase),
            passphrase,
            |b, p| b.iter(|| derive_key(black_box(p), HashType::Sha256 { iterations: 1000 }))
        );

        // SHA3-256
        group.bench_with_input(
            BenchmarkId::new("sha3_256", passphrase),
            passphrase,
            |b, p| b.iter(|| derive_key(black_box(p), HashType::Sha3_256))
        );
    }

    group.finish();
}

fn bench_address_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("brainwallet_address_generation");

    let secp = Secp256k1::new();
    let network = Network::Bitcoin;

    // Generate a test private key
    let privkey = derive_key("test_passphrase", HashType::Sha256 { iterations: 1 });
    let secret = SecretKey::from_slice(&privkey).unwrap();
    let pubkey = PublicKey::from_secret_key(&secp, &secret);
    let compressed = CompressedPublicKey(pubkey);
    let uncompressed_bytes = pubkey.serialize_uncompressed();

    // Benchmark different address types
    group.bench_function("p2pkh_uncompressed", |b| {
        b.iter(|| {
            use sha2::{Digest, Sha256};
            use ripemd::Ripemd160;
            let hash = Sha256::digest(&uncompressed_bytes);
            let hash160 = Ripemd160::digest(&hash);
            black_box(hash160)
        })
    });

    group.bench_function("p2pkh_compressed", |b| {
        b.iter(|| {
            let addr = Address::p2pkh(black_box(compressed), network);
            black_box(addr)
        })
    });

    group.bench_function("p2sh_p2wpkh", |b| {
        b.iter(|| {
            let addr = Address::p2shwpkh(&black_box(compressed), network);
            black_box(addr)
        })
    });

    group.bench_function("p2wpkh", |b| {
        b.iter(|| {
            let addr = Address::p2wpkh(&black_box(compressed), network);
            black_box(addr)
        })
    });

    group.finish();
}

fn bench_import_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("brainwallet_import_pipeline");

    // Test different wordlist sizes
    for size in [100, 1000, 10000] {
        group.throughput(Throughput::Elements(size as u64));

        group.bench_with_input(
            BenchmarkId::new("dry_run", size),
            &size,
            |b, &size| {
                b.iter_with_setup(
                    || {
                        // Setup: Create temp wordlist
                        let temp_dir = TempDir::new().unwrap();
                        let wordlist_path = temp_dir.path().join("passwords.txt");
                        let mut file = File::create(&wordlist_path).unwrap();

                        for i in 0..size {
                            writeln!(file, "password{}", i).unwrap();
                        }
                        drop(file);

                        (temp_dir, wordlist_path)
                    },
                    |(temp_dir, wordlist_path)| {
                        // Benchmark: Import in dry-run mode (no DB writes)
                        let stats = run_import(
                            wordlist_path.to_str().unwrap(),
                            None,
                            HashType::Sha256 { iterations: 1 },
                            AddressType::P2pkhCompressed,
                            true, // dry_run
                        ).unwrap();

                        assert_eq!(stats.total_processed, size);
                        black_box(stats);
                        drop(temp_dir);
                    }
                )
            }
        );
    }

    group.finish();
}

fn bench_batch_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("brainwallet_batch_processing");

    // Benchmark with database writes
    group.throughput(Throughput::Elements(1000));

    group.bench_function("with_database", |b| {
        b.iter_with_setup(
            || {
                // Setup: Create temp wordlist and DB
                let temp_dir = TempDir::new().unwrap();
                let wordlist_path = temp_dir.path().join("passwords.txt");
                let db_path = temp_dir.path().join("test.db");

                let mut file = File::create(&wordlist_path).unwrap();
                for i in 0..1000 {
                    writeln!(file, "password{}", i).unwrap();
                }
                drop(file);

                (temp_dir, wordlist_path, db_path)
            },
            |(temp_dir, wordlist_path, db_path)| {
                // Benchmark: Import with database writes
                let stats = run_import(
                    wordlist_path.to_str().unwrap(),
                    Some(db_path),
                    HashType::Sha256 { iterations: 1 },
                    AddressType::P2pkhCompressed,
                    false, // with database
                ).unwrap();

                assert_eq!(stats.total_processed, 1000);
                black_box(stats);
                drop(temp_dir);
            }
        )
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_derive_key,
    bench_address_generation,
    bench_import_pipeline,
    bench_batch_processing
);
criterion_main!(benches);
