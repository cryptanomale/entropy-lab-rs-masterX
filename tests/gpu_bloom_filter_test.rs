//! Integration tests for GPU Bloom Filter
//!
//! Part of STORY-003-001: Implement OpenCL Blocked Bloom Filter Kernel

#[cfg(feature = "gpu")]
mod gpu_bloom_tests {
    use temporal_planetarium_lib::utils::gpu_bloom_filter::{GpuBloomConfig, GpuBloomFilter};
    use ocl::{Platform, Device, Context, Queue, DeviceType};

    fn create_test_queue() -> Option<Queue> {
        let platform = Platform::default();
        let device = Device::first(platform).ok()?;
        let context = Context::builder()
            .platform(platform)
            .devices(device)
            .build()
            .ok()?;
        Queue::new(&context, device, None).ok()
    }

    #[test]
    fn test_bloom_config_calculation() {
        let config = GpuBloomConfig {
            expected_items: 1_000_000,
            fp_rate: 0.001,
            num_hashes: 15,
        };

        let size = config.calculate_filter_size();
        // Should be roughly 1.8 MB for 1M items at 0.1% FPR
        assert!(size > 1_000_000, "Filter should be > 1MB for 1M items");
        assert!(size < 3_000_000, "Filter should be < 3MB for 1M items");

        let k = config.calculate_optimal_k();
        // k should be around 10-15 for this configuration
        assert!(k >= 8, "k should be >= 8");
        assert!(k <= 20, "k should be <= 20");
    }

    #[test]
    fn test_config_default() {
        let config = GpuBloomConfig::default();
        assert_eq!(config.expected_items, 1_000_000);
        assert_eq!(config.num_hashes, 15);
        assert!(config.fp_rate < 0.01);
    }

    #[test]
    fn test_config_scaling() {
        // Test that filter size scales appropriately with expected items
        let config_small = GpuBloomConfig {
            expected_items: 100_000,
            fp_rate: 0.001,
            num_hashes: 15,
        };
        
        let config_large = GpuBloomConfig {
            expected_items: 10_000_000,
            fp_rate: 0.001,
            num_hashes: 15,
        };

        let size_small = config_small.calculate_filter_size();
        let size_large = config_large.calculate_filter_size();

        // Size should scale roughly linearly with expected items
        // Large should be ~100x small (10M / 100K = 100)
        let ratio = size_large as f64 / size_small as f64;
        assert!(ratio > 50.0, "Large filter should be much bigger than small");
        assert!(ratio < 200.0, "But not excessively bigger");
    }

    #[test]
    #[ignore] // Requires GPU hardware
    fn test_gpu_bloom_filter_creation() {
        let queue = match create_test_queue() {
            Some(q) => q,
            None => {
                eprintln!("Skipping GPU test: no OpenCL device available");
                return;
            }
        };

        let config = GpuBloomConfig::default();
        let filter = GpuBloomFilter::new(queue, config);
        
        assert!(filter.is_ok(), "Failed to create GPU Bloom Filter: {:?}", filter.err());
        
        let filter = filter.unwrap();
        assert_eq!(filter.item_count(), 0);
        assert!(filter.filter_size() > 0);
    }

    #[test]
    #[ignore] // Requires GPU hardware
    fn test_gpu_bloom_filter_basic_operations() {
        let queue = match create_test_queue() {
            Some(q) => q,
            None => {
                eprintln!("Skipping GPU test: no OpenCL device available");
                return;
            }
        };

        let config = GpuBloomConfig {
            expected_items: 1000,
            fp_rate: 0.01,
            num_hashes: 10,
        };
        
        let mut filter = GpuBloomFilter::new(queue, config).unwrap();

        // Insert some test items
        let test_items = vec![
            b"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_vec(),
            b"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy".to_vec(),
            b"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_vec(),
        ];

        for item in &test_items {
            filter.insert_batch(&[item.clone()]).unwrap();
        }

        // Lookup should find them
        let results = filter.batch_lookup(&test_items).unwrap();
        for (i, result) in results.iter().enumerate() {
            assert!(*result, "Item {} should be found in filter", i);
        }

        // Non-existent items should (usually) not be found
        let non_existent = vec![
            b"1NonExistentAddress123456789".to_vec(),
            b"3AnotherFakeAddress987654321".to_vec(),
        ];

        let neg_results = filter.batch_lookup(&non_existent).unwrap();
        // Due to false positives, we can't assert all are false
        // But we can log the results
        let false_positives = neg_results.iter().filter(|&&r| r).count();
        eprintln!("False positives: {} / {}", false_positives, neg_results.len());
    }
}

#[cfg(not(feature = "gpu"))]
mod cpu_bloom_tests {
    use temporal_planetarium_lib::utils::gpu_bloom_filter::GpuBloomConfig;

    #[test]
    fn test_bloom_config_cpu_only() {
        let config = GpuBloomConfig::default();
        assert_eq!(config.expected_items, 1_000_000);
        assert_eq!(config.num_hashes, 15);
    }
}
