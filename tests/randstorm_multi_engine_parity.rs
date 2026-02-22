//! GPU-CPU Multi-Engine Parity Tests for Randstorm Scanner
//!
//! Verifies that all supported PRNG engines produce identical results on GPU and CPU.

#[cfg(test)]
mod multi_engine_tests {
    use temporal_planetarium_lib::scans::randstorm::integration::RandstormScanner;
    use temporal_planetarium_lib::scans::randstorm::config::ScanConfig;
    use temporal_planetarium_lib::scans::randstorm::prng::MathRandomEngine;
    use temporal_planetarium_lib::scans::randstorm::fingerprint::BrowserFingerprint;
    use temporal_planetarium_lib::scans::randstorm::prng::bitcoinjs_v013::BitcoinJsV013Prng;
    use bitcoin::secp256k1::{PublicKey, SecretKey, Secp256k1};
    use anyhow::Result;

    fn derive_cpu_address(timestamp: u64, engine: MathRandomEngine) -> String {
        let secp = Secp256k1::new();
        let key_bytes = BitcoinJsV013Prng::generate_privkey_bytes(timestamp, engine, None);
        let secret_key = SecretKey::from_slice(&key_bytes).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        temporal_planetarium_lib::scans::randstorm::derivation::derive_p2pkh_address(&public_key)
    }

    #[test]
    #[ignore] // Only run when GPU is available
    fn test_v8_mwc1616_parity() -> Result<()> {
        let ts = 1365000000000u64;
        let expected_addr = derive_cpu_address(ts, MathRandomEngine::V8Mwc1616);
        
        println!("V8 Target Address: {}", expected_addr);
        
        let mut config = ScanConfig::default();
        config.use_gpu = true;
        
        let mut scanner = RandstormScanner::with_config(config, MathRandomEngine::V8Mwc1616)?;
        
        // Scan a small range around the target
        let results = scanner.scan_with_progress(&[expected_addr.clone()], 
            temporal_planetarium_lib::scans::randstorm::integration::Phase::Full)?;
            
        assert!(!results.is_empty(), "GPU failed to find V8 address");
        assert_eq!(results[0].address, expected_addr);
        assert_eq!(results[0].timestamp, ts);
        
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_java_lcg_parity() -> Result<()> {
        let ts = 1400000000000u64;
        // Use SpiderMonkeyLcg which maps to Java LCG in GPU kernel
        let expected_addr = derive_cpu_address(ts, MathRandomEngine::SpiderMonkeyLcg);
        
        println!("Java LCG Target Address: {}", expected_addr);
        
        let mut config = ScanConfig::default();
        config.use_gpu = true;
        
        let mut scanner = RandstormScanner::with_config(config, MathRandomEngine::SpiderMonkeyLcg)?;
        
        let results = scanner.scan_with_progress(&[expected_addr.clone()], 
            temporal_planetarium_lib::scans::randstorm::integration::Phase::Full)?;
            
        assert!(!results.is_empty(), "GPU failed to find Java LCG address");
        assert_eq!(results[0].address, expected_addr);
        assert_eq!(results[0].timestamp, ts);
        
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_msvc_crt_parity() -> Result<()> {
        let ts = 1300000000000u64;
        let expected_addr = derive_cpu_address(ts, MathRandomEngine::SafariWindowsCrt);
        
        println!("MSVC CRT Target Address: {}", expected_addr);
        
        let mut config = ScanConfig::default();
        config.use_gpu = true;
        
        let mut scanner = RandstormScanner::with_config(config, MathRandomEngine::SafariWindowsCrt)?;
        
        let results = scanner.scan_with_progress(&[expected_addr.clone()], 
            temporal_planetarium_lib::scans::randstorm::integration::Phase::Full)?;
            
        assert!(!results.is_empty(), "GPU failed to find MSVC CRT address");
        assert_eq!(results[0].address, expected_addr);
        assert_eq!(results[0].timestamp, ts);
        
        Ok(())
    }
}
