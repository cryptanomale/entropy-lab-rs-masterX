use anyhow::Result;
use sha2::{Sha256, Digest};
use temporal_planetarium_lib::scans::randstorm::{
    ChromeV8State, V8Reference,
    config::{ScanConfig, ScanMode},
    integration::RandstormScanner,
    prng::MathRandomEngine,
    synthetic_wallet::SyntheticWalletGenerator,
};

#[test]
fn test_synthetic_wallet_detection_full_pipeline() -> Result<()> {
    // 1. Generate a synthetic vulnerable wallet (Chrome V8)
    // Timestamp: 2013-04-15 12:00:00 UTC
    let target_timestamp = 1366027200000;
    
    let generator = SyntheticWalletGenerator::new();
    let wallet = generator.generate_wallet_v8(target_timestamp)?;
    
    println!("Generated Synthetic Wallet:");
    println!("  Address: {}", wallet.address);
    println!("  Timestamp: {}", wallet.timestamp_ms);

    // 2. Configure Scanner with Heuristic Search (Spiral)
    // Set target timestamp to the wallet's timestamp
    // Window +/- 1 hour (3,600,000 ms)
    let mut config = ScanConfig::default();
    config.scan_mode = ScanMode::Standard;
    config.use_gpu = false; // Force CPU
    config.target_timestamp = Some(target_timestamp);
    config.timestamp_window = Some(3_600_000); 
    
    // 3. Initialize Scanner
    let mut scanner = RandstormScanner::with_config(config, MathRandomEngine::V8Mwc1616)?;

    // 4. Run Scan
    println!("\nStarting Scan...");
    // Phase::One scans top 100 browser configs (Chrome V8 is high priority)
    let result = scanner.scan(&wallet.address, temporal_planetarium_lib::scans::randstorm::fingerprints::Phase::One)?;

    // 5. Verify Detection
    assert!(result.is_some(), "Scanner failed to detect synthetic wallet");
    
    let finding = result.unwrap();
    println!("\nDetection Successful!");
    println!("  Found Address: {}", finding.address);
    println!("  Confidence: {:?}", finding.confidence);
    println!("  Timestamp Found: {}", finding.timestamp);
    println!("  Browser: {}", finding.browser_config.user_agent);

    // Verify metadata
    assert_eq!(finding.address, wallet.address);
    assert_eq!(finding.timestamp, target_timestamp, "Timestamp mismatch");
    assert!(finding.browser_config.user_agent.contains("Chrome") || finding.browser_config.user_agent.contains("Chromium"));

    Ok(())
}

/// Tier 4 Verification Test: MWC1616 PRNG 1000-output validation
///
/// This test validates that the V8Reference implementation produces
/// bit-perfect outputs matching the V8 3.14.5.9 MWC1616 algorithm.
///
/// Reference: tests/fixtures/randstorm_vectors.json
#[test]
fn test_tier4_mwc1616_1000_output_verification() {
    // Canonical seed from randstorm_vectors.json
    let mut state = ChromeV8State {
        s1: 0x12345678,
        s2: 0x9ABCDEF0,
    };

    let mut hasher = Sha256::new();

    // Generate 1000 consecutive outputs
    for _ in 0..1000 {
        let output = V8Reference::next_state(&mut state);
        hasher.update(output.to_le_bytes());
    }

    let hash = hasher.finalize();
    let hash_hex = hex::encode(&hash);

    // Expected hash from randstorm_vectors.json
    let expected_hash = "466326718f1550191ee60476fb98299c1ad45cbfcdb61d621f83e0a6527323f2";

    assert_eq!(
        hash_hex, expected_hash,
        "Tier 4 verification FAILED: MWC1616 1000-output hash mismatch!\n\
         Expected: {}\n\
         Got: {}\n\
         This indicates V8Reference implementation has diverged from V8 3.14.5.9 reference.",
        expected_hash, hash_hex
    );

    // Also verify final state
    assert_eq!(state.s1, 0x27ccd9e8, "Final s1 state mismatch");
    assert_eq!(state.s2, 0x67abb1c6, "Final s2 state mismatch");

    println!("✅ Tier 4 MWC1616 1000-output verification PASSED");
}
