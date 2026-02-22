//! Known Randstorm vulnerability test vectors
//!
//! Integration tests to validate the scanner can detect known vulnerable configurations
//! from the Randstorm research paper.

use temporal_planetarium_lib::scans::randstorm::{
    derivation, fingerprint::BrowserFingerprint, fingerprints::BrowserConfig, prng::ChromeV8Prng,
    test_vectors::TEST_VECTORS, PrngEngine,
};

// TEST-ID: 1.9-INTEGRATION-001
// AC: AC-6 (Known Vulnerability Detection)
// PRIORITY: P0
#[test]
fn test_known_randstorm_vulnerability() {
    // This test validates that the scanner can reconstruct PRNG state
    // from a known vulnerable browser configuration

    let test_vector = &TEST_VECTORS[0];

    // Create browser config from test vector
    let config = BrowserConfig {
        priority: 1,
        user_agent: test_vector.user_agent.to_string(),
        screen_width: test_vector.screen_width,
        screen_height: test_vector.screen_height,
        color_depth: test_vector.color_depth,
        timezone_offset: test_vector.timezone_offset,
        language: test_vector.language.to_string(),
        platform: test_vector.platform.to_string(),
        market_share_estimate: 1.0,
        year_min: 2011,
        year_max: 2015,
    };

    // Create fingerprint with test timestamp
    let fingerprint =
        BrowserFingerprint::from_config_and_timestamp(&config, test_vector.timestamp_ms);

    // Verify fingerprint was created correctly
    assert_eq!(fingerprint.timestamp_ms, test_vector.timestamp_ms);
    assert_eq!(fingerprint.screen_width, test_vector.screen_width);
    assert_eq!(fingerprint.user_agent, test_vector.user_agent);

    // End-to-end validation: derive address and verify expected match
    let prng = ChromeV8Prng::new();
    let seed = temporal_planetarium_lib::scans::randstorm::prng::SeedComponents {
        timestamp_ms: fingerprint.timestamp_ms,
        user_agent: fingerprint.user_agent.clone(),
        screen_width: fingerprint.screen_width,
        screen_height: fingerprint.screen_height,
        color_depth: fingerprint.color_depth,
        timezone_offset: fingerprint.timezone_offset as i16,
        language: fingerprint.language.clone(),
        platform: fingerprint.platform.clone(),
    };
    let state = prng.generate_state(&seed);
    let key_bytes = prng.generate_bytes(&state, 32);

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes[..32]);

    let expected_address = test_vector.expected_address;
    let derived_address =
        derivation::derive_p2pkh_address_from_bytes(&key_array).expect("derive address");

    println!("Derived Randstorm test vector address: {}", derived_address);

    assert_eq!(
        derived_address, expected_address,
        "Derived address must match known vulnerable vector"
    );
}

#[test]
fn test_test_vectors_validity() {
    // Validate test vector structure
    for (idx, vector) in TEST_VECTORS.iter().enumerate() {
        assert!(
            !vector.description.is_empty(),
            "Test vector {} missing description",
            idx
        );
        assert!(
            !vector.expected_address.is_empty(),
            "Test vector {} missing address",
            idx
        );
        assert!(
            vector.timestamp_ms > 1293840000000,
            "Test vector {} timestamp before 2011",
            idx
        );
        assert!(
            vector.timestamp_ms < 1451606400000,
            "Test vector {} timestamp after 2016",
            idx
        );
        assert!(
            vector.screen_width > 0,
            "Test vector {} invalid screen width",
            idx
        );
        assert!(
            vector.screen_height > 0,
            "Test vector {} invalid screen height",
            idx
        );
    }
}

#[test]
fn test_chrome_v8_prng_initialization() {
    // Verify ChromeV8Prng can be initialized
    let _prng = ChromeV8Prng::new();

    // PRNG should be ready to generate sequences
    // Actual generation tested in unit tests
}
