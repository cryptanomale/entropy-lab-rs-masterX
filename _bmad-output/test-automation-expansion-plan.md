# Test Automation Expansion Plan - Entropy Lab RS

**Project:** Temporal Planetarium  
**Generated:** 2025-12-19 01:31 UTC  
**Architect:** Murat (Test Architect)  
**Scope:** Coverage gap analysis and test generation for untested code paths

---

## Executive Summary

**Current Coverage:**
- **Source Files:** 45 files (11,277 lines)
- **Files with Unit Tests:** 24 (53%)
- **Files WITHOUT Tests:** 21 (47%) ❌
- **Integration Tests:** 20 files, 103 test functions
- **Test Quality Score:** 72/100 (from test-review)

**Critical Gaps:**
1. **BLOCKER-4:** Checkpoint/resume functions not implemented
2. **7 scanner modules** without unit tests
3. **GUI module** completely untested
4. **Bloom filter utility** untested

**Priority:** Resolve Story 1.9.1 blockers first (19-27 hours), then expand coverage (12-18 hours)

---

## Coverage Gap Analysis

### Priority 1: Story 1.9.1 Blocker Resolution (CRITICAL)

#### BLOCKER-4: Checkpoint/Resume Implementation
**Status:** 🔴 NOT IMPLEMENTED  
**Tests Created:** `tests/randstorm_checkpoint.rs` (5 tests, all `#[ignore]`)  
**Missing Implementation:**

```rust
// src/scans/randstorm/checkpoint.rs (NEW FILE NEEDED)

use serde::{Deserialize, Serialize};
use std::path::Path;
use anyhow::Result;

#[derive(Serialize, Deserialize)]
pub struct ScanCheckpoint {
    pub addresses_scanned: usize,
    pub addresses_remaining: usize,
    pub current_config_idx: usize,
    pub current_timestamp_idx: usize,
    pub findings: Vec<String>,
    pub timestamp: String,
}

impl ScanCheckpoint {
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
    
    pub fn load(path: &Path) -> Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let checkpoint = serde_json::from_str(&json)?;
        Ok(checkpoint)
    }
}
```

**Integration Point:**
```rust
// src/scans/randstorm/integration.rs
// Add methods to StreamingScan:

impl StreamingScan {
    pub fn save_checkpoint(&self, path: &Path) -> Result<()> {
        let checkpoint = ScanCheckpoint {
            addresses_scanned: self.scanned_count,
            addresses_remaining: self.total - self.scanned_count,
            current_config_idx: self.config_idx,
            current_timestamp_idx: self.timestamp_idx,
            findings: self.findings.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        checkpoint.save(path)
    }
    
    pub fn resume_from_checkpoint(path: &Path) -> Result<Self> {
        let checkpoint = ScanCheckpoint::load(path)?;
        // Reconstruct scanner state from checkpoint
        // ...
    }
}
```

**Tests to Enable:**
- `test_checkpoint_save_load()` - Remove `#[ignore]`
- `test_resume_identical_results()` - Remove `#[ignore]`
- `test_sigterm_graceful_shutdown()` - Remove `#[ignore]`
- `test_checkpoint_corruption_handling()` - Remove `#[ignore]`
- `test_checkpoint_automatic_interval()` - Remove `#[ignore]`

**Effort:** 4-6 hours

---

#### BLOCKER-1: End-to-End Cryptographic Validation
**Status:** 🔴 TESTS CREATED, AWAITING VECTORS  
**Tests Created:** `tests/randstorm_comprehensive_configs.rs` (5 of 20 tests)  
**Missing:** 15 more test vectors with citations

**Action Required:**
1. Obtain test vectors from Randstorm research paper
2. Replace `PLACEHOLDER` addresses with actual expected values
3. Add 15 more configurations (Chrome 20, 40, 48, pt-BR, macOS, Linux, Android, iOS)
4. Remove `#[ignore]` when vectors obtained

**Effort:** 4-6 hours (requires research coordination)

---

#### BLOCKER-2: Performance Assertion
**Status:** 🔴 TEST CREATED, AWAITING IMPLEMENTATION  
**Test:** `tests/randstorm_performance.rs`  
**Missing:** GPU scanner integration

**Action Required:**
1. Implement `RandstormScanner::new_gpu()`
2. Implement `scan_batch()` method
3. Remove simulation code
4. Remove `#[ignore]`
5. Verify ≥50K keys/sec on GPU hardware

**Effort:** 4-6 hours

---

#### BLOCKER-3: GPU Tests Mapped
**Status:** 🟡 DOCUMENTATION ONLY  
**Tests Exist:** `tests/test_gpu_cpu_parity.rs`, `tests/randstorm_gpu_cpu_parity.rs`  
**Missing:** Traceability mapping

**Action Required:**
1. Update `_bmad-output/traceability-matrix-story-1.9.md`
2. Add GPU tests to AC-3 section
3. Change coverage: PARTIAL → FULL

**Effort:** 1 hour

---

#### BLOCKER-5: Test Vector Citations
**Status:** 🟡 DESIGN NEEDED  
**Missing:** `VectorSource` enum

**Action Required:**
1. Define `VectorSource` enum in `src/scans/randstorm/test_vectors.rs`
2. Add `source` field to `RandstormTestVector`
3. Update existing test vectors with citations
4. Add 9 more cited vectors (10 total minimum)

**Effort:** 8-12 hours

**Total Blocker Effort:** 19-27 hours (Story 1.9.1 estimate validated)

---

## Priority 2: Untested Scanner Modules (HIGH)

### Module 1: Malicious Extension Scanner
**File:** `src/scans/malicious_extension.rs`  
**Status:** ❌ NO UNIT TESTS  
**Risk:** HIGH (security-critical feature)

**Test File to Create:** `src/scans/malicious_extension.rs` (add `#[cfg(test)] mod tests`)

**Test Coverage Needed:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_malicious_extension_detection_known_pattern() {
        // Test against known malicious extension patterns
        let extension_id = "fake-metamask-12345";
        let is_malicious = detect_malicious_extension(extension_id);
        assert!(is_malicious);
    }
    
    #[test]
    fn test_legitimate_extension_not_flagged() {
        let extension_id = "metamask-official";
        let is_malicious = detect_malicious_extension(extension_id);
        assert!(!is_malicious);
    }
    
    #[test]
    fn test_extension_entropy_reduction_calculation() {
        // Verify entropy calculation for extension-injected randomness
        let entropy = calculate_extension_entropy_impact();
        assert!(entropy < 128); // Reduced from full 256-bit
    }
}
```

**Effort:** 2-3 hours

---

### Module 2: Mobile Sensor Scanner
**File:** `src/scans/mobile_sensor.rs`  
**Status:** ❌ NO UNIT TESTS  
**Risk:** MEDIUM

**Test Coverage Needed:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensor_data_parsing() {
        let sensor_json = r#"{"accelerometer": [0.1, 0.2, 0.3], "gyroscope": [1.0, 2.0, 3.0]}"#;
        let data = parse_sensor_data(sensor_json).unwrap();
        assert_eq!(data.accelerometer.len(), 3);
    }
    
    #[test]
    fn test_sensor_entropy_estimation() {
        let sensor_data = SensorData::mock();
        let entropy_bits = estimate_sensor_entropy(&sensor_data);
        assert!(entropy_bits < 64); // Limited entropy from sensors
    }
    
    #[test]
    fn test_sensor_based_key_derivation() {
        let sensor_data = SensorData::mock();
        let key1 = derive_key_from_sensors(&sensor_data);
        let key2 = derive_key_from_sensors(&sensor_data);
        assert_eq!(key1, key2); // Deterministic
    }
}
```

**Effort:** 2-3 hours

---

### Module 3: Profanity Vanity Address Scanner
**File:** `src/scans/profanity.rs`  
**Status:** ❌ NO UNIT TESTS  
**Risk:** HIGH (known vulnerability)

**Test Coverage Needed:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profanity_seed_reconstruction() {
        // Test against known Profanity vulnerability
        let target_prefix = "1Love";
        let seed = find_profanity_seed(target_prefix);
        assert!(seed.is_some());
    }
    
    #[test]
    fn test_profanity_private_key_recovery() {
        // Given a Profanity-generated address, recover private key
        let address = "1LoveXXXXXXXXXXXXXXXXXXXXXXXXX";
        let private_key = recover_profanity_key(address);
        assert!(private_key.is_some());
    }
    
    #[test]
    fn test_profanity_performance_estimation() {
        // Estimate time to crack 4-character prefix
        let prefix_length = 4;
        let estimated_time = estimate_crack_time(prefix_length);
        assert!(estimated_time < 3600); // <1 hour for 4 chars
    }
}
```

**Effort:** 3-4 hours

---

### Module 4: Cake Wallet Crack
**File:** `src/scans/cake_wallet_crack.rs`  
**Status:** ❌ NO UNIT TESTS  
**Risk:** MEDIUM

**Test Coverage Needed:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cake_wallet_dart_prng_crack() {
        let timestamp = 1609459200000; // Jan 1, 2021
        let seed = crack_dart_prng_seed(timestamp);
        assert!(seed.is_some());
    }
    
    #[test]
    fn test_cake_wallet_date_range_scan() {
        let start = 1609459200000;
        let end = 1640995200000; // Jan 1, 2022
        let vulnerable_seeds = scan_date_range(start, end);
        assert!(!vulnerable_seeds.is_empty());
    }
}
```

**Effort:** 2-3 hours

---

### Module 5: EC New (Elliptic Curve)
**File:** `src/scans/ec_new.rs`  
**Status:** ❌ NO UNIT TESTS  
**Risk:** LOW

**Test Coverage Needed:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ec_new_vulnerability_detection() {
        // Test for EC_NEW PRNG vulnerability
        let config = ECNewConfig::default();
        let is_vulnerable = check_ec_new_vulnerability(&config);
        assert!(is_vulnerable);
    }
}
```

**Effort:** 1-2 hours

---

### Module 6: BIP3x Scanner
**File:** `src/scans/bip3x.rs`  
**Status:** ❌ NO UNIT TESTS  
**Risk:** MEDIUM

**Test Coverage Needed:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip32_derivation_path_validation() {
        let path = "m/44'/0'/0'/0/0";
        assert!(validate_derivation_path(path));
    }
    
    #[test]
    fn test_bip39_mnemonic_weakness_detection() {
        let weak_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(is_weak_mnemonic(weak_mnemonic));
    }
}
```

**Effort:** 2-3 hours

---

### Module 7: Trust Wallet LCG
**File:** `src/scans/trust_wallet_lcg.rs`  
**Status:** ❌ NO UNIT TESTS  
**Risk:** MEDIUM

**Test Coverage Needed:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lcg_state_prediction() {
        let observed_outputs = vec![12345, 67890, 11111];
        let next_output = predict_next_lcg_output(&observed_outputs);
        assert!(next_output.is_some());
    }
}
```

**Effort:** 2-3 hours

---

## Priority 3: Utility Modules (MEDIUM)

### Bloom Filter
**File:** `src/utils/bloom_filter.rs`  
**Status:** ❌ NO UNIT TESTS  
**Risk:** MEDIUM (performance-critical)

**Test Coverage Needed:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter_insert_and_query() {
        let mut filter = BloomFilter::new(1000, 0.01);
        filter.insert("test_address");
        assert!(filter.contains("test_address"));
        assert!(!filter.contains("other_address"));
    }
    
    #[test]
    fn test_bloom_filter_false_positive_rate() {
        let mut filter = BloomFilter::new(10000, 0.01);
        // Insert 10,000 items
        for i in 0..10000 {
            filter.insert(&format!("addr_{}", i));
        }
        
        // Test 10,000 non-existent items
        let mut false_positives = 0;
        for i in 10000..20000 {
            if filter.contains(&format!("addr_{}", i)) {
                false_positives += 1;
            }
        }
        
        let fp_rate = false_positives as f64 / 10000.0;
        assert!(fp_rate < 0.02); // Within 2% tolerance
    }
}
```

**Effort:** 2-3 hours

---

## Priority 4: GUI Module (LOW - Optional)

### GUI
**File:** `src/gui.rs`  
**Status:** ❌ NO UNIT TESTS  
**Risk:** LOW (feature flag, not security-critical)

**Test Coverage Needed:**
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "gui")]
    fn test_gui_state_initialization() {
        let app = EntropyLabApp::default();
        assert_eq!(app.scan_mode, ScanMode::Quick);
    }
    
    // Note: GUI testing is difficult without UI framework mocks
    // Consider visual regression tests or snapshot tests
}
```

**Effort:** 1-2 hours (low priority)

---

## Integration Test Gaps

### Missing Integration Tests

#### Scan Mode Behavior Test
**File:** `tests/scan_mode_behavior.rs` (NEW)  
**Priority:** HIGH (from test-review HIGH-7)

```rust
//! Scan Mode Behavior Tests
//!
//! Validates that different scan modes (Quick/Standard/Deep/Exhaustive)
//! produce different fingerprint counts as specified.

use entropy_lab_rs::scans::randstorm::{ScanMode, count_fingerprints};

#[test]
fn test_scan_mode_quick_fingerprint_count() {
    let count = count_fingerprints(ScanMode::Quick);
    assert!(count >= 10 && count <= 50, "Quick mode: 10-50 fingerprints");
}

#[test]
fn test_scan_mode_standard_fingerprint_count() {
    let count = count_fingerprints(ScanMode::Standard);
    assert!(count >= 200 && count <= 300, "Standard mode: 200-300 fingerprints");
}

#[test]
fn test_scan_mode_deep_fingerprint_count() {
    let count = count_fingerprints(ScanMode::Deep);
    assert!(count >= 1000, "Deep mode: 1000+ fingerprints");
}

#[test]
fn test_scan_mode_exhaustive_fingerprint_count() {
    let count = count_fingerprints(ScanMode::Exhaustive);
    assert!(count >= 10000, "Exhaustive mode: 10K+ fingerprints");
}

#[test]
fn test_scan_mode_progression() {
    let quick = count_fingerprints(ScanMode::Quick);
    let standard = count_fingerprints(ScanMode::Standard);
    let deep = count_fingerprints(ScanMode::Deep);
    
    // Standard should be ~10x more than Quick
    assert!(standard > quick * 5);
    
    // Deep should be ~5x more than Standard
    assert!(deep > standard * 3);
}
```

**Effort:** 1-2 hours

---

#### CLI Output Format Validation
**File:** `tests/cli_output_formats.rs` (NEW)  
**Priority:** MEDIUM

```rust
//! CLI Output Format Tests
//!
//! Validates that CLI output formats (JSON, CSV, plain text) are correct.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_cli_json_output_valid() {
    let mut cmd = Command::cargo_bin("entropy-lab-rs").unwrap();
    cmd.args(&["randstorm-scan", "--format", "json"]);
    
    let output = cmd.output().unwrap();
    let json_str = String::from_utf8(output.stdout).unwrap();
    
    // Validate JSON parses
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert!(parsed.is_object());
}

#[test]
fn test_cli_csv_output_has_headers() {
    let mut cmd = Command::cargo_bin("entropy-lab-rs").unwrap();
    cmd.args(&["randstorm-scan", "--format", "csv", "--output", "test.csv"]);
    
    cmd.assert().success();
    
    // Read CSV and verify headers
    let csv_content = std::fs::read_to_string("test.csv").unwrap();
    assert!(csv_content.starts_with("address,confidence,"));
    
    std::fs::remove_file("test.csv").ok();
}
```

**Effort:** 1-2 hours

---

## Summary: Test Automation Expansion Plan

### Total Coverage Gaps Identified

| Category | Files | Effort |
|----------|-------|--------|
| **Story 1.9.1 Blockers** | 3 test files + 2 docs | 19-27 hours |
| **Untested Scanners** | 7 modules | 14-21 hours |
| **Untested Utilities** | 1 module | 2-3 hours |
| **Missing Integration Tests** | 2 new files | 2-4 hours |
| **GUI (Optional)** | 1 module | 1-2 hours |

**Total Effort:** 38-57 hours

---

### Recommended Implementation Order

**Week 1: Story 1.9.1 Blockers (CRITICAL)**
1. BLOCKER-4: Implement checkpoint/resume (4-6 hours)
2. BLOCKER-2: Add GPU scanner integration (4-6 hours)
3. BLOCKER-3: Map GPU tests to traceability (1 hour)
4. BLOCKER-5: Add VectorSource enum and citations (8-12 hours)
5. BLOCKER-1: Obtain and add 20 test vectors (4-6 hours)

**Result:** Story 1.9.1 complete, quality score 72 → 85

**Week 2: High-Risk Scanners**
6. Profanity scanner tests (3-4 hours)
7. Malicious extension tests (2-3 hours)
8. Mobile sensor tests (2-3 hours)
9. Cake Wallet crack tests (2-3 hours)
10. Bloom filter tests (2-3 hours)

**Result:** Security-critical modules tested, quality score 85 → 90

**Week 3: Remaining Gaps**
11. Scan mode behavior tests (1-2 hours)
12. CLI output format tests (1-2 hours)
13. BIP3x tests (2-3 hours)
14. Trust Wallet LCG tests (2-3 hours)
15. EC New tests (1-2 hours)

**Result:** Comprehensive coverage, quality score 90 → 95

---

## Test Generation Templates

### Unit Test Template
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_<module>_<function>_<scenario>_<expected_outcome>() {
        // Arrange
        let input = create_test_input();
        
        // Act
        let result = function_under_test(input);
        
        // Assert
        assert_eq!(result, expected_value);
    }
    
    #[test]
    fn test_<module>_<function>_error_handling() {
        let invalid_input = create_invalid_input();
        let result = function_under_test(invalid_input);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_<module>_<function>_edge_case() {
        // Test boundary conditions
        let edge_input = create_edge_case();
        let result = function_under_test(edge_input);
        assert!(result.is_ok());
    }
}
```

### Integration Test Template
```rust
//! <Feature> Integration Tests
//!
//! TEST SUITE: <Story ID>
//! AC: <Acceptance Criteria>
//! PRIORITY: <P0/P1/P2>

use entropy_lab_rs::<module>;
use anyhow::Result;

// TEST-ID: <ID>
// AC: <AC Number>
// PRIORITY: <P0/P1/P2>
#[test]
fn test_<feature>_<scenario>() -> Result<()> {
    // Arrange
    let setup = create_test_setup()?;
    
    // Act
    let result = execute_feature(&setup)?;
    
    // Assert
    assert_eq!(result.status, ExpectedStatus::Success);
    assert!(result.data.len() > 0);
    
    Ok(())
}
```

---

## Next Steps

**Immediate Actions:**
1. Review this automation plan
2. Prioritize blockers (Story 1.9.1)
3. Generate test stubs for untested modules
4. Implement missing functionality (checkpoint, GPU integration)
5. Run `cargo test` after each module completion

**Validation:**
- Run `cargo test` after each test addition
- Verify tests fail initially (RED phase)
- Implement features to make tests pass (GREEN phase)
- Refactor with test protection (REFACTOR phase)

**Tracking:**
- Update traceability matrix after each blocker resolved
- Re-run test-review after Week 2
- Monitor quality score progression: 72 → 85 → 90 → 95

---

**Generated By:** Murat (Test Architect)  
**Date:** 2025-12-19 01:31 UTC  
**Next Review:** After Story 1.9.1 completion

---
