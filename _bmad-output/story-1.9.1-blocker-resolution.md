# Story 1.9.1: Randstorm Scanner - Blocker Resolution

**Story ID:** 1.9.1  
**Epic:** Phase 1 - Randstorm/BitcoinJS Scanner  
**Parent Story:** 1.9 - Comprehensive Randstorm Scanner  
**Priority:** P0 (CRITICAL - Release Blocker)  
**Status:** review  
**Estimated Effort:** 19-27 hours  
**Dependencies:** Story 1.9 implementation complete

---

## Context

Story 1.9 traceability analysis revealed **5 critical blockers** preventing release:
- Initial assessment: 80% coverage, PASS ✅
- Red Team findings: 0% FULL coverage, FAIL ❌
- Root cause: Structural validation ≠ cryptographic correctness

**Risk:** $32M+ potential loss if scanner deployed with gaps (70-80% probability)

See: `_bmad-output/traceability-matrix-story-1.9.md` (Red Team Analysis, Pre-mortem sections)

---

## User Story

**As a** security researcher  
**I want** all 5 critical blockers resolved with validated tests  
**So that** the Randstorm scanner is cryptographically correct and safe for production

---

## Acceptance Criteria

### AC-1: End-to-End Cryptographic Validation (BLOCKER-1)

**Priority:** P0  
**Effort:** 4-6 hours

**Given** 20 diverse browser configurations (Chrome versions 14-48, multiple languages/platforms)  
**When** each config + timestamp is processed through PRNG → private key → address derivation  
**Then** derived address matches expected value from cited test vector

**Requirements:**
- ✅ 20 test vectors covering:
  - Chrome versions: 14, 20, 26, 35, 40, 45, 48
  - Languages: en-US, ru-RU, zh-CN, es-ES, pt-BR
  - Resolutions: 1024×768, 1366×768, 1920×1080, 2560×1440
  - Platforms: Windows, macOS, Linux, Android, iOS
- ✅ Each test vector cited from Randstorm research or derived with documented rationale
- ✅ Test format: `test_config_<chrome_version>_<language>_<resolution>_end_to_end()`
- ✅ All tests must PASS (cryptographic correctness validated)

**Test Implementation:**
```rust
#[test]
fn test_config_chrome_46_ru_ru_1920x1080_end_to_end() {
    // CITED: Randstorm paper Section 4.2, Table 5, Row 12
    let config = BrowserConfig {
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/46.0.2490.80",
        screen_width: 1920,
        screen_height: 1080,
        language: "ru-RU",
        // ... other fields
    };
    
    let timestamp_ms = 1447286400000; // Nov 12, 2015
    let expected_address = "1Chrome46RuRu1920x1080..."; // From research
    
    // End-to-end: config + timestamp → PRNG state → private key → address
    let fingerprint = BrowserFingerprint::from_config_and_timestamp(&config, timestamp_ms);
    let prng = ChromeV8Prng::new();
    let seed = prng.generate_state(&fingerprint);
    let key_bytes = prng.generate_bytes(&seed, 32);
    let address = derive_p2pkh_address_from_bytes(&key_bytes).unwrap();
    
    // Cryptographic correctness validation
    assert_eq!(address, expected_address);
}
```

**Validation:**
- Test file: `tests/randstorm_comprehensive_configs.rs`
- All 20 tests PASS
- No Chrome/46 typo or similar config errors

---

### AC-2: Performance Requirement Validated (BLOCKER-2)

**Priority:** P0  
**Effort:** 2 hours

**Given** GPU-accelerated Randstorm scanner  
**When** benchmark is executed  
**Then** throughput is ≥50,000 keys/second

**Requirements:**
- ✅ Performance assertion in test suite: `assert!(throughput >= 50_000)`
- ✅ Benchmark runs in CI (smoke test: compile only)
- ✅ Local benchmark validates actual throughput
- ✅ Documentation updated with actual measured performance

**Test Implementation:**
```rust
#[test]
#[cfg(feature = "gpu")]
fn test_randstorm_meets_50k_keys_per_second_requirement() {
    use std::time::Instant;
    
    let configs = load_comprehensive_configs();
    let addresses = vec!["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"; 10000];
    
    let start = Instant::now();
    let scanner = RandstormScanner::new(&configs[0..10]); // 10 configs
    scanner.scan_batch(&addresses);
    let elapsed = start.elapsed();
    
    let keys_per_sec = (10 * 10000) as f64 / elapsed.as_secs_f64();
    
    assert!(
        keys_per_sec >= 50_000.0,
        "Performance requirement not met: {} keys/sec (expected ≥50K)",
        keys_per_sec
    );
}
```

**Validation:**
- Test file: `tests/randstorm_performance.rs`
- Test PASSES on GPU-enabled hardware
- Benchmark: `cargo bench --bench randstorm_streaming` shows ≥50K keys/sec

---

### AC-3: GPU Tests Mapped to Traceability (BLOCKER-3)

**Priority:** P0  
**Effort:** 1 hour (documentation only)

**Given** existing GPU parity tests  
**When** traceability matrix is updated  
**Then** GPU tests are mapped to AC-3 (Production Scan Infrastructure)

**Requirements:**
- ✅ Update `_bmad-output/traceability-matrix-story-1.9.md`
- ✅ Add section: "GPU Acceleration Validation"
- ✅ Map tests:
  - `tests/test_gpu_cpu_parity.rs` → AC-3
  - `tests/randstorm_gpu_cpu_parity.rs` → AC-3
- ✅ Document GPU kernel validation approach
- ✅ Re-run Red Team review with GPU tests included

**Documentation Update:**
```markdown
### AC-3: Production Scan Infrastructure (P0)

**Coverage:** FULL ✅ (UPDATED after BLOCKER-3 resolution)

**Tests:**
- ✅ **1.9-UNIT-008** - `test_streaming_scan_iteration()` - Nested iteration
- ✅ **1.9-INTEGRATION-004** - `test_cli_scan_output_file()` - CSV output
- ✅ **1.9-INTEGRATION-005** - `test_cli_scan_valid_addresses_cpu()` - No caps
- ✅ **1.9-GPU-001** - `test_gpu_cpu_parity_randstorm()` - GPU/CPU identical results
- ✅ **1.9-GPU-002** - `test_gpu_cpu_parity_general()` - General parity validation
- ✅ **1.9-PERFORMANCE-001** - `test_randstorm_meets_50k_keys_per_second_requirement()`
```

**Validation:**
- Traceability matrix updated
- GPU tests documented
- Red Team review: BLOCKER-3 resolved

---

### AC-4: Checkpoint/Resume Tests Implemented (BLOCKER-4)

**Priority:** P0  
**Effort:** 4-6 hours

**Given** long-running Randstorm scans (multi-day)  
**When** checkpoint/resume functionality is tested  
**Then** scan state is saved/restored correctly with identical results

**Requirements:**
- ✅ `test_checkpoint_save_load()` - Save and load checkpoint file
- ✅ `test_resume_identical_results()` - Resume produces same results as uninterrupted scan
- ✅ `test_sigterm_graceful_shutdown()` - SIGTERM saves checkpoint before exit
- ✅ `test_checkpoint_corruption_handling()` - Gracefully handle corrupted checkpoint

**Test Implementation:**
```rust
#[test]
fn test_checkpoint_save_load() -> Result<()> {
    use tempfile::tempdir;
    
    let temp_dir = tempdir()?;
    let checkpoint_path = temp_dir.path().join("scan.checkpoint");
    
    // Create scanner with partial progress
    let mut scanner = StreamingScan::new(configs, timestamps);
    scanner.scan_batch(&addresses[0..50]); // Process 50 addresses
    
    // Save checkpoint
    scanner.save_checkpoint(&checkpoint_path)?;
    
    // Verify checkpoint file exists and is valid JSON
    assert!(checkpoint_path.exists());
    let checkpoint_data = fs::read_to_string(&checkpoint_path)?;
    let checkpoint: ScanCheckpoint = serde_json::from_str(&checkpoint_data)?;
    
    assert_eq!(checkpoint.addresses_scanned, 50);
    assert!(checkpoint.current_config_idx > 0);
    
    Ok(())
}

#[test]
fn test_resume_identical_results() -> Result<()> {
    let temp_dir = tempdir()?;
    let checkpoint_path = temp_dir.path().join("scan.checkpoint");
    
    // Run scan with checkpoint at 50%
    let mut scanner1 = StreamingScan::new(configs.clone(), timestamps.clone());
    let results1_partial = scanner1.scan_batch(&addresses[0..50]);
    scanner1.save_checkpoint(&checkpoint_path)?;
    let results1_rest = scanner1.scan_batch(&addresses[50..]);
    let results1_full = [results1_partial, results1_rest].concat();
    
    // Run scan from checkpoint
    let mut scanner2 = StreamingScan::resume_from_checkpoint(&checkpoint_path)?;
    let results2_rest = scanner2.scan_batch(&addresses[50..]);
    let results2_full = [results1_partial.clone(), results2_rest].concat();
    
    // Results must be identical
    assert_eq!(results1_full, results2_full);
    
    Ok(())
}

#[test]
#[cfg(unix)]
fn test_sigterm_graceful_shutdown() -> Result<()> {
    // Spawn scanner process
    // Send SIGTERM
    // Verify checkpoint saved before exit
    // (Implementation uses process spawning and signal handling)
    Ok(())
}
```

**Validation:**
- Test file: `tests/randstorm_checkpoint.rs`
- All checkpoint tests PASS
- Manual test: 30-day scan interrupted and resumed successfully

---

### AC-5: Validated Test Vectors with Citations (BLOCKER-5)

**Priority:** P0  
**Effort:** 8-12 hours (requires research coordination)

**Given** 10 test vectors from Randstorm research  
**When** each vector is tested  
**Then** scanner detects vulnerability correctly AND vector source is documented

**Requirements:**
- ✅ 10 test vectors (minimum) with diversity:
  - Chrome 14 (2011, first vulnerable)
  - Chrome 26 (2013, peak vulnerability)
  - Chrome 35 (2014, different seed pattern)
  - Chrome 45 (2015, last vulnerable)
  - Multiple languages: en-US, ru-RU, zh-CN, es-ES
  - Multiple resolutions: 1366×768, 1920×1080, 1024×768, 2560×1440
  - Edge timestamps: June 1 2011, Dec 31 2014, June 30 2015
- ✅ Each vector MUST have `VectorSource` enum:
  - `ResearchPaper { paper, section, page }`
  - `PublicDisclosure { url, date }`
  - `SyntheticDerived { rationale }` (only for supplementary)
- ✅ Uncited vectors = test failure

**Test Vector Format:**
```rust
pub enum VectorSource {
    ResearchPaper {
        paper: &'static str,
        section: &'static str,
        page: u32,
    },
    PublicDisclosure {
        url: &'static str,
        date: &'static str,
    },
    SyntheticDerived {
        rationale: &'static str,
    },
}

pub struct RandstormTestVector {
    pub description: &'static str,
    pub expected_address: &'static str,
    pub timestamp_ms: u64,
    pub user_agent: &'static str,
    pub screen_width: u32,
    pub screen_height: u32,
    pub color_depth: u8,
    pub timezone_offset: i32,
    pub language: &'static str,
    pub platform: &'static str,
    pub source: VectorSource, // MANDATORY
}

pub const TEST_VECTORS: &[RandstormTestVector] = &[
    RandstormTestVector {
        description: "Chrome 14, first vulnerable version (June 2011)",
        expected_address: "1Chrome14EnUs1366x768...",
        timestamp_ms: 1306886400000, // June 1, 2011
        user_agent: "Chrome/14.0.835.163",
        screen_width: 1366,
        screen_height: 768,
        color_depth: 24,
        timezone_offset: -300,
        language: "en-US",
        platform: "Win32",
        source: VectorSource::ResearchPaper {
            paper: "Randstorm: Cryptanalysis of JavaScript Wallet Generators",
            section: "4.2 Vulnerable Browser Configurations",
            page: 12,
        },
    },
    // ... 9 more vectors
];
```

**Validation:**
- Test file: `src/scans/randstorm/test_vectors.rs` updated
- Integration test: `tests/known_randstorm_vectors.rs` updated
- All 10 vectors have valid `VectorSource`
- All 10 tests PASS
- No synthetic-only vectors (all referenced or derived with rationale)

---

## Definition of Done

- [ ] **AC-1:** 20 end-to-end config tests PASS (4-6 hours)
- [ ] **AC-2:** Performance test asserts ≥50K keys/sec (2 hours)
- [ ] **AC-3:** GPU tests mapped to traceability (1 hour)
- [ ] **AC-4:** 4 checkpoint tests PASS (4-6 hours)
- [ ] **AC-5:** 10 cited test vectors PASS (8-12 hours)
- [ ] **Traceability:** Matrix updated with FULL coverage for all ACs
- [ ] **Red Team Review:** Re-run with all blockers resolved → PASS ✅
- [ ] **CI:** All tests passing in GitHub Actions
- [ ] **Documentation:** README updated with new tests

**Total Effort:** 19-27 hours  
**Expected Coverage:** 100% P0, 100% P1, 100% FULL (all 5 ACs)

---

## Success Metrics

**Before (Story 1.9 Initial):**
- Coverage: 80% (initial), 0% (Red Team)
- Gate Decision: FAIL ❌
- Blockers: 5 critical
- Risk: $32M+ (70-80% probability)

**After (Story 1.9.1):**
- Coverage: 100% P0, 100% FULL
- Gate Decision: PASS ✅
- Blockers: 0
- Risk: LOW (validated cryptographic correctness)

---

## Test Files to Create/Update

**New Files:**
1. `tests/randstorm_comprehensive_configs.rs` - 20 config tests (AC-1)
2. `tests/randstorm_performance.rs` - Performance assertion (AC-2)
3. `tests/randstorm_checkpoint.rs` - 4 checkpoint tests (AC-4)

**Updated Files:**
1. `src/scans/randstorm/test_vectors.rs` - Add VectorSource enum, 10 cited vectors (AC-5)
2. `tests/known_randstorm_vectors.rs` - Use cited vectors (AC-5)
3. `_bmad-output/traceability-matrix-story-1.9.md` - Map GPU tests, update coverage (AC-3)

---

## Risk Assessment

**Impact of NOT Resolving Blockers:**
- Pre-mortem scenario: $32M+ loss, 70-80% probability
- Chrome/46 typo → 127 wallets exploited → class-action lawsuit
- Scanner validates against wrong pattern → false negatives → user funds stolen

**Impact of Resolving Blockers:**
- 1 week of work (19-27 hours)
- $32M+ risk eliminated
- 1,500:1 ROI on doing it right
- Safe production release

---

## Review Follow-ups (AI)

- [ ] [AI-Review][Critical] Implement 20+ end-to-end cryptographic validation tests across diverse configs [tests/randstorm_comprehensive_configs.rs:29]
- [ ] [AI-Review][Critical] Add automated performance assertion (throughput >= 50k keys/sec) to test suite [tests/randstorm_performance.rs]
- [ ] [AI-Review][Critical] Update test vectors with explicit citations to Randstorm research paper [crates/temporal-planetarium-lib/src/scans/randstorm/test_vectors.rs]
- [ ] [AI-Review][Critical] Complete ECC/Hashing implementation in WGPU WGSL kernels [crates/temporal-planetarium-lib/src/scans/randstorm/integration.rs:299]
- [ ] [AI-Review][Medium] Implement integration tests proving checkpoint/resume produces identical results [crates/temporal-planetarium-lib/src/scans/randstorm/checkpoint.rs]
- [ ] [AI-Review][Medium] Fix hardcoded metadata (incorrect year range 2014-2016) in findings [crates/temporal-planetarium-lib/src/scans/randstorm/integration.rs:465]
- [ ] [AI-Review][Medium] Extend address payload extraction to support SegWit (P2WPKH/P2WSH) [crates/temporal-planetarium-lib/src/scans/randstorm/integration.rs:438]
- [ ] [AI-Review][Low] Clean up unused debug print statements and trace logs [crates/temporal-planetarium-lib/src/scans/randstorm/integration.rs:502]

---

## References

- **Parent Story:** `_bmad-output/story-1.9-comprehensive-randstorm.md`
- **Traceability:** `_bmad-output/traceability-matrix-story-1.9.md`
- **Test Guide:** `tests/README.md`
- **Randstorm Paper:** https://eprint.iacr.org/2024/291

---

**Created:** 2025-12-19  
**Status:** ready (pending ATDD test generation)  
**Next Step:** Run `*atdd` workflow to generate failing tests for all 5 ACs
