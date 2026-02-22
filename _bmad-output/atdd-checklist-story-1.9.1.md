# ATDD Checklist - Story 1.9.1 Blocker Resolution

**Story:** 1.9.1 - Randstorm Scanner Blocker Resolution  
**Generated:** 2025-12-19  
**Test Architect:** Murat  
**Status:** 🔴 RED (All tests failing - implementation pending)

---

## ATDD Cycle: Red → Green → Refactor

**Current Phase:** 🔴 **RED** (Tests written, all failing)

**Next Steps:**
1. Run tests: `cargo test --test randstorm_* -- --ignored --nocapture`
2. Verify all tests FAIL (expected in RED phase)
3. Implement features to make tests PASS (GREEN phase)
4. Refactor with confidence (tests protect against regressions)

---

## Test Files Created

### ✅ AC-1: End-to-End Cryptographic Validation
**File:** `tests/randstorm_comprehensive_configs.rs`  
**Tests:** 5 (of 20 required)  
**Status:** 🔴 FAILING (marked `#[ignore]`)

**Tests Created:**
- `test_config_chrome_14_en_us_1024x768_end_to_end()` - First vulnerable version
- `test_config_chrome_26_en_us_1366x768_end_to_end()` - Peak vulnerability  
- `test_config_chrome_46_ru_ru_1920x1080_end_to_end()` - **Critical: Chrome 46 typo prevention**
- `test_config_chrome_35_zh_cn_1920x1080_end_to_end()` - Chinese language
- `test_config_chrome_45_es_es_2560x1440_end_to_end()` - Last vulnerable version

**TODO to reach GREEN:**
- [ ] Obtain 20 test vectors from Randstorm research (cited sources)
- [ ] Replace `PLACEHOLDER` addresses with actual expected values
- [ ] Implement helper: `derive_address_from_fingerprint()`
- [ ] Add 15 more test vectors (Chrome 20, 40, 48, pt-BR, macOS, Linux, Android, iOS)
- [ ] Remove `#[ignore]` attribute
- [ ] Run: `cargo test --test randstorm_comprehensive_configs`
- [ ] Verify all 20 tests PASS

---

### ✅ AC-2: Performance Requirement Validated
**File:** `tests/randstorm_performance.rs`  
**Tests:** 3  
**Status:** 🔴 FAILING (marked `#[ignore]`, requires GPU feature)

**Tests Created:**
- `test_randstorm_meets_50k_keys_per_second_requirement()` - **CRITICAL: ≥50K keys/sec**
- `test_randstorm_gpu_vs_cpu_throughput_ratio()` - GPU ≥10x faster than CPU
- `test_randstorm_cpu_baseline_performance()` - CPU ≥5K keys/sec

**TODO to reach GREEN:**
- [ ] Implement GPU scanner integration: `RandstormScanner::new_gpu()`
- [ ] Implement `scan_batch()` method
- [ ] Remove `std::thread::sleep()` simulation
- [ ] Run with GPU: `cargo test --features gpu --test randstorm_performance -- --ignored`
- [ ] Verify performance meets ≥50K keys/sec threshold
- [ ] Remove `#[ignore]` attribute
- [ ] Update benchmark: `cargo bench --bench randstorm_streaming`

---

### ❌ AC-3: GPU Tests Mapped to Traceability
**File:** *Documentation update only (no new tests)*  
**Status:** 🟡 PENDING

**TODO to reach GREEN:**
- [ ] Update `_bmad-output/traceability-matrix-story-1.9.md`
- [ ] Add section mapping existing GPU tests to AC-3:
  - `tests/test_gpu_cpu_parity.rs`
  - `tests/randstorm_gpu_cpu_parity.rs`
- [ ] Document GPU kernel validation approach
- [ ] Re-run Red Team review with GPU tests included
- [ ] Update coverage: AC-3 PARTIAL → FULL

---

### ✅ AC-4: Checkpoint/Resume Tests
**File:** `tests/randstorm_checkpoint.rs`  
**Tests:** 5  
**Status:** 🔴 FAILING (marked `#[ignore]`)

**Tests Created:**
- `test_checkpoint_save_load()` - Save and load checkpoint file
- `test_resume_identical_results()` - **CRITICAL: Identical results after resume**
- `test_sigterm_graceful_shutdown()` - SIGTERM saves checkpoint (Unix only)
- `test_checkpoint_corruption_handling()` - Graceful error handling
- `test_checkpoint_automatic_interval()` - Auto-checkpoint every 5 minutes

**TODO to reach GREEN:**
- [ ] Implement `StreamingScan::save_checkpoint()`
- [ ] Implement `StreamingScan::resume_from_checkpoint()`
- [ ] Add checkpoint data structure (JSON serialization)
- [ ] Implement SIGTERM signal handler (Unix)
- [ ] Remove simulation code (replace with real implementation)
- [ ] Remove `#[ignore]` attribute
- [ ] Run: `cargo test --test randstorm_checkpoint -- --ignored`
- [ ] Verify all tests PASS

---

### ❌ AC-5: Validated Test Vectors with Citations
**File:** *Update existing: `src/scans/randstorm/test_vectors.rs`*  
**Status:** 🟡 PENDING

**TODO to reach GREEN:**
- [ ] Define `VectorSource` enum:
  ```rust
  pub enum VectorSource {
      ResearchPaper { paper: &'static str, section: &'static str, page: u32 },
      PublicDisclosure { url: &'static str, date: &'static str },
      SyntheticDerived { rationale: &'static str },
  }
  ```
- [ ] Add `source: VectorSource` field to `RandstormTestVector`
- [ ] Update existing test vector with citation
- [ ] Add 9 more test vectors (10 total minimum)
- [ ] Ensure diversity: Chrome 14/26/35/45, en-US/ru-RU/zh-CN/es-ES, various resolutions
- [ ] Update `tests/known_randstorm_vectors.rs` to use cited vectors
- [ ] Run: `cargo test --test known_randstorm_vectors`
- [ ] Verify all tests PASS

---

## Implementation Order (Recommended)

### Priority 1: Quick Wins (3-4 hours)
1. **AC-3:** Update traceability matrix (1 hour)
2. **AC-5:** Add `VectorSource` enum and update 1 test vector (2-3 hours)

### Priority 2: Core Functionality (8-12 hours)
3. **AC-4:** Implement checkpoint/resume (4-6 hours)
4. **AC-2:** Integrate GPU scanner and validate performance (4-6 hours)

### Priority 3: Comprehensive Coverage (4-6 hours)
5. **AC-1:** Obtain and add 20 test vectors (4-6 hours, requires research coordination)

**Total Estimated Effort:** 19-27 hours (matches Story 1.9.1 estimate)

---

## Running Tests

### Run All ATDD Tests (will fail initially)
```bash
# All new tests (marked #[ignore])
cargo test --test randstorm_comprehensive_configs -- --ignored
cargo test --test randstorm_performance -- --ignored --features gpu
cargo test --test randstorm_checkpoint -- --ignored

# Check test compilation
cargo test --no-run
```

### Expected Output (RED Phase)
```
running 5 tests
test test_config_chrome_14_en_us_1024x768_end_to_end ... FAILED
test test_config_chrome_26_en_us_1366x768_end_to_end ... FAILED
test test_config_chrome_46_ru_ru_1920x1080_end_to_end ... FAILED
test test_config_chrome_35_zh_cn_1920x1080_end_to_end ... FAILED
test test_config_chrome_45_es_es_2560x1440_end_to_end ... FAILED

failures: 5
```

**This is EXPECTED and CORRECT in the RED phase!**

---

## Transition to GREEN Phase

### For Each Test:
1. **Implement minimum code** to make test pass
2. **Run test:** `cargo test <test_name> -- --ignored --nocapture`
3. **Verify PASS:** Green checkmark ✅
4. **Remove `#[ignore]`:** Test becomes part of standard suite
5. **Commit:** `git commit -m "GREEN: test_<name> passing"`

### When All Tests Pass:
- Update Story 1.9.1 status: 🔴 blocked → 🟢 ready
- Update traceability matrix: 0% FULL → 100% FULL
- Re-run Red Team review: FAIL → PASS
- Create PR with all tests passing

---

## Traceability Update

After reaching GREEN phase, update `_bmad-output/traceability-matrix-story-1.9.md`:

**Before (Story 1.9):**
```yaml
coverage:
  overall: 0%
  p0: 0%
status: "FAIL"
blocker_gaps: 5
```

**After (Story 1.9.1 complete):**
```yaml
coverage:
  overall: 100%
  p0: 100%
status: "PASS"
blocker_gaps: 0
```

---

## Definition of Done Checklist

- [ ] **AC-1:** 20 end-to-end config tests PASS
- [ ] **AC-2:** Performance test asserts ≥50K keys/sec PASS
- [ ] **AC-3:** GPU tests mapped in traceability matrix
- [ ] **AC-4:** 5 checkpoint tests PASS
- [ ] **AC-5:** 10 cited test vectors PASS
- [ ] All `#[ignore]` attributes removed
- [ ] `cargo test` runs all tests (no failures)
- [ ] `cargo test --features gpu` validates GPU performance
- [ ] Traceability matrix updated with FULL coverage
- [ ] Red Team review re-run: PASS ✅
- [ ] PR created with all tests passing

---

## Resources

**Story Documentation:**
- Story: `_bmad-output/story-1.9.1-blocker-resolution.md`
- Traceability: `_bmad-output/traceability-matrix-story-1.9.md`
- Test Guide: `tests/README.md`

**Test Files:**
- `tests/randstorm_comprehensive_configs.rs` (AC-1)
- `tests/randstorm_performance.rs` (AC-2)
- `tests/randstorm_checkpoint.rs` (AC-4)
- `src/scans/randstorm/test_vectors.rs` (AC-5 - update)

**References:**
- Randstorm Paper: https://eprint.iacr.org/2024/291
- BIP32 Spec: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
- Rust Testing: https://doc.rust-lang.org/book/ch11-00-testing.html

---

**ATDD Workflow Complete: RED Phase**  
**Next Action:** Implement features to make tests PASS (GREEN phase)  
**Test Architect:** Murat 🧪

---
