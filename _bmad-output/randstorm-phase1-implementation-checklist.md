# Randstorm Scanner - Phase 1 Implementation Checklist

**Generated:** 2025-12-22  
**Based On:** PRD v2.1 (coverage-corrected), Tech Spec, Gap Analysis Research  
**Target:** Phase 1 MVP - Chrome V8 MWC1616 Scanner (~29% coverage)

---

## Pre-Implementation Setup

### Documentation Review
- [ ] Read PRD v2.1 completely (1,960 lines, updated coverage model)
- [ ] Read Tech Spec (201 lines, implementation details)
- [ ] Read Gap Analysis Research (1,604 lines, coverage validation)
- [ ] Understand 29% coverage limitation and user expectation management

### Development Environment
- [ ] Rust 1.70+ installed
- [ ] OpenCL development libraries installed (`ocl-icd-opencl-dev` on Ubuntu)
- [ ] GPU drivers installed (NVIDIA/AMD/Intel)
- [ ] Test GPU detection: Run existing `gpu_solver` examples
- [ ] Create feature branch: `git checkout -b feature/randstorm-phase1`

---

## Core Implementation (Stories 1.1 - 1.10)

### Story 1.1: Chrome V8 MWC1616 PRNG Implementation

**Acceptance Criteria (Given/When/Then):**

**AC-1.1.1: MWC1616 PRNG Correctness**
- [ ] Create `src/scans/randstorm/prng/mwc1616.rs`
- [ ] Implement MWC1616 with exact constants: 18000, 30903
- [ ] Create test `tests/prng/test_mwc1616.rs`
- [ ] Test vectors from V8 source: seed (12345, 67890) → 1000 outputs
- [ ] **Given:** Seed values s1=12345, s2=67890
- [ ] **When:** Generate 1000 sequential random numbers
- [ ] **Then:** Output matches Chrome V8 reference bit-for-bit
- [ ] **Verification:** `cargo test test_mwc1616` passes 100%

**AC-1.1.2: Browser Fingerprint Loading**
- [ ] Verify `src/scans/randstorm/fingerprints/data/phase1_top100.csv` exists
- [ ] Create `src/scans/randstorm/fingerprints/database.rs`
- [ ] Implement CSV parsing with schema validation
- [ ] Create test `tests/fingerprints/test_database_loading.rs`
- [ ] **Given:** File `phase1_top100.csv` exists
- [ ] **When:** Scanner initializes and loads fingerprint database
- [ ] **Then:** Exactly 100 fingerprints loaded with all required fields
- [ ] **Verification:** `cargo test test_database_loading` passes

**AC-1.1.3: Synthetic Vulnerable Wallet Detection**
- [ ] Create `tests/fixtures/synthetic_wallets.rs`
- [ ] Implement `generate_synthetic_vulnerable_wallet(fingerprint_id, timestamp_ms)`
- [ ] Generate test wallet: fingerprint_id=5, timestamp_ms=1389744000000
- [ ] Create test `tests/integration/test_synthetic_detection.rs`
- [ ] **Given:** Synthetic vulnerable address with known params
- [ ] **When:** Run `randstorm-scan --targets test.csv --gpu`
- [ ] **Then:** JSON output shows `vulnerable: true, fingerprint_id: 5, timestamp_ms: 1389744000000`
- [ ] **Verification:** `cargo test test_synthetic_detection` passes

**AC-1.1.4: Test Vector Validation (100% Accuracy)**
- [ ] Obtain 10 synthetic vulnerable wallets from Randstorm disclosure
- [ ] Create `tests/integration/test_randstorm_vectors.rs`
- [ ] **Given:** 10 known vulnerable wallets
- [ ] **When:** Scanner processes all 10 addresses
- [ ] **Then:** All 10 detected with correct fingerprint/timestamp
- [ ] **Verification:** `cargo test test_randstorm_vectors` 10/10 pass

**AC-1.1.5: False Positive Rate**
- [ ] Create dataset: 1000 known-secure addresses (Genesis, hardware wallets, post-2015)
- [ ] Create test `tests/integration/test_false_positives.rs`
- [ ] **Given:** 1000 known-secure addresses
- [ ] **When:** Scanner processes all 1000
- [ ] **Then:** Zero false positives (<0.01% = 0/1000)
- [ ] **Verification:** `cargo test test_false_positives` 0 false positives

---

### Story 1.2: GPU Acceleration Implementation

**Acceptance Criteria:**

**AC-1.2.1: GPU Auto-Detection**
- [ ] Create `cl/randstorm_crack.cl` OpenCL kernel
- [ ] Implement `compute_randstorm_crack()` in `src/scans/gpu_solver.rs`
- [ ] Follow `compute_trust_wallet_crack()` pattern
- [ ] Create test `tests/gpu/test_gpu_detection.rs`
- [ ] **Given:** System has GPU with OpenCL support
- [ ] **When:** Scanner starts without --cpu flag
- [ ] **Then:** GPU detected and logged: "✓ GPU detected: [device name] (OpenCL [version])"
- [ ] **Verification:** `cargo test test_gpu_detection` on GPU system

**AC-1.2.2: GPU Performance Baseline**
- [ ] Create benchmark `benches/gpu_performance.rs`
- [ ] Test 1 address: 100 fingerprints × 172,800 timestamps = 17.28M combinations
- [ ] **Given:** Mid-range GPU (RTX 3060 or equivalent)
- [ ] **When:** Scan 1 address with full search space
- [ ] **Then:** Scan completes in ≤30 seconds
- [ ] **Verification:** `cargo bench gpu_performance` on RTX 3060

**AC-1.2.3: GPU Speedup vs CPU**
- [ ] Create benchmark `benches/gpu_vs_cpu.rs`
- [ ] **Given:** Same address scanned on GPU and CPU
- [ ] **When:** Compare execution times for 1M seed combinations
- [ ] **Then:** GPU is ≥10x faster than CPU
- [ ] **Verification:** `cargo bench gpu_vs_cpu` shows 10x+ speedup

**AC-1.2.4: CPU Fallback**
- [ ] Implement CPU fallback with Rayon parallelization
- [ ] Create test `tests/cpu/test_cpu_fallback.rs`
- [ ] **Given:** No GPU available OR --cpu flag
- [ ] **When:** Scanner starts
- [ ] **Then:** Logs "⚠️ GPU unavailable, using CPU fallback" and completes successfully
- [ ] **Verification:** `cargo test test_cpu_fallback` with --no-gpu

**AC-1.2.5: GPU/CPU Parity**
- [ ] Create test `tests/integration/test_gpu_cpu_parity.rs`
- [ ] **Given:** Same CSV input with 10 addresses
- [ ] **When:** Run once with --gpu, once with --cpu
- [ ] **Then:** JSON output files bit-identical
- [ ] **Verification:** `cargo test test_gpu_cpu_parity` diff shows 0 bytes difference

---

### Story 1.3: CLI Interface Implementation

- [ ] Add `RandstormScan` subcommand to `src/main.rs` using clap derive
- [ ] Implement CLI arguments:
  - [ ] `--targets <csv>` (required)
  - [ ] `--phase <1|2|3>` (default: 1)
  - [ ] `--gpu` (default if available)
  - [ ] `--cpu` (force CPU mode)
  - [ ] `--output <file>` (optional JSON/CSV output)
  - [ ] `--timestamp-hint <ms>` (optional, for accuracy)
  - [ ] `--extended-window` (optional, ±7 days instead of ±24h)
- [ ] Implement progress reporting with ETA
- [ ] Display coverage estimate: "Scanning ~29% of potential vulnerable wallets (Chrome V8, Phase 1)"
- [ ] Create integration test `tests/cli/test_cli_interface.rs`

---

### Story 1.4: Address Derivation Implementation

- [ ] Implement secp256k1 private key → public key derivation
- [ ] Implement SHA-256 + RIPEMD-160 → Hash160
- [ ] Implement Base58Check encoding → P2PKH address
- [ ] Follow `bitcoin` crate patterns
- [ ] Create test `tests/derivation/test_address_derivation.rs`
- [ ] Validate against known test vectors

---

### Story 1.5: Timestamp Search Strategy

- [ ] Implement 3-tier timestamp estimation:
  - [ ] Tier 1: RPC blockchain lookup (getaddresstxids → earliest TX)
  - [ ] Tier 2: User-provided --timestamp-hint
  - [ ] Tier 3: Default (current time - 5 years ±24h)
- [ ] Implement ±24h window (172,800 timestamps at 1-second granularity)
- [ ] Optional: Implement ±7 days window (--extended-window flag)
- [ ] Create test `tests/timestamp/test_timestamp_strategy.rs`

---

### Story 1.6: GPU/CPU Bridge Integration

- [ ] Create `src/scans/randstorm.rs` main scanner module
- [ ] Implement fingerprint × timestamp iteration
- [ ] Call `compute_randstorm_crack()` for GPU path
- [ ] Implement Rayon parallel iteration for CPU path
- [ ] Parse result buffer: `Vec<(u32, u64)>` → match list
- [ ] Create integration test `tests/integration/test_gpu_cpu_bridge.rs`

---

### Story 1.7: CSV Input/Output

- [ ] Implement CSV input parsing (headerless or 'address' column)
- [ ] Validate Bitcoin addresses (Base58/Bech32)
- [ ] Reject invalid addresses with line numbers
- [ ] Implement JSON output schema:
```json
{
  "address": "1A1zP1...",
  "vulnerable": false,
  "fingerprint_id": null,
  "timestamp_ms": null,
  "confidence": null,
  "coverage_phase": 1,
  "coverage_estimate": "~29%",
  "coverage_note": "Chrome V8 only. Not found ≠ safe. May be Firefox/Safari/IE (Phase 2+)"
}
```
- [ ] Implement CSV output (same schema, CSV format)
- [ ] Create test `tests/csv/test_csv_io.rs`

---

### Story 1.8: Security Implementation

**GPU Kernel (cl/randstorm_crack.cl):**
- [ ] Private keys in `__local` memory ONLY
- [ ] Keys NEVER transferred to `__global` or CPU
- [ ] Only Hash160 comparison on GPU
- [ ] On match: write `(config_idx, timestamp)` NOT privkey

**CPU Fallback:**
- [ ] Use `zeroize` crate for sensitive buffers
- [ ] Derive → hash160 → compare → zeroize immediately
- [ ] No privkey variables in scope longer than necessary

**Logging:**
- [ ] Use `tracing` crate for structured logging
- [ ] NEVER log privkeys, seeds, ARC4 pool state
- [ ] Redact sensitive data from error messages
- [ ] Create automated test: `grep -r "priv" logs/ target/` returns 0

**Security Audit:**
- [ ] Create test `tests/security/test_key_non_materialization.rs`
- [ ] Verify no key leakage in logs, stdout, stderr
- [ ] Memory dump inspection (manual)

---

### Story 1.9: Testing Suite

**Unit Tests (100+ tests, <30 seconds):**
- [ ] PRNG: MWC1616 state transitions, seeding, determinism (20 tests)
- [ ] Derivation: privkey → pubkey → hash160 → P2PKH (15 tests)
- [ ] Fingerprints: CSV loading, validation, priority sorting (10 tests)
- [ ] Helpers: Timestamp calc, error formatting (10 tests)
- [ ] Total unit tests: 100+

**Integration Tests (20 tests, ~5 minutes):**
- [ ] GPU solver integration (5 tests)
- [ ] CSV parser integration (5 tests)
- [ ] RPC client integration (3 tests)
- [ ] Config loading (3 tests)
- [ ] CLI interface (4 tests)

**End-to-End Tests (5 tests, ~15 minutes):**
- [ ] Full scan: CSV → GPU → JSON output
- [ ] CPU fallback: No GPU → CPU → identical results
- [ ] Batch: 1000 addresses → complete results
- [ ] Errors: Invalid CSV → clear messages
- [ ] Performance: Reference hardware → targets met

**Run all tests:**
- [ ] `cargo test` (all tests pass)
- [ ] `cargo test --features gpu` (GPU tests, may fail in CI)
- [ ] `cargo bench` (performance baselines)

---

### Story 1.10: Documentation

**README Coverage Section:**
- [ ] Add coverage disclaimer (use `randstorm-readme-coverage-disclaimer.md`)
- [ ] Explain 29% Phase 1 limitation
- [ ] "Not found ≠ safe" warning prominent
- [ ] Phase 2 roadmap (52% coverage, Firefox + Safari)

**Usage Guide:**
- [ ] CLI examples
- [ ] Input CSV format
- [ ] Output JSON schema
- [ ] Timestamp estimation strategies
- [ ] Performance expectations (30 sec/address)

**Responsible Disclosure:**
- [ ] Legal warnings (CFAA compliance)
- [ ] Authorized use only
- [ ] No automated fund transfer
- [ ] Key recovery protocol (prove ownership → manual re-derivation)

**SECURITY.md:**
- [ ] Private key handling policy
- [ ] Logging policy (no key materialization)
- [ ] Reporting vulnerabilities

---

## Pre-Release Quality Gates

### Code Quality
- [ ] `cargo fmt` (formatting)
- [ ] `cargo clippy -- -D warnings` (linting, zero warnings)
- [ ] `cargo check` (compilation)
- [ ] No regressions in existing 18 scanners

### Testing
- [ ] All unit tests pass (100+)
- [ ] All integration tests pass (20)
- [ ] All E2E tests pass (5)
- [ ] GPU tests pass on RTX 3060 (or equivalent)
- [ ] 100% detection of 10 Randstorm test vectors
- [ ] 0/1000 false positives on known-secure addresses

### Performance
- [ ] ≥10x GPU speedup vs CPU (validated)
- [ ] <30 seconds per address on RTX 3060
- [ ] 10,000 addresses in <24 hours (batch processing)

### Security
- [ ] Private key non-materialization audit passes
- [ ] `grep -r "priv" logs/ target/` returns 0 matches
- [ ] Memory dump inspection clean
- [ ] zeroize buffers implemented

### Documentation
- [ ] README coverage disclaimer added
- [ ] Usage guide complete
- [ ] SECURITY.md updated
- [ ] Responsible disclosure documented
- [ ] 29% coverage transparency throughout

---

## Release Checklist

### Pre-Release
- [ ] All quality gates passed
- [ ] Version bump: `Cargo.toml` version 0.1.0
- [ ] Changelog updated
- [ ] Git tag created: `v0.1.0-randstorm-phase1`

### Release
- [ ] GitHub release created
- [ ] Release notes: Emphasize 29% coverage, Phase 1 scope
- [ ] Binary artifacts built (Linux, macOS, Windows)
- [ ] Docker image (optional)

### Post-Release
- [ ] Monitor GitHub issues (<48h response)
- [ ] Security issues response (<24h)
- [ ] Community feedback: Coverage expectations met?
- [ ] Plan Phase 2: Firefox + Safari implementation (Q1 2026)

---

## Phase 2 Planning (Future)

**Deferred to Q1 2026:**
- [ ] Firefox SpiderMonkey LCG implementation (+11% coverage)
- [ ] Safari JavaScriptCore Xorshift128+ (+6% coverage)
- [ ] BIP32 HD derivation (+4% coverage)
- [ ] Expand Chrome fingerprints to 200 (+2% coverage)
- [ ] **Target:** 52% total coverage

---

## Critical Success Factors

✅ **Accuracy:** 100% detection of test vectors  
✅ **Transparency:** 29% coverage documented prominently  
✅ **Security:** Zero key materialization (audited)  
✅ **Performance:** 30 sec/address on RTX 3060  
✅ **Quality:** Zero regressions in existing scanners  
✅ **Community:** First open-source Randstorm scanner  

**Remember:** Phase 1 success = Accurate expectations + High quality + Clear roadmap to Phase 2!
