# Test Architecture - Entropy Lab RS

**Project:** Temporal Planetarium (Entropy Lab RS)  
**Test Framework:** Rust built-in (`cargo test`) + Criterion benchmarks  
**Test Count:** 160+ tests (17 integration files, 24 modules with unit tests)  
**Documentation:** Test Architect (Murat)  
**Date:** 2025-12-19

---

## Overview

This project uses a **multi-layered testing strategy** for cryptocurrency vulnerability scanning:

1. **Unit Tests** - Cryptographic primitives, PRNG algorithms, address derivation
2. **Integration Tests** - Scanner pipelines, CLI interface, GPU/CPU parity
3. **Cross-Project Verification** - Validation against external tools (BitcoinJS, Electrum)
4. **Benchmarks** - Performance validation (GPU throughput, streaming efficiency)

**Risk Profile:** HIGH - Handles $60B+ in vulnerable cryptocurrency wallets. Test quality is critical.

---

## Quick Start

### Run All Tests
```bash
# Full test suite (unit + integration)
cargo test

# Unit tests only
cargo test --lib

# Integration tests only
cargo test --test '*'

# Specific test file
cargo test --test randstorm_validation_test

# Specific test function
cargo test test_known_randstorm_vulnerability

# With output (nocapture)
cargo test -- --nocapture

# Parallel execution (default)
cargo test -- --test-threads=8
```

### Run Benchmarks
```bash
# GPU optimization benchmark (requires GPU feature)
cargo bench --features gpu --bench gpu_optimization_benchmark

# Randstorm streaming benchmark
cargo bench --bench randstorm_streaming
```

### Run with Features
```bash
# GPU tests (requires OpenCL)
cargo test --features gpu

# GUI tests
cargo test --features gui

# All features
cargo test --all-features
```

---

## Directory Structure

```
tests/
├── README.md                           # This file
├── fixtures/                           # Test data
│   ├── addresses_p2pkh.csv            # Legacy address fixtures
│   ├── addresses_mixed.csv            # Multi-format addresses
│   ├── addresses_edge_cases.csv       # Boundary conditions
│   └── synthetic_vulnerable_wallets.json  # Randstorm test vectors
│
├── integration/                        # (Empty - using root-level files)
│
├── address_validation.rs               # Bitcoin address format validation
├── cross_project_verification.rs       # External tool cross-validation
├── crypto_pipeline_verification.rs     # End-to-end cryptographic pipeline
├── gpu_cpu_comparison.rs               # GPU vs CPU parity
├── integration_tests.rs                # General integration tests
├── known_randstorm_vectors.rs          # Randstorm vulnerability validation
├── randstorm_cli_integration.rs        # CLI interface tests
├── randstorm_gpu_cpu_parity.rs         # Randstorm GPU/CPU parity
├── randstorm_validation_test.rs        # Randstorm core validation
├── test_bip39_validation.rs            # BIP39 mnemonic validation
├── test_brainwallet_cryptography.rs    # Brainwallet crypto primitives
├── test_cake_wallet_parity.rs          # Cake Wallet scanner validation
├── test_gpu_cpu_parity.rs              # General GPU parity
├── test_hashcat_passphrase_vectors.rs  # Hashcat module validation
├── test_milk_sad_pipeline.rs           # Milk Sad vulnerability tests
├── test_mt19937_vectors.rs             # MT19937 PRNG tests
└── test_trust_wallet.rs                # Trust Wallet scanner validation

src/
├── main.rs                             # CLI entry (no tests)
├── lib.rs                              # Library exports (no tests)
└── scans/
    ├── cake_wallet.rs                  # Unit tests: #[cfg(test)] mod tests
    ├── randstorm/
    │   ├── fingerprints/mod.rs         # Unit tests: 55+ tests
    │   ├── integration.rs              # Unit tests: streaming scan
    │   ├── cli.rs                      # Unit tests: CLI validation
    │   └── ...                         # Unit tests throughout
    └── ...                             # 24 modules with unit tests

benches/
├── gpu_optimization_benchmark.rs       # GPU throughput benchmarks
└── randstorm_streaming.rs              # Streaming efficiency benchmarks
```

---

## Test Organization Patterns

### 1. Unit Tests (Embedded in Source)

**Location:** `src/**/*.rs` with `#[cfg(test)] mod tests { ... }`

**Purpose:** Test individual functions, structs, and cryptographic primitives in isolation.

**Example:**
```rust
// src/scans/randstorm/fingerprints/mod.rs

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_generator_iteration() {
        let gen = TimestampGenerator::new(
            1306886400000, // June 1, 2011
            1435708799000, // June 30, 2015
            3600000,       // 1 hour intervals
        );
        
        let count = gen.count();
        assert!(count > 35000); // ~35K hours
    }
}
```

**Best Practices:**
- ✅ Test one function per test
- ✅ Use descriptive names: `test_<functionality>_<scenario>`
- ✅ Include Given-When-Then in comments if complex
- ✅ Keep tests < 50 lines
- ✅ Use `#[should_panic]` for error cases

### 2. Integration Tests (Standalone Files)

**Location:** `tests/*.rs`

**Purpose:** Test end-to-end workflows, scanner pipelines, CLI interface, cross-module interactions.

**Example:**
```rust
// tests/randstorm_validation_test.rs

use entropy_lab_rs::scans::randstorm::*;

#[test]
fn test_synthetic_vulnerable_wallets_detection() -> Result<()> {
    // Load test vectors from fixtures
    let vectors = load_test_vectors()?;
    
    for vector in vectors {
        // Generate address from test vector
        let address = generate_address_from_test_vector(&vector)?;
        
        // Verify detection
        assert_eq!(detected, vector.expected_behavior.should_detect);
    }
    
    Ok(())
}
```

**Best Practices:**
- ✅ One integration test file per scanner or major feature
- ✅ Use fixtures from `tests/fixtures/`
- ✅ Document test purpose in file header comment
- ✅ Use `Result<()>` for error propagation
- ✅ Add TEST-ID, AC, PRIORITY comments for traceability

### 3. Test Fixtures

**Location:** `tests/fixtures/`

**Purpose:** Shared test data (addresses, test vectors, configurations) used across multiple tests.

**Fixture Types:**
- **CSV:** Bitcoin addresses (P2PKH, P2SH, Bech32)
- **JSON:** Complex test vectors (Randstorm vulnerable wallets)

**Loading Example:**
```rust
fn load_test_vectors() -> Result<Vec<SyntheticVulnerableWallet>> {
    let fixture_path = "tests/fixtures/synthetic_vulnerable_wallets.json";
    let json_data = fs::read_to_string(fixture_path)?;
    let wallets = serde_json::from_str(&json_data)?;
    Ok(wallets)
}
```

**Best Practices:**
- ✅ Use relative paths from project root
- ✅ Version control fixtures (small files only)
- ✅ Document fixture format in README or header comment
- ✅ Use meaningful filenames: `addresses_<type>.csv`

### 4. Benchmarks

**Location:** `benches/*.rs`

**Purpose:** Performance validation, throughput measurement, regression detection.

**Example:**
```rust
// benches/randstorm_streaming.rs

use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_streaming_scan(c: &mut Criterion) {
    c.bench_function("randstorm_streaming_10k", |b| {
        b.iter(|| {
            let scanner = StreamingScan::new(configs, timestamps);
            scanner.scan_batch(black_box(&addresses))
        });
    });
}

criterion_group!(benches, benchmark_streaming_scan);
criterion_main!(benches);
```

**Best Practices:**
- ✅ Use `criterion` for statistical rigor
- ✅ Measure representative workloads (10K addresses)
- ✅ Use `black_box()` to prevent compiler optimizations
- ✅ Set required features: `required-features = ["gpu"]`

---

## Test Categories by Scanner

### Randstorm Scanner
- **Unit Tests:** `src/scans/randstorm/fingerprints/mod.rs` (55 tests)
- **Integration Tests:** `tests/randstorm_*.rs` (5 files)
- **Test Vectors:** `tests/fixtures/synthetic_vulnerable_wallets.json`
- **Benchmarks:** `benches/randstorm_streaming.rs`

### Cake Wallet Scanner
- **Unit Tests:** `src/scans/cake_wallet*.rs` (embedded)
- **Integration Tests:** `tests/test_cake_wallet_parity.rs`

### Trust Wallet Scanner
- **Unit Tests:** `src/scans/trust_wallet.rs` (embedded)
- **Integration Tests:** `tests/test_trust_wallet.rs`
- **Test Vectors:** `tests/test_mt19937_vectors.rs`

### Milk Sad Scanner
- **Unit Tests:** `src/scans/milk_sad.rs` (embedded)
- **Integration Tests:** `tests/test_milk_sad_pipeline.rs`

### Brainwallet Scanner
- **Unit Tests:** `src/scans/brainwallet.rs` (embedded)
- **Integration Tests:** `tests/test_brainwallet_cryptography.rs`
- **Test Vectors:** `tests/test_hashcat_passphrase_vectors.rs`

### GPU Acceleration
- **Unit Tests:** `src/scans/*/gpu_integration.rs` (embedded)
- **Integration Tests:** `tests/gpu_cpu_*.rs` (3 files)
- **Benchmarks:** `benches/gpu_optimization_benchmark.rs`

---

## Test Quality Standards

Based on Red Team analysis from Story 1.9 traceability review:

### For Security-Critical Code (Cryptographic Operations)

**MANDATORY Requirements:**
1. ✅ **End-to-end cryptographic validation** - Test full pipeline, not just structure
2. ✅ **Cited test vectors** - Reference source (Randstorm paper, BIP specs)
3. ✅ **Adversarial test cases** - Wrong inputs, corrupted data, edge cases
4. ✅ **Performance assertions** - Validate throughput meets requirements
5. ✅ **GPU/CPU parity** - Verify identical outputs across execution modes

**Example (GOOD):**
```rust
#[test]
fn test_known_randstorm_vulnerability() {
    // CITED: Randstorm paper Appendix B, Table 3
    let vector = TEST_VECTORS[0];
    
    // End-to-end: config → PRNG → private key → address
    let address = derive_address_from_vector(&vector);
    
    // Cryptographic correctness validation
    assert_eq!(address, vector.expected_address);
}
```

**Example (BAD - Caught by Red Team):**
```rust
#[test]
fn test_comprehensive_database_loads() {
    let db = FingerprintDatabase::load_comprehensive();
    assert!(db.configs.len() >= 240); // ❌ Only checks structure, not correctness
}
```

### Test Naming Convention

**Format:** `test_<feature>_<scenario>_<expected_outcome>`

**Examples:**
- ✅ `test_timestamp_generator_iteration_returns_correct_count`
- ✅ `test_chrome_v8_prng_deterministic_output`
- ✅ `test_cli_scan_file_not_found_returns_error`
- ❌ `test_1` (too vague)
- ❌ `test_it_works` (meaningless)

### Test Documentation

**For Integration Tests:**
```rust
//! Randstorm Validation Tests
//!
//! Validates the Randstorm scanner against synthetic vulnerable wallets
//! based on the Unciphered "Randstorm" disclosure (November 2023).
//!
//! Test Strategy:
//! - Generate Bitcoin addresses from known-weak seeds
//! - Verify scanner detects them correctly
//! - Validate 95%+ confidence without real-world test vectors

// TEST-ID: 1.9-INTEGRATION-001
// AC: AC-5 (Known Vulnerability Detection)
// PRIORITY: P0
#[test]
fn test_known_randstorm_vulnerability() { ... }
```

### Test Isolation

**Each test must:**
- ✅ Run independently (no shared state)
- ✅ Clean up resources (temp files, network connections)
- ✅ Not depend on execution order
- ✅ Be deterministic (same input → same output)

**Example (Cleanup):**
```rust
#[test]
fn test_checkpoint_save_load() -> Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let checkpoint_path = temp_dir.path().join("checkpoint.json");
    
    // ... test logic ...
    
    // Automatic cleanup when temp_dir goes out of scope
    Ok(())
}
```

---

## CI/CD Integration

### GitHub Actions Configuration

**File:** `.github/workflows/ci.yml`

```yaml
test:
  runs-on: ubuntu-latest
  steps:
    - name: Checkout
      uses: actions/checkout@v4
    
    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: stable
    
    - name: Install OpenCL (for GPU tests)
      run: sudo apt-get install -y ocl-icd-opencl-dev
    
    - name: Run tests
      run: cargo test --lib --verbose
      continue-on-error: true  # GPU tests may fail in CI
    
    - name: Run benchmarks (smoke test)
      run: cargo bench --no-run  # Compile only, don't execute
```

**Why `continue-on-error: true`?**
- GPU tests require OpenCL runtime
- CI runners may not have GPU hardware
- Unit tests validate logic; integration tests validate hardware

### Test Execution Strategy

**Local Development:**
```bash
# Fast feedback loop
cargo test --lib  # Unit tests only (~5s)

# Pre-commit check
cargo test  # All tests (~30s)

# Full validation
cargo test --all-features  # GPU + GUI tests (~60s)
```

**CI Pipeline:**
```bash
# Check compilation
cargo check

# Test (with OpenCL tolerance)
cargo test --lib

# Clippy (warnings)
cargo clippy -- -W clippy::all

# Format check (blocking)
cargo fmt --check

# Security audit
cargo audit
```

---

## Common Patterns

### 1. Testing Cryptographic Derivation

```rust
use secp256k1::{Secp256k1, SecretKey};
use crate::derivation::derive_p2pkh_address;

#[test]
fn test_address_derivation_deterministic() {
    let secp = Secp256k1::new();
    let key_bytes = [1u8; 32];
    let secret_key = SecretKey::from_slice(&key_bytes).unwrap();
    let public_key = secret_key.public_key(&secp);
    
    // Derive address twice
    let addr1 = derive_p2pkh_address(&public_key);
    let addr2 = derive_p2pkh_address(&public_key);
    
    // Must be deterministic
    assert_eq!(addr1, addr2);
    
    // Must be valid P2PKH format
    assert!(addr1.starts_with('1'));
    assert!(addr1.len() >= 26 && addr1.len() <= 35);
}
```

### 2. Testing PRNG Algorithms

```rust
use crate::scans::randstorm::prng::{ChromeV8Prng, PrngEngine};

#[test]
fn test_mwc1616_prng_deterministic() {
    let prng = ChromeV8Prng::new();
    
    let seed = SeedComponents {
        timestamp_ms: 1366070400000,
        user_agent: "Chrome/26".to_string(),
        screen_width: 1366,
        screen_height: 768,
        // ... other fields
    };
    
    let state = prng.generate_state(&seed);
    let bytes1 = prng.generate_bytes(&state, 32);
    let bytes2 = prng.generate_bytes(&state, 32);
    
    // PRNG must be deterministic
    assert_eq!(bytes1, bytes2);
}
```

### 3. Testing CLI Interface

```rust
use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_cli_help_comprehensive() {
    let mut cmd = Command::cargo_bin("entropy-lab-rs").unwrap();
    
    cmd.arg("randstorm-scan").arg("--help");
    
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Randstorm"))
        .stdout(predicate::str::contains("--target-addresses"));
}
```

### 4. Testing GPU/CPU Parity

```rust
#[test]
#[cfg(feature = "gpu")]
fn test_gpu_cpu_identical_results() {
    let addresses = vec!["1A1zP1...", "12cbQL..."];
    
    // CPU scan
    let cpu_results = scan_cpu(&addresses);
    
    // GPU scan
    let gpu_results = scan_gpu(&addresses);
    
    // Results must be identical
    assert_eq!(cpu_results, gpu_results);
}
```

### 5. Loading Test Fixtures

```rust
use std::fs;
use serde::Deserialize;

#[derive(Deserialize)]
struct TestVector {
    description: String,
    expected_address: String,
    // ... fields
}

fn load_test_vectors() -> Vec<TestVector> {
    let fixture_path = "tests/fixtures/synthetic_vulnerable_wallets.json";
    let json_data = fs::read_to_string(fixture_path)
        .expect("Failed to read test fixture");
    serde_json::from_str(&json_data)
        .expect("Failed to parse test fixture")
}
```

---

## Troubleshooting

### OpenCL Tests Failing

**Error:** `OpenCL platform not found`

**Solution:**
```bash
# Ubuntu/Debian
sudo apt-get install ocl-icd-opencl-dev

# macOS (built-in OpenCL)
# No action needed

# Skip GPU tests
cargo test --lib  # Unit tests only
```

### Test Timeouts

**Error:** `test took too long`

**Solution:**
- Reduce test data size (use smaller fixtures)
- Mark long tests with `#[ignore]`: `cargo test -- --ignored`
- Increase timeout (not recommended)

### Flaky Tests

**Symptoms:** Tests pass/fail randomly

**Common Causes:**
- Shared mutable state
- Race conditions
- Timing dependencies
- Non-deterministic randomness

**Solution:**
- Use `rand::SeedableRng::seed_from_u64(0)` for deterministic randomness
- Avoid `std::thread::sleep` in tests
- Clean up shared resources (temp files, network)

### Test Vector Mismatches

**Error:** `Expected address X, got Y`

**Debugging:**
```rust
#[test]
fn test_debug_derivation() {
    let address = derive_address(&vector);
    
    println!("Expected: {}", vector.expected_address);
    println!("Got: {}", address);
    println!("Seed: {:?}", vector.seed);
    
    // Run with: cargo test -- --nocapture
}
```

---

## Performance Benchmarks

### Current Performance Targets

From traceability analysis (Story 1.9):

**Requirement:** ≥50,000 keys/sec (AC-3)

**Actual Performance:**
- Run: `cargo bench --bench randstorm_streaming`
- Check output for throughput metrics

**If below 50K keys/sec:**
- Verify GPU feature enabled: `--features gpu`
- Check GPU kernel optimizations
- Review batch sizing (10K fingerprints per batch)

---

## Knowledge Base References

From Test Architect (TEA) knowledge base:

### Core Testing Principles
- **test-quality.md** - Deterministic, isolated, explicit assertions, length/time limits
- **fixture-architecture.md** - Pure functions, auto-cleanup patterns
- **data-factories.md** - Faker-based factories (web apps) vs hardcoded fixtures (CLI)

### Domain-Specific (Security/Crypto)
- **Red Team Review** - Mandatory for security-critical stories
- **End-to-end cryptographic validation** - Structure ≠ Correctness
- **Cited test vectors** - Reference authoritative sources (research papers, BIPs)

### Process Improvements (from Story 1.9 Lessons Learned)
- **5 Whys Root Cause:** Testing strategy developed in isolation → domain expertise gap
- **Pre-mortem Risk Assessment:** $32M+ impact if validation gaps ignored
- **Mandatory Red Team Review:** For `vulnerability`, `cryptography`, `security` tags

---

## Next Steps

### For New Features

1. **Write tests first** (ATDD workflow: `*atdd`)
2. **Implement feature**
3. **Validate end-to-end** (not just structure)
4. **Add cited test vectors** (reference sources)
5. **Run Red Team review** (adversarial testing)
6. **Update traceability matrix** (`*trace` workflow)

### For Existing Code

1. **Review Story 1.9 blockers** (5 critical gaps identified)
2. **Add end-to-end cryptographic validation** (20+ test vectors)
3. **Map GPU tests to traceability** (already exist, just document)
4. **Add performance assertions** (`assert!(throughput >= 50_000)`)
5. **Cite test vector sources** (Randstorm paper references)

### For Documentation

1. **This README** - Test organization guide ✅
2. **Individual test file headers** - Purpose, strategy, references
3. **Fixture documentation** - Format, source, update procedures
4. **Benchmark reports** - Performance baselines, regression tracking

---

## Resources

### Internal Documentation
- `_bmad-output/traceability-matrix-story-1.9.md` - Coverage analysis
- `project-context.md` - Project overview
- `CONTRIBUTING.md` - Development guidelines
- `SECURITY.md` - Responsible disclosure

### External References
- [Rust Book - Testing](https://doc.rust-lang.org/book/ch11-00-testing.html)
- [Criterion.rs Documentation](https://bheisler.github.io/criterion.rs/book/)
- [assert_cmd Documentation](https://docs.rs/assert_cmd/)
- [Randstorm Paper](https://eprint.iacr.org/2024/291) - Test vector source

---

**Test Architect:** Murat  
**Last Updated:** 2025-12-19  
**Next Review:** After Story 1.9.1 blocker resolution

**Quality Mantra:** *"For security-critical systems, passing tests ≠ correct behavior. End-to-end cryptographic validation is mandatory, not optional."*

---
