# CI/CD Pipeline Documentation - Entropy Lab RS

**Project:** Temporal Planetarium (Entropy Lab RS)  
**CI Platform:** GitHub Actions  
**Updated:** 2025-12-19  
**Architect:** Murat (Test Architect)

---

## Overview

This project uses **GitHub Actions** for continuous integration with the following strategies:
1. **Multi-stage pipeline** - Fast feedback loop (check → test → quality → build)
2. **Parallel execution** - Unit, integration, GPU tests run concurrently
3. **ATDD support** - Story 1.9.1 blocker tests tracked in CI
4. **Burn-in loop** - Weekly flaky test detection
5. **Quality gates** - Block PRs until blockers resolved

---

## Workflows

### Primary: `test-enhanced.yml` (Story 1.9.1 Support)

**File:** `.github/workflows/test-enhanced.yml`

**Stages:**
1. ✅ **Check** - `cargo check --all-targets --all-features` (~1 min)
2. ✅ **Unit Tests** - `cargo test --lib` (~3 min)
3. ✅ **Integration Tests** - `cargo test --test '*'` + ATDD tests (~5 min)
4. ⚠️ **GPU Tests** - `cargo test --features gpu` (conditional, may fail)
5. ✅ **Benchmarks** - Compile-only smoke test (~2 min)
6. ✅ **Code Quality** - `rustfmt`, `clippy`, `cargo audit` (~2 min)
7. ✅ **Build Release** - `cargo build --release` (~4 min)
8. 🔥 **Burn-In Loop** - 10 iterations (weekly or on-demand)
9. 📊 **Quality Gate** - Block PR if blockers unresolved

**Total Time:** ~20 minutes (parallel execution)

**Triggers:**
- `push` to `main` or `develop`
- `pull_request` to `main` or `develop`
- `schedule`: Weekly on Sundays at 00:00 UTC (burn-in)
- Manual: Commit message contains `[burn-in]`

---

### Legacy: `ci.yml` (Original)

**File:** `.github/workflows/ci.yml`

**Stages:**
1. Check
2. Test Suite (`continue-on-error: true` for GPU)
3. Rustfmt
4. Clippy
5. Security Audit
6. Build Release

**Status:** ✅ Active (can coexist with enhanced pipeline)

**Recommendation:** Migrate to `test-enhanced.yml` for Story 1.9.1 support, then archive `ci.yml`

---

## CI Stages Explained

### Stage 1: Check
**Command:** `cargo check --all-targets --all-features`  
**Purpose:** Fast compilation check without running tests  
**Time:** ~1 minute  
**Caching:** Cargo registry + index

**Fails if:**
- Compilation errors
- Missing dependencies
- Syntax errors

---

### Stage 2: Unit Tests
**Command:** `cargo test --lib --verbose`  
**Purpose:** Run embedded unit tests (`#[cfg(test)] mod tests`)  
**Time:** ~3 minutes  
**Caching:** Dependencies + build artifacts

**Covers:**
- 24 modules with unit tests
- PRNG algorithms
- Address derivation
- Fingerprint generation
- 55+ Randstorm tests

**Fails if:**
- Any unit test fails
- Assertion failures
- Panics

**Artifacts on failure:** `unit-test-failures` (target/debug/, 7 days)

---

### Stage 3: Integration Tests
**Command:** `cargo test --test '*' --verbose`  
**Purpose:** Run standalone integration tests (`tests/*.rs`)  
**Time:** ~5 minutes  
**Caching:** Dependencies + build artifacts

**Includes:**
- 17 integration test files
- Cross-project verification
- Crypto pipeline validation
- CLI interface tests

**ATDD Tests (Story 1.9.1):**
```bash
# Currently marked #[ignore] - expected to fail (RED phase)
cargo test --test randstorm_comprehensive_configs -- --ignored --nocapture
cargo test --test randstorm_checkpoint -- --ignored --nocapture
```

**Status:** 🔴 RED (13 tests failing - implementation pending)

**Fails if:**
- Integration tests fail
- CLI tests fail
- Fixture loading errors

**Artifacts on failure:** `integration-test-results` (target/debug/, 7 days)

---

### Stage 4: GPU Tests (Conditional)
**Command:** `cargo test --features gpu --verbose`  
**Purpose:** Validate GPU acceleration and CPU/GPU parity  
**Time:** ~3 minutes (if GPU available)  
**Status:** ⚠️ `continue-on-error: true` (GPU not guaranteed in CI)

**Tests:**
- `tests/test_gpu_cpu_parity.rs`
- `tests/randstorm_gpu_cpu_parity.rs`
- GPU kernel validation

**OpenCL Setup:**
```bash
sudo apt-get install -y ocl-icd-opencl-dev pocl-opencl-icd
```

**Fails if:**
- GPU/CPU results differ
- OpenCL initialization errors
- Kernel compilation errors

**Note:** Red Team identified these tests as **UNMAPPED** in traceability (BLOCKER-3). Story 1.9.1 will map them to AC-3.

**Artifacts on failure:** `gpu-test-results` (target/debug/, 7 days)

---

### Stage 5: Benchmarks (Smoke Test)
**Command:** `cargo bench --no-run --verbose`  
**Purpose:** Verify benchmarks compile without executing them  
**Time:** ~2 minutes  
**Caching:** Release build artifacts

**Benchmarks:**
- `benches/gpu_optimization_benchmark.rs`
- `benches/randstorm_streaming.rs`

**Why compile-only:**
- CI runners lack GPU hardware for realistic perf tests
- Actual benchmarks run locally: `cargo bench --bench randstorm_streaming`
- Story 1.9.1 BLOCKER-2 requires ≥50K keys/sec validation

**Fails if:**
- Benchmark code doesn't compile
- Missing dependencies

**Artifacts on success:** `benchmark-binaries` (target/release/deps/, 7 days)

---

### Stage 6: Code Quality

#### Rustfmt
**Command:** `cargo fmt --all -- --check`  
**Purpose:** Enforce consistent code formatting  
**Time:** ~30 seconds

**Fails if:**
- Code not formatted per Rust style guide
- Use `cargo fmt` to auto-fix

#### Clippy
**Command:** `cargo clippy --all-targets --all-features -- -W clippy::all`  
**Purpose:** Linting and best practice enforcement  
**Time:** ~2 minutes

**Note:** Uses `-W` (warn) not `-D` (deny) - warnings don't block build  
**Story 1.9 CI:** Currently reports warnings, doesn't block

**Common warnings:**
- Unused variables
- Inefficient code patterns
- Potential bugs

#### Security Audit
**Command:** `cargo audit`  
**Purpose:** Check dependencies for known vulnerabilities  
**Time:** ~1 minute  
**Status:** `continue-on-error: true` (advisories reported, don't block)

**Fails if (strict mode):**
- Known CVEs in dependencies
- Yanked crates
- Unsound dependencies

---

### Stage 7: Build Release
**Command:** `cargo build --release --verbose`  
**Purpose:** Produce optimized binary for distribution  
**Time:** ~4 minutes  
**Caching:** Release build artifacts

**Dependencies:**
- ✅ Check passed
- ✅ Unit tests passed
- ✅ Integration tests passed
- ✅ Rustfmt passed
- ✅ Clippy passed

**Artifacts on success:** `entropy-lab-rs-<commit-sha>` (30 days)

**Binary:** `target/release/entropy-lab-rs`

---

### Stage 8: Burn-In Loop (Weekly)
**Command:** `for i in {1..10}; do cargo test --lib; done`  
**Purpose:** Detect flaky (non-deterministic) tests  
**Time:** ~30 minutes (10 iterations)  
**Trigger:** 
- Weekly schedule (Sundays 00:00 UTC)
- Commit message contains `[burn-in]`

**Why 10 iterations:**
- Catches flaky tests with ~10% failure rate
- 10 iterations = 99.9% confidence for 50% flaky test

**Fails if:**
- Any iteration fails
- Different results across runs (non-deterministic)

**Flaky test causes:**
- Race conditions
- Timing dependencies
- Shared mutable state
- Non-deterministic randomness

**Artifacts on failure:** `burn-in-failures` (target/debug/, 30 days)

---

### Stage 9: Quality Gate (Story 1.9.1)
**Command:** Check blocker status and fail if unresolved  
**Purpose:** Prevent PR merge until blockers resolved  
**Time:** ~10 seconds  
**Trigger:** Pull requests only

**Current Status:**
```
- BLOCKER-1: End-to-end crypto validation (5 tests) - 🔴 RED
- BLOCKER-2: Performance validation (3 tests) - 🔴 RED
- BLOCKER-3: GPU tests mapped - 🟡 PENDING
- BLOCKER-4: Checkpoint/resume (5 tests) - 🔴 RED
- BLOCKER-5: Test vectors cited - 🟡 PENDING
```

**Gate PASSES when:**
- All 13 ATDD tests PASS (no `#[ignore]`)
- Traceability matrix updated: 0% → 100% FULL
- Red Team review: FAIL → PASS

**Status:** `continue-on-error: true` (allows PR for visibility)  
**Recommendation:** Set to `false` when blockers resolved

---

## Caching Strategy

**What's cached:**
1. **Cargo registry** - Downloaded crates (`~/.cargo/registry`)
2. **Cargo index** - Crate metadata (`~/.cargo/git`)
3. **Build artifacts** - Compiled dependencies (`target/`)

**Cache keys:**
- `${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}`

**Benefits:**
- 2-5 minute reduction per run
- Faster PR feedback loop
- Reduced CI credits usage

**Cache invalidation:**
- `Cargo.lock` changes
- OS changes (unlikely)
- Manual cache clear (Settings → Actions → Caches)

---

## Running CI Locally

### Full test suite
```bash
# Mimic CI environment
cargo check --all-targets --all-features
cargo test --lib --verbose
cargo test --test '*' --verbose
cargo test --features gpu --verbose  # If GPU available
cargo bench --no-run --verbose
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -W clippy::all
cargo audit
cargo build --release --verbose
```

### Quick feedback loop
```bash
# Fastest CI checks (~5 min)
cargo check && cargo test --lib
```

### ATDD tests (Story 1.9.1)
```bash
# Run failing tests (RED phase)
cargo test --test randstorm_comprehensive_configs -- --ignored --nocapture
cargo test --test randstorm_performance -- --ignored --features gpu --nocapture
cargo test --test randstorm_checkpoint -- --ignored --nocapture

# Check compilation
cargo test --no-run
```

---

## Troubleshooting

### Tests fail in CI but pass locally
**Cause:** Environment differences (OpenCL, GPU, timing)

**Solution:**
1. Check CI logs for specific error
2. Run locally with same conditions: `cargo test --lib --verbose`
3. Check `continue-on-error: true` jobs (GPU tests)

### OpenCL tests fail
**Error:** `OpenCL platform not found`

**Solution:**
- CI: Expected (no GPU hardware) - `continue-on-error: true` handles this
- Local: Install OpenCL runtime (`ocl-icd-opencl-dev`)

### Benchmark compilation fails
**Error:** Missing dependencies

**Solution:**
1. Check `Cargo.toml` for `[[bench]]` entries
2. Verify `criterion` version compatibility
3. Run locally: `cargo bench --no-run`

### Cache not working
**Symptom:** CI always installs dependencies from scratch

**Solution:**
1. Verify `Cargo.lock` is committed
2. Check cache key matches: `hashFiles('**/Cargo.lock')`
3. Clear and rebuild cache (Settings → Actions → Caches)

### Quality gate blocks PR
**Error:** `❌ Quality gate: FAIL (blockers unresolved)`

**Solution:**
1. Review `_bmad-output/traceability-matrix-story-1.9.md`
2. Resolve 5 blockers (Story 1.9.1)
3. Remove `#[ignore]` from ATDD tests when passing
4. Update quality gate check in `test-enhanced.yml`

---

## Migration Guide

### From `ci.yml` to `test-enhanced.yml`

**Step 1:** Test enhanced pipeline on branch
```bash
git checkout -b ci-enhancement
# Commit already created test-enhanced.yml
git push origin ci-enhancement
```

**Step 2:** Verify all stages pass
- Check GitHub Actions tab
- Review artifacts
- Confirm quality gate behavior

**Step 3:** Update branch protection rules
- Settings → Branches → Branch protection rules
- Add required checks:
  - `Check`
  - `Unit Tests`
  - `Integration Tests`
  - `Rustfmt`
  - `Clippy`
  - `Build Release`

**Step 4:** Merge to main
```bash
git checkout main
git merge ci-enhancement
git push origin main
```

**Step 5:** Archive old workflow (optional)
```bash
mv .github/workflows/ci.yml .github/workflows/ci.yml.bak
```

---

## Performance Targets

**From Story 1.9 traceability:**

| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| CI Runtime | <30 min | ~20 min | ✅ PASS |
| Unit Tests | <5 min | ~3 min | ✅ PASS |
| Integration Tests | <10 min | ~5 min | ✅ PASS |
| GPU Throughput | ≥50K keys/sec | TBD | 🔴 RED (BLOCKER-2) |
| Build Time | <5 min | ~4 min | ✅ PASS |

**Note:** GPU throughput validation added in Story 1.9.1 (BLOCKER-2)

---

## Notifications

**GitHub Actions default:**
- Email on failure (first failure only)
- PR checks show status

**Custom notifications (optional):**
- Slack: Use `slack-send` action
- Discord: Use `discord-webhook` action
- Email: Use `mail` action

---

## Artifacts

**Retention policies:**
- Test failures: **7 days**
- Burn-in failures: **30 days**
- Release binaries: **30 days**
- Benchmark binaries: **7 days**

**Download artifacts:**
1. GitHub Actions tab
2. Select workflow run
3. Scroll to "Artifacts" section
4. Click artifact name to download

---

## Security

**Secrets (if needed):**
- Settings → Secrets → Actions
- Add: `CARGO_REGISTRY_TOKEN` (for publishing)
- Add: `SENTRY_DSN` (for error tracking)

**Current setup:** No secrets required for CI

---

## Next Steps

### For Story 1.9.1 (Blocker Resolution)

1. **Implement blockers** - Make ATDD tests pass
2. **Remove `#[ignore]`** - Integrate tests into standard suite
3. **Update quality gate** - Remove `exit 1` when blockers resolved
4. **Run burn-in** - Commit with `[burn-in]` to trigger 10 iterations
5. **Verify GREEN** - All checks pass on PR

### For Production Release

1. **Enable strict mode** - Change `continue-on-error: false` for critical jobs
2. **Add coverage** - Use `tarpaulin` or `llvm-cov` for code coverage reporting
3. **Performance regression detection** - Compare benchmark results across commits
4. **Release automation** - Auto-publish to crates.io on tag push

---

**CI Architect:** Murat  
**Last Updated:** 2025-12-19  
**Next Review:** After Story 1.9.1 blocker resolution

**CI Mantra:** *"Tests fail fast, feedback flows faster, flaky tests get found first."*

---
