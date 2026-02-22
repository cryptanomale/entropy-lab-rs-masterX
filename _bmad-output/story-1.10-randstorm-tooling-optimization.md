# Story 1.10: Randstorm Tooling Optimization & WGPU Parity

**Story ID:** 1.10  
**Epic:** Phase 1 - Randstorm/BitcoinJS Scanner  
**Priority:** P1  
**Status:** ready-for-dev  
**Estimated Effort:** 15-20 hours  

---

## Context

Current Randstorm implementation has a "structural validation" layer but lacks "cryptographic depth" in several areas. The `attack_estimator.rs` uses hardcoded throughput values, and the WGPU kernels do not yet perform full ECC/Address derivation, necessitating a CPU "Golden Reference" re-validation which is the primary system bottleneck.

## User Story

**As a** security researcher  
**I want** accurate attack estimation and full cryptographic parity in WGPU  
**So that** I can predict scan times reliably and utilize the GPU at its theoretical maximum efficiency.

---

## Acceptance Criteria

### AC-1: Dynamic Attack Estimator (P1)
- [ ] Remove hardcoded `gpu_rate` (30k) and `cpu_rate` (5k) from `attack_estimator.rs`.
- [ ] Implement `estimate_for_phase(phase, backend)` which uses actual benchmark results from `docs/wgpu-metal-performance.md`.
- [ ] Add support for "Custom" scan modes in the estimator (arbitrary window/interval).

### AC-2: Full Cryptographic Parity in WGSL (P0)
- [ ] Implement `sha256`, `ripemd160`, and `secp256k1` address derivation directly in `randstorm.wgsl`.
- [ ] Eliminate the need for CPU "Golden Reference" re-validation for every GPU hit.
- [ ] Achieve ≥50,000 keys/second throughput with full derivation active.

### AC-3: Tooling Refinement (P2)
- [ ] Update `print_complexity_report` to include "Price to Crack" estimates (using AWS/GCP instance rates).
- [ ] Add "Targeting Recommendations" based on window size (e.g., "Recommend narrowing to 1-week window if > 1 month").

---

## Technical Tasks

1. **Estimator Refactor**:
    - Modify `AttackComplexity` struct to accept `throughput_kps`.
    - Update `estimate` method to calculate more granularly based on `Phase`.
2. **WGSL Enhancement**:
    - Port `sha2` crate logic to WGSL shader.
    - Port `secp256k1` point-multiplication to WGSL (can reuse existing open-source webgpu-crypto libraries as reference).
3. **Integration**:
    - Update `RandstormScanner` to rely on the WGSL match result without CPU re-validation.

---

## Success Metrics
- Speed: Scan throughput ≥50,000 keys/sec (with full derivation).
- Accuracy: 0% False Positives from GPU (validated against CPU reference).
- Estimation Error: < 5% variance between estimated and actual scan time.

---

## References
- `crates/temporal-planetarium-lib/src/scans/randstorm/attack_estimator.rs`
- `crates/temporal-planetarium-lib/src/scans/randstorm/wgpu_integration.rs`
- `docs/wgpu-metal-performance.md`
