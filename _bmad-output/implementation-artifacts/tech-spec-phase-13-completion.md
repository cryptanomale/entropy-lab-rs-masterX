# Tech-Spec: Phase 13 Completion - Vulnerability Intelligence & GPU Modernization

**Created:** 2025-12-23  
**Status:** Ready for Development  
**Stories:** STORY-007-001, STORY-007-003, STORY-007-004, STORY-008-002, STORY-008-003  
**Total Points:** 39

---

## Overview

### Problem Statement

Phase 13 of temporal-planetarium has 5 remaining stories blocking completion:
1. **EPIC-007** (Vulnerability Intelligence) - Missing CLI database import, brainwallet dictionary, and nonce reuse detection
2. **EPIC-008** (GPU Modernization) - wgpu scanner exists but isn't integrated into CLI, no Metal performance validation

### Solution

Implement all 5 stories in a logical dependency order, building on existing infrastructure:
- `WgpuScanner` in `wgpu_integration.rs` - already functional
- `TargetDatabase` in `utils/db.rs` - schema exists
- `derive_brainwallet_p2pkh` in `utils/brainwallet.rs` - single passphrase logic exists
- `recover_privkey_from_nonce_reuse` in `randstorm/forensics.rs` - recovery algorithm exists

### Scope

**In Scope:**
- ✅ CLI `db-import` command for target address ingestion
- ✅ Brainwallet dictionary generator with SecLists support
- ✅ Nonce reuse signature detection (scan blockchain data)
- ✅ `--backend wgpu` CLI flag for randstorm-scan
- ✅ Mac/Metal performance benchmarks

**Out of Scope:**
- Full blockchain node integration (use pre-exported signature data)
- Production deployment scripts
- GUI integration

---

## Context for Development

### Codebase Patterns

| Pattern | File | Usage |
|---------|------|-------|
| Scanner architecture | `scans/randstorm/integration.rs` | `RandstormScanner::new()`, `scan_batch()` |
| GPU batching | `wgpu_integration.rs` | `WgpuScanner::process_batch()` |
| Database CRUD | `utils/db.rs` | `TargetDatabase::upsert_target()`, `query_by_class()` |
| CLI structure | `scans/randstorm/cli.rs` | `run_scan()` with flag handling |
| Test pattern | All modules | `#[cfg(test)] mod tests { ... }` |

### Files to Reference

```
crates/temporal-planetarium-lib/src/
├── scans/randstorm/
│   ├── wgpu_integration.rs    -- Existing WgpuScanner (extend)
│   ├── cli.rs                 -- Add --backend flag
│   ├── integration.rs         -- Wire up backend selection
│   ├── forensics.rs           -- Nonce reuse recovery (extend)
│   └── config.rs              -- Add GpuBackend enum
├── utils/
│   ├── db.rs                  -- TargetDatabase (add CLI commands)
│   └── brainwallet.rs         -- Extend with batch processing
crates/temporal-planetarium-cli/src/
└── main.rs                    -- Add db-import, brainwallet subcommands
```

### Technical Decisions

1. **Backend selection**: Enum-based (`GpuBackend::OpenCL`, `GpuBackend::Wgpu`) with optional feature flag
2. **Dictionary format**: One passphrase per line (SecLists compatible)
3. **Nonce detection**: Offline mode (CSV input of signatures), not live blockchain
4. **Benchmark harness**: Use `criterion` for Metal vs OpenCL comparison with system info capture
5. **Security hardening**: SQLite WAL mode, passphrase opt-in output, nonce dedup filtering

### Architecture Decision Records

#### ADR-001: GPU Backend Selection Strategy
- **Context**: Need validation of wgpu alongside existing OpenCL.
- **Decision**: Platform-aware auto-selection with manual override.
  - **macOS** defaults to `Wgpu` (Native Metal support)
  - **Linux/Windows** defaults to `OpenCl` (Broader driver support)
  - **CLI** accepts `--backend auto` (default), or explicit override.
- **Status**: Accepted

---

## Implementation Plan

### Task 0: Infrastructure Hardening (Red Team Findings)

- [ ] **0.1** Add `wgpu` as optional Cargo feature with compile-time checks:
  ```toml
  [features]
  wgpu = ["dep:wgpu"]
  ```
- [ ] **0.2** Enable SQLite WAL mode in `TargetDatabase::new()` for concurrent access
- [ ] **0.3** Add `sysinfo` crate for benchmark system info capture

### Task 1: STORY-008-002 - Integrate wgpu in Randstorm Scanner (8 pts)

- [ ] **1.1** Add `GpuBackend` enum to `config.rs` with platform detection:
  ```rust
  #[derive(Default)]
  pub enum GpuBackend { #[default] Auto, OpenCl, Wgpu, Cpu }
  // impl Default logic: target_os="macos" => Wgpu, else => OpenCl
  ```
- [ ] **1.2** Update `run_scan()` in `cli.rs` to accept `--backend auto|wgpu|opencl|cpu`
- [ ] **1.3** Wire backend selection in `integration.rs` to dispatch to `WgpuScanner` (for Wgpu/Auto-on-Mac) or `GpuScanner` (match existing)
- [ ] **1.4** Add integration test that runs wgpu backend with test fingerprints

### Task 2: STORY-008-003 - Verify Mac/Metal Performance (5 pts)

- [ ] **2.1** Create `benches/wgpu_metal_benchmark.rs` using `criterion`
- [ ] **2.2** Benchmark 10k fingerprints on wgpu backend
- [ ] **2.2b** Include system specs in benchmark output (chip model, memory, OS version)
- [ ] **2.3** Document results in `docs/wgpu-metal-performance.md`
- [ ] **2.4** Assert performance ≥30k keys/sec or document gap with hardware context

### Task 3: STORY-007-001 - Target Address Database CLI (8 pts)

- [ ] **3.1** Add `db-import` subcommand to CLI:
  ```bash
  temporal-planetarium db-import --file targets.csv --vuln-class randstorm
  ```
- [ ] **3.2** Implement CSV parser with columns: `address,vuln_class,metadata_json`
- [ ] **3.3** Add `--db-path` global flag for database location
- [ ] **3.4** Add query command `db-query --class randstorm --limit 100`
- [ ] **3.5** Test with sample CSV file

### Task 4: STORY-007-003 - Brainwallet Dictionary Generator (5 pts)

- [ ] **4.1** Create `brainwallet-generate` subcommand:
  ```bash
  temporal-planetarium brainwallet-generate --wordlist rockyou.txt --output addresses.csv
  ```
- [ ] **4.2** Extend `brainwallet.rs` with batch processing:
  ```rust
  pub fn derive_batch(passphrases: &[String]) -> Vec<(String, String)>
  ```
- [ ] **4.3** Add progress bar with `indicatif`
- [ ] **4.4** Output CSV format: `address` only (default secure mode)
- [ ] **4.5** Add `--output-passphrases` flag (disabled by default, requires explicit opt-in)
- [ ] **4.6** Test with 1000-line wordlist

### Task 5: STORY-007-004 - Nonce Reuse Signature Detection (13 pts)

- [ ] **5.1** Create `nonce-reuse-scan` subcommand:
  ```bash
  temporal-planetarium nonce-reuse-scan --input signatures.csv --output vulnerable.csv
  ```
- [ ] **5.2** Implement signature CSV parser:
  ```csv
  txid,r,s,z,address
  ```
- [ ] **5.3** Detect duplicate `r` values across signatures
- [ ] **5.3b** Filter false positives: require matching `r` AND differing `z` (message hashes)
- [ ] **5.4** For matches, call `recover_privkey_from_nonce_reuse()`
- [ ] **5.5** Output recovered private keys to `vulnerable.csv`
- [ ] **5.6** Add to TargetDatabase as `vuln_class: nonce_reuse`
- [ ] **5.7** Unit test with synthetic duplicate-r signature pairs (include false positive test)

---

## Acceptance Criteria

### STORY-008-002
- [ ] AC1: `randstorm-scan --backend wgpu` executes without error
- [ ] AC2: Native execution on Apple Metal successful (no OpenCL fallback)
- [ ] AC3: Test `test_wgpu_backend_integration` passes

### STORY-008-003
- [ ] AC1: Performance benchmarks documented in `docs/wgpu-metal-performance.md`
- [ ] AC2: Benchmark can run on both Apple Silicon and Intel Mac
- [ ] AC3: Results show ≥30k keys/sec OR documented explanation of gap

### STORY-007-001
- [ ] AC1: `db-import` command imports 10k+ addresses
- [ ] AC2: Index on `vuln_class` shows 10x speedup in queries
- [ ] AC3: Test `test_db_import_cli` passes

### STORY-007-003
- [ ] AC1: `brainwallet-generate --wordlist rockyou.txt` completes
- [ ] AC2: Output CSV contains valid P2PKH addresses
- [ ] AC3: Benchmark shows ≥100k derivations/sec

### STORY-007-004
- [ ] AC1: `nonce-reuse-scan` detects synthetic duplicate-r signatures
- [ ] AC2: Private key recovery outputs valid secp256k1 keys
- [ ] AC3: Vulnerabilities auto-populated in TargetDatabase

---

## Additional Context

### Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `wgpu` | 23.0 | Already in use |
| `rusqlite` | 0.31 | Already in use |
| `criterion` | 0.5 | Benchmarking (add if missing) |

### Testing Strategy

**Existing tests to leverage:**
```bash
# wgpu parity (already passing)
cargo test -p temporal-planetarium-lib test_wgpu_hashing_parity

# Database CRUD
cargo test -p temporal-planetarium-lib test_upsert_and_query

# Brainwallet derivation
cargo test -p temporal-planetarium-lib test_derive_brainwallet

# Nonce reuse recovery
cargo test -p temporal-planetarium-lib test_nonce_reuse_recovery_smoke
```

**New tests to add:**
```bash
# 1. wgpu backend integration
cargo test -p temporal-planetarium-lib test_wgpu_backend_selection

# 2. CLI db-import
cargo test -p temporal-planetarium-cli test_db_import_command

# 3. Brainwallet batch
cargo test -p temporal-planetarium-lib test_brainwallet_batch

# 4. Nonce reuse detection
cargo test -p temporal-planetarium-lib test_nonce_reuse_detection
```

**Manual verification:**
1. Run `cargo run -- randstorm-scan --backend wgpu --help` and verify flag exists
2. Run Metal benchmark on M1/M2 Mac and record throughput
3. Import sample CSV with 1000 addresses and query back

### Notes

- Prioritize STORY-008-002/003 first (wgpu integration) since SHA256 parity already verified
- STORY-007-004 (nonce reuse) is complex but has solid forensics.rs foundation
- Consider parallelizing brainwallet derivation with `rayon`
