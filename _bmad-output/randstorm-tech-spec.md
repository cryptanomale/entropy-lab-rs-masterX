# Randstorm/BitcoinJS Scanner – Tech Spec

**Date:** 2025-12-17 (Updated: 2025-12-22)  
**Owner:** Moe / temporal-planetarium  
**Context:** Brownfield, Quick-Dev Mode A (tech-spec) for the missing Randstorm scanner.

**Changelog:**
- 2025-12-22: Enhanced with File Structure, Timestamp Algorithm, GPU Integration Pattern, and Security/Ethics sections (validation-driven refinement)

## Objective
Ship the Randstorm/BitcoinJS scanner as scanner #19 with GPU-first acceleration and CPU fallback, covering 2011-2015 browser-generated BitcoinJS wallets (weak JSBN `SecureRandom()` + Math.random() entropy). Target ≥60–70% coverage in Phase 1, then extend.

## Background
- Vulnerability: JSBN `SecureRandom()` type error skips CSPRNG; falls back to Math.random() (48-bit LCG seeded by timestamp) → recoverable private keys.
- Disclosure: Unciphered “Randstorm: You Can’t Patch a House of Cards” (Nov 2023), original Ketamine disclosure (Apr 2018).
- Impact: ~1.2–2.1B USD; affected: Blockchain.info/Blockchain.com legacy, Dogechain, Litecoin web wallets, other BitcoinJS forks.

## In Scope (Phase 1)
- Chrome/V8 Math.random() (MWC1616) replication.
- Top-100 browser fingerprints (2011–2015) prioritized by market share.
- Direct private-key → P2PKH address derivation (no BIP32).
- GPU kernel `randstorm_crack.cl` integration; CPU fallback path.
- CLI subcommand `randstorm-scan` with CSV address input.
- Synthetic vulnerable vector generation for validation.

## Out of Scope (Phase 1)
- Firefox/Safari/IE PRNGs (Phase 2).
- Multi-path derivation (BIP44/49/84/86) and extended indices.
- KeyBleed.com integration.
- Multi-GPU orchestration.

## Requirements
### Functional
1) CLI: `randstorm-scan --targets <csv> [--phase 1|2|3] [--gpu|--cpu] [--output <file>]`  
2) Fingerprint DB: load `phase1_top100.csv` (existing); sort by priority; phase flag controls slice (Phase 1 uses top 100).  
3) PRNG: Chrome V8 MWC1616 exact constants (18000, 30903), deterministic seeding from timestamp + fingerprint hash.  
4) Keygen: replicate JSBN weak pool → ARC4 → 32-byte privkey → secp256k1 → P2PKH hash160.  
5) GPU path: batch configs × timestamp candidates; early-exit on match; result buffer returns config idx + timestamp only (no privkeys).  
6) CPU fallback: parity with GPU output; Rayon parallelism; same acceptance.  
7) Progress: per-address progress with ETA; warn when GPU unavailable and auto-fallback.  
8) Output: CSV/JSON containing address, confidence, browser_config_id, timestamp_range, phase.  
9) Logging: structured (tracing); no private keys logged or materialized on CPU.  
10) Tests: unit tests for PRNG, fingerprint loading, seed-to-address derivation; integration GPU/CPU parity; synthetic vector detection.

### Non-Functional
- Performance: ≥10x GPU speedup vs CPU baseline in Phase 1; <30 minutes per address for Phase 1 coverage on a single GPU.  
- Security: private keys remain only in GPU local memory; CPU path avoids logging secrets; zeroize sensitive buffers.  
- Reliability: CPU fallback always available; deterministic results; reproducible seeds.  
- Maintainability: follows existing scanner patterns (`milk_sad`, `trust_wallet`), minimal new abstractions.

## Interfaces
- **Input CSV:** headerless or `address` column; validate Bech32/Base58; reject invalid rows with line numbers.  
- **Config data:** `src/scans/randstorm/fingerprints/data/phase1_top100.csv` (✓ existing, validated) with schema: `priority, user_agent, screen_width, screen_height, color_depth, timezone_offset, language, platform, market_share_estimate, year_min, year_max`. Future phase2/phase3 files follow same schema.  
- **Kernel:** `cl/randstorm_crack.cl`; invoked via `gpu_solver` work-group sizing following `compute_trust_wallet_crack()` pattern.

## Data & Algorithms
- **Seed components:** timestamp_ms (range around first TX when available, else user-provided or default ±24h), user_agent hash, screen dims, timezone, language, platform.  
- **MWC1616:**  
  - s1 = 18000 * (s1 & 0xFFFF) + (s1 >> 16)  
  - s2 = 30903 * (s2 & 0xFFFF) + (s2 >> 16)  
  - result = (s1 << 16) + s2  
- **ARC4 seeding:** Call Math.random() 256 times using MWC1616; fill pool[0..255] with `(random() * 256) & 0xFF`; initialize ARC4 state; generate 32 bytes for privkey using ARC4 output. (Note: JSBN-specific behavior - verify skip-bytes if needed during implementation.)

## Plan (Phase 1 execution)
1) Integrate GPU/CPU bridge (Story 1.6): wire `ocl::ProQue`, batch inputs, result buffer parsing.  
2) CPU fallback (Story 1.7): reuse PRNG + derivation with Rayon.  
3) CLI subcommand (Story 1.8): add to `main.rs`, progress reporting, output writer.  
4) Tests (Story 1.9): synthetic vectors (Chrome V8), GPU/CPU parity, fingerprint counts.  
5) Docs & disclosure (Story 1.10): responsible use, no key export, usage examples.

## File Structure & Dependencies (Phase 1)
### New Files to Create
- `src/scans/randstorm.rs` - Main scanner module (follow `milk_sad.rs` / `trust_wallet_lcg.rs` patterns)
- `cl/randstorm_crack.cl` - GPU kernel for MWC1616 + ARC4 + secp256k1 derivation

### Existing Files to Modify
- `src/scans/mod.rs` - Add `pub mod randstorm;`
- `src/main.rs` - Add CLI subcommand `RandstormScan` with clap derive
- `src/scans/gpu_solver.rs` - Add `pub fn compute_randstorm_crack()` method

### Existing Data Files (No Changes Required)
- `src/scans/randstorm/fingerprints/data/phase1_top100.csv` ✓ Validated - 100 rows with complete schema

### Dependencies (Already in Cargo.toml)
- `ocl` - OpenCL bindings
- `bitcoin`, `secp256k1` - Address derivation
- `rayon` - CPU parallelism
- `tracing` - Structured logging
- `zeroize` - Secure memory cleanup

## Timestamp Search Algorithm
### Search Parameters
- **Default range:** ±24 hours (86,400 seconds) from estimated wallet creation timestamp
- **Granularity:** 1 second (1000ms steps for millisecond timestamps)
- **Total candidates per address:** 100 fingerprints × 172,800 timestamps = **17.28M combinations**

### Timestamp Estimation Strategy
1. **If address provided with RPC access:**
   - Call `getaddresstxids` → retrieve earliest txid
   - Call `getrawtransaction` with txid → extract block timestamp
   - Use block timestamp as center point ±24h

2. **If user provides `--timestamp-hint <unix_ms>` flag:**
   - Use provided timestamp as center point ±24h

3. **Default fallback:**
   - Current time minus 5 years (conservative estimate for 2011-2015 wallets)
   - Scan ±24h around that point

### GPU Batch Processing
- **Work group size:** 256 work items (optimal for most GPUs)
- **Global size:** 1024 work groups = 262,144 parallel timestamp checks per kernel invocation
- **Batching:** Iterate through all fingerprints × timestamp ranges in batches
- **Estimated time:** ~30 seconds per address on mid-range GPU (RTX 3060 equivalent)

### CPU Fallback
- Use Rayon parallel iterator over same fingerprint × timestamp combinations
- Estimated time: ~5 minutes per address (10x slower than GPU)

## GPU Integration Pattern
Following `compute_trust_wallet_crack()` in `gpu_solver.rs`:

### Method Signature
```rust
pub fn compute_randstorm_crack(
    &self,
    fingerprints: &[FingerprintConfig], // struct with UA, screen, timezone, etc.
    timestamp_start_ms: u64,
    timestamp_end_ms: u64,
    target_h160: &[u8; 20],
) -> ocl::Result<Vec<(u32, u64)>>  // Returns (fingerprint_idx, timestamp_ms) pairs
```

### Buffer Setup
- **Input buffer 1:** Fingerprint config array (packed u32 components: screen_w, screen_h, color_depth, timezone_offset, etc.)
- **Input buffer 2:** Target Hash160 split into 3 components: `(u64, u64, u32)` for efficient GPU comparison
- **Output buffer 1:** Result pairs `[(u32 config_idx, u64 timestamp_ms)]` - max 1024 results
- **Output buffer 2:** Atomic counter `u32` for result count

### Kernel Execution
- Kernel name: `"randstorm_crack"`
- Each work item processes one (fingerprint, timestamp) pair
- Early-exit on match: write (config_idx, timestamp) to result buffer, increment counter
- **CRITICAL:** Private keys never leave GPU local memory - only Hash160 comparison performed

### Return Value
- Parse result buffer into `Vec<(u32, u64)>` containing all matches
- Caller uses (fingerprint_idx, timestamp_ms) to reproduce derivation if needed for authorized recovery

## Security & Responsible Use
### Private Key Handling Policy
**GPU Execution Path:**
- Private keys generated in GPU **local memory ONLY**
- Keys **never** transferred to CPU/host memory
- Only Hash160 comparison performed on GPU (secp256k1 pubkey → hash160 → compare)
- On match: write `(config_idx, timestamp)` to result buffer - **NOT the private key**

**CPU Fallback Path:**
- Same policy: never materialize full privkey in memory
- Derive → compute pubkey → hash160 → compare → **immediately discard**
- Use `zeroize` crate for any temporary buffers containing sensitive data

**Logging:**
- Structured logging via `tracing` crate
- **NEVER** log private keys, seeds, or ARC4 pool state
- Redact sensitive data from error messages and debug output

### Key Recovery Protocol
When a vulnerable wallet is detected, the tool outputs **ONLY**:
- ✓ **Address** (already known to user)
- ✓ **Fingerprint ID** (index in phase1_top100.csv)
- ✓ **Timestamp (ms)** (exact timestamp that produced the match)
- ✓ **Confidence score** (based on fingerprint market share)
- ✗ **NO private key output** to stdout, logs, or files

### Authorized Recovery Process
For legitimate wallet recovery, user must:
1. **Prove ownership** of the address (sign message, provide transaction history, etc.)
2. **Manually re-derive** the private key using:
   - Published fingerprint data (from CSV)
   - Detected timestamp
   - Tool's derivation logic (open-source, auditable)
3. **Sweep funds** immediately to secure wallet with proper entropy
4. **Report vulnerability** if third-party wallet service affected (responsible disclosure)

### Legal & Ethical Compliance
- **Authorized use ONLY:** This tool is for security research on wallets you own or have explicit permission to test
- **No unauthorized access:** Using this tool to access wallets without permission is **illegal** and violates the Computer Fraud and Abuse Act (CFAA) and similar laws worldwide
- **Follows Entropy Lab RS guidelines:** See `SECURITY.md` in repository root for full ethical guidelines
- **Research purpose:** Intended to help identify and secure vulnerable wallets, not exploit them

**⚠️ WARNING:** Unauthorized use of this tool for wallet theft or unauthorized access is a **federal crime** in most jurisdictions. Use responsibly.

## Acceptance Criteria (Phase 1)
- CLI `randstorm-scan` runs with CSV input; GPU preferred, CPU fallback automatic.  
- Detects 100% of synthetic vulnerable vectors for Chrome/V8; false positives <0.01%.  
- GPU speedup ≥10x vs CPU on 1M seed sample.  
- No private key materialization on CPU; logs redact sensitive data.  
- Tests: all new unit + integration tests passing; no regressions in existing suite.  
- Formatting/lint: `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test` all pass.

