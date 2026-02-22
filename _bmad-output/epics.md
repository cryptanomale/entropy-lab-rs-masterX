---
stepsCompleted: ['step-01-validate-prerequisites', 'step-02-design-epics', 'step-03-create-stories', 'step-04-final-validation']
inputDocuments:
  - "_bmad-output/prd.md"
  - "_bmad-output/architecture.md"
  - "_bmad-output/specs/epics-phase-1-mvp.md"
  - "_bmad-output/specs/epics-phase-13.md"
  - "_bmad-output/implementation-artifacts/epics.md"
  - "_bmad-output/randstorm-tech-spec.md"
  - "_bmad-output/phase-13-tech-spec.md"
---

# temporal-planetarium - Epic Breakdown

## Overview

This document provides the complete epic and story breakdown for temporal-planetarium, decomposing the requirements from the PRD, Architecture, existing epics, and tech specs into implementable stories for the Randstorm/BitcoinJS Scanner feature.

**Project Scope:** GPU-accelerated vulnerability scanner for Bitcoin wallets generated between 2011-2015 using weak JavaScript PRNGs.

**Phase Coverage:**
- Phase 1 MVP: Chrome V8 PRNG, Top 100 fingerprints, P2PKH addresses, basic GPU acceleration
- Phase 13: Vulnerability Intelligence, Milk Sad, Nonce Reuse, WGPU modernization
- Future: Firefox/Safari/IE PRNGs, Multi-path derivation, Professional reporting

## Requirements Inventory

### Functional Requirements

**FR-1: JavaScript PRNG Reconstruction** (Priority: P0 - Critical MVP Blocker, Phase: 1)
- FR-1.1: Chrome V8 PRNG (MWC1616) Implementation - exact constants (18000, 30903), deterministic seeding
- FR-1.2: Firefox SpiderMonkey PRNG Implementation (Phase 2) - LCG variant
- FR-1.3: Safari JavaScriptCore PRNG (Xorshift128+) (Phase 2)
- FR-1.4: IE Chakra PRNG (Mersenne Twister variant) (Phase 2)

**FR-2: Browser Fingerprint Database** (Priority: P0 - Critical MVP Blocker, Phase: 1)
- FR-2.1: Browser Configuration Schema - user_agent, screen_width, screen_height, color_depth, timezone_offset, language, platform, market_share_estimate, year_range
- FR-2.2: Top 100 Configurations (Phase 1) - Chrome 20-40, Firefox 10-30, Safari 5-8, US/EU timezones
- FR-2.3: Extended 500 Configurations (Phase 2) - additional versions, mobile, global timezones
- FR-2.4: Configuration Prioritization - sorted by market_share_estimate descending

**FR-3: Derivation Path Support** (Priority: P0 - Critical, Phase: 1 simple, 2 multi-path)
- FR-3.1: Pre-BIP32 Direct Derivation (Phase 1) - direct private key to P2PKH
- FR-3.2: BIP32 Simple Paths (Phase 2) - m/0, m/0/0
- FR-3.3: BIP44 Standard Path (Phase 2) - m/44'/0'/0'/0/0
- FR-3.4: SegWit Paths (Phase 2) - BIP49, BIP84
- FR-3.5: Extended Index Support (Phase 3) - indices 0-100

**FR-4: GPU Acceleration via OpenCL** (Priority: P0 - Critical, Phase: 1)
- FR-4.1: Basic OpenCL Kernel - parallel PRNG, secp256k1, address generation
- FR-4.2: Device-Aware Work Group Sizing - auto-configure for NVIDIA/AMD/Intel
- FR-4.3: Batch Processing - 1M+ seeds per invocation, pinned memory
- FR-4.4: GPU Optimization (Phase 2) - device-specific tuning, constant memory
- FR-4.5: Multi-GPU Support (Phase 3) - distributed workload
- FR-4.6: CPU Fallback - automatic when GPU unavailable

**FR-5: Validation Framework & Test Suite** (Priority: P0 - Critical Pre-Release Blocker, Phase: 1)
- FR-5.1: 2023 Randstorm Test Vectors - 100% match on disclosed examples
- FR-5.2: Integration Tests - PRNG, fingerprints, derivation paths
- FR-5.3: Performance Benchmarks - GPU speedup, scan completion time
- FR-5.4: Regression Tests - existing 18 scanners unaffected
- FR-5.5: False Positive/Negative Validation - <1% FP, <5% FN

**FR-6: CLI Interface** (Priority: P0 - Critical, Phase: 1)
- FR-6.1: Subcommand Structure - `entropy-lab randstorm-scan [OPTIONS]`
- FR-6.2: Required Arguments - `--target-addresses <FILE>` or `--scan-range`
- FR-6.3: Optional Arguments - --phase, --gpu, --cpu, --output, --threads, --batch-size
- FR-6.4: Progress Reporting - real-time bar, ETA, seeds/second
- FR-6.5: Results Output - CSV format with Address, Status, Confidence, Config, Timestamp
- FR-6.6: Error Handling - clear messages, CSV validation, GPU warnings

**FR-7: Responsible Disclosure Framework** (Priority: P0 - Critical Legal/Ethical, Phase: 1)
- FR-7.1: Disclosure Protocol Documentation - 90-day window, exchange coordination
- FR-7.2: Findings Report Format - address, risk level, recommendations
- FR-7.3: Private Key Handling - scanner identifies only, no export to user
- FR-7.4: Ethical Use Guidelines - prominent disclaimer, white-hat only, legal warnings
- FR-7.5: Coordination Support - template emails for notifications

**FR-8: CSV Import/Export** (Priority: P1 - High, Phase: 2)
- FR-8.1: Input CSV Format - Address, Notes columns
- FR-8.2: Output CSV Format - standard results format
- FR-8.3: Batch Scanning - 10,000+ addresses efficiently
- FR-8.4: Export Options - CSV, JSON, PDF (Phase 3)

**FR-9: Checkpoint/Resume Support** (Priority: P2 - Medium, Phase: 3)
- FR-9.1: Checkpoint File Format - JSON with scan progress
- FR-9.2: Auto-checkpoint - every 5 minutes, on SIGTERM/SIGINT
- FR-9.3: Resume Command - `--resume <checkpoint_file>`

**FR-13: Phase 13 Vulnerability Intelligence** (Priority: P0, Phase: 13)
- FR-13.1: Persistent Storage Backend - SQLite/PostgreSQL for target addresses
- FR-13.2: Milk Sad Integration - bx 3.x weak seed identification
- FR-13.3: ECDSA Nonce Reuse Forensics - signature-based key recovery
- FR-13.4: Brainwallet Passphrase Dictionary - phrase ingestion and address generation
- FR-13.5: WGPU Port - core kernels to WGSL for Metal/Vulkan/DX12

### Non-Functional Requirements

**NFR-1: Performance** (Priority: P0 - Critical)
- NFR-1.1: GPU Acceleration - 10x minimum (Phase 1), 50-100x target (Phase 2)
- NFR-1.2: Scan Completion Time - <30 min/wallet (Phase 1), <10 min (Phase 2), <5 min (Phase 3)
- NFR-1.3: Throughput - 100M-1B seeds/sec (Phase 1), 1B-10B (Phase 2), 10B+ (Phase 3)
- NFR-1.4: Resource Usage - <8GB RAM, <4GB VRAM, <1GB disk
- NFR-1.5: Scalability - >80% efficiency per additional GPU

**NFR-2: Accuracy & Reliability** (Priority: P0 - Critical)
- NFR-2.1: False Negative Rate - <5% target, <10% maximum
- NFR-2.2: False Positive Rate - <1% target, <2% maximum
- NFR-2.3: Test Vector Validation - 100% match on disclosure examples
- NFR-2.4: Reproducibility - identical results across runs
- NFR-2.5: Error Handling - no crashes, graceful degradation

**NFR-3: Security & Ethics** (Priority: P0 - Critical)
- NFR-3.1: No Private Key Exposure - GPU local memory only, secure clearing
- NFR-3.2: White-Hat Only - no fund transfer capability
- NFR-3.3: Data Privacy - local execution only, no telemetry
- NFR-3.4: Code Security - Rust memory safety, security audit

**NFR-4: Usability** (Priority: P1 - High)
- NFR-4.1: CLI Clarity - clear help, intuitive naming
- NFR-4.2: Progress Transparency - real-time updates, ETA
- NFR-4.3: Documentation - README, tech docs, examples
- NFR-4.4: Error Messages - clear, actionable

**NFR-5: Maintainability** (Priority: P1 - High)
- NFR-5.1: Code Quality - Rust 2021, cargo fmt, clippy
- NFR-5.2: Testing - >80% coverage
- NFR-5.3: Modularity - scanner patterns, reusable components
- NFR-5.4: Documentation - doc comments, architecture docs

**NFR-6: Portability** (Priority: P1 - High)
- NFR-6.1: Platform Support - Linux, macOS, Windows
- NFR-6.2: GPU Compatibility - NVIDIA, AMD, Intel, CPU fallback
- NFR-6.3: Dependency Management - minimal external deps

**NFR-7: Compliance & Legal** (Priority: P0 - Critical)
- NFR-7.1: Open Source Licensing - compatible with project license
- NFR-7.2: Responsible Disclosure Compliance - 90-day window
- NFR-7.3: Legal Review - counsel review before release

**NFR-13: Phase 13 Performance** (Priority: P0, Phase: 13)
- NFR-13.1: Target Address Lookup - <10ms for 1,000,000+ targets
- NFR-13.2: Target Indexing - support 1,000,000+ addresses
- NFR-13.3: WGPU Performance - >30,000 keys/sec on Apple Metal

### Additional Requirements

**From Architecture:**
- Unified Shader Bridge: Standardized trait between OpenCL and WGPU with 100% logic parity
- Fixed-Point Bitwise Integers Only: No floats/doubles in scanner kernels (prevent driver divergence)
- Dual-Execution Cross-Check: GPU hits auto-verified by CPU Golden Reference
- Bit-Perfect CI Lock: 100% bit-parity between CPU/GPU required in CI
- Endianness & Alignment Standard: All shared structs must be `#[repr(C)]` with u32 fields
- Double-Buffered GPU Synchronization: Staging buffers with explicit fences
- Zero-Copy DMZ: Specific memory regions for Rust/GPU buffer mapping via bytemuck
- Progress-Aware Scanner Trait: Interface for real-time ETA reporting

**From PRD Implementation Guidance:**
- File Structure: `src/scans/randstorm.rs`, `cl/randstorm_crack.cl`
- GPU Integration Pattern: Follow `compute_trust_wallet_crack()` in `gpu_solver.rs`
- Timestamp Search: ±24h window, 172,800 timestamps × 100 fingerprints = 17.28M combinations
- Security: Private keys in GPU `__local` memory only, CPU uses `zeroize` crate

**From Tech Specs:**
- MWC1616 Algorithm: s1 = 18000 * (s1 & 0xFFFF) + (s1 >> 16), s2 = 30903 * (s2 & 0xFFFF) + (s2 >> 16)
- ARC4 Pool: 256 Math.random() calls to initialize pool
- Database Backend: rusqlite for Phase 13 target intelligence
- WGSL Port: MWC1616 + SHA256 + RIPEMD160 for WGPU

**Testing Strategy (from PRD):**
- 3-Tier Risk Classification: Critical (PRNG, GPU/CPU parity, key non-materialization), High (address derivation, fingerprint loading), Medium (CSV validation, progress reporting)
- Test Pyramid: 100+ unit, 20 integration, 5 E2E tests
- CI Pipeline: Pre-commit hooks, PR checks, merge to main, weekly/release
- Quality Gates: Pre-merge (all tests pass), Pre-release (GPU tests, security audit, performance benchmarks)

### FR Coverage Map

| FR # | Epic | Description |
|------|------|-------------|
| FR-1.1 | Epic 1 | Chrome V8 PRNG (MWC1616) |
| FR-3.1 | Epic 1 | Pre-BIP32 Direct Derivation (merged) |
| FR-4.1 | Epic 1 | Basic OpenCL Kernel |
| FR-4.2 | Epic 1 | Device-Aware Work Groups |
| FR-4.3 | Epic 1 | Batch Processing |
| FR-4.6 | Epic 1 | CPU Fallback |
| FR-2.1 | Epic 2 | Browser Configuration Schema |
| FR-2.2 | Epic 2 | Top 100 Configurations |
| FR-2.4 | Epic 2 | Configuration Prioritization |
| FR-6.1 | Epic 3 | CLI Subcommand Structure |
| FR-6.2 | Epic 3 | Required Arguments |
| FR-6.3 | Epic 3 | Optional Arguments |
| FR-6.4 | Epic 3 | Progress Reporting |
| FR-6.5 | Epic 3 | Results Output (+ coverage disclaimer) |
| FR-6.6 | Epic 3 | Error Handling |
| FR-5.1 | Epic 4 | Randstorm Test Vectors |
| FR-5.2 | Epic 4 | Integration Tests |
| FR-5.3 | Epic 4 | Performance Benchmarks |
| FR-5.4 | Epic 4 | Regression Tests |
| FR-5.5 | Epic 4 | FP/FN Validation |
| FR-7.1 | Epic 5 | Disclosure Protocol |
| FR-7.2 | Epic 5 | Findings Report Format |
| FR-7.3 | Epic 5 | Private Key Handling (architectural constraint) |
| FR-7.4 | Epic 5 | Ethical Use Guidelines |
| FR-7.5 | Epic 5 | Coordination Support |
| FR-13.1 | Epic 6 | Target Database Backend |
| FR-13.2 | Epic 6 | Milk Sad Integration |
| FR-13.3 | Epic 6 | Nonce Reuse Forensics |
| FR-13.4 | Epic 6 | Brainwallet Pipeline |
| FR-13.5 | Epic 7 | WGPU Port (with OpenCL parity requirement) |

**Coverage:** 30/30 Phase 1+13 FRs mapped (100%)

## Epic List

**Pre-mortem Analysis Applied:** Epic structure refined to prevent sequencing issues, validation gaps, ethics afterthoughts, and WGPU divergence risks.

---

### Epic 1: Core Scanning Engine

**User Outcome:** Security researchers can scan Bitcoin addresses for Chrome V8 PRNG vulnerabilities using GPU acceleration with CPU fallback, producing verified address matches.

**FRs Covered:** FR-1.1, FR-3.1, FR-4.1, FR-4.2, FR-4.3, FR-4.6

**Value Delivered:**
- MWC1616 PRNG reconstruction (exact Chrome V8 constants)
- P2PKH address derivation from PRNG entropy (merged from old Epic 3)
- GPU-accelerated scanning (10x+ speedup)
- Automatic CPU fallback when GPU unavailable
- Data contract for Phase 13 compatibility (scan result output format)

**Architectural Constraints (from Epic 5):**
- Private keys in GPU `__local` memory only
- CPU path uses `zeroize` crate for sensitive buffers
- No private key logging or export

**Hardening Stories (from Red Team analysis):**
- **Story: Define Scan Result Data Contract v1.0**
  - AC: JSON schema published for scan results
  - AC: Breaking changes require major version bump
  - AC: Epic 3 and Epic 6 depend on contract, not implementation
- **Story: Implement PrivateKey Newtype with Zeroize**
  - AC: `PrivateKey` type has no `Display`, `Debug`, or `Serialize` impl
  - AC: CI grep scan rejects any logging call with "privkey" in scope
  - AC: Integration test verifies no private key appears in any log output

**User Feedback Stories (from Focus Group):**
- **Story: Performance SLA Definition** (HIGH priority)
  - AC: Document target throughput: X keys/second on reference hardware
  - AC: Benchmark included in CI with regression detection
  - AC: CLI displays actual keys/sec during scan
  - AC: README includes "Expected scan time for 100 addresses: Y minutes"
  - AC: Benchmark uses addresses with 0, 1, and multiple potential matches (Red Team R2)
  - AC: SLA measures full scan completion, not time-to-first-match (Red Team R2)
  - AC: Scanner finds ALL matching (fingerprint, timestamp) pairs, not just first (Red Team R2)
- **Story: Fast Mode for High-Probability Configs** (LOW priority)
  - AC: `--fast` flag scans only top 20 fingerprints (highest market share)
  - AC: Output includes warning: "Fast mode - reduced coverage"
  - AC: Estimated 3-5x speedup vs full scan

**Standalone:** Yes - complete scan-to-address pipeline

---

### Epic 2: Browser Fingerprint Intelligence

**User Outcome:** Security researchers can target scans using prioritized browser fingerprint database, testing most likely configurations first for maximum efficiency.

**FRs Covered:** FR-2.1, FR-2.2, FR-2.4

**Value Delivered:**
- Browser configuration schema (UA, screen, timezone, etc.)
- Top 100 fingerprint database (2011-2015 era)
- Market-share prioritization for efficient scanning
- Browser engine field for future Firefox/Safari expansion

**User Feedback Stories (from Focus Group):**
- **Story: Browser Hint Filter** (MEDIUM priority)
  - AC: `--browser-hint <chrome|firefox|safari>` filters fingerprint database
  - AC: `--year-hint <2011-2015>` narrows to fingerprints from that year
  - AC: Hints are combinable: `--browser-hint chrome --year-hint 2013`
  - AC: Invalid hints produce helpful error with valid options
  - AC: Use case: Client remembers "I used Firefox on Ubuntu in 2013"

**Architectural Decisions (from ADR analysis):**
- **ADR-002: Fingerprint Database Override Flag**
  - Decision: Embedded default with optional `--fingerprint-db <path>` override
  - AC: Default fingerprints embedded in binary (works out of box)
  - AC: `--fingerprint-db <path>` loads custom CSV for power users
  - AC: Custom DB validated against schema on load
  - AC: Sanity check warns if fingerprint distribution is suspiciously narrow (Red Team R2)
  - AC: Custom DB file hash logged for reproducibility/audit (Red Team R2)
  - Rationale: Works by default, flexible for researchers testing new configs

**Hardening (from Red Team Round 2):**
- **Browser Hint vs Filter Modes**
  - AC: `--browser-hint` PRIORITIZES matching fingerprints but scans ALL (default safe behavior)
  - AC: `--browser-filter` EXCLUDES non-matching (requires explicit flag for exclusion)
  - AC: Warning displayed when using filter mode: "Excluding fingerprints may cause false negatives"
  - Rationale: Prevent false negatives from overly narrow user hints

**Standalone:** Yes - fingerprint database usable independently; integrates with Epic 1

---

### Epic 3: CLI Interface & Batch Processing

**User Outcome:** Security researchers can use a complete CLI to batch-scan addresses from CSV files with real-time progress, results output, and coverage disclaimers.

**FRs Covered:** FR-6.1, FR-6.2, FR-6.3, FR-6.4, FR-6.5, FR-6.6

**Value Delivered:**
- `entropy-lab scan randstorm [OPTIONS]` subcommand (ADR-006)
- CSV input/output for batch processing
- Real-time progress with ETA
- Clear error handling and help text
- **Coverage disclaimer in output:** "Chrome V8 only - ~29% estimated coverage"

**User Feedback Stories (from Focus Group):**
- **Story: Streaming Output for Large Batches** (MEDIUM priority)
  - AC: Results written incrementally as discovered (not buffered until end)
  - AC: Memory usage stays constant regardless of input size
  - AC: Supports 10M+ address inputs without OOM
  - AC: `--output-mode streaming` enables line-by-line output
  - AC: Use case: Exchange scanning millions of customer addresses
- **Story: Quiet/JSON Mode for Scripting** (LOW priority)
  - AC: `--quiet` suppresses progress bars and disclaimers
  - AC: `--format json` outputs machine-parseable JSON per line (JSONL)
  - AC: Errors go to stderr, results to stdout
  - AC: Exit code indicates success/failure for automation
  - AC: Input validation rejects addresses containing control characters (Red Team R2)
  - AC: JSON output uses proper escaping library, not string concatenation (Red Team R2)
  - AC: Fuzz test: malformed CSV inputs never produce invalid JSON output (Red Team R2)

**Hardening (from Red Team Round 2):**
- **Streaming Output Timing Protection**
  - AC: `--shuffle-output` option randomizes result order before writing
  - AC: Documentation notes timing side-channel risk for high-security scenarios
  - Rationale: Prevent timing analysis from revealing which fingerprint/timestamp matched

**Architectural Decisions (from ADR analysis):**
- **ADR-004: Configurable Error Strictness**
  - Decision: Graceful by default, `--strict` for fail-fast
  - AC: Default: skip invalid CSV rows with warning, continue scanning
  - AC: `--strict` flag: fail immediately on first error
  - AC: Summary at end shows count of skipped rows with reasons
  - Rationale: Large batch friendly by default, strict mode for reproducibility
- **ADR-006: CLI Command Structure**
  - Decision: `entropy-lab scan randstorm` (grouped under scan subcommand)
  - AC: `entropy-lab scan --help` lists all available scanners
  - AC: Tab completion works naturally with nested structure
  - Rationale: Scales well as scanner count grows, discoverable

**Dependencies:** Requires Epic 1 (scanning) and Epic 2 (fingerprints) to be stable

**Standalone:** Yes - complete user interface to scanner capabilities

---

### Epic 4: Release Certification & Validation

**User Outcome:** Security researchers can trust scanner accuracy through validated test vectors, verified GPU/CPU parity, and performance benchmarks meeting release criteria.

**FRs Covered:** FR-5.1, FR-5.2, FR-5.3, FR-5.4, FR-5.5

**Value Delivered:**
- 100% validation on Randstorm disclosure test vectors
- GPU/CPU bit-parity verification (mandatory for release)
- Performance benchmarks (10x GPU speedup gate)
- Regression tests for existing 18 scanners
- <1% FP, <5% FN certification

**Hardening Stories (from Red Team analysis):**
- **Story: Test Vector Cross-Validation**
  - AC: Vectors validated against 3 independent sources (Unciphered disclosure, CryptoDeepTools Python, synthetic wallet)
  - AC: Synthetic wallet generated with known seed, scanned successfully
  - AC: Vector provenance documented (source, date, verification method)
  - AC: No "validation theater" - vectors are independently verified, not assumed correct

**User Feedback Stories (from Focus Group):**
- **Story: Deterministic/Reproducible Builds** (HIGH priority)
  - AC: `Cargo.lock` committed and pinned for all dependencies
  - AC: `--seed <N>` flag for deterministic PRNG initialization in tests
  - AC: Same inputs + same seed = byte-identical outputs across machines
  - AC: Build instructions include exact Rust toolchain version
  - AC: Use case: Academic researchers reproducing results for peer review
  - AC: `--seed` flag only available in debug builds or with `--features test-reproducibility` (Red Team R2)
  - AC: Release builds have no user-controllable PRNG seeding (Red Team R2)
  - AC: Documentation warns: seed flag is for testing only, not production (Red Team R2)
- **Story: Scanner Isolation Test** (LOW priority)
  - AC: Adding new scanner cannot affect existing scanner outputs
  - AC: CI test runs all scanners before/after new scanner addition
  - AC: Output diff must be empty for unrelated scanners

**Architectural Decisions (from ADR analysis):**
- **ADR-005: Test Data Management**
  - Decision: Test vectors in-repo with schema versioning
  - AC: Vectors stored in `tests/fixtures/randstorm_vectors.json`
  - AC: Schema includes `version` field for future migration
  - AC: Each vector includes provenance (source, date, verification method)
  - Rationale: Simple for Phase 1, scalable pattern for growth

**Quality Gate:** This epic serves as release certification - blocks release until all criteria pass

**Standalone:** Yes - validation gate for all prior epics

---

### Epic 5: Ethical Framework & Documentation (Parallel Track)

**User Outcome:** Security researchers have proper ethical guidelines, disclosure protocols, and documentation for responsible use from day one.

**FRs Covered:** FR-7.1, FR-7.2, FR-7.3, FR-7.4, FR-7.5

**Value Delivered:**
- Responsible disclosure documentation (90-day window)
- Findings report templates
- SECURITY.md with legal warnings
- Ethical use guidelines and disclaimers
- Exchange/wallet owner notification templates

**Execution Note:** This epic runs in PARALLEL starting Sprint 1, not after code epics complete. Security constraints (FR-7.3) are architectural and embedded in Epic 1.

**Sprint-Gated Deliverables (from Red Team analysis):**
| Sprint | Required Deliverable |
|--------|---------------------|
| Sprint 1 | SECURITY.md skeleton with legal warnings |
| Sprint 2 | Disclosure protocol documentation |
| Sprint 3 | Legal review STARTED (not completed) |
| Sprint 4 | Report templates finalized |
| Release Gate | Legal sign-off received |

**Constraint:** One Epic 5 story must complete per sprint - documentation is not optional.

**User Feedback Stories (from Focus Group):**
- **Story: Client-Facing Vulnerability Guide** (MEDIUM priority)
  - AC: Non-technical document: "What to do if your wallet is vulnerable"
  - AC: Plain language, no jargon, actionable steps
  - AC: Includes: Don't panic, secure funds, report to exchange, timeline
  - AC: PDF-exportable for wallet recovery specialists to share with clients
  - AC: Use case: Raj sends guide to grandmother who lost savings
- **Story: Audit Trail for Compliance** (LOW priority)
  - AC: Optional `--audit-log <file>` records all scan operations
  - AC: Log includes: timestamp, user, addresses scanned, results, duration
  - AC: Log is append-only, tamper-evident (hash chain)
  - AC: Use case: Exchange proving to regulators they scanned for vulnerabilities
  - AC: Document limitation: local audit trail is best-effort, not forensically tamper-proof (Red Team R2)
  - AC: Optional `--audit-anchor <url>` for external timestamp anchoring (Phase 2) (Red Team R2)
  - AC: Log file permissions set to append-only where OS supports (Red Team R2)

**Standalone:** Yes - documentation framework independent of code delivery

---

### Epic 6: Target Intelligence Infrastructure (Phase 13)

**User Outcome:** Security researchers can maintain persistent target databases and apply specialized vulnerability detection (Milk Sad, nonce reuse, brainwallet).

**FRs Covered:** FR-13.1, FR-13.2, FR-13.3, FR-13.4

**Value Delivered:**
- SQLite target database (1M+ addresses, <10ms lookup)
- Milk Sad weak seed detection
- ECDSA nonce reuse forensics
- Brainwallet passphrase scanning

**Data Contract:** Uses scan result format from Epic 1 for database ingestion

**Hardening Stories (from Red Team analysis):**
- **Story: Vulnerability Scanner Isolation**
  - AC: `VulnerabilityClass` enum with distinct variants (`Randstorm`, `MilkSad`, `NonceReuse`, `Brainwallet`)
  - AC: Each scanner validates only its own test vectors
  - AC: Database schema includes `vuln_class` column with constraint
  - AC: CLI `--vuln-type` flag prevents accidental cross-scanning
  - AC: No cross-contamination of vulnerability classifications

**Standalone:** Yes - builds on Phase 1 foundation; requires Epic 1 data contract

---

### Epic 7: Cross-Platform GPU via WGPU (Phase 13)

**User Outcome:** Security researchers on Apple Silicon and other platforms can use native GPU acceleration via Metal/Vulkan/DX12 with guaranteed result parity.

**FRs Covered:** FR-13.5

**Value Delivered:**
- WGSL ports of MWC1616, SHA256, RIPEMD160 kernels
- Native Apple Metal support
- Cross-platform GPU compatibility (Vulkan, DX12)

**Parity Requirement:** 100% bit-identical output to OpenCL backend (mandatory AC)

**Hardening Stories (from Red Team analysis):**
- **Story: WGPU Parity CI Gate**
  - AC: CI runs 10,000 seeds through both OpenCL and WGPU backends
  - AC: Any bit divergence = build failure, merge blocked
  - AC: Feature flag `wgpu` can be disabled to ship OpenCL-only if parity unachievable
  - AC: **NO `--allow-divergence` flag exists in codebase** (escape hatch forbidden)
  - AC: Parity test runs on every PR touching GPU code

**Architectural Decisions (from ADR analysis):**
- **ADR-001: GPU Backend Strategy**
  - Decision: Separate implementations with mandatory parity CI gate
  - AC: OpenCL and WGPU are separate codebases with shared test vectors
  - AC: WGPU feature-flagged, disabled if parity unachievable
  - Rationale: Ship Phase 1 fast with OpenCL, WGPU gated by parity in Phase 13

**Standalone:** Yes - alternative GPU backend; OpenCL remains functional

---

## Architectural Decision Record Summary

| ADR | Decision | Applied To |
|-----|----------|------------|
| ADR-001 | Separate GPU backends + parity gate | Epic 7 |
| ADR-002 | Embedded fingerprints + override flag | Epic 2 |
| ADR-004 | Graceful errors by default, `--strict` option | Epic 3 |
| ADR-005 | Test vectors in-repo with schema version | Epic 4 |
| ADR-006 | `entropy-lab scan randstorm` CLI structure | Epic 3 |

---

# Detailed Epic Stories

## Epic 1: Core Scanning Engine - Stories

### Story 1.1: MWC1616 PRNG Implementation

As a **security researcher**,
I want the scanner to exactly replicate Chrome V8's MWC1616 Math.random() algorithm,
So that I can reconstruct the PRNG state used by vulnerable BitcoinJS wallets (2011-2015).

**Acceptance Criteria:**

**Given** a known MWC1616 seed pair (s1, s2)
**When** the PRNG generates the next random value
**Then** the output matches the formula: `s1 = 18000 * (s1 & 0xFFFF) + (s1 >> 16)`, `s2 = 30903 * (s2 & 0xFFFF) + (s2 >> 16)`, result = `(s1 << 16) + (s2 & 0xFFFF)`
**And** 1000 consecutive outputs match reference V8 implementation byte-for-byte

**Given** a timestamp in milliseconds (Unix epoch)
**When** the PRNG is seeded from timestamp
**Then** the seed derivation matches Chrome V8's seeding algorithm for the 2011-2015 era
**And** the same timestamp always produces identical PRNG sequences

**Given** the MWC1616 implementation
**When** compiled in release mode
**Then** all arithmetic uses wrapping u32 operations (no overflow panics)
**And** no floating-point operations are used (Integer Isolation Law)

---

### Story 1.2: ARC4 Key Derivation Pipeline

As a **security researcher**,
I want the scanner to replicate JSBN's SecureRandom ARC4 pool initialization,
So that I can derive the same private keys that vulnerable wallets generated.

**Acceptance Criteria:**

**Given** an initialized MWC1616 PRNG
**When** the ARC4 pool is seeded
**Then** Math.random() is called exactly 256 times to fill pool[0..255]
**And** each pool byte is computed as `(random() * 256) & 0xFF`

**Given** a seeded ARC4 pool
**When** 32 bytes are extracted for a private key
**Then** the ARC4 state machine (i, j swap) matches RFC 4345
**And** the output bytes match reference JSBN implementation

**Given** multiple private key requests from the same pool
**When** keys are derived sequentially
**Then** each key is different (ARC4 state advances)
**And** the sequence is deterministic for the same initial seed

---

### Story 1.3: P2PKH Address Generation

As a **security researcher**,
I want to derive Bitcoin P2PKH addresses from private keys,
So that I can compare generated addresses against target addresses for vulnerability detection.

**Acceptance Criteria:**

**Given** a 32-byte private key
**When** the address is derived
**Then** secp256k1 public key is computed (compressed format, 33 bytes)
**And** Hash160 is computed as RIPEMD160(SHA256(pubkey))
**And** P2PKH address is Base58Check encoded with version byte 0x00

**Given** known test vectors (privkey → address)
**When** addresses are generated
**Then** 100% of test vectors match expected addresses
**And** both compressed and uncompressed pubkey formats are supported

**Given** an invalid private key (zero, >= curve order)
**When** derivation is attempted
**Then** an error is returned (not a panic)
**And** the error message identifies the issue

---

### Story 1.4: OpenCL GPU Kernel Implementation

As a **security researcher**,
I want GPU-accelerated scanning using OpenCL,
So that I can achieve 10x+ speedup over CPU-only scanning.

**Acceptance Criteria:**

**Given** an OpenCL-capable GPU
**When** the scanner initializes
**Then** the GPU is detected and kernel is compiled
**And** work group size is auto-configured for the device (256 default)

**Given** a batch of (fingerprint, timestamp) candidates
**When** the GPU kernel executes
**Then** each work item processes one candidate independently
**And** matching addresses write (fingerprint_idx, timestamp) to result buffer
**And** atomic counter tracks result count

**Given** GPU execution completes
**When** results are read back
**Then** all matches are returned to the host
**And** private keys are NEVER transferred to host memory (GPU local only)

**Given** a batch of 1M+ candidates
**When** scanning executes
**Then** memory is managed via pinned buffers
**And** throughput meets Performance SLA (documented keys/sec)

---

### Story 1.5: CPU Fallback Implementation

As a **security researcher**,
I want automatic CPU fallback when GPU is unavailable,
So that I can run scans on any machine regardless of GPU availability.

**Acceptance Criteria:**

**Given** no OpenCL GPU is available
**When** the scanner starts
**Then** it automatically falls back to CPU mode
**And** a warning is displayed: "GPU unavailable, using CPU fallback (slower)"

**Given** CPU fallback mode
**When** scanning executes
**Then** Rayon parallel iterators are used for multi-core utilization
**And** the same (fingerprint, timestamp) candidates are tested as GPU mode

**Given** identical inputs
**When** CPU and GPU modes produce results
**Then** outputs are bit-identical (parity requirement)
**And** parity is verified in CI tests

**Given** CPU execution
**When** private keys are derived
**Then** `zeroize` crate is used to clear sensitive buffers
**And** no private keys appear in logs or error messages

---

### Story 1.6: Scan Result Data Contract v1.0

As a **developer**,
I want a versioned data contract for scan results,
So that Epic 3 (CLI) and Epic 6 (Target Intelligence) can depend on stable interfaces.

**Acceptance Criteria:**

**Given** a scan result
**When** serialized to JSON
**Then** the schema matches:
```json
{
  "schema_version": "1.0",
  "address": "1ABC...",
  "status": "vulnerable|not_found|error",
  "matches": [
    {
      "fingerprint_id": 42,
      "timestamp_ms": 1400000000000,
      "confidence": 0.95
    }
  ]
}
```
**And** the schema is documented in `docs/data-contract-v1.md`

**Given** a future schema change
**When** breaking changes are needed
**Then** schema_version is incremented to "2.0"
**And** migration guide is provided

**Given** Epic 6 Target Intelligence
**When** ingesting scan results
**Then** it reads schema_version and handles appropriately
**And** unknown schema versions produce clear error

---

### Story 1.7: PrivateKey Security Wrapper

As a **security researcher**,
I want private keys to be handled securely with no accidental exposure,
So that the tool maintains its ethical security posture.

**Acceptance Criteria:**

**Given** the `PrivateKey` newtype
**When** inspected
**Then** it has NO `Display`, `Debug`, or `Serialize` implementations
**And** attempting to log it produces a compile error

**Given** a `PrivateKey` instance
**When** it goes out of scope
**Then** `Zeroize` trait clears the memory
**And** memory is zeroed before deallocation

**Given** the codebase
**When** CI runs grep scan
**Then** no `println!`, `tracing::info!`, etc. contain "privkey" or "private_key"
**And** integration tests verify no private key appears in any output

**Given** a scan that finds a vulnerable address
**When** results are returned
**Then** only (fingerprint_id, timestamp_ms) are provided
**And** private key reconstruction requires external tool with those parameters

---

## Epic 1 Summary

| Story | Title | Status |
|-------|-------|--------|
| 1.1 | MWC1616 PRNG Implementation | Ready |
| 1.2 | ARC4 Key Derivation Pipeline | Ready |
| 1.3 | P2PKH Address Generation | Ready |
| 1.4 | OpenCL GPU Kernel Implementation | Ready |
| 1.5 | CPU Fallback Implementation | Ready |
| 1.6 | Scan Result Data Contract v1.0 | Ready |
| 1.7 | PrivateKey Security Wrapper | Ready |

**Total Stories:** 7
**FRs Covered:** FR-1.1, FR-3.1, FR-4.1, FR-4.2, FR-4.3, FR-4.6 ✓

---

## Epic 2: Browser Fingerprint Intelligence - Stories

### Story 2.1: Browser Fingerprint Schema

As a **security researcher**,
I want a well-defined schema for browser fingerprint configurations,
So that I can understand and extend the fingerprint database systematically.

**Acceptance Criteria:**

**Given** the `BrowserFingerprint` struct definition
**When** a fingerprint is loaded
**Then** it contains all required fields:
- `id: u32` - Unique identifier
- `user_agent: String` - Full UA string
- `screen_width: u16` - Screen resolution width
- `screen_height: u16` - Screen resolution height
- `color_depth: u8` - Color depth (typically 24 or 32)
- `timezone_offset: i16` - Minutes from UTC
- `language: String` - Browser language (e.g., "en-US")
- `platform: String` - OS platform string
- `market_share: f32` - Estimated market share (0.0-1.0)
- `year_min: u16` - Earliest year this config was common
- `year_max: u16` - Latest year this config was common
- `browser_engine: BrowserEngine` - Enum (ChromeV8, FirefoxSM, etc.)

**Given** a fingerprint with missing required fields
**When** deserialization is attempted
**Then** a clear error identifies the missing field
**And** the line number in the CSV is included

**Given** the schema
**When** documented
**Then** `docs/fingerprint-schema.md` explains each field's purpose and valid values

---

### Story 2.2: Top 100 Fingerprint Database

As a **security researcher**,
I want an embedded database of the top 100 browser configurations from 2011-2015,
So that I can scan for the most likely vulnerable wallet configurations out of the box.

**Acceptance Criteria:**

**Given** the embedded fingerprint database
**When** the scanner loads
**Then** exactly 100 fingerprints are available
**And** no external file is required

**Given** the fingerprint data
**When** reviewed for coverage
**Then** it includes:
- Chrome 20-40 on Windows 7 (1366x768, 1920x1080)
- Firefox 10-30 on Windows 7
- Safari 5-8 on macOS
- US/EU timezone configurations prioritized
**And** estimated coverage is 60-70% of 2011-2015 wallet sessions

**Given** the embedded CSV
**When** compiled into the binary
**Then** it is included via `include_str!()` macro
**And** the binary size increase is <100KB

**Given** each fingerprint entry
**When** validated
**Then** all fields pass schema validation
**And** year_min <= year_max for all entries

---

### Story 2.3: Market Share Prioritization

As a **security researcher**,
I want fingerprints sorted by market share descending,
So that I test the most likely configurations first for faster vulnerability detection.

**Acceptance Criteria:**

**Given** the fingerprint database
**When** loaded and sorted
**Then** fingerprints are ordered by `market_share` descending
**And** highest market share fingerprints are tested first

**Given** fingerprints with equal market share
**When** sorted
**Then** secondary sort is by `id` ascending (deterministic)
**And** sort order is reproducible across runs

**Given** a scan in progress
**When** a match is found early
**Then** higher market share configs are tested before lower
**And** progress reporting shows "Testing config X/100 (Chrome 30 Win7, 12% share)"

**Given** Performance SLA requirements
**When** fingerprints are processed
**Then** lookup and iteration is O(1) per fingerprint
**And** no runtime sorting required (pre-sorted at load)

---

### Story 2.4: Fingerprint Database Override

As a **power user**,
I want to provide a custom fingerprint database,
So that I can test configurations not in the default set or use updated research data.

**Acceptance Criteria:**

**Given** the `--fingerprint-db <path>` flag
**When** a valid CSV path is provided
**Then** custom fingerprints are loaded instead of embedded defaults
**And** schema validation is applied to all entries

**Given** a custom fingerprint database
**When** loaded successfully
**Then** the file hash (SHA256) is logged for reproducibility
**And** count of loaded fingerprints is displayed

**Given** a custom database with suspicious distribution
**When** >50% of fingerprints have identical timestamps or narrow year ranges
**Then** a warning is displayed: "Fingerprint distribution appears narrow - may cause false negatives"
**And** scanning proceeds with user acknowledgment

**Given** a malformed custom CSV
**When** loading fails
**Then** error message includes line number and field name
**And** scanner exits with non-zero status (no partial load)

**Given** no `--fingerprint-db` flag
**When** scanner starts
**Then** embedded defaults are used automatically
**And** no file system access is required

---

### Story 2.5: Browser Hint Filtering

As a **wallet recovery specialist**,
I want to filter fingerprints by browser and year hints from my client,
So that I can narrow the search space when the client remembers their browser.

**Acceptance Criteria:**

**Given** the `--browser-hint <chrome|firefox|safari>` flag
**When** provided
**Then** matching fingerprints are PRIORITIZED (tested first)
**And** non-matching fingerprints are still tested afterward (safe default)

**Given** the `--browser-filter <chrome|firefox|safari>` flag
**When** provided
**Then** ONLY matching fingerprints are tested (exclusive mode)
**And** warning is displayed: "Filter mode active - non-matching configs excluded, may cause false negatives"

**Given** the `--year-hint <2011-2015>` flag
**When** provided
**Then** fingerprints where year_min <= hint <= year_max are prioritized
**And** hints can be combined: `--browser-hint chrome --year-hint 2013`

**Given** an invalid hint value
**When** parsed
**Then** error lists valid options: "Invalid browser hint 'netscape'. Valid: chrome, firefox, safari"
**And** scanner exits with helpful message

**Given** hint and filter flags combined
**When** both `--browser-hint` and `--browser-filter` are provided
**Then** error: "Cannot use both --browser-hint and --browser-filter"
**And** user must choose one mode

---

## Epic 2 Summary

| Story | Title | Status |
|-------|-------|--------|
| 2.1 | Browser Fingerprint Schema | Ready |
| 2.2 | Top 100 Fingerprint Database | Ready |
| 2.3 | Market Share Prioritization | Ready |
| 2.4 | Fingerprint Database Override | Ready |
| 2.5 | Browser Hint Filtering | Ready |

**Total Stories:** 5
**FRs Covered:** FR-2.1, FR-2.2, FR-2.4 ✓

---

## Epic 3: CLI Interface & Batch Processing - Stories

### Story 3.1: CLI Command Structure

As a **security researcher**,
I want a well-organized CLI with intuitive subcommand structure,
So that I can easily discover and use scanner capabilities.

**Acceptance Criteria:**

**Given** the CLI binary `entropy-lab`
**When** the user runs `entropy-lab --help`
**Then** available subcommands are listed including `scan`
**And** version and description are displayed

**Given** the `scan` subcommand
**When** the user runs `entropy-lab scan --help`
**Then** available scanners are listed including `randstorm`
**And** each scanner has a brief description

**Given** the `randstorm` scanner
**When** the user runs `entropy-lab scan randstorm --help`
**Then** all options are documented with examples
**And** required vs optional arguments are clearly marked

**Given** shell completion
**When** tab completion is configured
**Then** `entropy-lab scan rand<TAB>` completes to `randstorm`
**And** option flags complete with `--<TAB>`

---

### Story 3.2: Target Address Input

As a **security researcher**,
I want to provide target addresses via CSV file,
So that I can batch-scan multiple addresses efficiently.

**Acceptance Criteria:**

**Given** the `--targets <file.csv>` argument
**When** a valid CSV is provided
**Then** addresses are parsed from the first column (or `address` header)
**And** duplicate addresses are deduplicated with warning

**Given** a CSV with headers
**When** `address` column exists
**Then** that column is used regardless of position
**And** other columns are ignored (but preserved in output)

**Given** a headerless CSV
**When** loaded
**Then** first column is assumed to be addresses
**And** warning suggests using headers for clarity

**Given** address validation
**When** each address is parsed
**Then** Base58Check and Bech32 formats are validated
**And** invalid addresses are reported with line numbers

**Given** control characters in input (Red Team R2)
**When** addresses contain newlines, tabs, or other control chars
**Then** they are rejected with clear error
**And** no injection into output is possible

---

### Story 3.3: Scan Options & Configuration

As a **security researcher**,
I want configurable scan options for GPU/CPU selection and performance tuning,
So that I can optimize scans for my hardware and use case.

**Acceptance Criteria:**

**Given** the `--gpu` flag (default)
**When** OpenCL GPU is available
**Then** GPU acceleration is used
**And** device name is logged at startup

**Given** the `--cpu` flag
**When** explicitly provided
**Then** CPU-only mode is forced even if GPU is available
**And** Rayon thread count matches `--threads` or system cores

**Given** the `--threads <N>` option
**When** provided with CPU mode
**Then** Rayon uses exactly N threads
**And** default is number of logical cores

**Given** the `--batch-size <N>` option
**When** provided
**Then** GPU processes N candidates per kernel invocation
**And** default is optimized for typical VRAM (1M candidates)

**Given** the `--phase <1|2|3>` option
**When** provided
**Then** fingerprint coverage is limited to that phase
**And** Phase 1 = top 100, Phase 2 = top 500, Phase 3 = all

---

### Story 3.4: Progress Reporting

As a **security researcher**,
I want real-time progress reporting with ETA,
So that I can monitor long-running scans and estimate completion time.

**Acceptance Criteria:**

**Given** a scan in progress
**When** running in interactive mode (TTY)
**Then** progress bar shows: `[=====>    ] 45% | 450/1000 addresses | ETA: 12:34`
**And** updates at least every second

**Given** progress reporting
**When** displaying current status
**Then** actual keys/sec throughput is shown
**And** current fingerprint being tested is displayed

**Given** a match found during scan
**When** result is discovered
**Then** immediate notification: `[HIT] 1ABC... vulnerable (Chrome 30, ts=1400000000)`
**And** progress continues without interruption

**Given** non-interactive mode (pipe, redirect)
**When** stdout is not a TTY
**Then** progress updates are suppressed or minimal
**And** only final results are written to stdout

**Given** the `--quiet` flag
**When** provided
**Then** all progress output is suppressed
**And** only results and errors are output

---

### Story 3.5: Results Output & Formatting

As a **security researcher**,
I want scan results in multiple formats with coverage disclaimers,
So that I can integrate results into my workflow and understand limitations.

**Acceptance Criteria:**

**Given** scan completion
**When** results are written
**Then** default format is CSV with headers:
`address,status,confidence,fingerprint_id,timestamp_ms,browser_config`

**Given** the `--format json` flag
**When** provided
**Then** output is JSON Lines (one JSON object per line)
**And** proper escaping is used (no string concatenation - Red Team R2)

**Given** the `--output <file>` flag
**When** provided
**Then** results are written to file instead of stdout
**And** file is created/overwritten with appropriate permissions

**Given** scan results output
**When** header is written
**Then** coverage disclaimer is included:
`# Coverage: Chrome V8 only (~29% estimated for 2011-2015 wallets)`
**And** phase and fingerprint count are noted

**Given** a vulnerable address found
**When** result is written
**Then** all matching (fingerprint_id, timestamp_ms) pairs are included
**And** confidence score reflects fingerprint market share

---

### Story 3.6: Error Handling & Strictness

As a **security researcher**,
I want configurable error handling with graceful defaults,
So that large batch scans don't abort on minor issues.

**Acceptance Criteria:**

**Given** default mode (graceful)
**When** an invalid address is encountered in CSV
**Then** warning is logged with line number
**And** scanning continues with remaining addresses

**Given** default mode
**When** GPU initialization fails
**Then** automatic fallback to CPU mode
**And** warning is displayed, scan continues

**Given** the `--strict` flag
**When** any error is encountered
**Then** scan aborts immediately with non-zero exit code
**And** error message identifies the problem

**Given** scan completion in graceful mode
**When** errors occurred
**Then** summary shows: `Completed: 998/1000 addresses (2 skipped due to errors)`
**And** skipped addresses are listed with reasons

**Given** exit codes
**When** scan completes
**Then** 0 = success, 1 = partial (some errors in graceful mode), 2 = fatal error
**And** exit code is documented in `--help`

---

### Story 3.7: Streaming & Large Batch Support

As an **exchange security team**,
I want to scan millions of addresses without memory exhaustion,
So that I can verify our entire customer address database.

**Acceptance Criteria:**

**Given** the `--output-mode streaming` flag
**When** results are found
**Then** they are written immediately (not buffered)
**And** memory usage stays constant regardless of input size

**Given** a 10M address input file
**When** scan executes
**Then** addresses are processed in streaming fashion
**And** no OOM occurs with default heap limits

**Given** streaming output
**When** multiple results are written
**Then** each result is a complete line (atomic writes)
**And** partial results never appear in output file

**Given** the `--shuffle-output` flag (Red Team R2)
**When** provided
**Then** results are collected and shuffled before writing
**And** timing side-channel is mitigated for high-security scenarios

**Given** a very large scan
**When** checkpoint is needed (future Phase 3)
**Then** streaming mode is compatible with checkpoint/resume
**And** no results are lost on graceful shutdown

---

## Epic 3 Summary

| Story | Title | Status |
|-------|-------|--------|
| 3.1 | CLI Command Structure | Ready |
| 3.2 | Target Address Input | Ready |
| 3.3 | Scan Options & Configuration | Ready |
| 3.4 | Progress Reporting | Ready |
| 3.5 | Results Output & Formatting | Ready |
| 3.6 | Error Handling & Strictness | Ready |
| 3.7 | Streaming & Large Batch Support | Ready |

**Total Stories:** 7
**FRs Covered:** FR-6.1, FR-6.2, FR-6.3, FR-6.4, FR-6.5, FR-6.6 ✓

---

## Epic 4: Release Certification & Validation - Stories

### Story 4.1: Randstorm Test Vector Suite

As a **security researcher**,
I want validated test vectors from the original Randstorm disclosure,
So that I can trust the scanner correctly identifies known vulnerable wallets.

**Acceptance Criteria:**

**Given** the test vector file `tests/fixtures/randstorm_vectors.json`
**When** loaded
**Then** schema version field is present (`"version": "1.0"`)
**And** each vector includes provenance (source, date, verification method)

**Given** vectors from Unciphered disclosure
**When** scanner processes them
**Then** 100% are correctly identified as vulnerable
**And** correct (fingerprint_id, timestamp_ms) are returned

**Given** cross-validation requirement (Red Team R1)
**When** vectors are added
**Then** they are validated against 3 independent sources:
- Unciphered original disclosure
- CryptoDeepTools Python implementation
- Synthetic wallet generated with known seed

**Given** a synthetic test wallet
**When** generated with known seed during CI
**Then** scanner detects it correctly
**And** derivation matches expected address

**Given** vector provenance documentation
**When** reviewed
**Then** each vector has: source URL, verification date, method used
**And** no "assumed correct" vectors exist

---

### Story 4.2: GPU/CPU Parity Verification

As a **developer**,
I want automated GPU/CPU parity tests,
So that I can guarantee bit-identical results regardless of execution backend.

**Acceptance Criteria:**

**Given** identical inputs (fingerprints, timestamps, target addresses)
**When** processed by GPU and CPU backends
**Then** outputs are bit-identical
**And** any divergence fails the test

**Given** the parity test suite
**When** executed in CI
**Then** at least 10,000 random seeds are tested
**And** test completes in <5 minutes

**Given** a new PR touching GPU kernel code
**When** CI runs
**Then** parity tests are mandatory
**And** merge is blocked on any divergence

**Given** parity test failure
**When** divergence is detected
**Then** exact seed and expected/actual values are logged
**And** debugging information identifies the divergent operation

**Given** the Integer Isolation Law
**When** kernels are reviewed
**Then** no floating-point operations exist in PRNG or crypto code
**And** all arithmetic uses wrapping u32/u64

---

### Story 4.3: Performance Benchmarks

As a **security researcher**,
I want documented performance benchmarks,
So that I can estimate scan times and verify the tool meets its SLA.

**Acceptance Criteria:**

**Given** the benchmark suite
**When** executed on reference hardware
**Then** throughput is measured in keys/second
**And** results are reproducible (±5% variance)

**Given** Performance SLA
**When** benchmarks complete
**Then** GPU mode achieves ≥10x speedup vs CPU
**And** specific keys/sec target is documented in README

**Given** benchmark CI job
**When** PR is submitted
**Then** performance regression is detected (>10% slowdown)
**And** warning is raised for review

**Given** benchmark addresses (Red Team R2)
**When** testing
**Then** mix includes: 0 matches, 1 match, multiple matches
**And** full scan completion is measured (not time-to-first-match)

**Given** benchmark results
**When** documented
**Then** reference hardware specs are included
**And** expected scan time for 100 addresses is stated

---

### Story 4.4: Regression Test Suite

As a **developer**,
I want regression tests for all existing scanners,
So that Randstorm changes don't break the other 18 scanners.

**Acceptance Criteria:**

**Given** the 18 existing scanners
**When** Randstorm code is modified
**Then** all existing scanner tests pass
**And** no behavioral changes in unrelated scanners

**Given** scanner isolation test (Focus Group)
**When** new scanner is added
**Then** CI runs all scanners before/after
**And** output diff is empty for unrelated scanners

**Given** shared infrastructure changes
**When** GPU solver or crypto libs are modified
**Then** all scanner test suites run
**And** any failure blocks merge

**Given** test coverage metrics
**When** measured
**Then** critical paths have >80% coverage
**And** coverage report is generated in CI

---

### Story 4.5: False Positive/Negative Validation

As a **security researcher**,
I want validated accuracy metrics,
So that I can trust the scanner's results and understand its limitations.

**Acceptance Criteria:**

**Given** known vulnerable addresses (true positives)
**When** scanned
**Then** detection rate is ≥95% (false negative rate <5%)
**And** any misses are investigated and documented

**Given** known secure addresses (post-2015, proper entropy)
**When** scanned
**Then** false positive rate is <1%
**And** no secure addresses are incorrectly flagged

**Given** accuracy test suite
**When** run in CI
**Then** FP and FN rates are calculated
**And** release is blocked if thresholds are exceeded

**Given** accuracy report
**When** generated
**Then** includes: total tested, TP, TN, FP, FN, rates
**And** confidence intervals are provided

**Given** edge cases
**When** tested
**Then** boundary timestamps, unusual fingerprints are covered
**And** behavior at limits is documented

---

### Story 4.6: Deterministic Build & Reproducibility

As an **academic researcher**,
I want deterministic, reproducible builds and test runs,
So that I can verify results for peer-reviewed publications.

**Acceptance Criteria:**

**Given** the repository
**When** cloned and built
**Then** `Cargo.lock` pins all dependency versions
**And** build instructions specify exact Rust toolchain version

**Given** the `--seed <N>` flag (debug builds only - Red Team R2)
**When** provided in test mode
**Then** PRNG initialization is deterministic
**And** same inputs + same seed = identical outputs

**Given** release builds
**When** compiled without test features
**Then** `--seed` flag is not available
**And** no user-controllable PRNG seeding exists

**Given** reproducibility test
**When** same inputs are run on different machines
**Then** outputs are byte-identical
**And** CI tests this across multiple runners

**Given** documentation
**When** building for reproducibility
**Then** exact commands are provided
**And** Docker image option is available for environment consistency

---

## Epic 4 Summary

| Story | Title | Status |
|-------|-------|--------|
| 4.1 | Randstorm Test Vector Suite | Ready |
| 4.2 | GPU/CPU Parity Verification | Ready |
| 4.3 | Performance Benchmarks | Ready |
| 4.4 | Regression Test Suite | Ready |
| 4.5 | False Positive/Negative Validation | Ready |
| 4.6 | Deterministic Build & Reproducibility | Ready |

**Total Stories:** 6
**FRs Covered:** FR-5.1, FR-5.2, FR-5.3, FR-5.4, FR-5.5 ✓
**Quality Gate:** All stories must pass before release

---

## Epic 5: Ethical Framework & Documentation - Stories

**Execution Note:** This epic runs in PARALLEL with code epics, starting Sprint 1.

### Story 5.1: SECURITY.md & Legal Warnings

As a **security researcher**,
I want clear ethical guidelines and legal warnings,
So that I understand the boundaries of authorized use before running the tool.

**Acceptance Criteria:**

**Given** the repository root
**When** viewed
**Then** `SECURITY.md` exists with prominent placement
**And** it is linked from README.md

**Given** SECURITY.md content
**When** read
**Then** it includes:
- Authorized use statement (white-hat only)
- Legal warnings (CFAA, international laws)
- Explicit prohibition of unauthorized access
- Requirement for explicit permission on target addresses
- Disclaimer of liability

**Given** the CLI tool
**When** first run
**Then** disclaimer is displayed: "For authorized security research only"
**And** user must acknowledge (or use `--accept-terms` flag)

**Given** ethical guidelines
**When** reviewed by legal counsel
**Then** sign-off is obtained before release
**And** sign-off date is documented

**Sprint Gate:** Sprint 1 - Skeleton with legal warnings complete

---

### Story 5.2: Responsible Disclosure Protocol

As a **security researcher**,
I want documented disclosure protocols,
So that I can coordinate responsibly with affected parties when vulnerabilities are found.

**Acceptance Criteria:**

**Given** `docs/DISCLOSURE.md`
**When** read
**Then** 90-day coordinated disclosure timeline is explained
**And** steps for responsible disclosure are documented

**Given** disclosure protocol
**When** followed
**Then** researcher knows:
1. Who to contact first (wallet owner, exchange, etc.)
2. How long to wait before public disclosure
3. What information to include in initial report
4. How to handle non-responsive parties

**Given** affected party types
**When** documented
**Then** guidance covers: individual wallet owners, exchanges, wallet software vendors
**And** escalation paths are provided

**Given** disclosure success stories
**When** available
**Then** anonymized examples are included
**And** lessons learned are documented

**Sprint Gate:** Sprint 2 - Disclosure protocol documentation complete

---

### Story 5.3: Findings Report Template

As a **wallet recovery specialist**,
I want a standardized report template,
So that I can document findings professionally for clients and affected parties.

**Acceptance Criteria:**

**Given** `docs/templates/vulnerability-report.md`
**When** used
**Then** template includes:
- Executive summary section
- Affected address(es)
- Vulnerability classification (Randstorm, etc.)
- Risk level (Critical/High/Medium/Low)
- Technical details (fingerprint, timestamp range)
- Recommended actions
- Disclosure timeline

**Given** the report template
**When** filled out
**Then** sensitive data placeholders are clearly marked
**And** instructions explain what to redact for different audiences

**Given** multiple output formats
**When** needed
**Then** template works in Markdown, exportable to PDF
**And** professional formatting is maintained

**Given** report generation
**When** automated (future)
**Then** CLI can generate report skeleton from scan results
**And** `--generate-report` flag populates template

**Sprint Gate:** Sprint 4 - Report templates finalized

---

### Story 5.4: Exchange Notification Templates

As a **security researcher**,
I want email templates for notifying exchanges,
So that I can professionally communicate discovered vulnerabilities.

**Acceptance Criteria:**

**Given** `docs/templates/exchange-notification.txt`
**When** read
**Then** professional email template is provided
**And** placeholders for specific details are marked

**Given** the notification template
**When** used
**Then** it includes:
- Subject line template
- Professional introduction
- Vulnerability summary (non-technical)
- Technical details section
- Requested actions
- Timeline for response
- Contact information

**Given** different recipient types
**When** considered
**Then** templates exist for:
- Exchange security teams
- Wallet software vendors
- Individual wallet owners (simplified)

**Given** follow-up templates
**When** no response received
**Then** 30-day and 60-day follow-up templates exist
**And** escalation guidance is provided

---

### Story 5.5: Client-Facing Vulnerability Guide

As a **wallet recovery specialist**,
I want a non-technical guide for affected clients,
So that I can help them understand and respond to vulnerabilities without causing panic.

**Acceptance Criteria:**

**Given** `docs/guides/what-to-do-if-vulnerable.md`
**When** read by a non-technical person
**Then** no jargon is used (or jargon is explained)
**And** steps are clear and actionable

**Given** the guide content
**When** reviewed
**Then** it includes:
1. "Don't Panic" reassurance section
2. Explanation of what vulnerability means (simple terms)
3. Step-by-step: secure your funds (move to new wallet)
4. How to create a secure new wallet
5. Timeline: how urgent is this?
6. Who to contact for help
7. What NOT to do (don't share private keys, etc.)

**Given** the guide format
**When** exported
**Then** PDF version is available
**And** formatting is professional and reassuring

**Given** client handoff
**When** specialist shares guide
**Then** it can be emailed as standalone document
**And** no scanner branding that might alarm client

---

### Story 5.6: Audit Trail Implementation

As an **exchange compliance officer**,
I want audit logging of all scan operations,
So that I can demonstrate due diligence to regulators.

**Acceptance Criteria:**

**Given** the `--audit-log <file>` flag
**When** provided
**Then** all scan operations are logged to file
**And** file is created if it doesn't exist

**Given** audit log entries
**When** written
**Then** each entry includes:
- ISO 8601 timestamp
- User/machine identifier
- Addresses scanned (count and sample)
- Results summary (vulnerable/safe/error counts)
- Scan duration
- Configuration used

**Given** audit log format
**When** designed
**Then** entries are JSON Lines (machine-parseable)
**And** hash chain links entries (tamper-evident)

**Given** audit log limitations (Red Team R2)
**When** documented
**Then** "best-effort, not forensically tamper-proof" is noted
**And** external anchoring option mentioned for Phase 2

**Given** log file permissions
**When** created on supported OS
**Then** append-only mode is set where available
**And** permissions restrict modification

---

## Epic 5 Summary

| Story | Title | Sprint Gate | Status |
|-------|-------|-------------|--------|
| 5.1 | SECURITY.md & Legal Warnings | Sprint 1 | Ready |
| 5.2 | Responsible Disclosure Protocol | Sprint 2 | Ready |
| 5.3 | Findings Report Template | Sprint 4 | Ready |
| 5.4 | Exchange Notification Templates | Sprint 3 | Ready |
| 5.5 | Client-Facing Vulnerability Guide | Sprint 4 | Ready |
| 5.6 | Audit Trail Implementation | Sprint 4 | Ready |

**Total Stories:** 6
**FRs Covered:** FR-7.1, FR-7.2, FR-7.3, FR-7.4, FR-7.5 ✓
**Release Gate:** Legal sign-off required

---

## Epic 6: Target Intelligence Infrastructure - Stories

**Phase:** 13 - Advanced Vulnerability Intelligence

### Story 6.1: SQLite Target Database

As a **security researcher**,
I want persistent SQLite storage for target addresses,
So that I can maintain and query large address databases efficiently across sessions.

**Acceptance Criteria:**

**Given** the target database module
**When** initialized
**Then** SQLite database is created at `data/targets.db`
**And** schema includes: `address TEXT PRIMARY KEY`, `vuln_class TEXT`, `source TEXT`, `added_at TIMESTAMP`, `last_scanned TIMESTAMP`, `status TEXT`

**Given** a database with 1,000,000+ addresses
**When** querying by address
**Then** lookup completes in <10ms (NFR-13.1)
**And** index on `address` column is used

**Given** address insertion
**When** adding new targets
**Then** batch inserts support 10,000 addresses per transaction
**And** duplicate addresses are handled via UPSERT (update existing)

**Given** database migration needs
**When** schema changes in future versions
**Then** migration scripts exist in `migrations/`
**And** version table tracks applied migrations

**Given** concurrent access
**When** multiple processes access database
**Then** WAL mode is enabled for concurrent reads
**And** write locks are handled gracefully with retry

---

### Story 6.2: Database Import CLI

As a **security researcher**,
I want CLI commands to import and manage target addresses,
So that I can build and maintain my target database efficiently.

**Acceptance Criteria:**

**Given** the `entropy-lab targets import <file.csv>` command
**When** a valid CSV is provided
**Then** addresses are imported to the target database
**And** count of imported/updated/skipped addresses is displayed

**Given** import with `--vuln-class <type>` flag
**When** specified
**Then** all imported addresses are tagged with that vulnerability class
**And** valid classes are: `randstorm`, `milksad`, `nonce-reuse`, `brainwallet`, `unknown`

**Given** the `entropy-lab targets list` command
**When** executed
**Then** summary statistics are displayed: total, by vuln_class, by status
**And** `--limit N` shows first N addresses with details

**Given** the `entropy-lab targets export <file.csv>` command
**When** executed
**Then** all addresses are exported with metadata
**And** filters apply: `--status vulnerable`, `--vuln-class randstorm`

**Given** the `entropy-lab targets clear` command
**When** executed with `--confirm` flag
**Then** all addresses are removed from database
**And** without `--confirm`, error prompts for confirmation

**Given** import validation
**When** processing addresses
**Then** invalid formats are skipped with warning
**And** summary shows skipped count and reasons

---

### Story 6.3: Milk Sad Integration

As a **security researcher**,
I want to detect Libbitcoin bx 3.x Milk Sad vulnerabilities,
So that I can identify wallets generated with weak seeds from the 2023 disclosure.

**Acceptance Criteria:**

**Given** the Milk Sad scanner module
**When** analyzing a seed
**Then** bx 3.x weak randomness patterns are detected
**And** PRNG state reconstruction uses documented Milk Sad methodology

**Given** Milk Sad test vectors
**When** validated
**Then** all disclosed vulnerable addresses are detected
**And** test vectors include provenance from original disclosure

**Given** address derivation from Milk Sad seeds
**When** deriving addresses
**Then** both P2PKH and P2WPKH formats are supported
**And** standard BIP44/84 derivation paths are used

**Given** a database scan
**When** `entropy-lab scan milksad --targets db` is run
**Then** only addresses tagged `milksad` or `unknown` are scanned
**And** results update database status

**Given** Milk Sad vulnerability classification
**When** a match is found
**Then** result includes `vuln_class: milksad`
**And** no cross-contamination with Randstorm results

**Given** GPU acceleration
**When** available
**Then** Milk Sad scan uses GPU for PRNG reconstruction
**And** CPU fallback works identically

---

### Story 6.4: Nonce Reuse Forensics

As a **security researcher**,
I want ECDSA nonce reuse detection from blockchain signatures,
So that I can identify private keys extractable from faulty signing implementations.

**Acceptance Criteria:**

**Given** the nonce reuse scanner
**When** analyzing transaction signatures
**Then** signatures with shared k-values are detected
**And** private key recovery formula is applied: `d = (z1 - z2) / (s1 - s2) mod n`

**Given** signature pair input
**When** two transactions share the same nonce
**Then** private key is recovered mathematically
**And** recovery is verified by re-deriving the public key

**Given** transaction data input format
**When** providing signatures
**Then** scanner accepts: `txid, vin, signature_r, signature_s, sighash`
**And** input can be CSV or JSON

**Given** blockchain data integration (future)
**When** connected to a node
**Then** scanner can fetch signatures directly
**And** batch processing scans entire address history

**Given** nonce reuse detection
**When** a vulnerability is found
**Then** result includes `vuln_class: nonce-reuse`
**And** affected transaction IDs are listed

**Given** test vectors
**When** validated
**Then** known nonce reuse cases are detected
**And** false positives from similar-looking signatures are avoided

---

### Story 6.5: Brainwallet Scanner

As a **security researcher**,
I want passphrase-based brainwallet detection,
So that I can identify addresses generated from weak or leaked passphrases.

**Acceptance Criteria:**

**Given** the brainwallet scanner
**When** processing a passphrase
**Then** SHA256(passphrase) is computed as private key
**And** P2PKH address is derived using standard secp256k1

**Given** a wordlist file
**When** `--wordlist <file>` is provided
**Then** each line is tested as a passphrase
**And** progress shows passphrases/second throughput

**Given** common password lists
**When** embedded defaults are used
**Then** top 10,000 leaked passwords are included
**And** `--wordlist` overrides or supplements defaults

**Given** a target address list
**When** comparing against derived addresses
**Then** Bloom filter provides fast negative filtering
**And** positive matches are verified precisely

**Given** brainwallet vulnerability
**When** detected
**Then** result includes: address, passphrase (redacted preview), `vuln_class: brainwallet`
**And** passphrase is NOT logged in full by default

**Given** GPU acceleration
**When** available
**Then** SHA256 and address derivation use GPU
**And** throughput exceeds 1M passphrases/second

**Given** the `--show-passphrase` flag
**When** provided
**Then** full passphrase is included in output
**And** warning about sensitivity is displayed

---

### Story 6.6: Vulnerability Class Isolation

As a **developer**,
I want strict isolation between vulnerability scanners,
So that there is no cross-contamination of results or test vectors.

**Acceptance Criteria:**

**Given** the `VulnerabilityClass` enum
**When** defined
**Then** distinct variants exist: `Randstorm`, `MilkSad`, `NonceReuse`, `Brainwallet`, `Unknown`
**And** enum is `#[non_exhaustive]` for future additions

**Given** scanner implementations
**When** returning results
**Then** each scanner sets its own `vuln_class` only
**And** no scanner can report a different class

**Given** the target database schema
**When** storing results
**Then** `vuln_class` column has CHECK constraint
**And** only valid enum values are accepted

**Given** test vector organization
**When** structured
**Then** separate files: `randstorm_vectors.json`, `milksad_vectors.json`, etc.
**And** each scanner validates only its own vectors

**Given** CLI `--vuln-type <type>` flag
**When** provided
**Then** only that scanner type runs
**And** database queries filter by vuln_class

**Given** combined scan output
**When** multiple vuln types are found for same address
**Then** each is listed as separate result entry
**And** no merging or deduplication of classifications

**Given** code review
**When** new scanner is added
**Then** checklist requires VulnerabilityClass assignment
**And** cross-scanner contamination is rejected

---

## Epic 6 Summary

| Story | Title | Status |
|-------|-------|--------|
| 6.1 | SQLite Target Database | Ready |
| 6.2 | Database Import CLI | Ready |
| 6.3 | Milk Sad Integration | Ready |
| 6.4 | Nonce Reuse Forensics | Ready |
| 6.5 | Brainwallet Scanner | Ready |
| 6.6 | Vulnerability Class Isolation | Ready |

**Total Stories:** 6
**FRs Covered:** FR-13.1, FR-13.2, FR-13.3, FR-13.4 ✓
**Dependencies:** Requires Epic 1 data contract for database ingestion

---

## Epic 7: Cross-Platform GPU via WGPU - Stories

**Phase:** 13 - Modern GPU Backend for Apple Silicon & Cross-Platform

### Story 7.1: WGSL MWC1616 Kernel Port

As a **security researcher on Apple Silicon**,
I want the MWC1616 PRNG implemented in WGSL,
So that I can run GPU-accelerated scans natively on Metal without OpenCL.

**Acceptance Criteria:**

**Given** the WGSL MWC1616 implementation
**When** generating random values
**Then** algorithm matches OpenCL exactly: `s1 = 18000 * (s1 & 0xFFFFu) + (s1 >> 16u)`
**And** all arithmetic uses `u32` with explicit wrapping semantics

**Given** a seed pair (s1, s2)
**When** 10,000 values are generated
**Then** output is bit-identical to OpenCL backend
**And** no divergence detected in any iteration

**Given** WGSL language constraints
**When** implementing PRNG
**Then** no floating-point operations are used (Integer Isolation Law)
**And** explicit bitwise operations replace implicit conversions

**Given** the kernel file location
**When** organized
**Then** WGSL source lives at `wgsl/mwc1616.wgsl`
**And** comments document OpenCL equivalent for each operation

**Given** test vectors
**When** validating WGSL implementation
**Then** shared vectors from `tests/fixtures/prng_vectors.json` are used
**And** same vectors test both OpenCL and WGSL

---

### Story 7.2: WGSL SHA256 Kernel Port

As a **security researcher**,
I want SHA256 hashing in WGSL,
So that address derivation works natively on Metal/Vulkan/DX12.

**Acceptance Criteria:**

**Given** the WGSL SHA256 implementation
**When** hashing arbitrary data
**Then** output matches FIPS 180-4 specification exactly
**And** test vectors from NIST are 100% passing

**Given** public key input (33 bytes compressed)
**When** SHA256 hash is computed
**Then** output matches OpenCL implementation bit-for-bit
**And** endianness is handled consistently

**Given** WGSL memory model
**When** processing input
**Then** padding and length encoding follow SHA256 spec
**And** message schedule uses workgroup memory for efficiency

**Given** batch processing
**When** multiple hashes are computed
**Then** each workgroup processes one hash independently
**And** throughput scales linearly with GPU compute units

**Given** the kernel file
**When** organized
**Then** WGSL source at `wgsl/sha256.wgsl`
**And** includes NIST test vector comments

---

### Story 7.3: WGSL RIPEMD160 Kernel Port

As a **security researcher**,
I want RIPEMD160 hashing in WGSL,
So that Hash160 (used in P2PKH addresses) works on modern GPU backends.

**Acceptance Criteria:**

**Given** the WGSL RIPEMD160 implementation
**When** hashing SHA256 output (32 bytes)
**Then** output matches reference implementation exactly
**And** test vectors from ISO 10118-3 pass 100%

**Given** Hash160 computation (RIPEMD160(SHA256(data)))
**When** applied to public key
**Then** result matches OpenCL backend bit-for-bit
**And** P2PKH address derivation produces identical addresses

**Given** WGSL implementation
**When** reviewed
**Then** left and right parallel rounds are correctly interleaved
**And** rotation amounts match specification

**Given** the kernel file
**When** organized
**Then** WGSL source at `wgsl/ripemd160.wgsl`
**And** combined Hash160 helper function is provided

**Given** performance
**When** benchmarked on M1/M2 Mac
**Then** throughput meets NFR-13.3 (>30,000 keys/sec)
**And** memory bandwidth is not the bottleneck

---

### Story 7.4: WGPU Backend Integration

As a **developer**,
I want unified WGPU backend integration,
So that scanners can use Metal/Vulkan/DX12 through a common interface.

**Acceptance Criteria:**

**Given** the `#[cfg(feature = "wgpu")]` feature flag
**When** enabled
**Then** WGPU backend is available for scanner use
**And** OpenCL remains default when both are available

**Given** WGPU initialization
**When** backend starts
**Then** adapter selection prefers high-performance GPU
**And** device limits are queried and respected

**Given** the `GpuBridge` trait
**When** implemented for WGPU
**Then** same interface as OpenCL backend
**And** scanners use trait without knowing backend

**Given** buffer management
**When** staging data for GPU
**Then** `bytemuck` zero-copy transfer is used
**And** double-buffering prevents torn writes

**Given** platform detection
**When** running on macOS
**Then** Metal backend is automatically selected
**And** on Windows, Vulkan or DX12 is preferred

**Given** the `--gpu-backend <opencl|wgpu>` flag
**When** provided
**Then** explicit backend selection is honored
**And** error if selected backend unavailable

---

### Story 7.5: WGPU/OpenCL Parity CI Gate

As a **developer**,
I want mandatory CI parity tests between WGPU and OpenCL,
So that no result divergence can reach production.

**Acceptance Criteria:**

**Given** the parity test suite
**When** executed in CI
**Then** 10,000 random seeds run through both backends
**And** any bit divergence = build failure

**Given** a PR touching `wgsl/*.wgsl` or `cl/*.cl`
**When** CI runs
**Then** parity tests are mandatory
**And** merge is blocked on divergence

**Given** parity test failure
**When** divergence detected
**Then** exact seed, expected, and actual values are logged
**And** divergent operation is identified (PRNG/SHA256/RIPEMD160)

**Given** escape hatch temptation
**When** code is reviewed
**Then** NO `--allow-divergence` flag exists in codebase
**And** feature flag can disable WGPU entirely, but never allow divergence

**Given** test coverage
**When** measured
**Then** all PRNG states, hash operations, and address derivations are tested
**And** edge cases (zero, max values) are explicitly covered

**Given** CI hardware matrix
**When** tests run
**Then** macOS Metal, Linux Vulkan, and Windows DX12 are all tested
**And** OpenCL baseline runs on Linux

---

### Story 7.6: Apple Silicon Performance Optimization

As a **security researcher on M1/M2/M3 Mac**,
I want optimized WGPU performance for Apple Silicon,
So that scans are as fast as possible on my hardware.

**Acceptance Criteria:**

**Given** Apple Silicon GPU
**When** WGPU backend is used
**Then** Metal backend is selected automatically
**And** unified memory architecture is leveraged

**Given** workgroup sizing
**When** configured for Metal
**Then** sizes are optimized for Apple GPU tile-based architecture
**And** occupancy is maximized for M1/M2/M3 chip variants

**Given** memory access patterns
**When** designed for Metal
**Then** coalesced reads/writes are prioritized
**And** register pressure is minimized

**Given** benchmark on M1 Max
**When** running full scan
**Then** throughput exceeds 30,000 keys/sec (NFR-13.3)
**And** energy efficiency is documented (keys/sec/watt)

**Given** comparison to OpenCL on same hardware
**When** benchmarked
**Then** WGPU/Metal performance is within 20% of OpenCL
**And** if faster, results are documented

**Given** thermal throttling
**When** running sustained workloads
**Then** scanner adapts batch size to maintain throughput
**And** no crashes from overheating

---

## Epic 7 Summary

| Story | Title | Status |
|-------|-------|--------|
| 7.1 | WGSL MWC1616 Kernel Port | Ready |
| 7.2 | WGSL SHA256 Kernel Port | Ready |
| 7.3 | WGSL RIPEMD160 Kernel Port | Ready |
| 7.4 | WGPU Backend Integration | Ready |
| 7.5 | WGPU/OpenCL Parity CI Gate | Ready |
| 7.6 | Apple Silicon Performance Optimization | Ready |

**Total Stories:** 6
**FRs Covered:** FR-13.5 ✓
**Parity Requirement:** 100% bit-identical to OpenCL (mandatory)
**Dependencies:** Epic 1 core scanning engine must be stable

---

# Document Summary

## Total Epic & Story Count

| Epic | Title | Stories | FRs Covered |
|------|-------|---------|-------------|
| 1 | Core Scanning Engine | 7 | FR-1.1, FR-3.1, FR-4.1, FR-4.2, FR-4.3, FR-4.6 |
| 2 | Browser Fingerprint Intelligence | 5 | FR-2.1, FR-2.2, FR-2.4 |
| 3 | CLI Interface & Batch Processing | 7 | FR-6.1, FR-6.2, FR-6.3, FR-6.4, FR-6.5, FR-6.6 |
| 4 | Release Certification & Validation | 6 | FR-5.1, FR-5.2, FR-5.3, FR-5.4, FR-5.5 |
| 5 | Ethical Framework & Documentation | 6 | FR-7.1, FR-7.2, FR-7.3, FR-7.4, FR-7.5 |
| 6 | Target Intelligence Infrastructure | 6 | FR-13.1, FR-13.2, FR-13.3, FR-13.4 |
| 7 | Cross-Platform GPU via WGPU | 6 | FR-13.5 |

**Total Epics:** 7
**Total Stories:** 43
**FR Coverage:** 30/30 Phase 1+13 FRs (100%)

## Implementation Sequence

1. **Sprint 1-2:** Epic 1 (Core Engine) + Epic 5 (Ethics - parallel)
2. **Sprint 2-3:** Epic 2 (Fingerprints) + Epic 5 continues
3. **Sprint 3-4:** Epic 3 (CLI) + Epic 5 continues
4. **Sprint 4-5:** Epic 4 (Validation/Release Gate)
5. **Phase 13:** Epic 6 (Target Intelligence) + Epic 7 (WGPU)

## Quality Gates

- **Pre-Release:** All Epic 4 stories pass
- **Parity:** 100% GPU/CPU and WGPU/OpenCL bit-identical
- **Legal:** Epic 5 legal sign-off received
- **Performance:** NFR-1 and NFR-13 benchmarks met

