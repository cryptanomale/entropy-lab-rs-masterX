---
stepsCompleted: [1, 2, 3, 4, 5, 6, 7]
inputDocuments:
  - "_bmad-output/prd.md"
  - "_bmad-output/analysis/product-brief-temporal-planetarium-2025-12-17.md"
  - "_bmad-output/architecture/architecture.md"
  - "_bmad-output/architecture/architecture-randstorm-scanner.md"
  - "_bmad-output/architecture/architecture-randstorm-validation.md"
  - "_bmad-output/index.md"
  - "project-context.md"
workflowType: 'architecture'
lastStep: 7
project_name: 'temporal-planetarium'
user_name: 'Moe'
date: '2025-12-24'
---

# Architecture Decision Document

**Project:** temporal-planetarium  
**Author:** Moe  
**Date:** 2025-12-24  

---

## Project Context Analysis

### Requirements Overview

**Functional Requirements:**
- **FR-1: Multi-Engine PRNG Reconstruction**: replicate exact JS Math.random() behavior for V8, SpiderMonkey, JSC, and Chakra (2011-2015).
- **FR-2: Browser Fingerprint Engine**: reconstruct seeds from UA, resolution, timezone, and timestamp constraints.
- **FR-3: Seed Search Framework**: 32-48 bit brute-force capability around estimated timestamps.
- **FR-4: Multi-Path Derivation**: support both direct key generation and BIP32/44/49/84/86 paths.
- **FR-5: GPU-Accelerated Pipelines**: OpenCL/WGPU integration for high-speed signature/address derivation.
- **FR-6: Responsible Disclosure**: built-in 90-day waiting periods and exchange coordination templates.

**Non-Functional Requirements:**
- **Performance**: 10x-100x GPU speedup vs CPU; <30s per address scan (Phase 1).
- **Correctness**: 100% match on Tier 1-4 validation vectors; bit-identical GPU/CPU output.
- **Safety**: zeroized buffers; no private key logging; memory safety via Rust.
- **Usability**: batch CSV processing (10k+ addresses); ETA/progress reporting.

**Scale & Complexity:**
- Primary domain: **System Security / Cryptographic Research**
- Complexity level: **Critical/High**
- Estimated architectural components: **6-8 core modules** (PRNGs, Fingerprinting, Search, GPU Bridge, Validation, CLI/Dispatcher)

### Technical Constraints & Dependencies
- **Existing GPU Patterns**: must integrate with 46+ established OpenCL kernels and `GpuSolver` patterns.
- **Rust Ecosystem**: target Rust 1.70+; heavy reliance on `secp256k1`, `bitcoin`, and `ocl`/`wgpu`.
- **Legacy Browser Logic**: requires fidelity to 2011-2015 JS engine internals.
- **Unified Shader Bridge**: Architecture must ensure bit-identical logic between OpenCL and WGPU targets to avoid divergence in PRNG reconstruction.

### Cross-Cutting Concerns Identified
- **Validation Determinism**: proving cross-language (JS/Rust) and cross-hardware (CPU/GPU) equivalence.
- **Ground Truth Validation Gate**: A non-bypassable CI gate requiring 100% success on "Ground Truth" (Tier 4) vectors before any release.
- **Memory Optimization (Zero-Copy)**: Implementation of zero-copy buffers and static memory pools to ensure high-throughput seed candidate processing.
- **Responsible Disclosure Protocol**: ensuring the tool cannot be easily repurposed for malicious sweeping.

---

## Starter Template Evaluation

### Primary Technology Domain
**Modular Rust Workspace** (CLI + System Library) based on project requirements analysis of `temporal-planetarium`.

### Selected Starter: Modernized Modular Workspace
**Rationale for Selection:**
The project is a mature brownfield workspace. Switching to a new template would create friction. However, the architecture must adopt 2025 best practices for workspace inheritance and unified shader logic to scale effectively.

**Initialization Command:**
Since the workspace already exists, the "initialization" will be a modernization story:
```bash
# Verify workspace inheritance and update core dependencies
cargo update && cargo audit
```

**Architectural Decisions Provided by this foundation:**

- **Language & Runtime**: Rust 2021 Edition with Workspace Inheritance.
- **Shader Logic**: Unified SPIR-V/Metal bridge via `wgpu`.
- **Testing**: Deterministic integration tests via `tests/randstorm_integration.rs`.
- **CLI Pattern**: `clap` v4 derive-based subcommand dispatch.

---

## Core Architectural Decisions

### Decision Priority Analysis

**Critical Decisions (Block Implementation):**
- **Unified Shader Bridge**: Standardized macro/trait bridge between OpenCL and WGPU to ensure 100% logic parity. MUST use **Fixed-Point Bitwise Integers only** to prevent driver-specific rounding divergence.
- **Probabilistic Search Framework**: Heuristic-driven search (timestamp windows) over naive brute-force.
- **Ground Truth Validation Gate**: Mandatory 100% success on Tier 4 validation vectors in CI.

**Important Decisions (Shape Architecture):**
- **Dual-Layer Error Strategy**: `thiserror` for library-level cryptographic failures; `anyhow` for CLI-level context.
- **Progress-Aware Scanner Trait**: Generic interface for scanners to report ETA and progress to the UI.
- **Double-Buffered GPU Synchronization**: Standardized staging buffers with explicit fences to prevent 'Torn Writes' during `bytemuck` zero-copy transfers.

**Deferred Decisions (Post-MVP):**
- **Native GUI Implementation**: `egui` support is feature-gated and deferred until CLI stabilization.
- **Automated Exchange Coordination**: The templates are provided, but the automated submission API is post-MVP.

### Data Architecture
- **Modeling**: Candidates modeled as `BrowserSeed` structs with era-specific entropy mixing logic.
- **Storage**: Discovery records stored in `rusqlite` for long-term research tracking.

### Authentication & Security
- **No Key Exposure**: Hardcoded prohibition on logging/exporting unencrypted private keys.
- **Hardened Disclosure Policy**: Vulnerability fingerprints for high-value windows are stored as **AES-Encrypted Blobs**. Decryption keys are managed via a remote 'Disclosure Server' to enforce the 90-day waiting period, preventing binary-patching bypasses.

### API & Communication Patterns
- **Dispatch**: `ScannerManager` trait-based dispatch in `temporal-planetarium-cli`.
- **Errors**: Structured `PrngError` and `GpuError` enums for programmatic mitigation.

### Infrastructure & Deployment
- **CI Readiness**: Headless validation harness implementing logical parity checks in GitHub Actions.
- **Hardware Feature Flagging**: Usage of `#[cfg(feature = "opencl")]` and `#[cfg(feature = "wgpu")]` to allow the library and CLI to build and run on environments missing specific hardware drivers.
- **Benchmarks**: Criterion-based benchmarks for both CPU and GPU paths.

### Decision Impact Analysis

**Implementation Sequence:**
1. Unified Shader Bridge & Trait Definition
2. PRNG Reconstruction & Ground Truth Validation
3. Probabilistic Search Framework
4. CLI Dispatcher & Error Management

**Cross-Component Dependencies:**
- The **Unified Shader Bridge** must be completed before **Search Framework** optimization to avoid logic divergence.
- **Ground Truth Gate** blocks any merging of scanner logic into the main branch.

---

## Architecture Validation & Accuracy Laws

### Zero-Tolerance Accuracy Laws

To ensure the project's scientific and forensic integrity, the following laws are architecturally mandated:

1.  **The Integer Isolation Law**: Use of `float` or `double` is **STRICTLY PROHIBITED** in all scanner kernels. All arithmetic MUST use explicit `u32`/`u64` with defined wrapping to prevent driver-specific rounding divergence.
2.  **The Dual-Execution Cross-Check**: Any "hit" found by a GPU or SIMD module MUST be automatically re-verified by the CPU **Golden Reference** implementation before being reported.
3.  **The Bit-Perfect CI Lock**: GitHub Actions MUST enforce 100% bit-parity between CPU and GPU paths on Tier 4 (Seed Search) vectors. Any divergence is a build-breaking failure.
4.  **Endianness & Alignment Standard**: All shared structs MUST be `#[repr(C)]` using `u32` for all fields to ensure identical memory layouts between Rust and GPU drivers.

### V-Model Verification Architecture

**The Golden Reference (CPU):**
- A mathematically pure, non-optimized Rust implementation of every PRNG engine serves as the "Universal Truth."
- Validated against community PoCs before being used to verify optimized modules.

**Mirror-Logic Pattern:**
- CPU and GPU modules share a common `core_types.rs` for constants and data structures.
- Logic transitions in optimized code MUST mirror the Reference Engine's state machine.

**Hardware Parity Checker:**
- A dedicated validation tool executes a high-concurrency sweep across all available hardware backends (SIMD, OpenCL, WGPU), asserting bit-level equality for 1M+ iterations.

> [!IMPORTANT]
> **System Failure Condition**: Any unhandled divergence between CPU and GPU modules is defined as a "Critical System Failure." The architecture explicitly prohibits production use if bit-perfect parity is not maintained.

---

## Implementation Patterns & Consistency Rules

### Pattern Categories Defined

**Critical Conflict Points Identified:** 4 key areas where AI agents could make different choices regarding hardware parity, kernel organization, and validation formats.

### Naming Patterns

**Hardware Parity Naming:**
Agents MUST use module-level separation for hardware backends to maintain Rust idiomatic standards.
- **Good**: `cpu::run_mwc1616()` vs `gpu::run_mwc1616()`
- **Anti-Pattern**: `run_mwc1616_cpu()` vs `run_mwc1616_gpu()`

**Code Naming Conventions:**
- **Structs**: `PascalCase` (e.g., `BrowserSeed`)
- **Functions**: `snake_case` (e.g., `reconstruct_seed`)

### Structure Patterns

**GPU Kernel Organization:**
All OpenCL kernel source files MUST be centralized in the root `cl/` directory to maintain compatibility with legacy build scripts.
- **Path**: `{project-root}/cl/*.cl`

**Project Organization:**
- **Tests**: Integration tests live in `{project-root}/tests/`.
- **Logic**: All Randstorm logic resides in `crates/temporal-planetarium-lib/src/scans/randstorm/`.

### Format Patterns

**Data Exchange Formats (JSON):**
Validation test vectors MUST follow the unified schema in `tests/fixtures/randstorm_vectors.json`.
```json
{
  "engine_name": [
    { "seed": [...], "internal_state": [...], "outputs": [...] }
  ]
}
```

### Communication Patterns

**Progress Reporting Interface:**
Every scanner implementation MUST implement the progress reporting trait, accepting an `UnboundedSender<ScanProgress>` to provide real-time ETAs to the CLI.

### Enforcement Guidelines

**All AI Agents MUST:**
1. Check `project-context.md` for existing rules before adding new files.
2. Ensure bit-identical logical parity between CPU and GPU modules.
3. Use **Feature Flags** (`opencl`/`wgpu`) to isolate hardware-dependent code for cross-platform builds.
4. Validate against Tier 1-4 vectors before marking any task as complete.

---

## Project Structure & Boundaries

### Complete Project Directory Structure

```text
temporal-planetarium/
├── cl/                                # CENTRALIZED GPU KERNELS
│   ├── randstorm_v8.cl                # V8-specific PRNG logic
│   ├── randstorm_spidermonkey.cl      # SM-specific logic
│   └── shared_dispatch.cl             # Unified kernel entry points
├── crates/
│   ├── temporal-planetarium-cli/
│   │   └── src/
│   │       ├── main.rs                # Clap v4 Dispatcher
│   │       └── scans/
│   │           └── randstorm.rs       # CLI bridge to Randstorm lib
│   └── temporal-planetarium-lib/
│       └── src/
│           ├── scans/
│           │   └── randstorm/
│           │       ├── mod.rs         # Unified Scanner Trait impl
│           │       ├── engines/       # FR-1: PRNG Engines
│           │       │   ├── v8.rs       
│           │       │   └── sm.rs
│           │       ├── fingerprint/   # FR-2: Browser Logic
│           │       ├── search/        # FR-3: Probabilistic Search
│           │       └── cpu/           # Local CPU Rebuilds
│           ├── utils/
│           │   └── gpu_bridge.rs      # Unified Shader Bridge (Trait)
│           └── lib.rs                 # Core library exports
├── tests/
│   ├── fixtures/
│   │   └── randstorm_vectors.json     # Standardized Test vectors
│   └── randstorm_integration.rs       # Tier 4 Ground Truth tests
└── Cargo.toml                         # Workspace Inheritance Root
```

### Architectural Boundaries

**API Boundaries:**
- **Library/CLI Boundary**: Trait-based dispatch using `ScannerManager`. All state recovery logic is private to `-lib`.
- **Hardware Boundary**: `GpuBridge` trait abstracts OpenCL/WGPU details from the high-level search logic.

**Component Boundaries:**
- **PRNG Engines**: Isolated modules in `engines/` that only export `next_u32()` style interfaces.
- **Fingerprint Resolver**: Dedicated module to convert browser metadata into entropy seed candidates.

**Data Boundaries:**
- **Zero-Copy DMZ**: Specific memory regions mapped between Rust structs and GPU buffers via `bytemuck`.
- **Audit Logs**: Research tracking database in `rusqlite` is the only external storage point.

### Requirements to Structure Mapping

**Feature: multi-Engine Reconstruction (FR-1)**
- Logic: `crates/temporal-planetarium-lib/src/scans/randstorm/engines/`
- Kernels: `cl/randstorm_*.cl`

**Feature: Probabilistic Search (FR-3)**
- Implementation: `crates/temporal-planetarium-lib/src/scans/randstorm/search/`

**Feature: Unified Hardware Bridge (FR-5)**
- Implementation: `crates/temporal-planetarium-lib/src/utils/gpu_bridge.rs`
