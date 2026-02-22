# Project Context: Temporal Planetarium (Entropy Lab RS)

**Last Updated:** 2025-12-25
**Version:** 0.4.0  
**Project Type:** Modular Rust Workspace (CLI + Library)  
**Status:** Active Development / Brownfield

---

## Executive Summary

Temporal Planetarium is a high-performance cryptocurrency security research tool designed to identify and analyze wallet vulnerabilities related to weak entropy generation. It utilizes bit-perfect PRNG reconstruction and GPU acceleration to perform Large-scale forensic recovery.

### Core Purpose
- **Security Research**: Identify vulnerabilities in cryptocurrency wallet implementations
- **Vulnerability Assessment**: Test wallet generation algorithms for weak entropy
- **Cross-Validation**: Integrate with third-party tools like CryptoDeepTools
- **Performance**: High-speed scanning using Unified GPU acceleration (OpenCL/WGPU)

---

## Architecture Overview

### Workspace Structure
- **`temporal-planetarium-lib`**: Core library containing all scanner logic, PRNG implementations, and cryptographic utilities.
- **`temporal-planetarium-cli`**: Command-line interface built on top of the core library using `clap` v4.

### Technology Stack
| Category | Technology | Version | Key Components |
|:---|:---|:---|:---|
| **Language** | Rust | 2021 Edition | `workspace`, `anyhow`, `tracing` |
| **Cryptography** | `bitcoin` | 0.32 | `secp256k1`, `bip39`, `sha2/3`, `ripemd` |
| **GPU/Acceleration**| **Unified Bridge** | 2025 Std | `ocl` (OpenCL) + `wgpu` (Metal/Vulkan) |
| **Interface** | `clap` | 4.5+ (Derive)| CLI subcommands & args |
| **Database** | `rusqlite` | 0.31 | Target & result tracking |
| **Solver** | `z3` | 0.12 | Formal PRNG state recovery |
| **Data Flow** | `bytemuck` | 1.15 | Zero-copy GPU memory mapping |

---

## Coding Patterns & Conventions

### 1. Module-Level Hardware Parity
Agents MUST use module-level separation for hardware backends to maintain Rust idiomatic standards and ensure bit-identical logic.
- **Pattern**: 
  - `cpu::mod_name`: Local SIMD/Sequential reference.
  - `gpu::mod_name`: OpenCL/WGPU optimized path.
- **Naming**: `PascalCase` for structs, `snake_case` for functions.

### 2. Unified Shader Bridge
- **Law**: All PRNG logic MUST be implemented using **Fixed-Point Bitwise Integers only**.
- **Constraint**: Floating-point math (`float`, `double`) is **STRICTLY PROHIBITED** in kernels to prevent driver-specific rounding divergence.

### 3. Progressive Scanning Trait
Every scanner in `src/scans/` MUST implement the `Scanner` trait:
- **Interface**: Uses `UnboundedSender<ScanProgress>` for real-time ETA/progress reporting.
- **Result Type**: Always return `anyhow::Result`.

### 4. Code Organization
- **Kernels (`cl/`)**: ANY OpenCL source files MUST be centralized in the root `cl/` directory.
- **Tests**: Integration tests live in `{project-root}/tests/`, specifically `randstorm_integration.rs`.

---

## Critical Implementation Rules (Zero-Tolerance)

> [!IMPORTANT]
> **Zero-Tolerance Accuracy Laws**:
> 1. **Integer Isolation**: No floats in shaders. Use `u32`/`u64` with explicit wrapping.
> 2. **Dual-Execution Cross-Check**: Every GPU "hit" MUST be verified by the CPU **Golden Reference** before reporting.
> 3. **Bit-Perfect CI Lock**: CI MUST enforce 100% parity on Tier 4 vectors. Divergence = System Failure.
> 4. **No Key Exposure**: Private keys MUST NEVER be logged or exported to plain text.

> [!WARNING]
> **Hardened Disclosure**: Vulnerability fingerprints for high-value targets are stored as **AES-Encrypted Blobs**. Decryption keys are managed via a remote server to enforce the 90-day waiting period.

### Performance & Safety
- **Zero-Allocation**: Minimal allocations in scanning hot loops.
- **Memory Alignment**: Shared structs MUST be `#[repr(C)]` using `u32` fields for `bytemuck` safety.
- **Rayon Parallelization**: Use for high-volume CPU data processing in fallback paths.

---

## Roadmap & Progress

The project has transitioned to a 7-Epic roadmap to reconcile legacy work with future milestones.

### Current Status (2025-12-25)
- **Phase 1 (MVP)**: Epics 1-5 (Core Scanning, Fingerprints, CLI, Certification, Ethics).
- **Phase 13 (Advanced)**: Epics 6-7 (Target Intelligence, WGPU).
- **Overall Completion**: 19% (8/43 stories).
- **Phase 13 Completion**: 67% (8/12 stories).

### Tiered Verification Gates
- **Tier 1 (Unit)**: <30s local run.
- **Tier 2 (Integration)**: ~5m CI run.
- **Tier 4 (Golden)**: 100% parity with `randstorm_vectors.json`.

---

**All AI Agents MUST check this document, `_bmad-output/architecture.md`, and `_bmad-output/epics.md` before adding new scanners or modifying hardware logic.**
