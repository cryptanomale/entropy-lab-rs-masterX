stepsCompleted: [1, 2, 3]
inputDocuments:
  - "_bmad-output/prd.md"
  - "_bmad-output/architecture.md"
  - "_bmad-output/analysis/research/technical-vulnerable-wallet-identification-2025-12-23.md"
---

# temporal-planetarium - Phase 13: Vulnerability Intelligence & Targeting

## Overview

This document defines the implementation plan for Phase 13 of the Randstorm/BitcoinJS Scanner. Moving beyond broad stochastic sweeps, this phase implements "Vulnerability Intelligence" to target known weak seeds (Milk Sad), on-chain forensic artifacts (Nonce Reuse), and modernizes the GPU stack via `wgpu` for cross-platform performance.

## Requirements Inventory

### Functional Requirements

- **FR13.1**: Implement a persistent storage backend (SQLite/PostgreSQL) for managing target addresses.
- **FR13.2**: Integrate the Milk Sad (bx 3.x) weak seed identification methodology.
- **FR13.3**: Implement a signature-based forensic module for detecting ECDSA nonce reuse.
- **FR13.4**: Create a brainwallet passphrase dictionary ingestion and address generation pipeline.
- **FR13.5**: Port core Randstorm PRNG and hashing kernels to WGSL for native GPU acceleration via `wgpu`.

### Non-Functional Requirements

- **NFR13.1**: Targeted address lookup performance < 10ms for 1,000,000+ targets.
- **NFR13.2**: Support indexing and monitoring over 1,000,000 target addresses.
- **NFR13.3**: WGPU implementation must achieve >30,000 keys/sec performance parity on Apple Metal.

### FR Coverage Map

| Requirement | Epic |
|---|---|
| **FR13.1** | Epic 1: Target Intelligence Infrastructure |
| **FR13.2** | Epic 2: Exploit Intelligence |
| **FR13.3** | Epic 2: Exploit Intelligence |
| **FR13.4** | Epic 1: Target Intelligence Infrastructure |
| **FR13.5** | Epic 3: Native GPU Modernization (WGPU) |

## Epic 1: Target Intelligence Infrastructure & Brainwallet Discovery

**Goal**: Provide the core "brain" for targeted scanning, enabling local storage of millions of addresses and discovery via brainwallet dictionaries.

### Story 1.1: Implement SQLite Database Backend for Target Addresses
As a **security researcher**,
I want a high-performance local database for target addresses,
So that I can verify hits against millions of known-vulnerable wallets without RAM exhaustion.

**Acceptance Criteria:**
- **Given** the requirement for persistent target storage.
- **When** the database is initialized.
- **Then** a `vulnerable_addresses` table is created with `address`, `vulnerability_class`, and `status`.
- **And** membership lookups (address existence check) take less than 5ms for 1,000,000 entries.

### Story 1.2: Implement `db-import` CLI Command
As a **security researcher**,
I want to import massive address lists from CSV/JSON files,
So that I can quickly populate my targeting database from public research data.

**Acceptance Criteria:**
- **Given** a CSV file with 1,000,000 Bitcoin addresses.
- **When** I run `tp-cli db-import --file targets.csv --format csv`.
- **Then** the addresses are successfully ingested into the local database.
- **And** the import process completes in under 60 seconds.

### Story 1.3: Brainwallet Passphrase Ingestion Module
As a **security researcher**,
I want to use external phrase dictionaries as seeds,
So that I can check common brainwallet passphrases for funds.

**Acceptance Criteria:**
- **Given** a text file containing 10,000,000 common passphrases.
- **When** the ingestion module is active.
- **Then** it reads and pipes phrases into the PRNG generation pipeline.
- **And** it reports real-time progress (phrases/sec and total percent).

### Story 1.4: Implement Brainwallet Heuristic Address Generator
As a **security researcher**,
I want to generate addresses from phrases using common SHA256-based pipelines,
So that I can recover funds from low-entropy brainwallets.

**Acceptance Criteria:**
- **Given** a list of passphrases.
- **When** the SHA256 derivation pipeline is selected.
- **Then** it correctly generates the derived private keys and corresponding addresses.
- **And** results match known brainwallet test vectors (e.g., "password" -> known address).

---

## Epic 2: Exploit Intelligence (Milk Sad & Nonce Reuse)

**Goal**: Integrate advanced vulnerability identification techniques to move from stochastic search to deliberate exploitation of known cryptographic weaknesses.

### Story 2.1: Implement Milk Sad (bx 3.x) Weak Seed Detector
As a **security researcher**,
I want to identify Bitcoin addresses generated from the "bx 3.x" Milk Sad vulnerability,
So that I can target wallets with known weak entropy sources.

**Acceptance Criteria:**
- **Given** the Milk Sad hash-based seed derivation logic.
- **When** the scanner processes a seed.
- **Then** it checks if the seed belongs to the high-probability Milk Sad subspace.
- **And** it marks any resulting addresses with the `milk_sad` vulnerability class in the database.

### Story 2.2: ECDSA Nonce Reuse Forensics Module
As a **security researcher**,
I want to scan on-chain transaction data for duplicate nonces (k-values) in ECDSA signatures,
So that I can recover the private keys of active wallets with broken RNGs.

**Acceptance Criteria:**
- **Given** two Bitcoin transactions signed by the same public key.
- **When** the transactions share the same `r` value but have different `s` values.
- **Then** the module MUST extract the non-shared secret `k` and derive the private key.
- **And** it logs the recovered key safely (not in the public result report).

### Story 2.3: Targeted Scan Mode Integration
As a **security researcher**,
I want to filter my scans to ONLY check addresses already present in the "Target Intelligence" database,
So that I can maximize GPU efficiency by skipping uninteresting address space.

**Acceptance Criteria:**
- **Given** a 1M+ entry `vulnerable_addresses` table.
- **When** the `--targeted` flag is passed to the scanner.
- **Then** the GPU comparator ONLY flags hits that exist in the local SQLite/Postgres backend.
- **And** lookup performance meets the < 10ms NFR13.1 target.

---

## Epic 3: Native GPU Modernization (WGPU)

**Goal**: Transition to the `wgpu` ecosystem to provide cross-platform native GPU acceleration (Metal, Vulkan, DX12) and future-proof the Randstorm toolkit.

### Story 3.1: WGPU Core Infrastructure Setup
As a **developer**,
I want to initialize the `wgpu` instance, adapter, and device in the scanner's GPU module,
So that I can execute shaders on any modern graphics hardware.

**Acceptance Criteria:**
- **Given** the `entropy-lab` codebase.
- **When** the scanner initializes in WGPU mode.
- **Then** it successfully detects the primary GPU adapter.
- **And** it creates a shared command queue and bind group layout for scanning.

### Story 3.2: Port MWC1616 Kernel to WGSL
As a **developer**,
I want to rewrite the Chrome V8 MWC1616 state transition logic in WGSL,
So that I can run the core Randstorm algorithm on Apple Metal and other WGPU-supported platforms.

**Acceptance Criteria:**
- **Given** the original OpenCL `ckd_priv` logic.
- **When** executed as a WGSL compute shader.
- **Then** it produces 100% bit-perfect parity results compared to the OpenCL implementation.
- **And** it meets the 30k keys/sec performance target for Phase 1.

### Story 3.3: Port Hashing (SHA256/RIPEMD160) Shaders to WGSL
As a **developer**,
I want native WGSL implementations of the Bitcoin address derivation hashing pipeline,
So that I can complete the full address recovery loop on the GPU.

**Acceptance Criteria:**
- **Given** a 33-byte public key in GPU memory.
- **When** the WGPU hashing pipeline runs.
- **Then** it produces the correct 20-byte Hash160 (RIPEMD160(SHA256(pubkey))).
- **And** results match the CPU `bitcoin` crate output for the same keys.

### Story 3.4: WGPU Parallel Dispatcher & Buffer Management
As a **developer**,
I want a streaming buffer management system for WGPU that handles massive batch sizes,
So that I can scan millions of keys without overloading VRAM.

**Acceptance Criteria:**
- **Given** a large batch of fingerprints.
- **When** the WGPU dispatcher processes the batch.
- **Then** it uses double-buffering to hide memory latency.
- **And** it correctly retrieves and parses matched hits from the GPU result buffer.
