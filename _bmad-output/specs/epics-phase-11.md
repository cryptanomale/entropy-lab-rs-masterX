---
stepsCompleted: [1]
inputDocuments:
  - "_bmad-output/prd.md"
  - "_bmad-output/architecture.md"
  - "_bmad-output/analysis/research/technical-randstorm-research-2025-12-17.md"
  - "_bmad-output/analysis/research/technical-foundation-scale-strategy-2025-12-23.md"
  - "_bmad-output/epic-002-retrospective.md"
workflowType: 'epics-and-stories'
lastStep: 1
project_name: 'temporal-planetarium'
user_name: 'Moe'
date: '2025-12-23'
phase: '11 - Foundation & Scale'
---

# Temporal Planetarium - Phase 11 Epic Breakdown

## Overview

This document provides the complete epic and story breakdown for **Phase 11: Foundation & Scale**, decomposing the requirements from the PRD (v2.1), Architecture, and Technical Research into implementable stories. This phase focuses on the infrastructure needed to achieve "All-In" success metrics identified in the Epic 002 Retrospective.

---

## Requirements Inventory

### Functional Requirements (Extracted from PRD v2.1 - Phase 2+ Scope)

| ID | Description | Source | Phase |
|----|-------------|--------|-------|
| FR-1.2 | Firefox SpiderMonkey LCG PRNG Implementation | PRD FR-1.2 | 2 |
| FR-1.3 | Safari JavaScriptCore Xorshift128+ PRNG | PRD FR-1.3 | 2 |
| FR-1.4 | IE Chakra Mersenne Twister PRNG | PRD FR-1.4 | 2 |
| FR-3.2 | BIP32 Simple Paths (m/0, m/0/0) | PRD FR-3.2 | 2 |
| FR-3.3 | BIP44 Standard Path (m/44'/0'/0'/0/0) | PRD FR-3.3 | 2 |
| FR-3.4 | SegWit Paths (BIP49, BIP84) | PRD FR-3.4 | 2 |
| FR-3.5 | Extended Index Support (0-100 per seed) | PRD FR-3.5 | 3 |
| FR-4.4 | GPU Optimization (50x+ speedup) | PRD FR-4.4 | 2 |
| FR-4.5 | Multi-GPU Support | PRD FR-4.5 | 3 |

### Non-Functional Requirements

| ID | Description | Source |
|----|-------------|--------|
| NFR-1 | 50x+ GPU speedup vs CPU for Phase 2 | PRD Phase 2 Success Criteria |
| NFR-2 | Near-linear scaling with GPU count | PRD FR-4.5 |
| NFR-3 | Zero regressions in existing 18 scanners | PRD FR-5.4 |
| NFR-4 | 100% parity between Rust and CryptoDeepTools for all engines | Retrospective Action Item |

### Additional Requirements (From Research)

| ID | Description | Source |
|----|-------------|--------|
| AR-1 | Implement GPU Bloom Filter for 1M+ target sets | Foundation & Scale Research |
| AR-2 | Implement Derivation Batcher (400+ addresses/seed) | Foundation & Scale Research |
| AR-3 | Expand `shared_test_vectors.json` to 10,000+ vectors | Foundation & Scale Research |
| AR-4 | Create `validate_parity.py` script | Foundation & Scale Research |
| AR-5 | Integrate parity check into CI/CD | Foundation & Scale Research |

---

## FR Coverage Map

| FR/NFR ID | Epic | Story |
|-----------|------|-------|
| AR-1 | EPIC-003 | STORY-003-001, STORY-003-002, STORY-003-003 |
| FR-3.2, FR-3.3, FR-3.4, FR-3.5, AR-2 | EPIC-004 | STORY-004-001, STORY-004-002, STORY-004-003, STORY-004-004 |
| NFR-4, AR-3, AR-4, AR-5 | EPIC-005 | STORY-005-001, STORY-005-002, STORY-005-003 |

---

## Epic List

1. **EPIC-003: GPU Bloom Filter Integration** - Enable massive target set lookups (1M+ addresses).
2. **EPIC-004: Multi-Path Derivation Batcher** - Cover BIP44/49/84/86 and indices 0-100+ in parallel.
3. **EPIC-005: Automated Parity Suite** - Ensure 100% cross-tool validation with CryptoDeepTools.

---

## Epic 003: GPU Bloom Filter Integration

**Goal:** Implement a GPU-accelerated Bloom filter to enable efficient membership testing against massive target address sets (1M+ addresses). This removes the O(n) lookup bottleneck and enables real-world "mass scan" use cases.

---

### Story 003.1: Implement OpenCL Blocked Bloom Filter Kernel

As a **security researcher**,
I want the scanner to use a GPU-resident Bloom filter for target address lookups,
So that I can scan against millions of target addresses without a performance bottleneck.

**Acceptance Criteria:**

**Given** a set of 1,000,000 target Bitcoin addresses
**When** the Bloom filter is populated and queried in a GPU kernel
**Then** the lookup time for each address is O(1) amortized
**And** false positive rate is < 0.1% for k=15 hash functions

**Implementation Guidance:**
- Use a Blocked Bloom Filter (BBF) aligned to 256-bit GPU cache lines.
- Reference: `technical-foundation-scale-strategy-2025-12-23.md` Section 1.

---

### Story 003.2: Benchmark Bloom Filter vs. Linear Scan

As a **developer**,
I want to benchmark the new Bloom filter against the existing linear scan,
So that I can quantify the performance improvement.

**Acceptance Criteria:**

**Given** a target set of 100,000 addresses
**When** both Bloom filter lookup and linear scan are benchmarked
**Then** Bloom filter lookup is at least 10x faster for membership testing
**And** results are documented in `_bmad-output/analysis/bloom-benchmark.md`

---

### Story 003.3: Integrate Bloom Filter with Randstorm Scanner

As a **security researcher**,
I want the `randstorm-scan` command to accept a `--bloom-filter` flag,
So that I can enable GPU Bloom filter mode for large target sets.

**Acceptance Criteria:**

**Given** a CSV file with 1,000,000 target addresses
**When** I run `randstorm-scan --targets large.csv --bloom-filter`
**Then** the scanner uses the GPU Bloom filter for lookups
**And** scan performance is within 20% of `30,000 keys/sec` baseline

---

## Epic 004: Multi-Path Derivation Batcher

**Goal:** Implement a "Derivation Batcher" module that generates 400+ addresses per seed in a single GPU kernel call, covering BIP44/49/84/86 and address indices 0-100.

---

### Story 004.1: Create `DerivationBatcher` Rust Module

As a **developer**,
I want a `DerivationBatcher` struct that takes a seed and outputs all addresses for all supported paths,
So that the scanner can cover the full derivation space efficiently.

**Acceptance Criteria:**

**Given** a single seed phrase
**When** `DerivationBatcher::derive_all(seed)` is called
**Then** it returns a `Vec<(DerivationPath, AddressIndex, Address)>` with 400+ entries
**And** paths include BIP44, BIP49, BIP84, BIP86 for indices 0-99

---

### Story 004.2: Implement GPU Kernel for HMAC-SHA512 Batching

As a **developer**,
I want the HMAC-SHA512 operations (the bottleneck in BIP32 derivation) to be parallelized on the GPU,
So that multi-path derivation is at least 10x faster than sequential CPU derivation.

**Acceptance Criteria:**

**Given** a batch of 400 `(path, index)` tuples
**When** the GPU kernel is invoked
**Then** all child keys are derived in parallel
**And** performance is at least 10x faster than single-threaded CPU derivation

---

### Story 004.3: Extend CLI to Accept `--path-coverage all`

As a **security researcher**,
I want to pass `--path-coverage all` to the `randstorm-scan` command,
So that the scanner automatically checks all supported derivation paths.

**Acceptance Criteria:**

**Given** the `--path-coverage all` flag
**When** the scan is executed
**Then** BIP44, BIP49, BIP84, and BIP86 paths are all checked for each seed
**And** address indices 0-99 are scanned for each path

---

### Story 004.4: Validate Multi-Path Derivation Parity

As a **developer**,
I want bit-perfect parity tests for multi-path derivation against `bitcoin-rust`,
So that I can guarantee correctness before scaling.

**Acceptance Criteria:**

**Given** a known seed and expected addresses for each path
**When** the `DerivationBatcher` is invoked
**Then** all addresses match the reference values from `bitcoin-rust`
**And** a new test file `tests/test_derivation_batcher.rs` passes

---

## Epic 005: Automated Parity Suite

**Goal:** Expand `shared_test_vectors.json` to 10,000+ vectors and create an automated validation script (`validate_parity.py`) that runs both Temporal Planetarium and CryptoDeepTools, failing CI if parity diverges.

---

### Story 005.1: Generate 10,000+ Test Vectors

As a **developer**,
I want to expand `shared_test_vectors.json` to include 10,000+ entries,
So that we have comprehensive coverage for regression testing.

**Acceptance Criteria:**

**Given** a test vector generation script
**When** it runs
**Then** it produces vectors covering V8, Java LCG, Safari, and IE PRNGs
**And** vectors span BIP44/49/84/86 paths and indices 0-10

---

### Story 005.2: Create `validate_parity.py` Script

As a **developer**,
I want a Python script that runs both Rust and CryptoDeepTools for each test vector,
So that we can automatically verify bit-perfect parity.

**Acceptance Criteria:**

**Given** `shared_test_vectors.json`
**When** `validate_parity.py` is executed
**Then** it runs `temporal-planetarium-lib` (via FFI or subprocess) for each vector
**And** it runs CryptoDeepTools Python for each vector
**And** it asserts byte-perfect equality on resulting addresses

---

### Story 005.3: Integrate Parity Check into GitHub Actions CI

As a **developer**,
I want the parity check to run on every push and PR,
So that any regression is caught immediately.

**Acceptance Criteria:**

**Given** a new commit is pushed
**When** the CI pipeline runs
**Then** `validate_parity.py` is executed as a job
**And** the build fails if any parity check fails
**And** the parity score (100% expected) is reported

---

## Sprint Planning Recommendation

| Sprint | Epics | Key Deliverables |
|--------|-------|------------------|
| Sprint 1 (Prep) | EPIC-005 (partial) | STORY-005-001 (Vector Generation), STORY-005-002 (Parity Script) |
| Sprint 2 (Foundation) | EPIC-003, EPIC-004 (partial) | STORY-003-001 (Bloom Kernel), STORY-004-001 (Batcher Module) |
| Sprint 3 (Integration) | EPIC-003, EPIC-004, EPIC-005 | All remaining stories, CI integration |

---

_This document is the authoritative source for Phase 11 epic and story planning._
