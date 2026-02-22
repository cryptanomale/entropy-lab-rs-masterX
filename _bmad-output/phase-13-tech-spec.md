# Phase 13: Vulnerability Intelligence & Targeting – Technical Specification

**Date:** 2025-12-23  
**Owner:** Moe / temporal-planetarium  
**Status:** DRAFT (Awaiting Review)  
**Context:** Pivoting Randstorm/BitcoinJS Scanner from broad sweeps to intelligence-led targeting and modernizing the GPU stack.

---

## 1. Objective
Enhance the scanner with a persistent target database, integrated vulnerability heuristics (Milk Sad, Nonce Reuse), and a modern GPU execution layer using WGPU.

## 2. Target Intelligence Infrastructure (Epic 1)

### 2.1 Database Backend
- **Technology:** `rusqlite` (v0.31+) for synchronous, file-based storage.
- **Location:** `$HOME/.entropy-lab/targets.db` (auto-created on first use).
- **Schema:**
  ```sql
  CREATE TABLE targets (
      address TEXT PRIMARY KEY,
      vuln_class TEXT NOT NULL,      -- 'randstorm', 'milk_sad', 'nonce_reuse', etc.
      first_seen_timestamp INTEGER,
      metadata_json TEXT,            -- Extra context (e.g., fingerprint_id, nonce_val)
      status TEXT DEFAULT 'pending'  -- 'pending', 'scanning', 'scanned', 'vulnerable'
  );
  CREATE INDEX idx_vuln_class ON targets(vuln_class);
  ```

### 2.2 CLI Integration
- **Command:** `entropy-lab db-import --csv <path> --class <vuln_class>`
  - Parses CSV and upserts into `targets` table.
- **Command:** `entropy-lab db-query --vuln <class> --limit <n>`
  - Returns target list for directed scanning.
- **Logic:** `randstorm-scan` will be updated to accept `--db-target <vuln_class>` instead of just a raw CSV.

## 3. Exploit Intelligence (Epic 2)

### 3.1 Milk Sad Seed Classification
- **Integration:** Reuse `temporal_planetarium_lib::scans::milk_sad::generate_entropy_msb`.
- **Logic:** During Randstorm seed generation, if a 256-bit seed is produced that aligns with the MT19937 MSB pattern, flag it with high confidence (Confidence: Critical).
- **Heuristic:** Add `is_milk_sad_candidate(seed: &[u8]) -> bool` to the Randstorm pipeline.

### 3.2 ECDSA Nonce Reuse Forensics
- **Algorithm:** Recover $k$ if two signatures $(r, s1)$ and $(r, s2)$ exist for messages $z1, z2$:
  - $k = (z1 - z2) / (s1 - s2) \pmod n$
  - Private Key $d = (s1 \cdot k - z1) / r \pmod n$
- **Implementation:** New module `src/scans/randstorm/forensics.rs`.
- **Input:** Transaction history from `bitcoincore-rpc`.

## 4. Native GPU Modernization (Epic 3)

### 4.1 WGPU Migration
- **Rationale:** Replace `ocl` (OpenCL) with `wgpu` for better cross-platform compatibility and cleaner Rust-native API.
- **Components:**
  - `WgpuDispatcher`: Manages `Device`, `Queue`, and `ComputePipeline`.
  - `BindGroupLayout`: Define inputs (fingerprints, targets) and outputs (results).
- **Shader Port:** Port `cl/randstorm_multi_path.cl` to `src/scans/randstorm/shaders/randstorm.wgsl`.

### 4.2 WGSL Kernel Highlights
- **PRNG:** Implementation of `MWC1616` in WGSL.
- **Crypto:** Port `sha256` and `ripemd160` fragments to WGSL (utilizing `u32` bitwise ops).
- **Memory:** Use `storage` buffers for targets and results.

## 5. Verification Plan

### 5.1 Automated Tests
- **Database:** Unit tests for `db-import` and `db-query` using in-memory SQLite.
- **Forensics:** Test `nonce_reuse` recovery against known vulnerable (r, s) pairs.
- **WGPU:** Parity test comparing `ocl` kernel output vs `wgpu` kernel output.

### 5.2 Performance Benchmarks
- **Targeting:** Time to query 1M targets from SQLite (< 100ms).
- **GPU:** Benchmark WGPU vs OpenCL execution time (Target: Parity or +10% improvement).

---
