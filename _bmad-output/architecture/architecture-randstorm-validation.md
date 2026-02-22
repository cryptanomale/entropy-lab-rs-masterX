---
stepsCompleted: [1, 2, 3, 4, 5]
inputDocuments:
  - "_bmad-output/prd.md"
  - "_bmad-output/analysis/research/technical-randstorm-research-2025-12-17.md"
  - "project-context.md"
workflowType: 'architecture'
lastStep: 5
project_name: 'temporal-planetarium'
user_name: 'Moe'
date: '2025-12-17T13:11:42.156Z'
feature: 'Randstorm PRNG Validation Architecture'
status: 'revised-complete'
revision_reason: 'Gap analysis - added multi-engine, seed brute-force, deterministic testing'
---

# Architecture Decision Document - Randstorm PRNG Validation System

**Feature:** Randstorm/BitcoinJS Scanner Validation Architecture  
**Project:** Temporal Planetarium (entropy-lab-rs)  
**Author:** Winston (Architect)  
**Date:** 2025-12-17  

---

_This document builds collaboratively through step-by-step discovery. Sections are appended as we work through each architectural decision together._

---

## Project Context Analysis

### Requirements Overview

**Functional Requirements:**

From the PRD, the Randstorm/BitcoinJS Scanner must:

1. **PRNG Reconstruction** - Replicate JavaScript Math.random() behavior from 2011-2015 era browsers
   - Chrome V8 MWC1616 algorithm (Phase 1 priority)
   - Firefox/SpiderMonkey LCG variant (Phase 2)
   - Safari/JavaScriptCore Xorshift128+ (Phase 2)
   - IE/Chakra Mersenne Twister (Phase 3)

2. **Browser Fingerprint Processing** - Calculate PRNG seed from:
   - User-Agent string (50-100 variants)
   - Screen resolution (20-50 common resolutions)
   - Timezone data (~400 timezones)
   - Date.now() timestamp constraints

3. **Search Space Exploration** - GPU-accelerated enumeration:
   - Reduced entropy space: 2^50 to 2^55 (vs full 2^256)
   - Top 100 browser configurations (Phase 1)
   - Extended 500 configurations (Phase 2)
   - Probabilistic search algorithms (Phase 3)

4. **Key Derivation** - Era-specific derivation paths:
   - 2011-2012: Simple private key generation
   - 2013-2015: BIP32/44 hierarchical derivation
   - Multi-path support (BIP44/49/84)

5. **Address Generation & Matching** - Support multiple formats:
   - P2PKH (Legacy, starts with '1')
   - P2WPKH (SegWit, starts with 'bc1q')
   - P2SH-P2WPKH (Wrapped SegWit, starts with '3')

**Non-Functional Requirements:**

1. **Validation/Correctness** (CRITICAL - Your Blocker):
   - 100% match on authoritative test vectors before production
   - Byte-for-byte PRNG output equivalence (JavaScript ↔ Rust)
   - GPU/CPU output identical for same inputs
   - Reproducible results for peer review
   - **No authoritative test vectors currently exist**

2. **Performance**:
   - GPU acceleration mandatory (search space too large for CPU)
   - Target: 60-70% vulnerable wallet coverage in Week 1 MVP
   - Scale to 95%+ coverage with probabilistic methods
   - Integration with existing 46 OpenCL kernels

3. **Security & Ethics**:
   - White-hat research only
   - Responsible disclosure framework
   - No unauthorized wallet access
   - Transparent methodology for community validation

4. **Reproducibility**:
   - Peer-review quality validation methodology
   - Test vectors shareable with security community
   - Deterministic results given same inputs

**Scale & Complexity:**

- **Primary domain:** Cryptographic security research / GPU computing / Cross-language validation
- **Complexity level:** CRITICAL/HIGH
  - Cross-runtime PRNG equivalence (JavaScript → Rust)
  - Cryptographic correctness requirements
  - GPU kernel validation complexity
  - 4 browser PRNG variants to support
  - Multi-phase rollout (3 phases)

- **Estimated architectural components:**
  - 4-6 PRNG implementation modules (per browser)
  - Browser fingerprint calculation engine
  - Timestamp space enumeration strategy
  - GPU kernel family (4+ variants)
  - Test vector generation framework
  - Validation test harness
  - Reference JavaScript implementation
  - End-to-end validation pipeline

### Technical Constraints & Dependencies

**Existing System Constraints:**
- Must integrate with 46 existing OpenCL kernels
- Rust + secp256k1 + bitcoin crate ecosystem (established)
- Existing scanner patterns (consistency required)
- GPU device-aware work group sizing (established patterns)

**New Technical Challenges:**
- **JavaScript PRNG Replication** - Must match vulnerable implementations exactly
- **No Reference Implementation** - Original vulnerable code may not be preserved
- **Multi-Browser Support** - 4 different PRNG algorithms with subtle differences
- **Cross-Language Validation** - JavaScript vs Rust output comparison strategy needed
- **Test Vector Authority** - How to create/validate authoritative test vectors without ground truth

**Dependencies:**
- Access to historical browser PRNG documentation (2011-2015 era)
- JavaScript reference implementation for test vector generation
- Known vulnerable addresses for end-to-end validation (limited availability)
- Randstorm 2023 disclosure materials (existing test data)

### Cross-Cutting Concerns Identified

**1. Validation-Driven Design**
- Cannot build scanner without validation strategy
- Validation requirements shape implementation architecture
- Test vector generation must precede scanner development

**2. PRNG Equivalence Testing**
- JavaScript reference → Rust implementation comparison
- Byte-level output matching requirements
- Multiple PRNG algorithms to validate independently

**3. GPU/CPU Equivalence**
- GPU kernel must produce identical results to CPU implementation
- Deterministic results critical for validation
- Floating point precision concerns

**4. End-to-End Pipeline Validation**
- Timestamp → PRNG seed → Private key → Address
- Each stage must be independently validatable
- Full pipeline must match JavaScript behavior

**5. Test Vector Management**
- Generation strategy (self-generated vs external)
- Storage and versioning
- Shareability with security research community
- Continuous validation during development

**6. Performance vs Correctness Tradeoffs**
- GPU optimizations cannot compromise correctness
- Validation overhead in production scanner
- Coverage vs speed decisions

---

## Architectural Foundation

### Existing Technical Stack (Temporal Planetarium)

**Language & Runtime:**
- Rust 1.70+ (edition 2021)
- Established Cargo workspace with feature flags (default, gpu, gui)

**GPU Acceleration:**
- OpenCL via `ocl` v0.19 crate
- 46 existing OpenCL kernels (proven patterns)
- Device-aware work group sizing
- Pinned memory for CPU-GPU transfers

**Cryptographic Libraries:**
- secp256k1 v0.29 (elliptic curve operations)
- bitcoin v0.32 (address generation, BIP32/39/44/49/84)
- bip39 v2.0 (mnemonic handling)
- sha2, sha3, ripemd, hmac (hashing)
- pbkdf2 (key derivation)

**Existing Scanner Patterns:**
- 18 vulnerability scanners implemented
- Consistent scanner module structure
- CPU/GPU execution path selection
- Rayon parallelization for CPU path

### Extension Strategy for Randstorm

**Integration Approach:**
- Follow existing scanner patterns for consistency
- Extend GPU kernel family (46 → 50+ kernels)
- Reuse cryptographic infrastructure (secp256k1, bitcoin crate)
- Leverage existing OpenCL optimization patterns

**New Components Required:**
1. **PRNG Module** (`src/scans/randstorm/prng/`)
   - Chrome V8 MWC1616 implementation
   - Firefox LCG variant
   - Safari Xorshift128+
   - IE Mersenne Twister

2. **Browser Fingerprint Module** (`src/scans/randstorm/fingerprint/`)
   - User-Agent parsing
   - Screen resolution database
   - Timezone calculation
   - Seed reconstruction logic

3. **Validation Framework** (`tests/randstorm_validation/`)
   - JavaScript reference implementation (Node.js)
   - Test vector generation harness
   - PRNG equivalence tests
   - End-to-end pipeline validation

4. **GPU Kernels** (`cl/randstorm_*.cl`)
   - `randstorm_mwc1616.cl` (Chrome V8)
   - `randstorm_lcg.cl` (Firefox)
   - `randstorm_xorshift.cl` (Safari)
   - `randstorm_mt.cl` (IE Mersenne Twister)

**Design Principles Applied:**
- ✅ Modularity - Each PRNG variant is self-contained
- ✅ Extensibility - New browser variants can be added easily
- ✅ Performance - GPU acceleration for search space exploration
- ✅ Safety - Rust memory safety + existing cryptographic patterns
- ✅ Validation-First - Cannot implement without validation framework

### Key Architectural Constraints

**Must Maintain:**
- Existing scanner CLI interface patterns (clap-based)
- GPU/CPU execution path selection logic
- Error handling patterns (anyhow::Result)
- Testing standards (cargo test, 100% pass requirement)

**Must Add:**
- **JavaScript Reference Implementation** - For test vector generation
- **Cross-Language Validation** - Rust ↔ JavaScript PRNG output comparison
- **Test Vector Authority** - Self-generated vectors with documented methodology

**Critical Success Factor:**
- **Validation precedes implementation** - Cannot build scanner without proving PRNG equivalence first

---

## Core Architectural Decisions

### Decision Priority Analysis

**Critical Decisions (Block Implementation):**
1. ✅ JavaScript Reference Implementation Strategy
2. ✅ Test Vector Format and Scope
3. 🔄 PRNG Implementation Architecture (Next)
4. 🔄 GPU Kernel Validation Strategy (Next)
5. 🔄 End-to-End Pipeline Validation (Next)

**Important Decisions (Shape Architecture):**
- Browser fingerprint calculation approach
- Timestamp space enumeration strategy
- Performance vs correctness tradeoffs

**Deferred Decisions (Post-MVP):**
- Multi-browser PRNG support (Firefox, Safari, IE)
- Probabilistic search algorithms
- Multi-GPU scaling

### Validation Framework Architecture

#### Decision 1: Multi-Engine PRNG Reference Implementation with Seed Brute-Force (REVISED)

**Decision:** Multi-Engine Reference Implementations + Deterministic Test Harness + Seed Search

**CRITICAL REVISION - Gap Analysis Findings:**

**Original Assumption (FLAWED):**
- ❌ Timestamp-only seeding
- ❌ Single-engine (V8 MWC1616 only)
- ❌ No internal validation vectors
- ❌ Compressed-only address derivation

**Reality (Your Gap Analysis):**
- ✅ Browsers mixed OS entropy with timestamp (need seed brute-force)
- ✅ Multiple browser engines (V8, SpiderMonkey, JSC, IE)
- ✅ No confirmed internal vectors (need deterministic test harness)
- ✅ Both compressed and uncompressed addresses vulnerable

**Revised Architecture:**

**1. Multi-Engine PRNG Implementation**

Extract and implement ALL browser PRNG variants from 2011-2015 era:

```
tests/randstorm_validation/reference_implementations/
├── v8_mwc1616/              # Chrome V8 (2011-2015)
│   ├── mwc1616.c            # Extracted from V8 source
│   ├── mwc1616.js           # JavaScript wrapper
│   ├── seed_mixer.js        # OS entropy + timestamp mixing
│   └── README.md            # V8 version mapping
│
├── spidermonkey_mwc/        # Firefox SpiderMonkey
│   ├── spidermonkey_prng.c  # SpiderMonkey PRNG (different from V8)
│   ├── seed_mixer.js        # Firefox-specific seeding
│   └── README.md            # Firefox version mapping
│
├── jsc_xorshift/            # Safari JavaScriptCore
│   ├── jsc_prng.c           # JSC Xorshift128+
│   ├── seed_mixer.js        # Safari-specific seeding
│   └── README.md            # Safari version mapping
│
├── chakra_mt/               # IE Chakra
│   ├── chakra_mt.c          # Mersenne Twister variant
│   ├── seed_mixer.js        # IE-specific seeding
│   └── README.md            # IE version mapping
│
└── jsbn_pool_flow/          # Critical: jsbn EC key generation
    ├── pool_fill.js         # Hi→Lo pool fill order
    ├── arc4_init.js         # ARC4 initialization
    ├── first32_to_privkey.js # First 32 bytes → private key
    └── README.md            # jsbn ordering documentation
```

**2. Seed Brute-Force Framework**

**Critical:** Timestamp alone is insufficient. Need seed search capability:

```rust
// src/scans/randstorm/seed_search.rs
pub struct SeedSearchConfig {
    pub timestamp_ms: u64,
    pub seed_bit_range: (u8, u8),  // e.g., (32, 48) bits
    pub engine: PrngEngine,         // V8, SpiderMonkey, JSC, Chakra
}

pub fn brute_force_seed_range(
    config: &SeedSearchConfig,
    target_address: &str,
) -> Result<Option<SeedMatch>> {
    // Iterate seed space around timestamp
    // Mix OS entropy candidates
    // Generate keys and match addresses
}
```

**3. Deterministic Test Harness**

**Critical:** Need (engine, seed, timestamp) → (pool, privkey, address) validation:

```
tests/randstorm_validation/
├── deterministic_harness/
│   ├── mod.rs                        # Main test harness
│   ├── engine_test.rs                # Per-engine validation
│   ├── seed_to_pool_test.rs          # PRNG seed → pool bytes
│   ├── pool_to_privkey_test.rs       # Pool → private key (jsbn order)
│   ├── privkey_to_address_test.rs    # Both compressed & uncompressed
│   └── end_to_end_test.rs            # Full pipeline validation
```

**Test Vector Format (Revised):**

```json
{
  "schema_version": "2.0",
  "test_type": "deterministic",
  "vectors": [
    {
      "id": "det-001",
      "engine": "v8_mwc1616",
      "input": {
        "prng_seed_48bit": "0x123456789ABC",
        "timestamp_ms": 1325376000000,
        "os_entropy_mix": "0xDEADBEEF",
        "timestamp_xor_count": 1
      },
      "internal_state": {
        "prng_state_after_init": "0x...",
        "pool_bytes_32": "0x...",
        "pool_fill_order": "hi_to_lo",
        "arc4_state": "0x..."
      },
      "cryptographic_output": {
        "private_key_hex": "0x...",
        "public_key_compressed": "0x02...",
        "public_key_uncompressed": "0x04...",
        "addresses": {
          "p2pkh_compressed": "1A1zP1eP...",
          "p2pkh_uncompressed": "1BvBMSE..."
        }
      }
    }
  ]
}
```

**4. Multi-Engine Abstraction**

```rust
// src/scans/randstorm/prng/mod.rs
pub trait PrngEngine {
    fn new_with_seed(seed: u64, os_entropy: Option<u64>) -> Self;
    fn next(&mut self) -> f64;
    fn fill_pool(&mut self, pool: &mut [u8]);
}

pub enum BrowserEngine {
    V8Mwc1616,
    SpiderMonkeyMwc,
    JscXorshift128,
    ChakraMT,
}

impl BrowserEngine {
    pub fn create_prng(&self, seed: u64) -> Box<dyn PrngEngine> {
        match self {
            V8Mwc1616 => Box::new(Mwc1616::new_with_seed(seed, None)),
            SpiderMonkeyMwc => Box::new(SpiderMonkeyPrng::new_with_seed(seed, None)),
            // ...
        }
    }
}
```

**5. Uncompressed Path Support**

```rust
// src/scans/randstorm/mod.rs
pub fn derive_addresses(
    private_key: &[u8],
    derivation_path: &str,
) -> Result<AddressSet> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(private_key)?;
    
    // CRITICAL: Generate BOTH compressed and uncompressed
    let public_key_compressed = PublicKey::from_secret_key(&secp, &secret_key);
    let public_key_uncompressed = public_key_compressed.uncompressed();
    
    Ok(AddressSet {
        p2pkh_compressed: Address::p2pkh(&public_key_compressed, Network::Bitcoin),
        p2pkh_uncompressed: Address::p2pkh(&public_key_uncompressed, Network::Bitcoin),
        // ... p2wpkh, p2sh variants
    })
}
```

**Implementation Approach (Revised):**

1. **Extract ALL browser PRNG implementations** (V8, SpiderMonkey, JSC, Chakra)
2. **Implement seed mixing logic** (OS entropy + timestamp)
3. **Build deterministic test harness** with known internal states
4. **Create seed brute-force framework** (32-48 bit search)
5. **Validate jsbn pool flow** (hi→lo fill, ARC4 init, first 32 bytes)
6. **Generate test vectors** with internal states (not just addresses)
7. **Reconcile with community PoCs** (RandstormBTC scripts, Python MT)
8. **Implement both compressed & uncompressed** address derivation

**Validation Strategy:**

- ✅ **Known address validation:** Published vulnerable address
- ✅ **Internal state validation:** Deterministic test harness
- ✅ **Community reconciliation:** Compare with RandstormBTC scripts
- ✅ **Multi-engine validation:** Test all 4 browser PRNGs
- ✅ **Seed search validation:** Brute-force around known timestamp

**Affects:** 
- All validation components (major redesign)
- Test vector generation (add internal states)
- PRNG implementation (multi-engine)
- Scanner implementation (seed search, uncompressed paths)
- GPU kernel design (per-engine kernels)

---

#### Decision 2: Test Vector Architecture - Deterministic + Tiered (REVISED)

**Decision:** Deterministic Test Harness + Multi-Tier JSON Vectors

**CRITICAL REVISION:**

**Original Approach (INSUFFICIENT):**
- ❌ Only final addresses as validation
- ❌ No internal PRNG state vectors
- ❌ Cannot prove intermediate steps correct

**Revised Approach:**

**1. Deterministic Test Vector Format**

Test vectors must include **ALL internal states** for full pipeline validation:

```json
{
  "schema_version": "2.0",
  "generator": "multi-engine-reference",
  "test_type": "deterministic",
  "vectors": [
    {
      "id": "det-v8-001",
      "tier": 1,
      "engine": "v8_mwc1616",
      "description": "V8 MWC1616 basic deterministic test",
      
      "input": {
        "prng_seed_48bit": "0x123456789ABC",
        "os_entropy_mix": "0xDEADBEEF",
        "timestamp_ms": 1325376000000,
        "timestamp_readable": "2012-01-01T00:00:00.000Z",
        "user_agent": "Mozilla/5.0 (Windows NT 6.1) Chrome/20.0",
        "timestamp_xor_count": 1
      },
      
      "prng_internal_state": {
        "initial_state": "0x...",
        "after_pool_fill": "0x...",
        "random_sequence_100": [0.123, 0.456, ...],
        "state_after_100": "0x..."
      },
      
      "jsbn_pool_flow": {
        "pool_bytes_256": "0x...",
        "fill_order": "hi_to_lo",
        "timestamp_xor_applied": true,
        "arc4_initial_state": "0x...",
        "arc4_after_init": "0x...",
        "first_32_bytes": "0x..."
      },
      
      "cryptographic_output": {
        "private_key_hex": "0x...",
        "private_key_wif_compressed": "L...",
        "private_key_wif_uncompressed": "5...",
        "public_key_compressed": "0x02...",
        "public_key_uncompressed": "0x04...",
        "addresses": {
          "p2pkh_compressed": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
          "p2pkh_uncompressed": "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        }
      },
      
      "derivation": {
        "path": "m/0'/0/0",
        "bip32_enabled": false,
        "era": "2011-2012"
      }
    }
  ]
}
```

**2. Test Harness Architecture**

```rust
// tests/randstorm_validation/deterministic_harness/mod.rs

pub struct DeterministicTest {
    pub id: String,
    pub engine: BrowserEngine,
    pub input: TestInput,
    pub expected: ExpectedOutput,
}

pub struct TestInput {
    pub prng_seed: u64,
    pub os_entropy: Option<u64>,
    pub timestamp_ms: u64,
}

pub struct ExpectedOutput {
    pub prng_state: PrngState,
    pub pool_bytes: [u8; 256],
    pub arc4_state: Arc4State,
    pub private_key: [u8; 32],
    pub addresses: AddressSet,
}

impl DeterministicTest {
    pub fn validate(&self) -> Result<ValidationReport> {
        // Stage 1: PRNG initialization and state
        let mut prng = self.engine.create_prng(self.input.prng_seed);
        assert_eq!(prng.state(), self.expected.prng_state);
        
        // Stage 2: Pool fill (hi→lo order)
        let mut pool = [0u8; 256];
        prng.fill_pool(&mut pool);
        assert_eq!(pool, self.expected.pool_bytes);
        
        // Stage 3: ARC4 initialization
        let arc4 = Arc4::init_from_pool(&pool);
        assert_eq!(arc4.state(), self.expected.arc4_state);
        
        // Stage 4: First 32 bytes → private key
        let privkey = arc4.first_32_bytes();
        assert_eq!(privkey, self.expected.private_key);
        
        // Stage 5: Address generation (compressed & uncompressed)
        let addresses = derive_addresses(&privkey)?;
        assert_eq!(addresses, self.expected.addresses);
        
        Ok(ValidationReport::success(self.id.clone()))
    }
}
```

**3. Multi-Tier Strategy (Updated)**

**Tier 1 - Deterministic Core (~50 vectors per engine)**
- Purpose: Validate each engine's PRNG correctness
- Coverage: 4 engines × 50 vectors = 200 total
- Internal states: FULL (all intermediate values)
- Execution time: <10 seconds
- Run: Every commit

**Tier 2 - Seed Search Validation (~500 vectors)**
- Purpose: Validate seed brute-force around known timestamps
- Coverage: Known vulnerable address with timestamp window
- Seed range: ±10,000 seeds around timestamp
- Execution time: ~2 minutes (GPU)
- Run: Pre-PR

**Tier 3 - Multi-Engine Coverage (~5,000 vectors)**
- Purpose: Comprehensive browser config × timestamp × engine
- Coverage: 100 configs × 50 timestamps × 4 engines
- Execution time: ~20 minutes (GPU)
- Run: Release candidates

**Tier 4 - Known Vulnerable Address (~1 vector)**
- Purpose: Validate against published Randstorm disclosure address
- Coverage: THE known vulnerable address from 2023 disclosure
- Seed search: Exhaustive around transaction timestamp
- Execution time: Variable (until found or exhausted)
- Run: Mandatory before claiming production-ready

**4. Community PoC Reconciliation**

**RandstormBTC Script Comparison:**
```
tests/randstorm_validation/community_poc/
├── randstorm_btc_comparison.md    # Divergence analysis
├── python_mt_comparison.rs         # Compare vs simplified MT PoC
├── 32byte_pool_comparison.rs       # Reconcile pool size assumptions
└── known_address_test.rs           # Match published address
```

**5. Storage Structure (Revised)**

```
tests/randstorm_validation/
├── test_vectors/
│   ├── deterministic/
│   │   ├── v8_mwc1616.json         # 50 V8 vectors with internal states
│   │   ├── spidermonkey_mwc.json   # 50 SpiderMonkey vectors
│   │   ├── jsc_xorshift.json       # 50 JSC vectors
│   │   ├── chakra_mt.json          # 50 Chakra vectors
│   │   └── schema_v2.json          # Schema with internal states
│   ├── seed_search/
│   │   └── known_timestamp_ranges.json
│   ├── multi_engine/
│   │   └── tier3_comprehensive.json
│   ├── known_vulnerable/
│   │   └── published_address.json  # THE address from disclosure
│   └── checksums.txt
```

**Versioning & Immutability:**
- v1.0: Address-only vectors (deprecated)
- v2.0: Deterministic vectors with internal states (current)
- Semantic versioning: 2.x.y
- Append-only after publication
- SHA256 checksums for integrity
- Git-tracked for transparency

**Validation Success Criteria:**

- ✅ **Tier 1:** 100% pass on deterministic vectors (all engines)
- ✅ **Tier 2:** Find correct seed in ±10,000 range
- ✅ **Tier 3:** 95%+ pass on multi-engine coverage
- ✅ **Tier 4:** MUST find the published vulnerable address

**Affects:** 
- Test harness implementation (major expansion)
- Vector generation scripts (add internal state capture)
- CI/CD pipeline (tiered validation gates)
- Scanner validation (cannot ship without Tier 4 success)

---


### PRNG Implementation Architecture

**Remaining Critical Decisions:**

**Decision 3: PRNG Module Organization**
**Decision 4: GPU Kernel Validation**
**Decision 5: End-to-End Pipeline Validation**

_(To be completed in next session)_

---

## Implementation Patterns & Consistency Rules

### Naming Patterns (Rust-Specific)

**Module Naming:**
```rust
// PRNG implementations
src/scans/randstorm/prng/
  ├── mod.rs
  ├── mwc1616.rs          // Chrome V8 (NOT v8_mwc1616 or chrome_prng)
  ├── lcg.rs              // Firefox (Phase 2)
  ├── xorshift128.rs      // Safari (Phase 2)
  └── mersenne_twister.rs // IE (Phase 3)

// Browser fingerprint calculations
src/scans/randstorm/fingerprint/
  ├── mod.rs
  ├── user_agent.rs
  ├── screen_resolution.rs
  └── timezone.rs
```

**Test Function Naming:**
```rust
// Follow existing pattern: test_<what>_<scenario>
#[test]
fn test_mwc1616_basic_output() { ... }

#[test]
fn test_mwc1616_matches_reference() { ... }

#[test]
fn test_vector_tier1_smoke() { ... }
```

**Variable Naming (snake_case per Rust conventions):**
```rust
let timestamp_ms: u64 = 1325376000000;
let user_agent_string: &str = "Mozilla...";
let prng_seed: u64 = calculate_seed(...);
let private_key_wif: String = encode_wif(...);
```

### Structure Patterns

**Validation Framework Location:**
```
tests/randstorm_validation/
├── reference_implementations/     # JavaScript/C reference code
│   └── v8_mwc1616/
│       ├── mwc1616.c
│       ├── mwc1616.js
│       └── README.md
├── test_vectors/                  # JSON test vectors
│   ├── tier1_core_smoke.json
│   ├── tier2_regression.json
│   ├── tier3_release.json
│   └── schema.json
├── vector_generator/              # Scripts to generate vectors
│   ├── generate.sh
│   └── validate_schema.js
├── mod.rs                         # Rust test harness
└── README.md                      # How to run validation
```

**Scanner Integration (follow existing pattern):**
```
src/scans/
├── randstorm.rs                   # Main scanner (like cake_wallet.rs)
└── randstorm/                     # Submodules
    ├── mod.rs
    ├── prng/                      # PRNG implementations
    ├── fingerprint/               # Browser fingerprinting
    └── search.rs                  # Search space enumeration
```

### Format Patterns

**Test Vector JSON Format:**
```json
{
  "schema_version": "1.0",
  "generator": "v8-mwc1616-reference",
  "vectors": [
    {
      "id": "core-001",
      "tier": 1,
      "input": {
        "timestamp_ms": 1325376000000,
        "user_agent": "...",
        "screen_resolution": "1920x1080"
      },
      "prng_output": {
        "seed": "0x...",
        "first_10_values": [...]
      },
      "cryptographic_output": {
        "private_key_hex": "0x...",
        "addresses": { ... }
      }
    }
  ]
}
```

**Error Handling (extend existing pattern):**
```rust
use anyhow::{Context, Result};

// Validation-specific error context
fn validate_prng_output(expected: &[f64], actual: &[f64]) -> Result<()> {
    if expected != actual {
        anyhow::bail!(
            "PRNG output mismatch:\nExpected: {:?}\nActual: {:?}",
            expected, actual
        );
    }
    Ok(())
}

// Follow existing scanner error pattern
pub fn scan_randstorm(args: &RandstormArgs) -> Result<Vec<Finding>> {
    let prng = Mwc1616::new(args.timestamp)?;
    // ... implementation
    Ok(findings)
}
```

### Process Patterns

**Validation-First Development Flow:**
```
1. Extract V8 PRNG from source → reference implementation
2. Generate Tier 1 test vectors (100) using reference
3. Implement Rust PRNG (CPU only)
4. Validate Rust PRNG matches 100% of Tier 1 vectors
5. Implement GPU kernel
6. Validate GPU matches CPU 100%
7. Generate Tier 2 vectors, validate
8. Only then: integrate into scanner
```

**CI/CD Validation Strategy:**
```yaml
# .github/workflows/randstorm-validation.yml
on: [push, pull_request]

jobs:
  tier1-smoke:
    runs-on: ubuntu-latest
    steps:
      - run: cargo test --test randstorm_validation -- --tier 1
    # MUST pass for merge

  tier2-regression:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - run: cargo test --test randstorm_validation -- --tier 2
    # Should pass, warnings reported

  tier3-release:
    runs-on: ubuntu-latest
    if: github.ref == 'refs/tags/*'
    steps:
      - run: cargo test --test randstorm_validation -- --tier 3
    # MUST pass for release
```

### Enforcement Guidelines

**All AI Agents implementing Randstorm MUST:**

1. Follow existing scanner patterns from `src/scans/*.rs` files
2. Use anyhow::Result for error handling (no unwrap() in production paths)
3. Write tests for ALL PRNG output before claiming implementation complete
4. Validate against JSON test vectors (not self-generated expected values)
5. Document V8 source mapping in reference implementation README
6. Use snake_case naming per Rust conventions
7. Pass cargo clippy before commit
8. Achieve 100% test vector validation before GPU implementation

**Pattern Verification:**
- Run `cargo test --test randstorm_validation` before every commit
- Check `cargo clippy -- -D warnings` passes
- Verify JSON test vectors validate against schema
- Ensure GPU/CPU output identical for same inputs

### Pattern Examples

**Good Example - PRNG Implementation:**
```rust
// src/scans/randstorm/prng/mwc1616.rs
pub struct Mwc1616 {
    state: [u32; 2],
}

impl Mwc1616 {
    pub fn new(seed: u64) -> Self {
        Self {
            state: [(seed >> 32) as u32, seed as u32],
        }
    }

    pub fn next(&mut self) -> f64 {
        // Exact V8 MWC1616 algorithm
        // Reference: V8 commit abc123, line 456
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mwc1616_matches_reference() {
        let vectors = load_test_vectors("tier1_core_smoke.json");
        for vector in vectors {
            let mut prng = Mwc1616::new(vector.prng_output.seed);
            let actual: Vec<f64> = (0..10).map(|_| prng.next()).collect();
            assert_eq!(actual, vector.prng_output.first_10_values);
        }
    }
}
```

**Anti-Pattern - What to Avoid:**
```rust
// ❌ DON'T: Self-generated expected values
#[test]
fn test_prng() {
    let mut prng = Mwc1616::new(0x12345678);
    let output = prng.next();
    assert_eq!(output, 0.123456); // Where did this come from?
}

// ❌ DON'T: unwrap() in production paths
pub fn scan_randstorm(args: &Args) -> Vec<Finding> {
    let prng = Mwc1616::new(args.timestamp).unwrap(); // Can panic!
}

// ❌ DON'T: Inconsistent naming
mod V8_PRNG { ... }  // Wrong: not snake_case
```

---


#### Decision 3: PRNG Implementation Architecture - Multi-Engine Trait System

**Decision:** Trait-Based Multi-Engine Architecture with Seed Search

**Architecture:**

```rust
// src/scans/randstorm/prng/mod.rs

/// Core PRNG trait that all browser engines must implement
pub trait PrngEngine: Send + Sync {
    /// Create PRNG with explicit seed (for deterministic testing)
    fn new_with_seed(seed: u64, os_entropy: Option<u64>) -> Self where Self: Sized;
    
    /// Create PRNG from browser fingerprint + timestamp (production)
    fn from_browser_context(ctx: &BrowserContext) -> Result<Self> where Self: Sized;
    
    /// Get next random float [0, 1)
    fn next(&mut self) -> f64;
    
    /// Fill byte pool using engine-specific logic
    fn fill_pool(&mut self, pool: &mut [u8], fill_order: PoolFillOrder);
    
    /// Get current internal state (for validation)
    fn state(&self) -> PrngState;
    
    /// Engine identifier
    fn engine_name(&self) -> &'static str;
}

/// Browser engine implementations
pub mod engines {
    pub struct V8Mwc1616 { /* ... */ }
    pub struct SpiderMonkeyMwc { /* ... */ }
    pub struct JscXorshift128 { /* ... */ }
    pub struct ChakraMT { /* ... */ }
}

/// Pool fill ordering (critical for jsbn compatibility)
pub enum PoolFillOrder {
    HiToLo,  // Default for jsbn (2011-2015)
    LoToHi,  // Alternative ordering
}

/// Browser context for realistic seeding
pub struct BrowserContext {
    pub timestamp_ms: u64,
    pub user_agent: String,
    pub screen_resolution: (u32, u32),
    pub timezone_offset: i32,
    pub os_entropy_estimate: Option<u64>,
}
```

**Implementation Pattern:**

```rust
// src/scans/randstorm/prng/engines/v8_mwc1616.rs

pub struct V8Mwc1616 {
    state: [u32; 2],  // MWC1616 state
    os_entropy_mixed: bool,
}

impl PrngEngine for V8Mwc1616 {
    fn new_with_seed(seed: u64, os_entropy: Option<u64>) -> Self {
        let mut state = [
            (seed >> 32) as u32,
            (seed & 0xFFFFFFFF) as u32,
        ];
        
        // Mix OS entropy if provided
        if let Some(entropy) = os_entropy {
            state[0] ^= (entropy >> 32) as u32;
            state[1] ^= (entropy & 0xFFFFFFFF) as u32;
        }
        
        Self {
            state,
            os_entropy_mixed: os_entropy.is_some(),
        }
    }
    
    fn from_browser_context(ctx: &BrowserContext) -> Result<Self> {
        // Calculate seed from browser fingerprint
        let seed = calculate_seed_from_context(ctx)?;
        Ok(Self::new_with_seed(seed, ctx.os_entropy_estimate))
    }
    
    fn next(&mut self) -> f64 {
        // V8 MWC1616 algorithm
        // Reference: V8 source v3.14.5.9, src/random.cc
        let mwc = (self.state[0] as u64) * 18030 + (self.state[1] as u64);
        self.state[0] = (mwc >> 16) as u32;
        self.state[1] = (mwc & 0xFFFF) as u32;
        
        // Convert to [0, 1) range (V8-specific scaling)
        (self.state[0] as f64) / 65536.0
    }
    
    fn fill_pool(&mut self, pool: &mut [u8], fill_order: PoolFillOrder) {
        match fill_order {
            PoolFillOrder::HiToLo => {
                // jsbn compatibility: fill hi→lo
                for i in (0..pool.len()).rev() {
                    let byte = (self.next() * 256.0) as u8;
                    pool[i] = byte;
                }
            },
            PoolFillOrder::LoToHi => {
                for i in 0..pool.len() {
                    let byte = (self.next() * 256.0) as u8;
                    pool[i] = byte;
                }
            }
        }
    }
    
    fn state(&self) -> PrngState {
        PrngState::V8Mwc1616 {
            state: self.state,
            os_entropy_mixed: self.os_entropy_mixed,
        }
    }
    
    fn engine_name(&self) -> &'static str {
        "v8_mwc1616"
    }
}
```

**Seed Search Implementation:**

```rust
// src/scans/randstorm/seed_search.rs

pub struct SeedSearchConfig {
    pub engine: BrowserEngine,
    pub timestamp_ms: u64,
    pub seed_bit_range: (u8, u8),  // e.g., (32, 48) bits to search
    pub target_address: String,
    pub compressed: bool,
    pub uncompressed: bool,
}

pub fn brute_force_seed_range(
    config: &SeedSearchConfig,
    progress_callback: Option<ProgressCallback>,
) -> Result<Option<SeedMatch>> {
    let min_seed = 1u64 << config.seed_bit_range.0;
    let max_seed = 1u64 << config.seed_bit_range.1;
    
    // Parallel search using rayon
    (min_seed..max_seed)
        .into_par_iter()
        .find_map_any(|seed| {
            let mut prng = config.engine.create_prng(seed);
            
            // Generate key from PRNG
            let privkey = generate_privkey_from_prng(&mut prng)?;
            
            // Check both compressed and uncompressed if requested
            let addresses = derive_both_addresses(&privkey)?;
            
            if (config.compressed && addresses.p2pkh_compressed == config.target_address) ||
               (config.uncompressed && addresses.p2pkh_uncompressed == config.target_address) {
                Some(SeedMatch {
                    seed,
                    engine: config.engine.name(),
                    timestamp_ms: config.timestamp_ms,
                    private_key: privkey,
                    address_compressed: addresses.p2pkh_compressed,
                    address_uncompressed: addresses.p2pkh_uncompressed,
                })
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow::anyhow!("Seed not found in range"))
}
```

**Affects:** Core scanner implementation, GPU kernel design, validation framework

---

#### Decision 4: GPU Kernel Validation - Deterministic CPU/GPU Equivalence

**Decision:** Mandatory CPU Reference + GPU Kernel Matching

**Strategy:**

**1. CPU Reference Implementation (Source of Truth)**

Every PRNG engine MUST have a CPU reference implementation that:
- Implements the `PrngEngine` trait
- Is deterministic (same seed → same output)
- Matches historical browser behavior
- Validated against deterministic test vectors

**2. GPU Kernel Development**

GPU kernels are optimized implementations that MUST match CPU output:

```c
// cl/randstorm_mwc1616.cl

__kernel void randstorm_mwc1616_search(
    __global const ulong *seed_range,
    __global const uchar *target_address_hash,
    __global ulong *results,
    const ulong timestamp_ms,
    const uint compressed,
    const uint uncompressed
) {
    // Each thread tests one seed
    ulong seed = seed_range[get_global_id(0)];
    
    // V8 MWC1616 PRNG (MUST match CPU implementation)
    uint mwc_state[2];
    mwc_state[0] = (uint)(seed >> 32);
    mwc_state[1] = (uint)(seed & 0xFFFFFFFF);
    
    // Fill pool (hi→lo order for jsbn compatibility)
    uchar pool[256];
    for (int i = 255; i >= 0; i--) {
        ulong mwc = (ulong)mwc_state[0] * 18030 + (ulong)mwc_state[1];
        mwc_state[0] = (uint)(mwc >> 16);
        mwc_state[1] = (uint)(mwc & 0xFFFF);
        
        float rand = (float)mwc_state[0] / 65536.0f;
        pool[i] = (uchar)(rand * 256.0f);
    }
    
    // ARC4 init + first 32 bytes → privkey
    // ... (follows jsbn ordering)
    
    // Generate addresses (both compressed & uncompressed)
    // ... secp256k1 operations
    
    // Match against target
    if (match_found) {
        results[0] = seed;
    }
}
```

**3. GPU/CPU Equivalence Testing**

```rust
// tests/randstorm_validation/gpu_cpu_equivalence_test.rs

#[test]
fn test_gpu_cpu_equivalence() {
    let test_vectors = load_deterministic_vectors("tier1_core_smoke.json");
    
    for vector in test_vectors {
        // CPU reference
        let cpu_result = run_cpu_search(&vector.input);
        
        // GPU kernel
        let gpu_result = run_gpu_search(&vector.input);
        
        // MUST match exactly
        assert_eq!(
            cpu_result.private_key,
            gpu_result.private_key,
            "GPU/CPU mismatch for vector {}: seed={}",
            vector.id,
            vector.input.prng_seed
        );
        
        assert_eq!(
            cpu_result.addresses,
            gpu_result.addresses,
            "Address mismatch for vector {}",
            vector.id
        );
    }
}
```

**4. CI/CD GPU Validation**

```yaml
# .github/workflows/randstorm-validation.yml

jobs:
  gpu-cpu-equivalence:
    runs-on: ubuntu-latest-gpu
    steps:
      - name: Run GPU/CPU equivalence tests
        run: cargo test --test gpu_cpu_equivalence_test --features gpu
      - name: Fail if any mismatch
        run: |
          if [ $? -ne 0 ]; then
            echo "GPU kernel does not match CPU reference!"
            exit 1
          fi
```

**Enforcement:**
- ✅ GPU kernel cannot be merged without 100% CPU equivalence
- ✅ Deterministic test vectors validate both CPU and GPU
- ✅ Any GPU optimization must preserve exact CPU output

**Affects:** GPU kernel implementation, CI/CD pipeline, validation framework

---

#### Decision 5: End-to-End Pipeline Validation

**Decision:** Stage-by-Stage Validation with Known Vulnerable Address Gate

**Validation Pipeline:**

```
Stage 1: PRNG Validation
  ├─ Input: (engine, seed, os_entropy)
  ├─ Output: PRNG state, random sequence
  └─ Validation: Matches deterministic test vectors

Stage 2: Pool Fill Validation
  ├─ Input: PRNG state
  ├─ Output: 256-byte pool (hi→lo order)
  └─ Validation: Matches reference pool bytes

Stage 3: ARC4 Initialization
  ├─ Input: Pool bytes
  ├─ Output: ARC4 state
  └─ Validation: Matches reference ARC4 state

Stage 4: Private Key Generation
  ├─ Input: ARC4 state
  ├─ Output: First 32 bytes → private key
  └─ Validation: Matches reference private key

Stage 5: Address Derivation
  ├─ Input: Private key
  ├─ Output: Compressed & uncompressed addresses
  └─ Validation: Matches reference addresses

Stage 6: Known Vulnerable Address (MANDATORY GATE)
  ├─ Input: Published vulnerable address + timestamp
  ├─ Output: Seed that generates that address
  └─ Validation: MUST find the published address
```

**Implementation:**

```rust
// tests/randstorm_validation/end_to_end_test.rs

#[test]
fn test_end_to_end_pipeline() {
    let vectors = load_deterministic_vectors("v8_mwc1616.json");
    
    for vector in vectors {
        // Stage 1: PRNG
        let mut prng = V8Mwc1616::new_with_seed(
            vector.input.prng_seed,
            vector.input.os_entropy,
        );
        assert_eq!(prng.state(), vector.expected.prng_state);
        
        // Stage 2: Pool fill
        let mut pool = [0u8; 256];
        prng.fill_pool(&mut pool, PoolFillOrder::HiToLo);
        assert_eq!(pool, vector.expected.pool_bytes);
        
        // Stage 3: ARC4 init
        let arc4 = Arc4::init_from_pool(&pool);
        assert_eq!(arc4.state(), vector.expected.arc4_state);
        
        // Stage 4: Private key
        let privkey = arc4.first_32_bytes();
        assert_eq!(privkey, vector.expected.private_key);
        
        // Stage 5: Addresses
        let addresses = derive_both_addresses(&privkey)?;
        assert_eq!(addresses.p2pkh_compressed, vector.expected.addresses.p2pkh_compressed);
        assert_eq!(addresses.p2pkh_uncompressed, vector.expected.addresses.p2pkh_uncompressed);
    }
}

#[test]
#[ignore] // Only run on demand (expensive)
fn test_known_vulnerable_address() {
    // THE mandatory gate: find the published Randstorm address
    let known_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"; // Example
    let transaction_timestamp = 1325376000000; // From blockchain
    
    // Seed search around timestamp
    let result = brute_force_seed_range(SeedSearchConfig {
        engine: BrowserEngine::V8Mwc1616,
        timestamp_ms: transaction_timestamp,
        seed_bit_range: (32, 48),
        target_address: known_address.to_string(),
        compressed: true,
        uncompressed: true,
    }, None);
    
    assert!(result.is_ok(), "Failed to find known vulnerable address!");
    
    let seed_match = result.unwrap();
    println!("Found vulnerable address!");
    println!("  Seed: {:#x}", seed_match.seed);
    println!("  Engine: {}", seed_match.engine);
    println!("  Address: {}", seed_match.address_compressed);
}
```

**Production Readiness Gate:**

```
CANNOT CLAIM PRODUCTION-READY UNTIL:
  ✅ 100% pass on deterministic vectors (Tier 1)
  ✅ 100% GPU/CPU equivalence
  ✅ 95%+ pass on multi-engine coverage (Tier 3)
  ✅ FOUND the known vulnerable address (Tier 4)
```

**Affects:** CI/CD pipeline, release criteria, scanner validation

---


### Implementation Requirements Summary

**Critical Implementation Specifications (From Gap Analysis):**

**1. Math.random Engine Coverage**

Implement ALL browser PRNG variants from 2011-2014 era:

- ✅ **V8 MWC1616** - Chrome (already specified)
- ✅ **SpiderMonkey-era Math.random** - Firefox (NEW: must add correct output scaling and seeding)
- ✅ **JSC-era Math.random** - Safari (NEW: must add correct output scaling and seeding)
- ✅ **drand48** - Linux/Unix systems (NEW: if relevant to web wallets)
- ✅ **Java Random** - If applicable to BitcoinJ-based wallets (NEW)

**Correct Output Scaling Requirements:**
- Each engine has different scaling from internal state → [0, 1) range
- Must match browser-specific scaling exactly
- Document the scaling formula per engine

**2. Configurable Engine & Seed Controls (CLI)**

```bash
# Scanner CLI interface
cargo run --release -- randstorm \
  --engine v8_mwc1616 \                 # Select engine
  --timestamp 1325376000000 \            # Base timestamp
  --seed-override 0x123456789ABC \       # Explicit seed (testing)
  --seed-brute-force-bits 32 \           # Brute-force 2^32 seeds
  --timestamp-window-ms 10000 \          # ±10s around timestamp
  --compressed \                         # Check compressed addresses
  --uncompressed \                       # Check uncompressed addresses
  --target-file addresses.txt            # Target address list
```

**Seed Brute-Force Guards:**
- ✅ Maximum 32 bits by default (4.3 billion seeds)
- ✅ Warn if >32 bits requested (feasibility check)
- ✅ GPU-accelerated brute-force only
- ✅ Progress reporting every 1M seeds

**3. Timestamp Handling - Fine-Grained**

```rust
// src/scans/randstorm/timestamp.rs

pub struct TimestampConfig {
    pub base_timestamp_ms: u64,
    pub window_before_ms: u64,      // e.g., -60000 (1 min before)
    pub window_after_ms: u64,       // e.g., +60000 (1 min after)
    pub step_size_ms: u64,          // e.g., 100 (sub-second steps)
}

impl TimestampConfig {
    pub fn generate_timestamp_range(&self) -> Vec<u64> {
        let start = self.base_timestamp_ms - self.window_before_ms;
        let end = self.base_timestamp_ms + self.window_after_ms;
        
        (start..=end)
            .step_by(self.step_size_ms as usize)
            .collect()
    }
}
```

**User-Specified Windows:**
- Support creation time windows (not just first-tx time)
- Allow offset lists for batch-checking plausible times
- Sub-second granularity if needed

**4. Key Derivation - Both Compressed & Uncompressed (MANDATORY)**

```rust
// src/scans/randstorm/derivation.rs

pub struct AddressSet {
    pub p2pkh_compressed: String,
    pub p2pkh_uncompressed: String,
    // Optional: other formats
    pub p2wpkh_compressed: Option<String>,
    pub p2sh_p2wpkh: Option<String>,
}

pub fn derive_both_addresses(privkey: &[u8]) -> Result<AddressSet> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(privkey)?;
    
    // CRITICAL: Generate BOTH
    let pubkey_compressed = PublicKey::from_secret_key(&secp, &secret_key);
    let pubkey_uncompressed = pubkey_compressed.uncompressed();
    
    Ok(AddressSet {
        p2pkh_compressed: Address::p2pkh(&pubkey_compressed, Network::Bitcoin).to_string(),
        p2pkh_uncompressed: Address::p2pkh(&pubkey_uncompressed, Network::Bitcoin).to_string(),
        p2wpkh_compressed: None, // Optional
        p2sh_p2wpkh: None,       // Optional
    })
}

// Direct sweep MUST check both
pub fn check_address_match(
    addresses: &AddressSet,
    target_set: &HashSet<String>,
) -> Option<String> {
    if target_set.contains(&addresses.p2pkh_compressed) {
        return Some(addresses.p2pkh_compressed.clone());
    }
    if target_set.contains(&addresses.p2pkh_uncompressed) {
        return Some(addresses.p2pkh_uncompressed.clone());
    }
    None
}
```

**5. Fast Target Matching - Bloom Filters & Large Address Lists**

```rust
// src/scans/randstorm/target_matching.rs

use bloomfilter::Bloom;

pub enum TargetMatcher {
    HashSet(HashSet<String>),           // Small sets (<1M addresses)
    BloomFilter(Bloom<String>),          // Large sets (>1M addresses)
    Hybrid {                             // Best of both
        bloom: Bloom<String>,
        hashset: HashSet<String>,
    },
}

impl TargetMatcher {
    pub fn from_file(path: &Path, estimated_size: usize) -> Result<Self> {
        if estimated_size > 1_000_000 {
            // Use Bloom filter for large sets
            let mut bloom = Bloom::new_for_fp_rate(estimated_size, 0.01);
            
            for line in BufReader::new(File::open(path)?).lines() {
                let address = line?;
                bloom.set(&address);
            }
            
            Ok(Self::BloomFilter(bloom))
        } else {
            // HashSet for smaller sets
            let mut hashset = HashSet::new();
            for line in BufReader::new(File::open(path)?).lines() {
                hashset.insert(line?);
            }
            Ok(Self::HashSet(hashset))
        }
    }
    
    pub fn contains(&self, address: &str) -> bool {
        match self {
            Self::HashSet(set) => set.contains(address),
            Self::BloomFilter(bloom) => bloom.check(address),
            Self::Hybrid { bloom, hashset } => {
                // Check bloom first (fast negative), then hashset (confirm positive)
                bloom.check(address) && hashset.contains(address)
            }
        }
    }
}
```

**Dataset Feeding:**
```bash
# Feed chain snapshot (compressed addresses)
cargo run -- randstorm \
  --target-file blockchain_snapshot_p2pkh.txt \
  --estimated-size 50000000

# Feed watchlist (smaller set)
cargo run -- randstorm \
  --target-file watchlist.txt \
  --estimated-size 10000
```

**6. Deterministic Test Harness (Already Specified, Reinforced)**

```rust
// tests/randstorm_validation/deterministic_harness/emit_test.rs

/// Emit full pipeline output for regression and validation
#[test]
fn emit_pipeline_outputs() {
    let engines = vec![
        BrowserEngine::V8Mwc1616,
        BrowserEngine::SpiderMonkeyMwc,
        BrowserEngine::JscXorshift128,
    ];
    
    for engine in engines {
        for seed in test_seeds() {
            let result = run_full_pipeline(engine, seed);
            
            // Emit for validation
            println!("Engine: {}", engine.name());
            println!("Seed: {:#x}", seed);
            println!("Pool (first 32): {:?}", &result.pool[..32]);
            println!("Private Key: {}", hex::encode(&result.privkey));
            println!("Address (compressed): {}", result.address_compressed);
            println!("Address (uncompressed): {}", result.address_uncompressed);
            println!("---");
        }
    }
}
```

---

