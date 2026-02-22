# temporal-planetarium Implementation Epics

**Project:** temporal-planetarium
**Generated:** 2025-12-18
**Based on Research:**
- Randstorm Vulnerability Integration Research (2025-12-17)
- CryptoDeepTools Analysis (2025-12-17)

---

## Epic 1: Randstorm Scanner Enhancement & Validation

**Epic ID:** EPIC-001
**Priority:** High
**Est. Duration:** 4-6 weeks
**Dependencies:** None
**Research Source:** technical-randstorm-integration-2025-12-17.md

### Epic Goal
Enhance and validate the Randstorm scanner implementation based on Ali Akhgar's deep-dive analysis, ensuring correctness, completeness, and attack feasibility alignment.

### Background & Context
Ali Akhgar's analysis reveals critical insights into the Randstorm vulnerability:
- Dual seeding provides minimal entropy gain
- RC4 state dependency complicates multi-wallet attacks
- LFSR seed generation makes initial seeds "hard to determine"
- Mass attacks are infeasible; targeted attacks viable for "experienced or funded hackers"

Current implementation status:
- ✅ MWC1616 PRNG with correct constants (18000, 30903)
- ✅ ARC4/RC4 stream cipher for key derivation
- ✅ GPU acceleration with OpenCL kernels
- ⚠️ LFSR seed generation complexity not fully modeled
- ⚠️ RC4 state dependency for multi-wallet attacks incomplete
- ❌ Z3 theorem prover integration missing

### Stories

#### Story 1.1: Generate Controlled Test Vectors
**Story ID:** STORY-001-001
**Priority:** Critical
**Est. Points:** 5
**Assignee:** TBD

**User Story:**
As a security researcher, I need to generate controlled test vectors with known seeds so that I can validate the Randstorm scanner produces correct results.

**Acceptance Criteria:**
- [ ] Create `tests/test_vector_generation.rs` with controlled test vector generation
- [ ] Generate 10+ test vectors with known seeds covering different timestamp ranges (2011-2015)
- [ ] Test both compressed and uncompressed address formats
- [ ] Document expected behavior for each test vector
- [ ] Never rely on unverified public examples (Ali Akhgar's disclaimer)
- [ ] Save test vectors to `tests/fixtures/randstorm_test_vectors.json`

**Technical Notes:**
```rust
// tests/test_vector_generation.rs
fn generate_controlled_test_vector() {
    let known_seed = 0x12345678u64;
    let known_timestamp = 1400000000000u64; // 2014-05-13
    
    let mut prng = WeakMathRandom::from_timestamp(
        MathRandomEngine::V8Mwc1616,
        known_timestamp,
        Some(known_seed)
    );
    
    let pool = generate_pool(&mut prng, known_timestamp);
    let privkey = arc4_derive(&pool);
    let address = privkey_to_p2pkh(&privkey);
    
    save_test_vector(TestVector {
        seed: known_seed,
        timestamp: known_timestamp,
        address,
        expected_privkey: privkey, // For test only
    });
}
```

---

#### Story 1.2: Validate Dual Seeding Behavior
**Story ID:** STORY-001-002
**Priority:** High
**Est. Points:** 3
**Assignee:** TBD

**User Story:**
As a researcher, I need to validate that timestamp is XORed into the pool twice (initialization + pre-ARC4) and document the actual entropy gain.

**Acceptance Criteria:**
- [ ] Confirm timestamp XOR occurs at pool initialization
- [ ] Confirm timestamp XOR occurs immediately before ARC4 initialization
- [ ] Measure timing delta between the two seedings (should be negligible)
- [ ] Document entropy analysis: does dual seeding add meaningful entropy?
- [ ] Add unit test `test_dual_seeding()` validating both XOR operations
- [ ] Update documentation with Ali Akhgar's finding: "minimal entropy gain"

**Reference:**
Ali Akhgar: "At the time of writing, I don't know whether seeding twice would introduce a higher entropy or not. But it is obvious that this effort to introduce entropy into the pool is not effective as the seed is Unix-Time in milliseconds."

---

#### Story 1.3: Document RC4 State Dependency
**Story ID:** STORY-001-003
**Priority:** Medium
**Est. Points:** 3
**Assignee:** TBD

**User Story:**
As a researcher, I need clear documentation explaining how RC4 state evolution affects multi-wallet generation from the same pool.

**Acceptance Criteria:**
- [ ] Create `docs/randstorm-rc4-state.md` explaining RC4 stream cipher mechanics
- [ ] Document that same pool generates different private keys for multiple wallets
- [ ] Add unit test demonstrating: `generate_wallet_from_pool(pool, index=0)` ≠ `generate_wallet_from_pool(pool, index=1)`
- [ ] Explain attack complexity increase for 2nd+ wallets
- [ ] Include Ali Akhgar's insight: "Same inputs to same RC4 will not have same output"
- [ ] Update attack planning documentation with multi-wallet considerations

---

#### Story 1.4: Implement LFSR Seed Generation Model
**Story ID:** STORY-001-004
**Priority:** High
**Est. Points:** 8
**Assignee:** TBD

**User Story:**
As a researcher, I need to model V8's LFSR seed generation to accurately simulate initial MWC1616 seed uncertainty.

**Acceptance Criteria:**
- [ ] Create `src/scans/randstorm/prng/lfsr_seed.rs`
- [ ] Implement LFSR polynomial matching V8 engine (verify against V8 source)
- [ ] Generate MWC1616 seeds from LFSR state
- [ ] Expand search space to include LFSR state uncertainty
- [ ] Document computational cost increase vs. direct MWC1616
- [ ] Add unit tests validating LFSR output determinism
- [ ] Update attack complexity estimator with LFSR search space

**Reference:**
Ali Akhgar: "MWC1616 initial seeds are generated by another LFSR algorithm, which makes the initial seeds hard to determine."

**Technical Specification:**
```rust
// src/scans/randstorm/prng/lfsr_seed.rs
pub struct LfsrSeedGenerator {
    state: u64,
}

impl LfsrSeedGenerator {
    pub fn new(process_entropy: u64) -> Self {
        Self { state: process_entropy }
    }
    
    pub fn next(&mut self) -> u32 {
        // LFSR polynomial (verify against V8 source)
        let bit = ((self.state >> 0) ^ (self.state >> 2) 
                  ^ (self.state >> 3) ^ (self.state >> 5)) & 1;
        self.state = (self.state >> 1) | (bit << 63);
        (self.state & 0xFFFFFFFF) as u32
    }
    
    pub fn generate_mwc1616_seeds(&mut self) -> (u32, u32) {
        (self.next(), self.next())
    }
}
```

---

#### Story 1.5: Integrate Z3 Theorem Prover for MWC1616 Seed Solving
**Story ID:** STORY-001-005
**Priority:** High
**Est. Points:** 13
**Assignee:** TBD

**User Story:**
As a researcher, I need Z3-based MWC1616 state recovery to implement advanced attacks as demonstrated by Unciphered Labs.

**Acceptance Criteria:**
- [ ] Add `z3` crate dependency to Cargo.toml
- [ ] Create `src/scans/randstorm/z3_solver.rs`
- [ ] Implement `MwcConstraintSolver` with MWC1616 state transition constraints
- [ ] Support solving for initial seeds given observed outputs
- [ ] Handle case where multiple addresses from same pool are known (constrains MWC1616 state)
- [ ] Document use case: attacker has multiple addresses from same page session
- [ ] Add integration test validating seed recovery
- [ ] Benchmark solver performance (expected: seconds to minutes)

**Reference:**
Ali Akhgar: "MWC1616 prediction which has been successfully done through Z3 and also UncipheredLabs announced that they had successfully predicted the MWC1616."

**Technical Specification:**
```rust
// src/scans/randstorm/z3_solver.rs
use z3::{Context, Solver, ast::{Int, Bool}};

pub struct MwcConstraintSolver<'ctx> {
    ctx: &'ctx Context,
    solver: Solver<'ctx>,
}

impl<'ctx> MwcConstraintSolver<'ctx> {
    pub fn add_mwc1616_constraints(
        &self,
        s1: &Int<'ctx>,
        s2: &Int<'ctx>,
        outputs: &[u32],
    ) {
        for &output in outputs {
            // s1_next = 18000 * (s1 & 0xFFFF) + (s1 >> 16)
            // s2_next = 30903 * (s2 & 0xFFFF) + (s2 >> 16)
            // Constrain combined output
        }
    }
    
    pub fn solve_for_seeds(&self) -> Option<(u32, u32)> {
        match self.solver.check() {
            z3::SatResult::Sat => {
                let model = self.solver.get_model()?;
                // Extract s1, s2
                Some((s1, s2))
            }
            _ => None,
        }
    }
}
```

---

#### Story 1.6: Add Firefox SpiderMonkey PRNG Support
**Story ID:** STORY-001-006
**Priority:** Medium
**Est. Points:** 8
**Assignee:** TBD

**User Story:**
As a researcher, I need support for Firefox's SpiderMonkey Math.random() implementation to expand coverage beyond Chrome V8.

**Acceptance Criteria:**
- [ ] Research SpiderMonkey MWC variant (similar to V8 but potentially different constants)
- [ ] Create `src/scans/randstorm/prng/firefox_sm.rs`
- [ ] Implement `BrowserEngine::FirefoxSM` enum variant
- [ ] Add browser engine selection to `BrowserFingerprint` struct
- [ ] Update fingerprint database with Firefox browser versions (2011-2015)
- [ ] Add unit tests for Firefox-specific PRNG behavior
- [ ] Document differences from V8 MWC1616

**Technical Specification:**
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserEngine {
    ChromeV8,        // MWC1616 (2011-2015)
    FirefoxSM,       // SpiderMonkey MWC variant
    SafariJSC,       // JavaScriptCore (future)
    ChromeV8Modern,  // XorShift128+ (2015+)
}

pub struct BrowserFingerprint {
    pub id: u32,
    pub browser_engine: BrowserEngine,  // NEW
    pub market_share: f32,
    pub version_range: (u32, u32),      // NEW
    // ... existing fields
}
```

---

#### Story 1.7: Create Attack Complexity Estimator Tool
**Story ID:** STORY-001-007
**Priority:** Medium
**Est. Points:** 5
**Assignee:** TBD

**User Story:**
As a researcher, I need an attack complexity estimator to assess feasibility before launching scans.

**Acceptance Criteria:**
- [ ] Create `src/scans/randstorm/attack_estimator.rs`
- [ ] Implement `AttackComplexityEstimate` struct with feasibility classification
- [ ] Calculate candidate count: timestamp_window × fingerprints_to_test
- [ ] Estimate GPU time: candidates / (1M per second)
- [ ] Estimate CPU time: candidates / (10K per second)
- [ ] Classify feasibility: HighlyFeasible (<24h), Feasible (1-7d), RequiresResources (>7d), Infeasible
- [ ] Add CLI command: `randstorm-scan --estimate-complexity`
- [ ] Document Ali Akhgar's guidance: targeted feasible, mass attack infeasible

**Reference:**
Ali Akhgar: "Even 1 single day is 86,400,000 milliseconds; Leaving the attacker 86 Million possible seeds for only one day."

---

### Epic Success Criteria
- [ ] All 7 stories completed and validated
- [ ] Test vector suite generates and validates successfully
- [ ] LFSR and Z3 integration functional
- [ ] Multi-browser support (Chrome + Firefox minimum)
- [ ] Attack complexity estimator operational
- [ ] Documentation updated with all Ali Akhgar insights
- [ ] Performance benchmarks meet targets (>1M candidates/sec GPU)

---

## Epic 2: CryptoDeepTools Integration & Cross-Validation

**Epic ID:** EPIC-002
**Priority:** Medium
**Est. Duration:** 3-4 weeks
**Dependencies:** EPIC-001 (Story 1.1 - test vectors)
**Research Source:** technical-cryptodeeptools-research-2025-12-17.md

### Epic Goal
Establish integration patterns with CryptoDeepTools for cross-validation, shared test vectors, and complementary tool usage.

### Background & Context
CryptoDeepTools provides a complementary Python-based toolkit:
- **Strengths:** Accessible Python code, rapid prototyping, educational value
- **Weaknesses:** 10-100x slower than Rust, no GPU acceleration
- **Integration Opportunity:** Use both tools complementarily

Strategic recommendation: Prototype in CryptoDeepTools (Python), optimize in temporal-planetarium (Rust)

### Stories

#### Story 2.1: Shared Test Vector Suite
**Story ID:** STORY-002-001
**Priority:** High
**Est. Points:** 5
**Assignee:** TBD

**User Story:**
As a researcher, I need a standardized test vector format compatible with both CryptoDeepTools and temporal-planetarium for cross-validation.

**Acceptance Criteria:**
- [ ] Define JSON schema for test vectors compatible with Python and Rust
- [ ] Export temporal-planetarium test vectors to shared format
- [ ] Create Python script to validate CryptoDeepTools against shared vectors
- [ ] Document cross-validation workflow
- [ ] Contribute test vectors back to CryptoDeepTools project (if accepted)
- [ ] Add CI check: both tools must pass same test vectors

**Test Vector Schema:**
```json
{
  "version": "1.0",
  "vulnerability": "randstorm",
  "test_vectors": [
    {
      "id": "tv-001",
      "seed": "0x12345678",
      "timestamp_ms": 1400000000000,
      "browser_engine": "chrome_v8",
      "expected_address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
      "address_type": "p2pkh_compressed"
    }
  ]
}
```

---

#### Story 2.2: Python Pseudocode Documentation
**Story ID:** STORY-002-002
**Priority:** Medium
**Est. Points:** 3
**Assignee:** TBD

**User Story:**
As a researcher learning the algorithms, I need Python pseudocode alongside Rust implementation for better understanding.

**Acceptance Criteria:**
- [ ] For each scanner (Randstorm, MilkSad, etc.), add Python pseudocode to docs
- [ ] Create `docs/algorithms/randstorm-pseudocode.md`
- [ ] Pseudocode should match CryptoDeepTools style for easy comparison
- [ ] Include references to CryptoDeepTools implementations
- [ ] Add "See CryptoDeepTools for runnable Python version" notes
- [ ] Maintain consistency between Rust code and pseudocode

**Example:**
```markdown
## Randstorm Algorithm (Simplified)

```python
# Reference implementation (see CryptoDeepTools)
def randstorm_scan(address, timestamp_range):
    for ts in timestamp_range:
        prng = MWC1616(seed=ts)
        pool = generate_pool(prng)
        privkey = arc4_derive(pool)
        if derive_address(privkey) == address:
            return Match(address, ts)
```
```

---

#### Story 2.3: Performance Comparison Benchmark Suite
**Story ID:** STORY-002-003
**Priority:** Medium
**Est. Points:** 5
**Assignee:** TBD

**User Story:**
As a researcher, I need benchmarks comparing temporal-planetarium vs CryptoDeepTools performance to validate the 10-100x speedup claim.

**Acceptance Criteria:**
- [ ] Create `benches/cryptodeeptools_comparison.rs`
- [ ] Benchmark identical workload: 1M address derivations
- [ ] Test on same hardware: CPU-only for fair comparison
- [ ] Measure: temporal-planetarium (Rust CPU), CryptoDeepTools (Python), temporal-planetarium (Rust GPU)
- [ ] Document results in `docs/performance-comparison.md`
- [ ] Validate 10-100x speedup claim
- [ ] Publish results for community validation

**Expected Results:**
- Python (CryptoDeepTools): ~10K addresses/sec
- Rust CPU (temporal-planetarium): ~100K-500K addresses/sec
- Rust GPU (temporal-planetarium): ~1M+ addresses/sec

---

#### Story 2.4: Modular Tool Export (Library Crate)
**Story ID:** STORY-002-004
**Priority:** Low
**Est. Points:** 8
**Assignee:** TBD

**User Story:**
As a tool developer, I need to use temporal-planetarium scanners as a library crate so external tools can leverage Rust performance.

**Acceptance Criteria:**
- [ ] Create `temporal-planetarium-lib` crate (library)
- [ ] Export scanner modules: `pub use crate::scans::randstorm::RandstormScanner`
- [ ] Provide clean API with documentation
- [ ] Add examples showing library usage
- [ ] Publish to crates.io (optional)
- [ ] Update main binary to depend on library crate
- [ ] Document integration workflow for external tools

**API Example:**
```rust
// External tool using temporal-planetarium-lib
use temporal_planetarium_lib::RandstormScanner;

fn main() {
    let scanner = RandstormScanner::new();
    let results = scanner.scan(&addresses, gpu_enabled=true);
}
```

---

#### Story 2.5: Python Bindings (PyO3)
**Story ID:** STORY-002-005
**Priority:** Low (Future Enhancement)
**Est. Points:** 13
**Assignee:** TBD

**User Story:**
As a Python researcher, I need to call temporal-planetarium's Rust scanners from Python to get GPU performance without rewriting code.

**Acceptance Criteria:**
- [ ] Add `pyo3` dependency for Python bindings
- [ ] Create `python/` directory with Python package
- [ ] Expose core scanners via PyO3 wrappers
- [ ] Build Python wheel with `maturin`
- [ ] Add Python examples and documentation
- [ ] Test on Python 3.8+
- [ ] Publish to PyPI (optional)

**Usage Example:**
```python
# Python researcher using Rust performance
import temporal_planetarium

scanner = temporal_planetarium.RandstormScanner()
results = scanner.scan(addresses, gpu=True)
print(f"Found {len(results)} vulnerable addresses")
```

---

### Epic Success Criteria
- [ ] All 5 stories completed
- [ ] Shared test vector suite validates both tools
- [ ] Python documentation aids learning
- [ ] Performance benchmarks published
- [ ] Library crate enables external integrations
- [ ] Optional: Python bindings functional

---

## Epic Priority & Roadmap

**Immediate (Sprint 1-2):**
- Epic 1, Story 1.1: Test vectors (CRITICAL)
- Epic 1, Story 1.2: Dual seeding validation
- Epic 1, Story 1.3: RC4 state documentation

**Short-term (Sprint 3-4):**
- Epic 1, Story 1.4: LFSR implementation
- Epic 1, Story 1.7: Attack complexity estimator
- Epic 2, Story 2.1: Shared test vectors

**Medium-term (Sprint 5-8):**
- Epic 1, Story 1.5: Z3 integration
- Epic 1, Story 1.6: Firefox support
- Epic 2, Story 2.2-2.3: Documentation & benchmarks

**Long-term (Future):**
- Epic 2, Story 2.4: Library crate
- Epic 2, Story 2.5: Python bindings

---

**Total Stories:** 12
**Total Estimated Points:** 78
**Estimated Timeline:** 7-10 weeks (depending on team velocity)

**Research Sources:**
- Ali Akhgar, "Randstorm: Bitcoin vulnerability deep dive" (Sep 2024)
- CryptoDeepTools GitHub Repository Analysis
- temporal-planetarium existing implementation
- Unciphered Labs Randstorm disclosure
