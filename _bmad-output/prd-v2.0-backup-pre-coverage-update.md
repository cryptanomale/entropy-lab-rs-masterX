---
stepsCompleted: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
inputDocuments:
  - "_bmad-output/analysis/product-brief-temporal-planetarium-2025-12-17.md"
  - "_bmad-output/analysis/research/technical-randstorm-research-2025-12-17.md"
  - "_bmad-output/index.md"
  - "project-context.md"
  - "_bmad-output/architecture.md"
  - "_bmad-output/randstorm-tech-spec.md"
documentCounts:
  briefs: 1
  research: 1
  brainstorming: 0
  projectDocs: 3
  techSpecs: 1
workflowType: 'prd'
lastStep: 11
status: 'revised'
project_name: 'temporal-planetarium'
user_name: 'Moe'
date: '2025-12-17'
revised_date: '2025-12-22'
feature: 'Randstorm/BitcoinJS Scanner'
version: '2.0'
changelog:
  - date: '2025-12-22'
    changes: 'Major revision: Researcher-focused Phase 1, added testing strategy, reformatted ACs to Given/When/Then, added implementation guidance, expanded security policies'
---

# Product Requirements Document - Randstorm/BitcoinJS Scanner

**Author:** Moe  
**Date:** 2025-12-17 (Revised: 2025-12-22)  
**Version:** 2.0  
**Project:** Temporal Planetarium (entropy-lab-rs)  
**Feature:** Randstorm/BitcoinJS Vulnerability Scanner

**Revision History:**
- v1.0 (2025-12-17): Initial PRD with multi-persona scope
- v2.0 (2025-12-22): Major revision - researcher-focused Phase 1, added testing strategy framework, reformatted acceptance criteria to Given/When/Then format, added implementation guidance, expanded security policies based on tech spec validation

---


## Executive Summary

### Product Vision

The Randstorm/BitcoinJS Scanner extends Temporal Planetarium's comprehensive vulnerability research platform by addressing its most critical gap: detecting Bitcoin wallets generated between 2011-2015 using weak JavaScript pseudo-random number generators (PRNGs). With an estimated 1.4 million BTC ($1+ billion) at risk and active attacker exploitation ongoing, this GPU-accelerated scanner provides the defensive capability **security researchers** desperately need.

**Phase 1 Focus:** This PRD defines a **researcher-focused implementation** designed for security professionals conducting vulnerability assessments on Bitcoin wallet datasets. Individual wallet owner support and professional consulting features are deferred to Phase 2+ to maintain tight scope and rapid delivery.

This feature transforms Temporal Planetarium from an excellent 18-scanner toolkit into a complete cryptocurrency vulnerability research platform, covering the highest-value security threat in the ecosystem while maintaining the project's white-hat, responsible disclosure focus.

### Problem Statement

Between 2011-2015, popular Bitcoin wallet services (Blockchain.info, CoinPunk, BrainWallet, BitAddress) used JavaScript's Math.random() and Date() functions for private key generation. These functions provided only 40-60 bits of effective entropy (versus the cryptographic requirement of 256 bits) due to:

- Predictable browser fingerprints (user-agent strings, screen resolutions, timezones)
- Timestamp constraints (Date.now() milliseconds)
- Limited PRNG implementations (MWC1616, LCG, Xorshift, Mersenne Twister)

The 2023 Randstorm disclosure revealed this systemic weakness affects 1.4 million BTC, yet:
- No comprehensive public scanner exists
- Temporal Planetarium (despite 18 scanners) lacks this critical capability
- Attackers are actively exploiting vulnerable wallets
- Security professionals cannot offer Randstorm auditing services
- Wallet owners have no way to check if their 2011-2015 wallets are at risk

**Time Pressure:** Every week without a defensive scanner = more wallets swept by attackers. MVP must ship fast.

### Solution Overview

**3-Phase GPU-Accelerated Scanner:**

**Phase 1 - MVP (Week 1): Speed-First Coverage**
- Chrome V8 PRNG reconstruction (MWC1616 algorithm)
- Top 100 browser configurations (35%+ market share combinations)
- Single derivation path (most common for 2011-2015)
- Basic OpenCL GPU kernel
- **Target: 60-70% vulnerable wallet coverage**
- **Validation: 100% match on 2023 Randstorm test vectors**

**Phase 2 - Expansion (Week 2): Comprehensive Coverage**
- Firefox/SpiderMonkey + Safari/JavaScriptCore PRNG implementations
- 500 browser configurations (extended historical database)
- Multi-path derivation (BIP32/44/49/84)
- GPU optimization (device-specific tuning)
- **Target: 85-90% vulnerable wallet coverage**

**Phase 3 - Optimization (Week 3+): Maximum Effectiveness**
- Probabilistic search algorithms
- ML-based browser configuration prediction
- Adaptive search based on findings
- Multi-GPU support, checkpoint/resume
- **Target: 95%+ vulnerable wallet coverage**

**Technical Approach:**
- Reconstruct JavaScript PRNG state from browser fingerprint + timestamp
- GPU-accelerated search of reduced entropy space (2^50 to 2^55)
- Era-specific logic (2011-2012 vs 2013-2015 derivation paths)
- Integration with existing 46 OpenCL kernels and scanner patterns
- Responsible disclosure framework (90-day window, coordination with exchanges)

### Target Users & Use Cases

**Primary User (Phase 1 - IN SCOPE):**

**Security Researcher (Dr. Sarah Chen archetype)**
- **Profile:** Technical professional with deep understanding of cryptocurrency security, cryptography, and vulnerability research
- **Technical Skills:** High - comfortable with command-line tools, GPU acceleration concepts, Bitcoin address formats
- **Environment:** Has access to GPU hardware (NVIDIA/AMD), can build from source or use pre-compiled binaries
- **Needs:** Accuracy, reproducibility, transparent methodology, test vectors, batch processing capabilities
- **Use Case:** Batch scanning of Bitcoin address datasets (100s-10,000s of addresses) to identify vulnerable wallets generated with weak JavaScript PRNGs between 2011-2015. Independent validation of Randstorm findings, publish CVE research.
- **Success Criteria:** Scan 10,000 addresses in <24 hours with accurate vulnerability detection. Can reproduce results with 100% validation on test vectors. Generate detailed JSON results for analysis/reporting.
- **Workflow:**
  1. Prepare CSV file with target Bitcoin addresses
  2. Run `randstorm-scan --targets addresses.csv --phase 1 --output results.json`
  3. Analyze JSON results for vulnerable addresses (fingerprint ID, timestamp, confidence)
  4. Generate vulnerability assessment reports
  5. Follow responsible disclosure protocols for findings

**Deferred Users (Phase 2+ - OUT OF SCOPE for this PRD):**

**Security Consultant (Marcus Wei archetype)**
- **Needs:** Professional PDF reports, client-ready deliverables, proof-of-work documentation
- **Use Case:** Offer Randstorm scanning as billable audit service
- **Success Metric:** Integrate into workflow, generate revenue from high-value audits
- **Rationale for deferral:** Requires additional reporting features (PDF export, branding), higher liability exposure. Phase 1 core can be leveraged manually for consulting work.

**Wallet Owner (Alex Rodriguez archetype)**
- **Needs:** Simple yes/no answer, privacy protection, actionable guidance, non-technical interface
- **Use Case:** Check if personal 2011-2015 wallet is vulnerable, understand what to do
- **Success Metric:** Clear vulnerability status, follows recommendations to secure funds
- **Rationale for deferral:** Requires different UX (simplified interface, clear messaging for non-technical users), legal liability concerns (direct fund recovery guidance), can seek researcher assistance using Phase 1 tools.

**4. Educators & Historians (Prof. Li Zhang archetype)**
- **Needs:** Educational materials, historical context, case studies
- **Use Case:** Teach students about real-world cryptographic failures
- **Success Metric:** Curriculum integration, academic publications

### Key Success Metrics

**Phase 1 (Researcher-Focused) Success Criteria:**
- ✅ **Accuracy:** 100% detection of synthetic vulnerable test vectors (Chrome V8 MWC1616)
- ✅ **Coverage:** 60-70% estimated vulnerable wallet coverage using top 100 browser fingerprints
- ✅ **Performance:** ≥10x GPU speedup vs CPU baseline on RTX 3060 (or equivalent mid-range GPU)
- ✅ **Performance:** <30 minutes per address scan time (17.28M combinations: 100 fingerprints × 172,800 timestamps)
- ✅ **Quality:** Zero regressions in existing 18 scanners (all integration tests pass)
- ✅ **Security:** Zero private key materialization in logs/stdout (automated security audit passes)
- ✅ **Usability:** Researcher can scan 10,000 addresses in <24 hours with batch CSV processing

**Phase 2+ (Deferred) Success Criteria:**
- ⏸️ 85-90% coverage with expanded browser configurations (Firefox, Safari, IE PRNGs)
- ⏸️ Multi-path derivation operational (BIP44/49/84/86)
- ⏸️ 50x+ GPU speedup with increased complexity
- ⏸️ Independent security audit completed
- ⏸️ Professional PDF reporting for consultants
- ⏸️ Simplified UI for individual wallet owners

**Measurement Methods:**
- **Coverage estimation:** Fingerprint market share data × timestamp hit probability
- **Performance benchmarking:** Time 1000-address scan on reference hardware (RTX 3060)
- **Accuracy validation:** Synthetic vulnerable wallet test suite (10 known-vulnerable addresses)
- **Security validation:** Automated log scanning + manual code review for key leakage
- **Researcher feedback:** Survey 5+ security researchers post-release (usability, trust, accuracy)
- ✅ Community validation of methodology (peer review)
- ✅ Real-world vulnerable wallet identification (controlled test)
- ✅ Responsible disclosure framework operational

**Adoption & Impact Metrics:**
- GitHub stars: 500+ within 3 months
- Downloads: 1,000+ within first month
- Active users: 200+ security professionals
- Vulnerable wallets identified: 10+ confirmed findings
- Value protected: $10M+ in BTC through responsible disclosure
- False positive rate: <1%
- False negative rate: <5%

### Strategic Rationale

**Why This Feature Matters:**

1. **Completes Critical Ecosystem Gap**
   - Only major cryptocurrency vulnerability missing from 18-scanner platform
   - Addresses highest-value threat ($1B+ vs other scanners)
   - Transforms Temporal Planetarium into complete vulnerability toolkit

2. **Time-Critical Competitive Advantage**
   - No comprehensive open-source Randstorm scanner exists
   - First-mover advantage in white-hat defensive scanning
   - Attackers already exploiting - defensive capability urgently needed

3. **Proven Technical Foundation**
   - Leverages 46 existing GPU kernels (patterns established)
   - Follows modular scanner architecture (18 successful implementations)
   - Minimal new infrastructure required (maximum reuse)

4. **Clear Value Proposition**
   - $1B+ in vulnerable BTC vs ~3 weeks development effort
   - Exceptional ROI for security community
   - Enables new revenue streams for security consultants
   - Protects vulnerable users from catastrophic loss

5. **Responsible Leadership**
   - White-hat focus with disclosure framework
   - Educational value for cryptocurrency security community
   - Aligns with Temporal Planetarium's mission and values

### Scope & Boundaries

**In Scope - Phase 1 (Researcher-Focused MVP):**
- ✅ **Chrome V8 PRNG:** MWC1616 algorithm implementation (exact constants: 18000, 30903)
- ✅ **Browser Fingerprints:** Top 100 configurations (2011-2015) from validated CSV (`phase1_top100.csv`)
- ✅ **Address Support:** P2PKH (legacy Bitcoin addresses starting with '1') only
- ✅ **Derivation:** Direct private key → P2PKH (no BIP32 HD wallet paths)
- ✅ **GPU Acceleration:** OpenCL kernel (`randstorm_crack.cl`) following existing `trust_wallet_crack` pattern
- ✅ **CPU Fallback:** Rayon-based parallel implementation with bit-identical results to GPU
- ✅ **CLI Interface:** `randstorm-scan --targets <csv> [--phase 1] [--gpu|--cpu] [--output <file>]`
- ✅ **Input:** CSV with Bitcoin addresses (headerless or with 'address' column)
- ✅ **Output:** JSON/CSV with vulnerability results (address, fingerprint_id, timestamp_ms, confidence)
- ✅ **Progress Reporting:** Per-address progress bars with ETA
- ✅ **Test Suite:** Synthetic vulnerable wallet generation, GPU/CPU parity tests, 100% test vector validation
- ✅ **Security:** Zero private key materialization (GPU local memory only, zeroize buffers)
- ✅ **Documentation:** Usage guide, responsible disclosure framework, legal warnings

**Out of Scope - Phase 1 (Deferred to Phase 2+):**
- ⏸️ **Other Browser PRNGs:** Firefox SpiderMonkey, Safari JavaScriptCore, IE Chakra (Phase 2)
- ⏸️ **Expanded Fingerprints:** 500+ configurations (Phase 2)
- ⏸️ **Multi-Path Derivation:** BIP32/44/49/84/86 HD wallet paths (Phase 2)
- ⏸️ **Segwit Addresses:** P2SH-SegWit (prefix '3'), Native SegWit (prefix 'bc1') (Phase 2)
- ⏸️ **GPU Optimization:** Multi-GPU orchestration, advanced kernel tuning (Phase 3)
- ⏸️ **Probabilistic Search:** ML-based configuration prediction, adaptive algorithms (Phase 3)
- ⏸️ **Professional Features:** PDF reporting, checkpoint/resume, branding (Phase 3)
- ⏸️ **Simplified UI:** Non-technical wallet owner interface (Phase 3+)

**Explicitly Never in Scope:**
- ❌ **Automated Fund Transfer:** Tool identifies vulnerabilities only, never moves funds
- ❌ **GUI Interface:** Command-line only (aligns with existing 18 scanners)
- ❌ **Real-Time Blockchain Monitoring:** Passive scanning of address lists only
- ❌ **Key Export:** Tool returns (fingerprint_id, timestamp) NOT private keys
- ❌ **Unauthorized Scanning:** Requires explicit permission for target addresses (legal/ethical boundary)
- ❌ Ethereum or non-Bitcoin chains
- ❌ Exhaustive search (probabilistic approach only)
- ❌ Cloud-based scanning service (local execution only)

### Risks & Mitigation

**Critical Risks:**

**Risk 1: Attackers Exploit Faster (CRITICAL)**
- **Probability:** High (already happening)
- **Impact:** Wallets swept before defensive scanning
- **Mitigation:** MVP in Week 1 delivers basic capability immediately; prioritize common configurations first; coordinate with security community for intelligence sharing

**Risk 2: Scanner Has Bugs - False Negatives (CRITICAL)**
- **Probability:** Medium (complex implementation)
- **Impact:** Missed vulnerable wallets
- **Mitigation:** Extensive test suite against all 2023 disclosure examples; 100% validation requirement before release; independent security audit; peer review by cryptography experts

**Risk 3: Legal/Ethical Issues (HIGH)**
- **Probability:** Low (white-hat focused)
- **Impact:** Project shutdown, legal liability
- **Mitigation:** Built-in responsible disclosure framework; 90-day waiting period; legal review before release; coordination with exchanges; clear ethical guidelines in documentation

**Risk 4: Performance Below Expectations (MEDIUM)**
- **Probability:** Low (proven architecture)
- **Impact:** Slow adoption, limited usefulness
- **Mitigation:** Early GPU prototyping; performance benchmarking against existing scanners (10x+ minimum); progressive optimization based on real data

**Secondary Risks:**

**Risk 5: Community Rejection (MEDIUM)**
- **Probability:** Low (fills critical gap)
- **Impact:** Limited adoption
- **Mitigation:** Transparent methodology; peer review; community engagement; publish validation results

**Risk 6: Incomplete PRNG Modeling (MEDIUM)**
- **Probability:** Medium (historical browser research challenging)
- **Impact:** Reduced coverage
- **Mitigation:** Historical browser database research; iterative expansion; community contributions for edge cases

---


## Functional Requirements

### FR-1: JavaScript PRNG Reconstruction

**Priority:** P0 (Critical - MVP Blocker)  
**Phase:** 1 (Week 1)

**Description:**  
Implement accurate reconstruction of JavaScript Math.random() PRNG algorithms used in major browsers during 2011-2015 era.

**Detailed Requirements:**

**FR-1.1:** Chrome V8 PRNG (MWC1616) Implementation
- Implement Multiply-With-Carry algorithm matching V8 engine behavior (2011-2015)
- Accept timestamp (Date.now() milliseconds) as seed input
- Generate PRNG state matching browser implementation
- **Acceptance Criteria:** Generates identical random sequence as Chrome 14-45 given same seed

**FR-1.2:** Firefox SpiderMonkey PRNG Implementation
- Implement Linear Congruential Generator matching SpiderMonkey behavior
- Seed from timestamp + process ID (simulated)
- **Acceptance Criteria:** Matches Firefox 7-42 random output for given seed
- **Phase:** 2 (Week 2)

**FR-1.3:** Safari JavaScriptCore PRNG (Xorshift128+)
- Implement Xorshift128+ algorithm
- **Acceptance Criteria:** Matches Safari 5-8 output
- **Phase:** 2 (Week 2)

**FR-1.4:** IE Chakra PRNG (Mersenne Twister variant)
- Implement MT variant used by IE
- **Acceptance Criteria:** Matches IE 9-11 output
- **Phase:** 2 (Week 2)

**Dependencies:**
- Must validate against known test vectors from 2023 Randstorm disclosure
- Integration with secp256k1 private key generation

**Test Cases:**
- TC-1.1: Given known timestamp + fingerprint, generate correct PRNG state
- TC-1.2: Validate against 10+ Randstorm disclosure examples (100% match required)
- TC-1.3: Performance test: Generate 1M+ PRNG states per second on CPU

---

### FR-2: Browser Fingerprint Database

**Priority:** P0 (Critical - MVP Blocker)  
**Phase:** 1 (Week 1 for top 100, Week 2 for expansion)

**Description:**  
Curated database of historical browser configurations from 2011-2015 era, prioritized by market share.

**Detailed Requirements:**

**FR-2.1:** Browser Configuration Schema
```rust
struct BrowserConfig {
    user_agent: String,
    screen_width: u32,
    screen_height: u32,
    color_depth: u8,
    timezone_offset: i32,
    language: String,
    platform: String,
    market_share_estimate: f32,
    year_range: (u16, u16),
}
```

**FR-2.2:** Top 100 Configurations (Phase 1)
- Chrome 20-40 on Windows 7 (1366x768, 1920x1080)
- Firefox 10-30 on Windows 7 (common resolutions)
- Safari 5-8 on macOS (higher resolutions)
- US/EU timezones prioritized
- **Acceptance Criteria:** Covers estimated 60-70% of 2011-2015 wallet generation sessions

**FR-2.3:** Extended 500 Configurations (Phase 2)
- Additional browser versions
- Mobile configurations (iOS Safari, Android Chrome)
- Global timezone coverage
- Less common screen resolutions
- **Acceptance Criteria:** Covers estimated 85-90% of sessions

**FR-2.4:** Configuration Prioritization
- Sort by market_share_estimate descending
- Scan high-probability configs first
- **Acceptance Criteria:** Scanner tests most likely configs before unlikely ones

**Data Sources:**
- StatCounter historical data (2011-2015)
- NetMarketShare archives
- EFF Panopticlick studies
- Browser version release databases

**Test Cases:**
- TC-2.1: Database loads successfully with all required fields
- TC-2.2: Top 100 configs represent 60-70% cumulative market share
- TC-2.3: Configurations validate against known Randstorm examples

---

### FR-3: Derivation Path Support

**Priority:** P0 (Critical)  
**Phase:** 1 (simple), 2 (multi-path)

**Description:**  
Support multiple Bitcoin key derivation paths matching era-appropriate wallet implementations.

**Detailed Requirements:**

**FR-3.1:** Pre-BIP32 Direct Derivation (Phase 1)
- Direct private key generation from PRNG output
- Used by 2011-2012 wallets
- **Acceptance Criteria:** Generates correct P2PKH addresses for direct keys

**FR-3.2:** BIP32 Simple Paths (Phase 2)
- m/0 (first key)
- m/0/0 (first child of first key)
- **Acceptance Criteria:** HD wallet derivation matches BIP32 spec

**FR-3.3:** BIP44 Standard Path (Phase 2)
- m/44'/0'/0'/0/0 (Bitcoin standard account, first address)
- Support account and address index variation
- **Acceptance Criteria:** Matches standard wallet implementations

**FR-3.4:** SegWit Paths (Phase 2)
- BIP49: m/49'/0'/0'/0/0 (P2WPKH-nested-in-P2SH)
- BIP84: m/84'/0'/0'/0/0 (Native SegWit P2WPKH)
- **Acceptance Criteria:** Generates correct SegWit addresses

**FR-3.5:** Extended Index Support (Phase 3)
- Scan address indices 0-100 per seed
- Configurable index range
- **Acceptance Criteria:** Can check first 100 addresses per derivation path

**Dependencies:**
- bitcoin crate for address generation
- bip39 crate for HD wallet support
- secp256k1 for cryptographic operations

**Test Cases:**
- TC-3.1: Direct derivation matches test vectors
- TC-3.2: BIP32/44 derivation matches reference implementations
- TC-3.3: SegWit addresses validate correctly
- TC-3.4: Extended index scanning completes for 100 indices

---

### FR-4: GPU Acceleration via OpenCL

**Priority:** P0 (Critical)  
**Phase:** 1 (basic), 2 (optimized), 3 (advanced)

**Description:**  
GPU-accelerated scanning using OpenCL kernels, leveraging existing temporal-planetarium infrastructure.

**Detailed Requirements:**

**FR-4.1:** Basic OpenCL Kernel (Phase 1)
- Parallel PRNG state generation (one thread per seed candidate)
- Inline secp256k1 public key derivation
- Address generation (P2PKH only in Phase 1)
- Result buffer for matches
- **Acceptance Criteria:** 10x+ speedup vs CPU baseline

**FR-4.2:** Device-Aware Work Group Sizing (Phase 1)
- Query GPU capabilities (max work group size, compute units)
- Auto-configure optimal work group dimensions
- **Acceptance Criteria:** Works on NVIDIA, AMD, Intel GPUs without manual tuning

**FR-4.3:** Batch Processing (Phase 1)
- Process 1M+ candidate seeds per kernel invocation
- Efficient CPU-GPU memory transfers using pinned memory
- **Acceptance Criteria:** Minimal transfer overhead (<10% of compute time)

**FR-4.4:** GPU Optimization (Phase 2)
- Device-specific tuning (NVIDIA CUDA cores, AMD wavefronts, Intel EUs)
- Constant memory for browser fingerprint database
- Coalesced memory access patterns
- **Acceptance Criteria:** 50x+ speedup vs CPU

**FR-4.5:** Multi-GPU Support (Phase 3)
- Distribute work across multiple GPUs
- Load balancing based on GPU capabilities
- **Acceptance Criteria:** Near-linear scaling with GPU count

**FR-4.6:** CPU Fallback
- Automatic fallback to CPU when GPU unavailable
- Maintain functionality without OpenCL
- **Acceptance Criteria:** Scans complete (slowly) on systems without GPU

**Integration Points:**
- Reuse existing gpu_solver.rs patterns from temporal-planetarium
- Leverage 46 existing OpenCL kernel patterns
- Follow established device detection and work group sizing

**Performance Targets:**
- Phase 1: 100M-1B seeds/second (single GPU)
- Phase 2: 1B-10B seeds/second (optimized single GPU)
- Phase 3: 10B-100B seeds/second (multi-GPU)

**Test Cases:**
- TC-4.1: GPU kernel produces identical results to CPU implementation
- TC-4.2: Performance meets 10x minimum (Phase 1), 50x target (Phase 2)
- TC-4.3: Works on NVIDIA, AMD, Intel GPUs
- TC-4.4: CPU fallback functions correctly
- TC-4.5: Multi-GPU scaling achieves >80% efficiency per additional GPU

---

### FR-5: Validation Framework & Test Suite

**Priority:** P0 (Critical - Pre-Release Blocker)  
**Phase:** 1

**Description:**  
Comprehensive test suite validating scanner accuracy against known Randstorm examples and test vectors.

**Detailed Requirements:**

**FR-5.1:** 2023 Randstorm Test Vectors
- Include all publicly disclosed vulnerable addresses from 2023 Randstorm research
- Test vectors with known browser configs + timestamps
- **Acceptance Criteria:** 100% match rate (zero misses, zero false positives)

**FR-5.2:** Integration Tests
- Test against each PRNG implementation independently
- Test browser configuration database coverage
- Test derivation path correctness
- **Acceptance Criteria:** All tests pass before release

**FR-5.3:** Performance Benchmarks
- Measure GPU speedup vs CPU baseline
- Measure scan completion time for typical wallets
- **Acceptance Criteria:** Meets performance targets (10x Phase 1, 50x Phase 2)

**FR-5.4:** Regression Tests
- Ensure existing 18 scanners not affected
- Validate no performance degradation in existing features
- **Acceptance Criteria:** Zero regressions in temporal-planetarium integration tests

**FR-5.5:** False Positive/Negative Validation
- Measure false positive rate on known-secure wallets
- Measure false negative rate on known-vulnerable wallets
- **Acceptance Criteria:** <1% FP, <5% FN

**Test Data:**
- Minimum 20 known vulnerable test cases from Randstorm disclosure
- Minimum 100 known-secure test cases (post-2015 wallets)
- Edge cases (unusual browser configs, rare timezones)

**Test Cases:**
- TC-5.1: All Randstorm disclosure examples detected (100% recall)
- TC-5.2: Zero false positives on secure wallet set
- TC-5.3: Performance benchmarks pass minimum thresholds
- TC-5.4: Existing scanner regression tests pass

---

### FR-6: CLI Interface

**Priority:** P0 (Critical)  
**Phase:** 1

**Description:**  
Command-line interface following temporal-planetarium patterns for consistency.

**Detailed Requirements:**

**FR-6.1:** Subcommand Structure
```bash
entropy-lab randstorm-scan [OPTIONS]
```

**FR-6.2:** Required Arguments
- `--target-addresses <FILE>` - CSV file with Bitcoin addresses to check
- OR `--scan-range <START_DATE> <END_DATE>` - Timestamp range to scan

**FR-6.3:** Optional Arguments
- `--phase <1|2|3>` - Scanner phase/coverage level (default: 1)
- `--gpu` - Force GPU acceleration (default: auto-detect)
- `--cpu` - Force CPU fallback
- `--output <FILE>` - Output file for results (default: stdout)
- `--threads <N>` - CPU thread count for CPU mode (default: auto)
- `--batch-size <N>` - GPU batch size (default: auto)
- `--checkpoint <FILE>` - Checkpoint file for resume support (Phase 3)

**FR-6.4:** Progress Reporting
- Real-time progress bar showing:
  - Configurations tested / total
  - Estimated time remaining
  - Current scan rate (seeds/second)
- **Acceptance Criteria:** Progress updates every 1 second

**FR-6.5:** Results Output
```
Address,Status,Confidence,BrowserConfig,Timestamp,DerivationPath
1A1zP1...,VULNERABLE,HIGH,Chrome/25/Win7/1366x768,2013-04-15T10:23:45Z,m/44'/0'/0'/0/0
```

**FR-6.6:** Error Handling
- Clear error messages for invalid inputs
- Validation of CSV format
- GPU availability warnings
- **Acceptance Criteria:** No crashes, helpful error messages

**Help Text:**
- Comprehensive `--help` output with examples
- Document all options and their defaults

**Test Cases:**
- TC-6.1: CLI accepts valid arguments and runs successfully
- TC-6.2: Invalid arguments produce clear error messages
- TC-6.3: Progress reporting updates correctly
- TC-6.4: Results output in correct CSV format
- TC-6.5: Help text is comprehensive and accurate

---

### FR-7: Responsible Disclosure Framework

**Priority:** P0 (Critical - Legal/Ethical Requirement)  
**Phase:** 1

**Description:**  
Built-in responsible disclosure workflow to prevent malicious use and coordinate with exchanges/wallet owners.

**Detailed Requirements:**

**FR-7.1:** Disclosure Protocol Documentation
- Document 90-day waiting period requirement
- Exchange coordination procedures
- Wallet owner contact attempts
- Public disclosure guidelines
- **Acceptance Criteria:** Clear documentation in README and CLI help

**FR-7.2:** Findings Report Format
- Vulnerable address identification
- Estimated risk level (HIGH/MEDIUM/LOW based on balance)
- Recommended actions
- Contact information for responsible disclosure
- **Acceptance Criteria:** Report template included in repository

**FR-7.3:** No Fund Transfer Capability
- Scanner identifies only (no private key export to user)
- No automated fund sweeping
- No transaction creation
- **Acceptance Criteria:** Code review confirms zero fund transfer capability

**FR-7.4:** Ethical Use Guidelines
- Prominent disclaimer in README
- White-hat use only requirement
- Legal warnings
- **Acceptance Criteria:** Legal review approval

**FR-7.5:** Coordination Support
- Template emails for exchange notification
- Template for wallet owner contact
- Disclosure timeline tracking
- **Acceptance Criteria:** Templates included in docs/

**Compliance:**
- Legal review before release
- Security community consultation
- Alignment with industry disclosure standards

**Test Cases:**
- TC-7.1: Documentation reviewed by legal counsel
- TC-7.2: No fund transfer code paths exist (security audit)
- TC-7.3: Ethical guidelines prominent and clear

---

### FR-8: CSV Import/Export

**Priority:** P1 (High - Phase 2)  
**Phase:** 2

**Description:**  
Batch processing support via CSV import/export for professional use cases.

**Detailed Requirements:**

**FR-8.1:** Input CSV Format
```csv
Address,Notes
1A1zP1...,Customer Wallet A
3J98t1...,Legacy Account 2012
```

**FR-8.2:** Output CSV Format (same as FR-6.5)

**FR-8.3:** Batch Scanning
- Process thousands of addresses in single run
- Progress tracking per-address
- **Acceptance Criteria:** Handles 10,000+ addresses efficiently

**FR-8.4:** Export Options
- CSV (default)
- JSON (structured data)
- PDF report (professional reporting - Phase 3)

**Test Cases:**
- TC-8.1: Import 1,000 address CSV successfully
- TC-8.2: Export results in all supported formats
- TC-8.3: Batch scan completes for large datasets

---

### FR-9: Checkpoint/Resume Support

**Priority:** P2 (Medium - Phase 3)  
**Phase:** 3

**Description:**  
Save scan state and resume long-running scans.

**Detailed Requirements:**

**FR-9.1:** Checkpoint File Format
- JSON with scan progress state
- Browser configs tested
- Results found so far
- **Acceptance Criteria:** Can resume from checkpoint without data loss

**FR-9.2:** Auto-checkpoint
- Save state every 5 minutes during long scans
- Save on SIGTERM/SIGINT (graceful shutdown)
- **Acceptance Criteria:** No progress lost on interruption

**FR-9.3:** Resume Command
```bash
entropy-lab randstorm-scan --resume <checkpoint_file>
```

**Test Cases:**
- TC-9.1: Scan resumes from checkpoint with correct state
- TC-9.2: Results identical to uninterrupted scan
- TC-9.3: Graceful shutdown creates valid checkpoint

---

## Non-Functional Requirements

### NFR-1: Performance

**Priority:** P0 (Critical)

**Requirements:**

**NFR-1.1:** GPU Acceleration
- Minimum 10x speedup vs CPU (Phase 1)
- Target 50-100x speedup (Phase 2)
- **Measurement:** Benchmark against identical algorithm on CPU

**NFR-1.2:** Scan Completion Time
- Phase 1: <30 minutes per wallet (common config)
- Phase 2: <10 minutes per wallet
- Phase 3: <5 minutes per wallet
- **Measurement:** Average across 100 test wallets

**NFR-1.3:** Throughput
- Phase 1: 100M-1B seeds/second (single GPU)
- Phase 2: 1B-10B seeds/second
- Phase 3: 10B+ seeds/second (multi-GPU)

**NFR-1.4:** Resource Usage
- RAM: <8GB for Phase 1, <16GB for Phase 2/3
- GPU VRAM: <4GB
- Disk: <1GB (database + code)

**NFR-1.5:** Scalability
- Multi-GPU: >80% efficiency per additional GPU
- Multi-core CPU: >70% efficiency scaling

---

### NFR-2: Accuracy & Reliability

**Priority:** P0 (Critical)

**Requirements:**

**NFR-2.1:** False Negative Rate
- Target: <5%
- Maximum acceptable: <10%
- **Measurement:** Test against known vulnerable wallets

**NFR-2.2:** False Positive Rate
- Target: <1%
- Maximum acceptable: <2%
- **Measurement:** Test against known secure wallets (post-2015)

**NFR-2.3:** Test Vector Validation
- 100% match on Randstorm disclosure examples
- Zero tolerance for missed known vulnerabilities

**NFR-2.4:** Reproducibility
- Identical results for same input across runs
- Deterministic when given same seed data

**NFR-2.5:** Error Handling
- No crashes on invalid input
- Graceful degradation on resource constraints
- Clear error messages

---

### NFR-3: Security & Ethics

**Priority:** P0 (Critical)

**Requirements:**

**NFR-3.1:** No Private Key Exposure
- Scanner never exports private keys to user
- Private keys only in memory during scanning
- Secure memory clearing after use

**NFR-3.2:** White-Hat Only
- No fund transfer capability in code
- Responsible disclosure framework mandatory
- Ethical use guidelines prominent

**NFR-3.3:** Data Privacy
- No wallet addresses uploaded to external services
- No telemetry or usage tracking without explicit consent
- Local execution only

**NFR-3.4:** Code Security
- Rust memory safety guarantees
- No unsafe code except where necessary (GPU interaction)
- Security audit before release

---

### NFR-4: Usability

**Priority:** P1 (High)

**Requirements:**

**NFR-4.1:** CLI Clarity
- Clear help text with examples
- Intuitive argument naming
- Consistent with existing temporal-planetarium scanners

**NFR-4.2:** Progress Transparency
- Real-time progress updates
- ETA estimation
- Current status visibility

**NFR-4.3:** Documentation
- README with quick start guide
- Technical documentation for methodology
- Examples for common use cases
- Troubleshooting guide

**NFR-4.4:** Error Messages
- Clear, actionable error messages
- Suggest fixes for common problems
- No cryptic error codes

---

### NFR-5: Maintainability

**Priority:** P1 (High)

**Requirements:**

**NFR-5.1:** Code Quality
- Rust 2021 edition (minimum 1.70)
- cargo fmt formatting enforced
- cargo clippy warnings addressed
- Comprehensive comments

**NFR-5.2:** Testing
- Unit tests for all critical functions
- Integration tests for end-to-end workflows
- >80% code coverage target

**NFR-5.3:** Modularity
- Follow existing scanner patterns from temporal-planetarium
- src/scans/randstorm.rs module structure
- Reusable components

**NFR-5.4:** Documentation
- Doc comments (///) for public APIs
- Architecture documentation
- Methodology explanation

---

### NFR-6: Portability

**Priority:** P1 (High)

**Requirements:**

**NFR-6.1:** Platform Support
- Linux (primary - fully supported)
- macOS (fully supported)
- Windows (supported)

**NFR-6.2:** GPU Compatibility
- NVIDIA GPUs (CUDA/OpenCL)
- AMD GPUs (OpenCL)
- Intel GPUs (OpenCL)
- CPU fallback (all platforms)

**NFR-6.3:** Dependency Management
- Minimal external dependencies
- OpenCL optional (feature flag)
- Standard Rust crates preferred

---

### NFR-7: Compliance & Legal

**Priority:** P0 (Critical)

**Requirements:**

**NFR-7.1:** Open Source Licensing
- Compatible with temporal-planetarium license
- Clear attribution requirements
- No commercial restrictions for research

**NFR-7.2:** Responsible Disclosure Compliance
- 90-day disclosure window
- Coordination with affected parties
- Industry standard practices

**NFR-7.3:** Legal Review
- Legal counsel review before release
- Ethical use guidelines
- Disclaimer of liability

---

## User Stories

### Epic 1: Researcher-Focused MVP Scanner (Phase 1)

**US-1.1:** As a security researcher, I want to scan for Randstorm vulnerabilities using Chrome PRNG patterns, so I can validate the 2023 disclosure findings and identify vulnerable wallets in my datasets.

**Acceptance Criteria (Given/When/Then Format):**

**AC-1.1.1: MWC1616 PRNG Correctness**
- **Given:** Seed values s1=12345, s2=67890
- **When:** Generate 1000 sequential random numbers using MWC1616 implementation
- **Then:** Output matches Chrome V8 reference implementation bit-for-bit
- **Verification:** Unit test `tests/prng/test_mwc1616.rs` with known test vectors from V8 source

**AC-1.1.2: Browser Fingerprint Loading**
- **Given:** File `src/scans/randstorm/fingerprints/data/phase1_top100.csv` exists
- **When:** Scanner initializes and loads fingerprint database
- **Then:** Exactly 100 fingerprints loaded with all required fields (user_agent, screen_width, screen_height, color_depth, timezone_offset, language, platform, market_share_estimate)
- **Verification:** Unit test `tests/fingerprints/test_database_loading.rs`

**AC-1.1.3: Synthetic Vulnerable Wallet Detection**
- **Given:** Synthetic vulnerable address generated with known fingerprint_id=5, timestamp_ms=1389744000000
- **When:** Run `randstorm-scan --targets test.csv --gpu`
- **Then:** JSON output shows `vulnerable: true, fingerprint_id: 5, timestamp_ms: 1389744000000`
- **Verification:** Integration test `tests/integration/test_synthetic_detection.rs`

**AC-1.1.4: Test Vector Validation (100% Accuracy)**
- **Given:** 10 synthetic vulnerable wallets from Randstorm 2023 disclosure
- **When:** Scanner processes all 10 addresses
- **Then:** All 10 detected as vulnerable with correct fingerprint/timestamp
- **Verification:** Integration test `tests/integration/test_randstorm_vectors.rs`

**AC-1.1.5: False Positive Rate**
- **Given:** 1000 known-secure addresses (Genesis block, modern hardware wallets, post-2015 wallets)
- **When:** Scanner processes all 1000 addresses
- **Then:** Zero false positives (<0.01% = 0 out of 1000)
- **Verification:** Integration test `tests/integration/test_false_positives.rs`

---

**US-1.2:** As a security researcher, I want GPU acceleration for scanning, so I can process large datasets efficiently (10,000+ addresses in <24 hours).

**Acceptance Criteria (Given/When/Then Format):**

**AC-1.2.1: GPU Auto-Detection**
- **Given:** System has NVIDIA/AMD/Intel GPU with OpenCL support
- **When:** Scanner starts without --cpu flag
- **Then:** GPU device detected and logged: "✓ GPU detected: [device name] (OpenCL [version])"
- **Verification:** Integration test `tests/gpu/test_gpu_detection.rs`

**AC-1.2.2: GPU Performance Baseline**
- **Given:** Mid-range GPU (RTX 3060 or equivalent) available
- **When:** Scan 1 address with 100 fingerprints × 172,800 timestamps (17.28M combinations)
- **Then:** Scan completes in ≤30 seconds
- **Verification:** Performance benchmark `benches/gpu_performance.rs`

**AC-1.2.3: GPU Speedup vs CPU**
- **Given:** Same address scanned on both GPU and CPU paths
- **When:** Compare execution times for 1M seed combinations
- **Then:** GPU is ≥10x faster than CPU
- **Verification:** Performance benchmark `benches/gpu_vs_cpu.rs`

**AC-1.2.4: CPU Fallback**
- **Given:** No GPU available OR --cpu flag specified
- **When:** Scanner starts
- **Then:** Logs "⚠️ GPU unavailable, using CPU fallback" and completes scan successfully
- **Verification:** Integration test `tests/cpu/test_cpu_fallback.rs`

**AC-1.2.5: GPU/CPU Parity**
- **Given:** Same CSV input file with 10 addresses
- **When:** Run once with --gpu, once with --cpu
- **Then:** JSON output files are bit-identical (same vulnerabilities, same fingerprints, same timestamps)
- **Verification:** Integration test `tests/integration/test_gpu_cpu_parity.rs`

---

**US-1.3 (MOVED TO PHASE 2+):** As a wallet owner, I want to check if my 2011-2015 Bitcoin wallet is vulnerable, so I can take action to protect my funds.

**Rationale for Deferral:** Individual wallet owners require simplified UX, non-technical documentation, and different legal safeguards. Phase 1 focuses on researcher tools; Phase 2+ will add simplified interface for end-users.

**Deferred Acceptance Criteria:**
- Simple CLI command to check single address (e.g., `--simple-mode`)
- Clear "VULNERABLE" or "SAFE" result (yes/no output)
- Guidance on next steps if vulnerable (automated recommendations)
- Non-technical error messages

---

### Epic 2: Comprehensive Coverage (Phase 2 - DEFERRED)

**Note:** Phase 2 features are out of scope for initial release. Focus remains on researcher-focused Chrome V8 scanning (Epic 1).

**US-2.1:** As a security consultant, I want to scan using all major browser PRNGs (Chrome, Firefox, Safari, IE), so I can provide complete audits to clients.

**Deferred Acceptance Criteria:**
- Firefox SpiderMonkey PRNG implemented
- Safari JavaScriptCore PRNG implemented
- IE Chakra PRNG implemented
- All PRNGs validated against test vectors

**US-2.2:** As a security consultant, I want batch processing for multiple wallets, so I can audit many clients efficiently.

**Note:** Phase 1 already supports batch CSV processing for researchers. This US refers to consultant-specific features (PDF reports, branding).

**Deferred Acceptance Criteria:**
- Professional PDF export format
- Client branding options
- Executive summary generation
- Billable hours tracking

**US-2.3:** As a security researcher, I want multi-path derivation support, so I can check all address types (legacy, SegWit, etc).

**Deferred Acceptance Criteria:**
- BIP32/44/49/84 paths supported
- Correct address generation for each path
- Validation against reference implementations

---

### Epic 3: Optimization & Professional Features (Phase 3 - DEFERRED)

**Note:** Phase 3 features are advanced optimization and professional tooling, deferred until Phase 1 & 2 are validated in production.

**US-3.1:** As a security consultant, I want professional PDF reports, so I can deliver client-ready audit results.

**Deferred Acceptance Criteria:**
- PDF export option
- Professional formatting
- Executive summary + technical details
- Branded with temporal-planetarium

**US-3.2:** As a security researcher, I want checkpoint/resume support, so I can run long scans without losing progress.

**Deferred Acceptance Criteria:**
- Auto-checkpoint every 5 minutes
- Resume from checkpoint file
- Graceful shutdown saves state
- Results identical to uninterrupted scan

**US-3.3:** As a security researcher, I want probabilistic search for maximum coverage, so I can find the last 5-10% of vulnerable wallets.

**Deferred Acceptance Criteria:**
- ML-based configuration prediction
- Adaptive search algorithms
- 95%+ coverage achieved
- Performance maintained

---

## Technical Architecture Overview

### System Components

**1. Scanner Module (`src/scans/randstorm.rs`)**
- Orchestrates scanning workflow
- Manages browser configuration iteration
- Coordinates GPU/CPU execution
- Generates results

**2. PRNG Implementations (`src/scans/randstorm/prng/`)**
- `chrome_v8.rs` - MWC1616 algorithm
- `firefox_spidermonkey.rs` - LCG variant
- `safari_jscore.rs` - Xorshift128+
- `ie_chakra.rs` - Mersenne Twister variant

**3. Browser Fingerprint Database (`src/scans/randstorm/fingerprints/`)**
- `database.rs` - Configuration storage and lookup
- `configs/` - CSV files with browser configurations
- Prioritization logic (market share sorting)

**4. GPU Kernels (`cl/randstorm/`)**
- `randstorm_crack.cl` - Main scanning kernel
- PRNG state generation
- secp256k1 operations (or precomputed tables)
- Address generation

**5. Integration (`src/scans/randstorm/integration.rs`)**
- Interface with existing gpu_solver.rs
- Reuse device detection and work group sizing
- Follow established patterns from 18 existing scanners

### Data Flow

```
User Input (CSV addresses)
    ↓
Browser Config Database
    ↓
PRNG State Generation (per config + timestamp)
    ↓
GPU Kernel (parallel processing)
    ↓
Address Generation & Comparison
    ↓
Results Collection
    ↓
Output (CSV/JSON/PDF)
```

### External Dependencies

**Rust Crates:**
- `secp256k1` - Elliptic curve cryptography
- `bitcoin` - Address generation
- `bip39` - HD wallet support (Phase 2)
- `ocl` - OpenCL bindings
- `clap` v4.5 - CLI parsing
- `serde` - Serialization (CSV/JSON)
- `anyhow` - Error handling
- `rayon` - CPU parallelization

**System Dependencies:**
- OpenCL development libraries (optional via feature flag)
- GPU drivers (NVIDIA/AMD/Intel)

---

---

## Testing Strategy & Risk Framework

**Source:** Party mode collaboration (Murat - Test Architect, Amelia - Developer, Winston - Architect)  
**Date:** 2025-12-22  
**Purpose:** Risk-based testing approach ensuring cryptographic correctness, security, and performance

### Risk-Based Testing Tiers

**Testing Philosophy:** Not all features carry equal risk. Cryptographic correctness and security are CRITICAL (zero tolerance for failure). UX and performance are HIGH/MEDIUM risk (important but not catastrophic if imperfect).

---

#### **CRITICAL RISK - Zero Tolerance (Must Test Exhaustively)**

**Risk #1: Cryptographic Correctness - MWC1616 PRNG Implementation**
- **Risk Impact:** Wrong constants or algorithm = 0% vulnerable wallet detection, complete feature failure
- **Test Strategy:** Known test vectors from Chrome V8 source code
- **Coverage Target:** 100% of PRNG state transitions validated
- **Test Cases:**
  - TC-CRIT-1.1: MWC1616 with seed (18000, 30903) produces exact V8 output for 10,000 iterations
  - TC-CRIT-1.2: State wraparound behavior matches V8 (s1, s2 overflow handling)
  - TC-CRIT-1.3: Seeding from timestamp produces deterministic, reproducible output
- **Acceptance:** 100% match with V8 reference, zero deviation tolerated

**Risk #2: GPU/CPU Parity - Bit-Identical Results**
- **Risk Impact:** GPU bugs = false negatives (missed vulnerable wallets), researcher loses trust in tool
- **Test Strategy:** Same inputs processed on GPU and CPU, compare outputs byte-for-byte
- **Coverage Target:** 1000+ random (fingerprint, timestamp) combinations
- **Test Cases:**
  - TC-CRIT-2.1: 1000 synthetic addresses scanned on GPU and CPU produce identical JSON output
  - TC-CRIT-2.2: Edge cases: minimum/maximum timestamp values, all 100 fingerprints
  - TC-CRIT-2.3: Stress test: 10,000-address batch produces identical results
- **Acceptance:** Bit-identical Hash160 values, zero byte differences in output files

**Risk #3: Private Key Non-Materialization - Security Invariant**
- **Risk Impact:** Key leakage = legal liability, reputational damage, violation of ethical guidelines
- **Test Strategy:** Memory inspection, log auditing, automated code review
- **Coverage Target:** All execution paths audited (GPU kernel, CPU fallback, error paths)
- **Test Cases:**
  - TC-CRIT-3.1: `grep -r "private.*key" logs/ target/` returns zero matches after scan
  - TC-CRIT-3.2: Memory dumps (GPU and CPU) contain no 32-byte private key patterns
  - TC-CRIT-3.3: JSON/CSV output contains only (fingerprint_id, timestamp), never privkey
  - TC-CRIT-3.4: Error messages and debug logs redact sensitive data
- **Acceptance:** Absolute zero key material in logs, stdout, stderr, temp files

---

#### **HIGH RISK - Comprehensive Testing Required**

**Risk #4: Address Derivation Correctness**
- **Risk Impact:** Wrong derivation = false negatives (missed vulnerabilities)
- **Test Strategy:** Known vulnerable wallets (synthetic + disclosed examples)
- **Coverage Target:** All address types in Phase 1 scope (P2PKH only)
- **Test Cases:**
  - TC-HIGH-4.1: secp256k1 privkey → pubkey → Hash160 → P2PKH matches bitcoin crate output
  - TC-HIGH-4.2: 10 Randstorm 2023 disclosure examples detected correctly
  - TC-HIGH-4.3: Genesis block address (1A1zP1...) correctly identified as NOT vulnerable
- **Acceptance:** 100% detection of known-vulnerable, 0% false positives on known-secure

**Risk #5: Fingerprint Database Loading**
- **Risk Impact:** Corrupted fingerprints = incomplete coverage, inaccurate results
- **Test Strategy:** Schema validation, integrity checks, all 100 fingerprints loaded correctly
- **Coverage Target:** All CSV fields, edge cases (malformed rows, missing columns)
- **Test Cases:**
  - TC-HIGH-5.1: Load `phase1_top100.csv`, verify exactly 100 rows with all required fields
  - TC-HIGH-5.2: Malformed CSV (missing column) produces clear error message with line number
  - TC-HIGH-5.3: Fingerprint priority sorting works (market_share_estimate descending)
- **Acceptance:** Graceful error handling, clear validation messages, no silent failures

---

#### **MEDIUM RISK - Focused Testing**

**Risk #6: CSV Input Validation**
- **Risk Impact:** Invalid addresses crash scanner or produce confusing errors
- **Test Strategy:** Malformed addresses, mixed formats, empty files
- **Coverage Target:** Common error cases, user-reported issues
- **Test Cases:**
  - TC-MED-6.1: Invalid Base58 address produces error: "Invalid address at line X"
  - TC-MED-6.2: Empty CSV file produces error: "No addresses found"
  - TC-MED-6.3: Mixed Bech32 and P2PKH addresses handled correctly
- **Acceptance:** Clear, actionable error messages; no crashes

**Risk #7: Progress Reporting Accuracy**
- **Risk Impact:** Poor UX, researcher can't estimate completion time
- **Test Strategy:** Manual verification of ETA accuracy
- **Coverage Target:** Different address counts, GPU vs CPU modes
- **Test Cases:**
  - TC-MED-7.1: Progress bar updates at least every 5 seconds
  - TC-MED-7.2: ETA within ±10% of actual completion time (after 10% progress)
  - TC-MED-7.3: GPU fallback warning displayed before scan starts
- **Acceptance:** ETA accuracy ±10%, progress updates responsive

---

### Test Pyramid Architecture

```
          /\
         /E2E\          ← 5 end-to-end tests (full CSV → JSON output flow)
        /------\
       /  Integ  \      ← 20 integration tests (GPU solver, CSV parser, RPC client)
      /----------\
     /    Unit     \    ← 100+ unit tests (PRNG, derivation, fingerprint structs)
    /--------------\
```

**Unit Tests (100+ tests, <30 seconds total):**
- PRNG implementations: MWC1616 state transitions, seeding, determinism
- Address derivation: privkey → pubkey → Hash160 → P2PKH
- Fingerprint parsing: CSV loading, struct creation, priority sorting
- Helper functions: timestamp calculation, error formatting

**Integration Tests (20 tests, ~5 minutes total):**
- GPU solver integration: buffer setup, kernel invocation, result parsing
- CSV parser integration: file I/O, validation, error handling
- RPC client integration: timestamp lookup, graceful fallback
- Config loading: fingerprint database, CLI arguments

**End-to-End Tests (5 tests, ~15 minutes total):**
- Full scan: CSV input → GPU scan → JSON output
- CPU fallback path: No GPU → CPU scan → identical results
- Batch processing: 1000-address CSV → complete results
- Error scenarios: Invalid CSV → clear error messages
- Performance baseline: Reference hardware → performance targets met

---

### Continuous Integration Requirements

**Pre-Commit Hooks (Local Developer):**
- `cargo fmt --check` (code formatting)
- `cargo clippy -- -D warnings` (linting, zero warnings)
- Unit tests only (fast feedback, <30 seconds)

**Pull Request CI Pipeline:**
- ✅ Compilation check: `cargo check`
- ✅ Unit tests: `cargo test --lib` (100+ tests)
- ✅ Integration tests: `cargo test --test '*'` (20 tests)
- ✅ Clippy linting: `cargo clippy -- -W clippy::all` (warnings reported, not blocking)
- ✅ Format check: `cargo fmt --check` (blocking)
- ⚠️ GPU tests: `cargo test --features gpu` (continue-on-error: true, may fail in CI without GPU)

**Merge to Main CI Pipeline:**
- ✅ All PR checks (must pass)
- ✅ End-to-end tests: Full CSV scan tests (15 minutes)
- ✅ Performance benchmarks: Track regression (>10% slowdown triggers warning)
- ✅ Security audit: `cargo audit` (advisories reported)
- ✅ Build release binary: Artifact upload for distribution

**Weekly/Release CI:**
- ✅ GPU hardware tests: Run on dedicated GPU runner (NVIDIA RTX 3060)
- ✅ Extended performance suite: 10,000-address batch scans
- ✅ Memory leak detection: Valgrind or similar tooling
- ✅ Security audit: Manual code review + automated scanning

---

### Test Fixtures & Data

**Synthetic Vulnerable Wallet Generator:**
```rust
// tests/fixtures/synthetic_wallets.rs
pub fn generate_synthetic_vulnerable_wallet(
    fingerprint_id: u32,
    timestamp_ms: u64,
) -> (String, PrivateKey) {
    // Use EXACT MWC1616 implementation from src/
    // Use EXACT ARC4 pool initialization
    // Return (P2PKH address, privkey) for verification
}
```

**Known-Secure Address Set (1000 addresses):**
- Genesis block: `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`
- Modern hardware wallets (Ledger, Trezor) - post-2015
- High-entropy brainwallets (>128-bit)
- Addresses from post-Randstorm era (2016+)

**Randstorm 2023 Disclosure Test Vectors (10 addresses):**
- Source: Official Randstorm disclosure publication
- Known fingerprint IDs and timestamps
- 100% detection rate required

**Chrome V8 MWC1616 Test Vectors:**
- Source: V8 engine source code test suite
- Seed values and expected output sequences
- Validates PRNG implementation correctness

---

### Quality Gates (Pass/Fail Criteria)

**Pre-Merge Quality Gate:**
- ✅ All unit tests pass (100%)
- ✅ All integration tests pass (100%)
- ✅ Code formatted (`cargo fmt`)
- ✅ Clippy linting clean (zero warnings with `-D warnings` locally)
- ✅ No regressions in existing 18 scanners

**Pre-Release Quality Gate:**
- ✅ All pre-merge checks pass
- ✅ GPU tests pass on reference hardware (RTX 3060)
- ✅ End-to-end tests pass (5/5)
- ✅ Security audit: Zero critical findings
- ✅ Performance benchmarks: ≥10x GPU speedup, <30 min per address
- ✅ Test vector validation: 100% detection rate (10/10 Randstorm examples)
- ✅ False positive test: 0/1000 known-secure addresses flagged

**Performance Regression Threshold:**
- Warning: >10% slowdown vs previous release
- Blocking: >25% slowdown (investigate before merge)

---

### Test Coverage Targets

- **Unit Test Coverage:** 90%+ of non-UI code
- **Critical Path Coverage:** 100% (PRNG, derivation, GPU kernel invocation)
- **Integration Test Coverage:** All major user workflows (CSV → scan → output)
- **GPU/CPU Parity Coverage:** 100% (every GPU path has equivalent CPU test)

---

## Success Criteria & Validation

### Phase 1 (Week 1) Definition of Done

- ✅ Chrome V8 PRNG implemented and validated
- ✅ Top 100 browser configs in database
- ✅ Basic GPU kernel functional (10x+ speedup)
- ✅ CLI interface operational
- ✅ 100% validation on Randstorm test vectors
- ✅ Integration tests pass (zero regressions)
- ✅ 60-70% estimated coverage achieved
- ✅ Documentation (README, usage guide)
- ✅ Responsible disclosure framework documented

### Phase 2 (Week 2) Definition of Done

- ✅ All browser PRNGs implemented (Firefox, Safari, IE)
- ✅ 500 browser configurations in database
- ✅ Multi-path derivation operational (BIP32/44/49/84)
- ✅ GPU optimization (50x+ speedup)
- ✅ Batch processing via CSV
- ✅ 85-90% estimated coverage achieved
- ✅ Independent security audit completed
- ✅ Zero critical vulnerabilities found

### Phase 3 (Week 3+) Definition of Done

- ✅ Probabilistic search algorithms implemented
- ✅ 95%+ estimated coverage achieved
- ✅ Multi-GPU support functional
- ✅ Checkpoint/resume operational
- ✅ Professional reporting (PDF)
- ✅ Community validation of methodology
- ✅ 5+ real-world vulnerable wallets identified (controlled test)
- ✅ Responsible disclosure framework operational

### Release Criteria

**Pre-Release Blockers:**
- ✅ 100% test vector validation
- ✅ Security audit completed (zero critical findings)
- ✅ Legal review approved
- ✅ Performance benchmarks met (10x minimum)
- ✅ Responsible disclosure documentation complete
- ✅ No regressions in existing scanners
- ✅ Documentation comprehensive

**Post-Release Monitoring:**
- GitHub issues response time: <48 hours
- Security issues response time: <24 hours
- Community feedback incorporation
- Continuous improvement based on findings

---

## Constraints & Assumptions

### Technical Constraints

**Hardware:**
- GPU recommended but not required (CPU fallback)
- Minimum 4GB RAM for basic operation
- 1GB disk space for database

**Software:**
- Rust 1.70+ required
- OpenCL development libraries (optional)
- Compatible with Linux/macOS/Windows

**Performance:**
- Search space cannot be exhaustively searched (too large)
- Probabilistic approach required for >90% coverage
- GPU performance varies by hardware (100M-10B seeds/second)

### Assumptions

**Market Assumptions:**
- 1.4 million BTC vulnerable estimate is accurate
- Security community needs defensive scanning capability
- Open-source approach is preferred over proprietary
- Responsible disclosure will be respected

**Technical Assumptions:**
- 2023 Randstorm disclosure is accurate and complete
- Browser fingerprint reconstruction is feasible
- GPU acceleration provides 10-100x speedup (validated by existing scanners)
- Test vectors are sufficient for validation

**User Assumptions:**
- Security professionals can build from source or use releases
- Basic command-line proficiency for users
- Understanding of Bitcoin basics
- Respect for ethical guidelines

### Legal & Ethical Constraints

**Source:** Tech Spec Security & Responsible Use Section (2025-12-22)

---

#### **Mandatory Requirements (Zero Tolerance)**

**1. Private Key Handling Policy**

**GPU Execution Path:**
- ✅ Private keys generated in GPU `__local` memory ONLY
- ✅ Keys NEVER transferred to CPU/host memory
- ✅ Only Hash160 comparison performed on GPU (secp256k1 pubkey → hash160 → compare)
- ✅ On match: write `(config_idx, timestamp)` to result buffer - **NOT the private key**

**CPU Fallback Path:**
- ✅ Derive → compute pubkey → hash160 → compare → **immediately discard**
- ✅ Use `zeroize` crate for any temporary buffers containing sensitive data
- ✅ No privkey variables in scope longer than necessary (minimize lifetime)

**Logging Policy:**
- ✅ Structured logging via `tracing` crate
- ✅ **NEVER** log private keys, seeds, or ARC4 pool state
- ✅ Redact sensitive data from error messages and debug output
- ✅ Automated security audit: `grep -r "private.*key" logs/` must return 0 matches

**2. Key Recovery Protocol**

When a vulnerable wallet is detected, the tool outputs **ONLY**:
- ✅ **Address** (already known to user)
- ✅ **Fingerprint ID** (index in phase1_top100.csv)
- ✅ **Timestamp (ms)** (exact timestamp that produced the match)
- ✅ **Confidence score** (based on fingerprint market share)
- ❌ **NO private key output** to stdout, logs, or files

**For legitimate wallet recovery, user must:**
1. **Prove ownership** of the address (sign message, provide transaction history, etc.)
2. **Manually re-derive** the private key using:
   - Published fingerprint data (from CSV)
   - Detected timestamp
   - Tool's derivation logic (open-source, auditable)
3. **Sweep funds** immediately to secure wallet with proper entropy
4. **Report vulnerability** if third-party wallet service affected (responsible disclosure)

**3. Authorized Use Only**

- ✅ **Permitted:** Security research on wallets you own or have explicit written permission to test
- ❌ **Prohibited:** Using this tool to access wallets without permission
- ⚖️ **Legal Consequence:** Unauthorized use violates the Computer Fraud and Abuse Act (CFAA) in the USA and similar laws worldwide
- ⚖️ **Criminal Penalty:** Federal crime punishable by fines and imprisonment in most jurisdictions

**WARNING:** Unauthorized use of this tool for wallet theft or unauthorized access is a **federal crime**. Use responsibly.

**4. Responsible Disclosure Framework**

- ✅ 90-day disclosure window for affected wallet services
- ✅ Coordination with cryptocurrency exchanges before public release
- ✅ Notification to affected wallet services (Blockchain.info, etc.)
- ✅ No automated fund transfer capability (identification only)
- ✅ Legal review before public release

**5. Documentation Requirements**

- ✅ Usage guide with explicit legal warnings
- ✅ Reference to `SECURITY.md` in repository root
- ✅ Ethical guidelines for security researchers
- ✅ Clear statement: "Research purpose only - intended to help identify and secure vulnerable wallets, not exploit them"

---

#### **Recommended Best Practices**

**1. Community Engagement:**
- Community peer review of methodology before release
- Transparent publication of algorithm specifications
- Open-source codebase for audit ability
- Active response to security vulnerability reports

**2. Collaboration:**
- Coordinate with affected wallet providers
- Share findings with cryptocurrency security community
- Contribute to industry-wide vulnerability mitigation efforts
- Support wallet owners in securing their funds (authorized cases only)

**3. Ongoing Compliance:**
- Monitor legal developments (CFAA, GDPR, cryptocurrency regulations)
- Update ethical guidelines as industry standards evolve
- Maintain responsible disclosure coordination
- Track and report any misuse incidents

---

#### **Liability Mitigation**

**Legal Disclaimers Required:**
- Tool provided "AS IS" without warranty
- User assumes all legal responsibility for authorized use
- Developers not liable for misuse or unauthorized access
- Explicit warning: "For authorized security research only"

**Pre-Release Legal Review Checklist:**
- [ ] Legal counsel review of all disclaimers
- [ ] Compliance with CFAA and international equivalents
- [ ] Responsible disclosure framework documented
- [ ] No automated fund transfer capability
- [ ] Clear usage restrictions in README and --help output

---

## Appendix

### A. Implementation Guidance

**Source:** Technical Specification (2025-12-22), Codebase Validation  
**Purpose:** Developer quick-reference for file structure, integration points, and implementation patterns

---

#### File Structure (Phase 1)

**New Files to Create:**

```
src/scans/randstorm.rs
│ Main scanner module orchestrating the workflow
│ Follows patterns from milk_sad.rs and trust_wallet_lcg.rs
│ Responsibilities:
│   - Load fingerprint database from CSV
│   - Iterate through addresses from input CSV
│   - Coordinate GPU/CPU execution
│   - Generate results (JSON/CSV output)
│   - Progress reporting with ETA

cl/randstorm_crack.cl
│ GPU OpenCL kernel for MWC1616 + ARC4 + secp256k1 derivation
│ Kernel name: "randstorm_crack"
│ Responsibilities:
│   - MWC1616 PRNG state generation (per fingerprint + timestamp)
│   - ARC4 pool initialization (256 Math.random() calls)
│   - secp256k1 private key → public key derivation
│   - P2PKH address generation (Hash160 comparison)
│   - Early-exit on match: write (config_idx, timestamp) to result buffer
```

**Existing Files to Modify:**

```
src/scans/mod.rs
│ Add: pub mod randstorm;
│ Export randstorm scanner for CLI access

src/main.rs
│ Add CLI subcommand using clap derive:
│   #[derive(Subcommand)]
│   enum Commands {
│       ...
│       RandstormScan {
│           #[arg(long)]
│           targets: PathBuf,
│           #[arg(long, default_value = "1")]
│           phase: u8,
│           #[arg(long)]
│           gpu: bool,
│           #[arg(long)]
│           cpu: bool,
│           #[arg(long)]
│           output: Option<PathBuf>,
│       },
│   }

src/scans/gpu_solver.rs
│ Add method following compute_trust_wallet_crack() pattern:
│   pub fn compute_randstorm_crack(
│       &self,
│       fingerprints: &[FingerprintConfig],
│       timestamp_start_ms: u64,
│       timestamp_end_ms: u64,
│       target_h160: &[u8; 20],
│   ) -> ocl::Result<Vec<(u32, u64)>>
│
│ Buffer setup:
│   - Input buffer 1: Fingerprint config array (packed u32 components)
│   - Input buffer 2: Target Hash160 → (u64, u64, u32) components
│   - Output buffer 1: Result pairs [(u32, u64)] max 1024 results
│   - Output buffer 2: Atomic counter u32
```

**Existing Data Files (No Changes Required):**

```
src/scans/randstorm/fingerprints/data/phase1_top100.csv
│ ✓ Already exists (validated 2025-12-22)
│ Schema: priority, user_agent, screen_width, screen_height, color_depth,
│         timezone_offset, language, platform, market_share_estimate,
│         year_min, year_max
│ 100 rows with complete data
```

---

#### Dependencies (Already in Cargo.toml)

All required dependencies are already present in the project:

- `ocl` - OpenCL bindings for GPU acceleration
- `bitcoin` - Address generation (P2PKH format)
- `secp256k1` - Elliptic curve cryptography
- `rayon` - CPU parallelism for fallback mode
- `tracing` - Structured logging
- `zeroize` - Secure memory cleanup
- `clap` v4.5 - CLI argument parsing
- `serde` - JSON/CSV serialization
- `anyhow` - Error handling

**No new dependencies required for Phase 1.**

---

#### Integration Patterns

**GPU Solver Integration (Follow trust_wallet_crack Pattern):**

Reference implementation: `src/scans/gpu_solver.rs::compute_trust_wallet_crack()`

Key patterns to follow:
1. **Buffer creation:** Use `MemFlags::new().read_write().alloc_host_ptr()`
2. **Kernel invocation:** Set work group size to 256 (optimal for most GPUs)
3. **Result parsing:** Read result buffer, check atomic counter for match count
4. **Error handling:** Return `ocl::Result<Vec<(u32, u64)>>` for composability

**Timestamp Search Strategy (3-Tier):**

```rust
// Tier 1: RPC timestamp lookup (if available)
if let Some(rpc_client) = rpc {
    if let Ok(first_tx_timestamp) = get_first_transaction_timestamp(rpc_client, address) {
        return (first_tx_timestamp - 86400_000, first_tx_timestamp + 86400_000); // ±24h
    }
}

// Tier 2: User-provided timestamp hint
if let Some(hint) = cli_args.timestamp_hint {
    return (hint - 86400_000, hint + 86400_000); // ±24h
}

// Tier 3: Default fallback (5 years ago ±24h)
let five_years_ago = current_timestamp_ms() - (5 * 365 * 24 * 3600 * 1000);
(five_years_ago - 86400_000, five_years_ago + 86400_000)
```

**Search Space Calculation:**
- Default range: ±24 hours (86,400 seconds)
- Granularity: 1 second (1000ms steps)
- Total timestamps per address: 172,800
- Total combinations: 100 fingerprints × 172,800 timestamps = **17.28M**

**GPU Batch Processing:**
- Work group size: 256 work items
- Global size: 1024 work groups = 262,144 parallel checks per invocation
- Estimated time: ~30 seconds per address on RTX 3060

---

#### Security Implementation Checklist

**GPU Kernel (cl/randstorm_crack.cl):**
- [ ] Private keys generated in GPU `__local` memory ONLY
- [ ] Keys NEVER transferred to `__global` memory or CPU
- [ ] Only Hash160 comparison performed on GPU
- [ ] On match: write `(config_idx, timestamp)` NOT privkey to result buffer

**CPU Fallback (src/scans/randstorm.rs):**
- [ ] Derive → hash160 → compare → zeroize immediately
- [ ] Use `zeroize` crate for sensitive buffers
- [ ] No privkey variables in scope longer than necessary
- [ ] Clear stack frames after derivation

**Logging (All Paths):**
- [ ] NEVER log privkeys, seeds, or ARC4 pool state
- [ ] Redact sensitive data from error messages: `error!("Derivation failed for address: {}", redact(addr))`
- [ ] Use structured logging: `tracing::info!(fingerprint_id = %id, "Match found")`
- [ ] Automated log scanning test: `grep -r "priv" logs/` must return 0 matches

---

#### Algorithm Specifications

**MWC1616 (Chrome V8 Math.random()):**
```rust
// Exact constants from V8 source
const MWC1616_MULTIPLIER_1: u32 = 18000;
const MWC1616_MULTIPLIER_2: u32 = 30903;

fn mwc1616_next(s1: &mut u32, s2: &mut u32) -> u32 {
    *s1 = MWC1616_MULTIPLIER_1 * (*s1 & 0xFFFF) + (*s1 >> 16);
    *s2 = MWC1616_MULTIPLIER_2 * (*s2 & 0xFFFF) + (*s2 >> 16);
    (*s1 << 16) + *s2
}
```

**ARC4 Pool Initialization (JSBN-specific):**
```rust
fn initialize_arc4_pool(mwc_state: &mut MWC1616State) -> [u8; 256] {
    let mut pool = [0u8; 256];
    for i in 0..256 {
        let rand_val = mwc_state.next();
        pool[i] = ((rand_val as f64 / u32::MAX as f64) * 256.0) as u8;
    }
    pool
}

// Note: Verify skip-bytes behavior from JSBN source if needed
```

**Timestamp Seeding:**
```rust
fn seed_from_fingerprint_and_timestamp(
    fingerprint: &FingerprintConfig,
    timestamp_ms: u64,
) -> (u32, u32) {
    // Hash fingerprint components (UA, screen, timezone, etc.)
    let fingerprint_hash = hash_fingerprint(fingerprint);
    
    // Combine with timestamp for s1, s2 seeds
    let s1 = (timestamp_ms as u32) ^ (fingerprint_hash & 0xFFFF_FFFF);
    let s2 = ((timestamp_ms >> 32) as u32) ^ ((fingerprint_hash >> 32) & 0xFFFF_FFFF);
    
    (s1, s2)
}
```

---

### Glossary

**PRNG:** Pseudo-Random Number Generator - algorithm that generates sequence of numbers approximating random numbers

**Randstorm:** Vulnerability in JavaScript-based Bitcoin wallet generators (2011-2015) due to weak PRNG entropy

**Browser Fingerprint:** Collection of browser/system characteristics (user-agent, screen resolution, etc.) that reduce entropy

**Entropy:** Measure of randomness/unpredictability in cryptographic key generation (256 bits required for Bitcoin)

**BIP32/44/49/84:** Bitcoin Improvement Proposals defining hierarchical deterministic wallet standards

**Derivation Path:** Sequence defining how to derive child keys from master key (e.g., m/44'/0'/0'/0/0)

**GPU Kernel:** Function executed in parallel on GPU

**False Positive:** Incorrectly identifying secure wallet as vulnerable

**False Negative:** Missing a vulnerable wallet (failing to detect vulnerability)

**Responsible Disclosure:** Practice of coordinating vulnerability publication with affected parties before public release

### References

**Primary Sources:**
- Randstorm Disclosure (2023) - Security researcher publication
- BIP32: Hierarchical Deterministic Wallets
- BIP39: Mnemonic Code for Generating Deterministic Keys
- BIP44/49/84: Derivation schemes

**Technical References:**
- V8 Engine documentation (Chrome JavaScript)
- SpiderMonkey documentation (Firefox JavaScript)
- JavaScriptCore documentation (Safari JavaScript)
- Chakra documentation (IE JavaScript)

**Project Documentation:**
- `project-context.md` - Temporal Planetarium overview
- `_bmad-output/architecture.md` - System architecture
- `_bmad-output/analysis/product-brief-temporal-planetarium-2025-12-17.md` - Product Brief
- `_bmad-output/analysis/research/technical-randstorm-research-2025-12-17.md` - Technical Research
- `_bmad-output/randstorm-tech-spec.md` - Technical Specification (Dec 22, 2025) - **Primary Reference**

---

**PRD Status:** REVISED (v2.0)  
**Version:** 2.0  
**Original Date:** 2025-12-17  
**Revision Date:** 2025-12-22  
**Original Author:** John (Product Manager)  
**Revision By:** Mary (Analyst), based on Party Mode collaboration (Murat, Amelia, Winston, John)  
**Next Step:** Implementation - Developer (Amelia) can begin with Epic 1 user stories using Given/When/Then acceptance criteria

---

## Revision Summary (v2.0 Changes)

**Major Scope Refinement:**
- ✅ Narrowed Phase 1 to **researcher-focused implementation** (deferred wallet owner & consultant personas to Phase 2+)
- ✅ Moved US-1.3 (wallet owner) out of Epic 1 to future phases
- ✅ Clarified all Epics 2 & 3 as DEFERRED

**Testing Strategy Added:**
- ✅ NEW SECTION: "Testing Strategy & Risk Framework" with 3-tier risk classification (Critical/High/Medium)
- ✅ Comprehensive test pyramid architecture (100+ unit, 20 integration, 5 E2E tests)
- ✅ CI/CD pipeline requirements specified
- ✅ Test fixtures documented (synthetic wallets, test vectors, known-secure addresses)
- ✅ Quality gates defined (pre-merge, pre-release)

**Acceptance Criteria Reformatted:**
- ✅ All Epic 1 acceptance criteria converted to **Given/When/Then/Verification** format
- ✅ Linked each AC to specific test file locations
- ✅ Made all criteria testable and measurable

**Implementation Guidance Added:**
- ✅ NEW APPENDIX A: Complete file structure (files to create, files to modify, existing data files)
- ✅ Integration patterns documented (GPU solver, timestamp search, security checklists)
- ✅ Algorithm specifications with code examples (MWC1616, ARC4, seeding)

**Legal & Ethical Expansion:**
- ✅ Detailed private key handling policies (GPU/CPU paths, logging)
- ✅ Explicit key recovery protocol (prove ownership → manual re-derivation)
- ✅ Legal compliance warnings (CFAA, federal crime consequences)
- ✅ Liability mitigation checklist

**Metrics & Success Criteria Enhanced:**
- ✅ Added measurement methods (how coverage/performance/accuracy are measured)
- ✅ Specified hardware baseline (RTX 3060 for performance targets)
- ✅ Added researcher-specific KPIs (10,000 addresses in <24 hours)

**Overall Impact:**
- Document length: ~1,209 lines → ~1,800+ lines (50% increase)
- Clarity: Removed multi-persona ambiguity, focused on single primary user
- Testability: All requirements now have explicit verification methods
- Implementation-readiness: Developers have complete file structure, integration patterns, and test requirements

