---
stepsCompleted: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
inputDocuments:
  - "_bmad-output/analysis/product-brief-temporal-planetarium-2025-12-17.md"
  - "_bmad-output/analysis/research/technical-randstorm-research-2025-12-17.md"
  - "_bmad-output/index.md"
  - "project-context.md"
  - "_bmad-output/architecture.md"
documentCounts:
  briefs: 1
  research: 1
  brainstorming: 0
  projectDocs: 3
workflowType: 'prd'
lastStep: 11
status: 'complete'
project_name: 'temporal-planetarium'
user_name: 'Moe'
date: '2025-12-17'
feature: 'Randstorm/BitcoinJS Scanner'
---

# Product Requirements Document - Randstorm/BitcoinJS Scanner

**Author:** Moe  
**Date:** 2025-12-17  
**Project:** Temporal Planetarium (entropy-lab-rs)  
**Feature:** Randstorm/BitcoinJS Vulnerability Scanner

---


## Executive Summary

### Product Vision

The Randstorm/BitcoinJS Scanner extends Temporal Planetarium's comprehensive vulnerability research platform by addressing its most critical gap: detecting Bitcoin wallets generated between 2011-2015 using weak JavaScript pseudo-random number generators (PRNGs). With an estimated 1.4 million BTC ($1+ billion) at risk and active attacker exploitation ongoing, this GPU-accelerated scanner provides the defensive capability security researchers, consultants, and wallet owners desperately need.

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

**Primary Users:**

**1. Security Researchers (Dr. Sarah Chen archetype)**
- **Needs:** Accuracy, reproducibility, transparent methodology, test vectors
- **Use Case:** Independent validation of Randstorm findings, publish CVE research
- **Success Metric:** Can reproduce results with 100% validation, publish peer-reviewed papers

**2. Security Consultants (Marcus Wei archetype)**
- **Needs:** Batch processing, professional PDF reports, client-ready deliverables
- **Use Case:** Offer Randstorm scanning as billable audit service
- **Success Metric:** Integrate into workflow, generate revenue from high-value audits

**Secondary Users:**

**3. Wallet Owners (Alex Rodriguez archetype)**
- **Needs:** Simple yes/no answer, privacy protection, actionable guidance
- **Use Case:** Check if 2011-2015 wallet is vulnerable, understand what to do
- **Success Metric:** Clear vulnerability status, follows recommendations

**4. Educators & Historians (Prof. Li Zhang archetype)**
- **Needs:** Educational materials, historical context, case studies
- **Use Case:** Teach students about real-world cryptographic failures
- **Success Metric:** Curriculum integration, academic publications

### Key Success Metrics

**Phase 1 (Week 1) Success Criteria:**
- ✅ 60-70% estimated vulnerable wallet coverage
- ✅ 100% validation against 2023 Randstorm disclosure test vectors
- ✅ 10x+ GPU speedup demonstrated vs CPU baseline
- ✅ Zero regressions in existing 18 scanners (integration tests pass)

**Phase 2 (Week 2) Success Criteria:**
- ✅ 85-90% coverage with expanded browser configurations
- ✅ Multi-path derivation operational (BIP32/44/49/84)
- ✅ 50x+ GPU speedup maintained with increased complexity
- ✅ Independent security audit completed, zero critical vulnerabilities

**Phase 3 (Week 3+) Success Criteria:**
- ✅ 95%+ coverage through probabilistic search methods
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

**In Scope - Phase 1 (MVP):**
- Chrome V8 PRNG reconstruction (MWC1616)
- Top 100 browser configurations (2011-2015)
- Single most-common derivation path
- Basic GPU OpenCL kernel
- CLI interface (no GUI)
- Test suite with 2023 disclosure examples
- CPU fallback
- Progress reporting

**In Scope - Phase 2:**
- Firefox, Safari, IE PRNG implementations
- 500 browser configurations
- Multi-path derivation (BIP32/44/49/84)
- GPU optimization (NVIDIA/AMD/Intel)
- Batch processing
- CSV import/export

**In Scope - Phase 3:**
- Probabilistic search algorithms
- Adaptive/ML-based configuration selection
- Multi-GPU support
- Checkpoint/resume
- Professional reporting (PDF)

**Explicitly Out of Scope:**
- ❌ GUI interface (CLI only, potential future feature)
- ❌ Automated fund recovery/transfer (identification only)
- ❌ Real-time blockchain monitoring
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

### Epic 1: MVP Scanner (Phase 1 - Week 1)

**US-1.1:** As a security researcher, I want to scan for Randstorm vulnerabilities using Chrome PRNG patterns, so I can validate the 2023 disclosure findings.

**Acceptance Criteria:**
- Scanner accepts target Bitcoin addresses as input
- Implements Chrome V8 MWC1616 PRNG
- Tests top 100 browser configurations
- Produces vulnerability report
- 100% validation against known test vectors

**US-1.2:** As a security researcher, I want GPU acceleration for scanning, so I can complete scans in reasonable time.

**Acceptance Criteria:**
- GPU automatically detected and utilized
- 10x+ speedup vs CPU demonstrated
- Works on NVIDIA, AMD, Intel GPUs
- Graceful CPU fallback when GPU unavailable

**US-1.3:** As a wallet owner, I want to check if my 2011-2015 Bitcoin wallet is vulnerable, so I can take action to protect my funds.

**Acceptance Criteria:**
- Simple CLI command to check single address
- Clear "VULNERABLE" or "SAFE" result
- Guidance on next steps if vulnerable
- Completes in <30 minutes

---

### Epic 2: Comprehensive Coverage (Phase 2 - Week 2)

**US-2.1:** As a security consultant, I want to scan using all major browser PRNGs (Chrome, Firefox, Safari, IE), so I can provide complete audits to clients.

**Acceptance Criteria:**
- Firefox SpiderMonkey PRNG implemented
- Safari JavaScriptCore PRNG implemented
- IE Chakra PRNG implemented
- All PRNGs validated against test vectors

**US-2.2:** As a security consultant, I want batch processing for multiple wallets, so I can audit many clients efficiently.

**Acceptance Criteria:**
- CSV import with thousands of addresses
- Batch scan completes for all addresses
- CSV export with results
- Progress tracking per address

**US-2.3:** As a security researcher, I want multi-path derivation support, so I can check all address types (legacy, SegWit, etc).

**Acceptance Criteria:**
- BIP32/44/49/84 paths supported
- Correct address generation for each path
- Validation against reference implementations

---

### Epic 3: Optimization & Professional Features (Phase 3 - Week 3+)

**US-3.1:** As a security consultant, I want professional PDF reports, so I can deliver client-ready audit results.

**Acceptance Criteria:**
- PDF export option
- Professional formatting
- Executive summary + technical details
- Branded with temporal-planetarium

**US-3.2:** As a security researcher, I want checkpoint/resume support, so I can run long scans without losing progress.

**Acceptance Criteria:**
- Auto-checkpoint every 5 minutes
- Resume from checkpoint file
- Graceful shutdown saves state
- Results identical to uninterrupted scan

**US-3.3:** As a security researcher, I want probabilistic search for maximum coverage, so I can find the last 5-10% of vulnerable wallets.

**Acceptance Criteria:**
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

**Mandatory:**
- White-hat use only (no malicious exploitation)
- Responsible disclosure framework required
- 90-day disclosure window
- No automated fund transfer capability
- Legal review before release

**Recommended:**
- Coordination with cryptocurrency exchanges
- Notification to affected wallet services
- Community peer review
- Transparent methodology publication

---

## Appendix

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

---

**PRD Status:** COMPLETE  
**Version:** 1.0  
**Date:** 2025-12-17  
**Author:** John (Product Manager), based on analysis by Mary (Analyst)  
**Next Step:** Architecture design by Winston (Architect)

