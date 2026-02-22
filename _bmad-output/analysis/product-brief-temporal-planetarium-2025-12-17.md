---
stepsCompleted: [1, 2, 3, 4, 5]
inputDocuments:
  - "_bmad-output/index.md"
  - "project-context.md"
  - "_bmad-output/architecture.md"
  - "_bmad-output/implementation-readiness-report-2025-12-17.md"
workflowType: 'product-brief'
lastStep: 5
status: 'complete'
project_name: 'temporal-planetarium'
user_name: 'Moe'
date: '2025-12-17'
feature: 'Randstorm/BitcoinJS Scanner'
---

# Product Brief: Randstorm/BitcoinJS Scanner

**Date:** 2025-12-17
**Author:** Moe
**Feature:** Randstorm/BitcoinJS Vulnerability Scanner
**Project:** Temporal Planetarium (entropy-lab-rs)

---

## Executive Summary

The Randstorm/BitcoinJS Scanner addresses the most critical vulnerability gap in Temporal Planetarium: identifying wallets generated between 2011-2015 using weak JavaScript PRNGs. With 1.4 million BTC ($1 billion+) potentially at risk, this scanner completes the vulnerability research toolkit by targeting the highest-impact weakness currently missing from the platform.

This feature leverages the existing GPU-accelerated architecture (46 OpenCL kernels, proven 10-100x speedup) to efficiently scan the Randstorm attack surface through a strategic 3-phase implementation: MVP in Week 1 (60-70% coverage), expansion in Week 2 (85-90% coverage), and optimization in Week 3+ (95%+ coverage).

**Success Metrics:**
- Phase 1: 60-70% vulnerable wallet identification (Week 1 MVP)
- Phase 2: 85-90% coverage with expanded browser configs (Week 2)
- Phase 3: 95%+ coverage with probabilistic search (Week 3+)
- GPU performance: 10-100x speedup matching existing scanners
- 100% validation against 2023 Randstorm disclosure test vectors
- Responsible disclosure framework operational before launch

---

## Core Vision

### Problem Statement

Between 2011-2015, popular Bitcoin wallet services (Blockchain.info, CoinPunk, BrainWallet) used JavaScript's Math.random() and Date() functions with insufficient entropy sources for private key generation. The browser's limited entropy (user-agent strings, screen resolution, timezone, and timestamps) created a predictable search space. The 2023 Randstorm disclosure revealed that 1.4 million BTC ($1+ billion) remain vulnerable to exploitation through systematic reconstruction of these weak entropy sources.

Despite Temporal Planetarium's comprehensive suite of 18 vulnerability scanners covering critical weaknesses (Milk Sad $1B+, Cake Wallet 224k+ wallets, Trust Wallet CVEs, Profanity, Android SecureRandom), the Randstorm vulnerability—the largest cryptocurrency security threat by value—remains unaddressed. Security researchers, wallet owners, and recovery specialists lack an automated, GPU-accelerated tool to scan for this specific vulnerability before malicious actors exhaust the search space.

### Problem Impact

**Magnitude:**
- 1.4 million BTC at risk ($1+ billion at current valuations)
- Wallets from 2011-2015 era still in active use with significant balances
- Window of opportunity closing as sophisticated attackers discover vulnerable wallets
- Race condition: attackers already scanning while defensive tools are unavailable

**Affected Stakeholders:**
- **Wallet Owners:** Unaware their 2011-2015 wallets have weak entropy, funds at imminent risk
- **Security Researchers:** No comprehensive tool to audit historical wallet vulnerabilities
- **White-Hat Teams:** Cannot proactively identify and secure vulnerable wallets
- **Cryptocurrency Exchanges:** Potential liability for vulnerable user wallets
- **Recovery Specialists:** Missing critical tool for legitimate fund recovery

**Current Gap:**
- No GPU-accelerated Randstorm scanner exists in open-source community
- Manual JavaScript PRNG analysis computationally prohibitive (years of CPU time)
- Temporal Planetarium's otherwise comprehensive toolkit has critical blind spot
- Highest-value vulnerability ($1B+) unaddressed while lower-value threats covered

### Why Existing Solutions Fall Short

**Current State:**
- **Temporal Planetarium's 18 Scanners:** Comprehensive coverage of Milk Sad (Libbitcoin CVE-2023-39910), Cake Wallet (224k+ vulnerable wallets), Trust Wallet (MT19937 CVEs), Profanity (CVE-2022-40769), Android SecureRandom (CVE-2013), and more—but critically NOT Randstorm
- **Manual JavaScript Analysis:** Too slow and error-prone; scanning all browser fingerprint combinations manually would take decades
- **General Entropy Analysis Tools:** Lack specific attack patterns for 2011-2015 era JavaScript PRNG weaknesses
- **No GPU Acceleration Available:** CPU-only analysis prohibitively expensive for the massive search space (browser configs × timestamps × derivation paths)

**Missing Capabilities:**
- **Historical Browser Fingerprint Reconstruction:** No database of actual browser configurations from 2011-2015
- **Era-Specific Derivation Paths:** 2011-2012 wallets used different derivation than 2014-2015 (pre-BIP44 vs post-BIP44)
- **Probabilistic Search Optimization:** No intelligence about which configurations were most common
- **Integrated Workflow:** No responsible disclosure framework for findings

### Proposed Solution

**Randstorm/BitcoinJS Scanner** - A GPU-accelerated, era-aware vulnerability scanner targeting weak JavaScript PRNG implementations from 2011-2015, delivered through a strategic 3-phase implementation.

**Core Capabilities:**

**Phase 1 - MVP (Week 1): Speed-First Coverage**
1. **JavaScript PRNG Reconstruction:** Math.random() + Date() entropy modeling for 2011-2015
2. **Top 100 Browser Configs:** Chrome, Firefox, Safari variants (user-agent, screen resolution, timezone)
3. **Era-Appropriate Derivation:** Single most-common path for 2011-2015 wallets
4. **GPU Acceleration:** Basic OpenCL kernel leveraging existing infrastructure
5. **Target:** 60-70% vulnerable wallet coverage in Week 1

**Phase 2 - Expansion (Week 2): Comprehensive Coverage**
1. **Expanded PRNG Variants:** Additional JavaScript entropy sources and browser APIs
2. **500 Browser Configurations:** Extended historical database
3. **Multi-Path Support:** Add BIP32/44 for 2014-2015 era wallets
4. **Optimized GPU Kernels:** Device-specific tuning (NVIDIA/AMD/Intel)
5. **Target:** 85-90% vulnerable wallet coverage

**Phase 3 - Optimization (Week 3+): Maximum Effectiveness**
1. **Probabilistic Search:** ML-based prediction of likely browser configurations
2. **Adaptive Algorithms:** Dynamically adjust search based on findings
3. **Complete Path Coverage:** All derivation variants
4. **Advanced GPU Optimization:** Multi-GPU support, checkpoint/resume
5. **Target:** 95%+ vulnerable wallet coverage

**Technical Approach:**
- **Browser State Reconstruction:** Model limited entropy from user-agent strings, screen resolutions (800×600, 1024×768, etc.), timezones, and Date() timestamps
- **Curated Historical Database:** Pre-researched browser fingerprints from 2011-2015 era
- **GPU-Accelerated Search:** Leverage 46 existing OpenCL kernels and patterns
- **Era-Specific Logic:** Different scanning approaches for 2011-2012 (pre-BIP32) vs 2013-2015 (post-BIP32)
- **Validation Framework:** Extensive test suite against 2023 Randstorm disclosure examples

**Implementation:**
- **Scanner Module:** `src/scans/randstorm.rs` following established patterns
- **GPU Kernels:** `cl/randstorm_crack.cl` with multipath variants
- **CLI Integration:** Subcommand following existing scanner patterns
- **Test Suite:** Integration tests with known vulnerable test vectors
- **Documentation:** User guide, technical reference, educational materials

### Key Differentiators

**1. Completes Critical Ecosystem Gap**
- Only major cryptocurrency vulnerability missing from comprehensive 18-scanner suite
- Addresses highest-value threat ($1B+ vs other scanners' smaller scope)
- Transforms Temporal Planetarium into complete vulnerability research platform
- First-mover advantage in open-source Randstorm scanning

**2. Proven Architecture Foundation**
- **Leverages 46 existing GPU kernels** - established optimization patterns
- **Follows modular scanner design** - 18 successful implementations to learn from
- **Built on solid crypto stack** - secp256k1, bitcoin, bip39 crates (battle-tested)
- **Reuses infrastructure** - Minimal new code, maximum leverage

**3. Performance Advantage Through GPU**
- **10-100x speedup** proven across existing scanners
- **Device-aware optimization** automatically tunes for NVIDIA/AMD/Intel
- **Efficient CPU-GPU transfers** using pinned memory
- **Graceful degradation** to CPU when GPU unavailable

**4. Strategic 3-Phase Implementation**
- **Week 1 MVP** delivers value immediately (60-70% coverage)
- **Iterative expansion** based on real findings
- **Beats attackers** by shipping fast, optimizing later
- **Manages complexity** through phased delivery

**5. Unique Market Position**
- **No comprehensive open-source alternative** exists
- **First GPU-accelerated implementation** of Randstorm scanning
- **Integrated platform** not standalone tool
- **White-hat focused** with responsible disclosure built-in

**6. Technical Excellence**
- **Rust memory safety** eliminates entire vulnerability classes
- **Comprehensive error handling** with anyhow::Result throughout
- **Multi-platform support** - Linux, macOS, Windows
- **BMAD methodology** ensures quality and completeness

**7. Time-to-Value Optimization**
- **~3 weeks total development** following proven BMAD workflow
- **Week 1 delivers usable MVP** not perfect final product
- **Reuses existing patterns** reduces implementation risk
- **Clear ROI:** $1B+ vulnerability vs 3 weeks effort = exceptional value

### Success Criteria & Validation

**Phase 1 Validation (Week 1):**
- ✅ 100% match rate on public Randstorm test vectors
- ✅ 60-70% estimated coverage of vulnerable wallet population
- ✅ GPU acceleration demonstrates 10x+ speedup vs CPU baseline
- ✅ Integration tests pass without regression in existing scanners

**Phase 2 Validation (Week 2):**
- ✅ 85-90% estimated coverage with expanded configurations
- ✅ Multi-path derivation working for all supported eras
- ✅ Performance maintains 50x+ speedup with increased complexity
- ✅ Professional security audit identifies zero critical vulnerabilities

**Phase 3 Validation (Week 3+):**
- ✅ 95%+ estimated coverage through probabilistic methods
- ✅ Researcher community validates methodology
- ✅ Real-world vulnerable wallet identification in controlled test
- ✅ Responsible disclosure framework operational

**User Acceptance Criteria:**
- **Security Researchers:** Can reproduce results independently, methodology is transparent
- **Wallet Owners:** Simple yes/no answer about wallet vulnerability with clear guidance
- **Security Firms:** Can integrate into professional audit workflows with batch processing
- **Performance Engineers:** Meets or exceeds existing scanner performance benchmarks

### Risk Mitigation & Responsible Disclosure

**Critical Risks Identified:**

**Risk 1: Attackers Have Head Start**
- Scanner development (3 weeks) gives attackers time advantage
- **Mitigation:** MVP in Week 1 delivers basic functionality immediately, optimize later

**Risk 2: Scanner Bugs Create False Negatives**
- Bugs in GPU kernel or JavaScript reconstruction = missed vulnerable wallets
- **Mitigation:** Extensive test suite against all known Randstorm examples before any public release

**Risk 3: Scanner Itself Becomes Attack Vector**
- Open-source code reveals gaps attackers can exploit
- **Mitigation:** Independent security audit, peer review, coordinated disclosure

**Risk 4: Social Engineering & Misuse**
- Fake vulnerability checkers steal wallet addresses
- **Mitigation:** Official distribution only, clear branding, prominent warnings

**Responsible Disclosure Protocol:**
1. **Identify vulnerable wallet** through scanner
2. **90-day waiting period** before public disclosure
3. **Attempt owner contact** if possible through blockchain metadata
4. **Coordinate with exchanges** to freeze vulnerable accounts
5. **Public disclosure** only after mitigation attempts or 90-day window
6. **Never exploit** for personal gain - white-hat only

### Educational & Historical Value

Beyond immediate security impact, this scanner serves important educational and historical preservation functions:

- **Document the vulnerability thoroughly** for future cryptocurrency security research
- **Track which services were affected when** to understand historical security landscape
- **Educational materials** help community understand JavaScript entropy risks
- **Archive findings** for academic research and security training

---

## Target Users

### Primary Users

**Security Researchers (Dr. Sarah Chen archetype)**
- **Profile:** PhD-level cryptographers, blockchain security professionals, CVE researchers
- **Context:** Work at security firms, publish vulnerability disclosures, need reproducible tools
- **Key Needs:** Accuracy (100% validation), transparent methodology, test vectors, peer review quality
- **Success Criteria:** Can independently validate Randstorm findings and publish results
- **Usage Pattern:** Deep technical analysis, contributing improvements, professional reputation

**Security Consultants (Marcus Wei archetype)**
- **Profile:** Run blockchain security firms, perform client audits, billable professional services
- **Context:** Need scalable tools for client work, professional deliverables, legal compliance
- **Key Needs:** Batch processing, professional reporting (PDF), client-ready outputs, responsible disclosure
- **Success Criteria:** Can add Randstorm scanning to service offerings and bill clients
- **Usage Pattern:** Weekly client audits, integration with existing workflows, commercial use

### Secondary Users

**Wallet Owners (Alex Rodriguez archetype)**
- **Profile:** 2011-2015 Bitcoin early adopters, non-technical, significant holdings at risk
- **Context:** Heard about Randstorm vulnerability, terrified but don't know how to check
- **Key Needs:** Simple yes/no answer, clear guidance, privacy protection, actionable steps
- **Success Criteria:** Understands if wallet is vulnerable and what to do about it
- **Usage Pattern:** One-time check, follows recommendations, refers friends

**Educators & Researchers (Prof. Li Zhang archetype)**
- **Profile:** Computer science professors, cryptocurrency historians, security trainers
- **Context:** Teaching about real-world cryptographic failures, preserving security history
- **Key Needs:** Educational materials, historical context, comprehensive documentation, case studies
- **Success Criteria:** Can teach students about Randstorm using real tools and examples
- **Usage Pattern:** Classroom demonstrations, academic research, curriculum development

### User Journey Highlights

**Security Researcher Path:**
Discovery → Methodology validation → Integration into workflow → Professional use → Community contribution

**Wallet Owner Path:**
Panic discovery → Simple check → Clear result → Peace of mind/Action → Recommendations to peers

**Security Consultant Path:**
Client need → Tool evaluation → Workflow integration → Regular professional use → Revenue generation

**Educator Path:**
Research → Classroom demonstration → Student engagement → Curriculum integration → Academic publication

---

## Success Metrics

### User Success Metrics

**Security Researchers:**
- ✅ 100% validation rate against 2023 Randstorm disclosure test vectors
- ✅ Methodology transparent enough for independent reproduction
- ✅ 3+ peer-reviewed publications citing temporal-planetarium within 12 months
- ✅ 80%+ of security researchers rate methodology as "rigorous" in surveys

**Security Consultants:**
- ✅ Scanner integrated into 10+ professional audit workflows within 6 months
- ✅ Batch processing handles 100+ wallets in single scan
- ✅ Professional PDF reports generated in <5 minutes
- ✅ Zero legal/compliance issues reported

**Wallet Owners:**
- ✅ 95%+ understand their wallet status (safe/vulnerable) after scan
- ✅ Clear action items provided for 100% of vulnerable wallets
- ✅ Privacy maintained - no wallet addresses leaked or compromised
- ✅ 85%+ user satisfaction with clarity of results

**Educators:**
- ✅ Educational materials integrated into 5+ university curricula within 12 months
- ✅ 90%+ of students understand Randstorm vulnerability after using tool
- ✅ 2+ academic case studies published

### Business & Project Objectives

**Phase 1 (Week 1 - MVP):**
- ✅ Basic scanner operational with 60-70% vulnerable wallet coverage
- ✅ 10x+ GPU speedup demonstrated vs CPU baseline
- ✅ Zero regressions in existing 18 scanners
- ✅ Test suite passes 100% with known examples

**Phase 2 (Week 2 - Expansion):**
- ✅ 85-90% coverage with expanded browser configurations
- ✅ Multi-path derivation (BIP32/44) operational
- ✅ 50x+ GPU speedup maintained
- ✅ Security audit completed with zero critical findings

**Phase 3 (Week 3+ - Optimization):**
- ✅ 95%+ coverage through probabilistic search
- ✅ Community validation of methodology
- ✅ Responsible disclosure framework operational
- ✅ 5+ vulnerable wallets responsibly disclosed

### Key Performance Indicators (KPIs)

**Adoption Metrics:**
- GitHub stars: 500+ within 3 months of launch
- Downloads: 1,000+ within first month
- Active users: 200+ security researchers/consultants using regularly

**Impact Metrics:**
- Vulnerable wallets identified: 10+ confirmed findings
- Value protected: $10M+ in BTC secured through responsible disclosure
- False positive rate: <1%
- False negative rate: <5%

**Technical Performance:**
- GPU speedup: 10-100x vs CPU (matching existing scanners)
- Scan time: <30 minutes for typical wallet (Phase 1), <10 minutes (Phase 3)
- Resource usage: <8GB RAM, scales to available GPU memory

**Community Health:**
- GitHub contributors: 10+ active contributors within 6 months
- Issues resolved: 80%+ within 2 weeks
- Pull requests merged: 60%+ within 1 week
- Documentation quality: 90%+ users find docs helpful

---

## Scope & Features

### In Scope (MVP - Phase 1)

**Core Functionality:**
- ✅ JavaScript PRNG reconstruction (Math.random() + Date())
- ✅ Top 100 browser configurations (2011-2015 era)
- ✅ Single most-common derivation path
- ✅ GPU-accelerated scanning with OpenCL
- ✅ CLI interface following existing patterns
- ✅ Basic progress reporting

**Essential Features:**
- ✅ Test suite with Randstorm disclosure examples
- ✅ Clear success/failure reporting
- ✅ CPU fallback when GPU unavailable
- ✅ Integration with existing temporal-planetarium

### In Scope (Phase 2-3)

**Expanded Coverage:**
- ✅ Additional JavaScript PRNG variants
- ✅ 500+ browser configurations
- ✅ Multi-path support (BIP32/44/49/84)
- ✅ Device-specific GPU optimization

**Professional Features:**
- ✅ Batch processing mode
- ✅ CSV import/export
- ✅ Progress bars and ETA
- ✅ Checkpoint/resume functionality

**Advanced Features:**
- ✅ Probabilistic search algorithms
- ✅ Adaptive search optimization
- ✅ Multi-GPU support
- ✅ Professional reporting (PDF)

### Explicitly Out of Scope

**Not Included:**
- ❌ Graphical user interface (CLI only for MVP)
- ❌ Automated fund recovery (identification only)
- ❌ Real-time blockchain monitoring
- ❌ Integration with hardware wallets
- ❌ Ethereum or non-Bitcoin chains (Bitcoin focus only)
- ❌ Exhaustive search of all possible configurations (probabilistic approach)

**Future Consideration:**
- GUI wrapper (post-MVP)
- Ethereum/altcoin support (if demand exists)
- Cloud-based scanning service (requires legal review)
- Mobile app (long-term)

---

## Constraints & Assumptions

### Technical Constraints

**Hardware:**
- OpenCL-compatible GPU recommended for performance (CPU fallback available)
- Minimum 4GB RAM for basic operation, 8GB+ recommended
- 1GB disk space for scanner + database

**Software:**
- Rust 1.70+ required
- OpenCL development libraries (for GPU features)
- Linux/macOS/Windows support (all platforms)

**Performance:**
- Search space is massive - cannot exhaustively search all combinations
- Probabilistic approach required for >95% coverage
- Scan times vary based on GPU capabilities (minutes to hours)

### Business Constraints

**Legal & Ethical:**
- White-hat use only - built-in responsible disclosure framework
- No automated exploitation or fund transfers
- 90-day disclosure window required
- Clear licensing (open-source but ethical use mandated)

**Resource:**
- 3-week development timeline (following BMAD workflow)
- Leverages existing infrastructure (46 GPU kernels, 18 scanner patterns)
- Community-driven development model

### Assumptions

**Market Assumptions:**
- Security researchers need Randstorm scanning capability
- $1B+ in vulnerable wallets justifies development effort
- Open-source community will contribute and validate
- Responsible disclosure will be respected

**Technical Assumptions:**
- 2023 Randstorm disclosure is accurate and complete
- Historical browser fingerprint data can be reconstructed
- GPU acceleration provides 10-100x speedup (proven by existing scanners)
- Test vectors from disclosure are sufficient for validation

**User Assumptions:**
- Security researchers can build from source
- Wallet owners can use CLI with clear documentation
- Professional users will integrate into existing workflows
- Educators value hands-on security tools

---

## Risks & Mitigation

### Critical Risks

**Risk 1: Attackers Exploit Vulnerability First**
- **Likelihood:** High (already happening)
- **Impact:** High ($1B+ at risk)
- **Mitigation:** MVP in Week 1, ship fast and iterate, coordinate with security community

**Risk 2: Scanner Has Bugs (False Negatives)**
- **Likelihood:** Medium (complex implementation)
- **Impact:** Critical (missed vulnerable wallets)
- **Mitigation:** Extensive test suite, independent security audit, peer review before launch

**Risk 3: Legal/Ethical Issues**
- **Likelihood:** Low (white-hat focus)
- **Impact:** High (project shutdown, legal action)
- **Mitigation:** Responsible disclosure framework, legal review, clear ethical guidelines

**Risk 4: Performance Below Expectations**
- **Likelihood:** Low (proven architecture)
- **Impact:** Medium (slower adoption)
- **Mitigation:** Early GPU prototyping, benchmark against existing scanners, progressive optimization

### Secondary Risks

**Risk 5: Community Rejection**
- **Likelihood:** Low (fills critical gap)
- **Impact:** Medium (limited adoption)
- **Mitigation:** Transparent methodology, peer review, community engagement

**Risk 6: Technical Complexity Too High**
- **Likelihood:** Medium (challenging problem)
- **Impact:** Medium (delayed timeline)
- **Mitigation:** Phased approach, reuse existing patterns, seek expert input

**Risk 7: Insufficient Coverage**
- **Likelihood:** Medium (massive search space)
- **Impact:** Medium (some vulnerable wallets missed)
- **Mitigation:** Probabilistic approach, continuous improvement, community contributions

---

## Product Brief Summary

**What:** GPU-accelerated Randstorm/BitcoinJS vulnerability scanner for temporal-planetarium

**Why:** 1.4M BTC ($1B+) at risk from 2011-2015 JavaScript PRNG weakness - critical gap in comprehensive security toolkit

**Who:** Security researchers, consultants, wallet owners, educators

**When:** 3-week phased development - Week 1 MVP (60-70% coverage), Week 2 expansion (85-90%), Week 3+ optimization (95%+)

**How:** Leverage existing 46 GPU kernels and 18 scanner patterns, implement browser fingerprint reconstruction with era-specific logic

**Success:** 95%+ vulnerable wallet coverage, 10-100x GPU speedup, 100% test vector validation, responsible disclosure operational, community adoption

---

**Product Brief Complete**
**Date:** 2025-12-17
**Status:** Ready for PRD Generation
**Next Step:** Use Product Manager agent to create comprehensive PRD from this brief

