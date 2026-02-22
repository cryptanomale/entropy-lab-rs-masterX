---
stepsCompleted: ['step-01-validate-prerequisites', 'step-02-design-epics']
inputDocuments:
  - "_bmad-output/prd.md"
  - "_bmad-output/architecture.md"
  - "_bmad-output/architecture-randstorm-scanner.md"
  - "_bmad-output/architecture-randstorm-validation.md"
---

# temporal-planetarium - Phase 1 MVP Epic Breakdown

## Overview

This document provides the epic and story breakdown for **Phase 1 MVP** requirements identified as missing in the implementation readiness assessment. These are the foundational P0 (Critical) requirements needed before Phase 13 advanced features can be implemented.

**Scope:** This epic document covers the three completely missing Phase 1 MVP requirement categories:
- **FR-2:** Browser Fingerprint Database (0% current coverage)
- **FR-3:** Derivation Path Support (0% current coverage)
- **FR-7:** Responsible Disclosure Framework (0% current coverage)

## Requirements Inventory

### Functional Requirements

**FR-2: Browser Fingerprint Database** (Priority: P0 - Critical MVP Blocker, Phase: 1 for top 100, Phase 2 for expansion)

- **FR-2.1: Browser Configuration Schema**
  - Struct with: user_agent, screen_width, screen_height, color_depth, timezone_offset, language, platform, market_share_estimate, year_range
  - Must support prioritization by market share

- **FR-2.2: Top 100 Configurations (Phase 1)**
  - Chrome 20-40 on Windows 7 (1366x768, 1920x1080)
  - Firefox 10-30 on Windows 7
  - Safari 5-8 on macOS
  - US/EU timezones prioritized
  - **AC:** Covers estimated 60-70% of 2011-2015 wallet generation sessions

- **FR-2.3: Extended 500 Configurations (Phase 2)**
  - Additional browser versions, mobile configs, global timezones
  - **AC:** Covers estimated 85-90% of sessions

- **FR-2.4: Configuration Prioritization**
  - Sort by market_share_estimate descending
  - **AC:** Scanner tests most likely configs before unlikely ones

---

**FR-3: Derivation Path Support** (Priority: P0 - Critical, Phase: 1 simple, 2 multi-path)

- **FR-3.1: Pre-BIP32 Direct Derivation (Phase 1)**
  - Direct private key generation from PRNG output
  - Used by 2011-2012 wallets
  - **AC:** Generates correct P2PKH addresses for direct keys

- **FR-3.2: BIP32 Simple Paths (Phase 2)**
  - m/0 (first key), m/0/0 (first child of first key)
  - **AC:** HD wallet derivation matches BIP32 spec

- **FR-3.3: BIP44 Standard Path (Phase 2)**
  - m/44'/0'/0'/0/0 (Bitcoin standard account, first address)
  - **AC:** Matches standard wallet implementations

- **FR-3.4: SegWit Paths (Phase 2)**
  - BIP49: m/49'/0'/0'/0/0 (P2WPKH-nested-in-P2SH)
  - BIP84: m/84'/0'/0'/0/0 (Native SegWit P2WPKH)
  - **AC:** Generates correct SegWit addresses

- **FR-3.5: Extended Index Support (Phase 3)**
  - Scan address indices 0-100 per seed
  - **AC:** Can check first 100 addresses per derivation path

---

**FR-7: Responsible Disclosure Framework** (Priority: P0 - Critical Legal/Ethical Requirement, Phase: 1)

- **FR-7.1: Disclosure Protocol Documentation (Optional Guidance)**
  - Document 90-day waiting period option for coordinated disclosure
  - Exchange coordination support for responsible researchers
  - Public disclosure guidelines available but not mandatory
  - **AC:** Protocol documentation available in docs/ as optional best practice

- **FR-7.2: Findings Report Format**
  - Vulnerable address ID, estimated risk level, recommended actions, contact info
  - **AC:** Report template included in repository

- **FR-7.3: Private Key Access & Export**
  - Scanner exports identified private keys to output (CSV/JSON/console)
  - Private keys logged for researcher analysis
  - Secure storage of exported keys (encrypted output files)
  - **AC:** Private keys available in results output with proper security warnings

- **FR-7.4: Ethical Use Guidelines**
  - Prominent disclaimer about authorized use only
  - Requires explicit permission for target addresses
  - Legal warnings about unauthorized access
  - Clear documentation about legal/ethical boundaries
  - **AC:** Documentation includes proper warnings and terms of use

- **FR-7.5: Coordination Support**
  - Template emails for exchange/wallet owner notification
  - **AC:** Templates included in docs/

### Non-Functional Requirements

**NFR-2: Accuracy & Reliability** (Priority: P0 - Critical)

- **NFR-2.1: False Negative Rate**
  - Target: <5%, Maximum acceptable: <10%
  - **Measurement:** Test against known vulnerable wallets

- **NFR-2.2: False Positive Rate**
  - Target: <1%, Maximum acceptable: <2%
  - **Measurement:** Test against known secure wallets (post-2015)

- **NFR-2.3: Test Vector Validation**
  - 100% match on Randstorm disclosure examples
  - Zero tolerance for missed known vulnerabilities

**NFR-3: Security & Ethics** (Priority: P0 - Critical)

- **NFR-3.1: Secure Private Key Handling**
  - Private keys exported to authorized users only
  - Secure storage of exported keys (encrypted output files recommended)
  - Clear warnings about key custody responsibilities
  - Secure memory clearing after export

- **NFR-3.2: Authorized Use Only**
  - Requires explicit permission for target addresses
  - Ethical use guidelines prominent
  - Legal compliance warnings displayed

- **NFR-3.3: Data Privacy**
  - No wallet addresses uploaded to external services
  - No telemetry without explicit consent
  - Local execution only

**NFR-7: Compliance & Legal** (Priority: P0 - Critical)

- **NFR-7.1: Open Source Licensing**
  - Compatible with temporal-planetarium license
  - Clear attribution requirements
  - No commercial restrictions for research

- **NFR-7.2: Responsible Disclosure Compliance**
  - 90-day disclosure window
  - Coordination with affected parties
  - Industry standard practices

- **NFR-7.3: Legal Review**
  - Legal counsel review before release
  - Ethical use guidelines
  - Disclaimer of liability

### Additional Requirements

**From Architecture:**

- **Browser Engine Integration:** Architecture specifies integration with existing PRNG modules (MWC1616, ARC4) - browser fingerprints must map to correct engine implementations
- **Database Integration:** Architecture includes fingerprint database loading and prioritization algorithms
- **Security Constraints:** Architecture mandates secure memory handling for private keys (GPU `__local` memory only, CPU immediate zeroize, no logging)
- **Testing Requirements:** Architecture requires 100% GPU/CPU parity tests for address derivation
- **Performance Targets:** Browser fingerprint lookups must be <1ms to avoid scanning bottleneck

**From PRD Implementation Guidance (Appendix A):**

- **File Structure:** New files required:
  - `src/scans/randstorm/fingerprints/database.rs` - Browser config database
  - `src/scans/randstorm/fingerprints/data/phase1_top100.csv` - Top 100 configs
  - `src/scans/randstorm/derivation.rs` - Address derivation module
  - `docs/SECURITY.md` - Responsible disclosure documentation
  - `docs/templates/disclosure-report.md` - Finding report template
  - `docs/templates/notification-email.txt` - Coordination templates

- **Dependencies:** All required crates already in Cargo.toml (bitcoin, secp256k1, bech32)

### FR Coverage Map

| FR # | Epic | Description |
|------|------|-------------|
| FR-2.1 | Epic 1 | Browser Configuration Schema |
| FR-2.2 | Epic 1 | Top 100 Browser Configurations (Phase 1) |
| FR-2.3 | Epic 1 | Extended 500 Configurations (Phase 2) |
| FR-2.4 | Epic 1 | Configuration Prioritization |
| FR-3.1 | Epic 2 | Pre-BIP32 Direct Derivation (Phase 1) |
| FR-3.2 | Epic 2 | BIP32 Simple Paths (Phase 2) |
| FR-3.3 | Epic 2 | BIP44 Standard Path (Phase 2) |
| FR-3.4 | Epic 2 | SegWit Paths (Phase 2) |
| FR-3.5 | Epic 2 | Extended Index Support (Phase 3) |
| FR-7.1 | Epic 3 | Disclosure Protocol (optional) |
| FR-7.2 | Epic 3 | Findings Report Format |
| FR-7.3 | Epic 3 | Private Key Export |
| FR-7.4 | Epic 3 | Ethical Use Guidelines |
| FR-7.5 | Epic 3 | Coordination Support |

**Coverage:** 14/14 sub-requirements mapped (100%)

## Epic List

### Epic 1: Browser Fingerprint Intelligence

Security researchers can target scans using browser fingerprint database, testing the most likely configurations first to maximize discovery efficiency.

**FRs Covered:** FR-2.1, FR-2.2, FR-2.3, FR-2.4

### Epic 2: Bitcoin Address Derivation Pipeline

Security researchers can derive Bitcoin addresses from recovered private keys, supporting Pre-BIP32 direct derivation and laying foundation for HD wallet paths.

**FRs Covered:** FR-3.1, FR-3.2, FR-3.3, FR-3.4, FR-3.5

### Epic 3: Secure Key Export & Research Framework

Security researchers can export discovered private keys securely with proper warnings, ethical guidelines, and optional disclosure protocols for coordinated research.

**FRs Covered:** FR-7.1, FR-7.2, FR-7.3, FR-7.4, FR-7.5
