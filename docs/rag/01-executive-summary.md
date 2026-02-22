# Executive Summary

**Version:** 1.0.0  
**Last Updated:** 2026-01-02  
**Document Type:** RAG - Executive Overview

## Project Identity

**Name**: Entropy Lab RS (Temporal Planetarium)  
**Type**: Cryptocurrency Security Research Tool  
**Language**: Rust (Edition 2021)  
**License**: Research/Educational Use  
**Status**: Active Development (v0.4.0)

## Mission Statement

Entropy Lab RS is a high-performance security research platform designed to identify, analyze, and demonstrate cryptocurrency wallet vulnerabilities arising from weak entropy generation. It serves security researchers, white-hat hackers, and blockchain security professionals in understanding and preventing critical wallet implementation flaws.

## Core Capabilities

### 1. Vulnerability Scanners
- **Trust Wallet** (CVE-2023-31290): MT19937 PRNG weakness
- **Cake Wallet** (2024): Entropy vulnerability  
- **Libbitcoin Milk Sad** (CVE-2023-39910): Deterministic RNG flaw
- **Android SecureRandom** (2013): Bitcoin wallet vulnerability
- **Profanity** (CVE-2022-40769): Vanity address weakness
- **Randstorm/BitcoinJS** (2011-2015): JavaScript PRNG weakness
- **Mobile Sensor**: Sensor-based entropy attacks
- **Brainwallet**: Weak passphrase analysis

### 2. GPU Acceleration
- **OpenCL**: Cross-platform GPU acceleration (10-100x speedup)
- **WGPU**: Modern graphics API (Metal/Vulkan/DX12)
- **Automatic Fallback**: CPU mode when GPU unavailable
- **Device-Aware Optimization**: Adapts to GPU architecture

### 3. Research Tools
- **PRNG Reconstruction**: Bit-perfect state recovery
- **Forensic Analysis**: Wallet state reconstruction
- **Cross-Validation**: Integration with CryptoDeepTools
- **Test Vector Generation**: Reproducible security testing

## Technology Stack

### Core Technologies
```
Language:       Rust 2021 (minimum 1.70)
Build System:   Cargo workspace (2 crates)
Architecture:   Modular library + CLI interface
GPU:            OpenCL 0.19, WGPU 22.1
Cryptography:   secp256k1, bitcoin 0.32, bip39
Parallelism:    Rayon, async/await
Database:       SQLite (rusqlite)
Testing:        Integration + unit tests
```

### Key Dependencies
- **bitcoin 0.32**: Core Bitcoin cryptography
- **secp256k1 0.29**: Elliptic curve operations
- **bip39 2.0**: Mnemonic seed phrases
- **ocl 0.19**: OpenCL GPU acceleration
- **clap 4.5**: CLI argument parsing
- **rayon 1.10**: CPU parallelization

## Architecture Highlights

### Workspace Structure
```
entropy-lab-rs/
├── crates/
│   ├── temporal-planetarium-lib/     # Core library (76 source files)
│   │   ├── src/scans/                # Vulnerability scanners
│   │   ├── src/utils/                # Utilities (RPC, bloom, crypto)
│   │   └── src/bin/                  # Helper binaries
│   └── temporal-planetarium-cli/     # CLI interface
├── cl/                               # OpenCL GPU kernels (51 files)
├── docs/                             # Comprehensive documentation
│   ├── rag/                         # AI model RAG system (this)
│   ├── research/                    # Vulnerability research
│   └── technical/                   # Technical guides
├── tests/                           # Integration tests
└── _bmad-output/                    # Project planning artifacts
```

### Design Patterns
1. **Module-Level Hardware Parity**: Separate CPU/GPU implementations
2. **Unified Shader Bridge**: Integer-only GPU kernels (no floats)
3. **Progressive Scanning Trait**: Real-time progress reporting
4. **Zero-Allocation Hot Paths**: Performance-critical code
5. **Dual-Execution Cross-Check**: GPU results verified by CPU

## Security Posture

### Critical Security Rules (Zero-Tolerance)
1. **Integer Isolation**: No floating-point in GPU shaders
2. **Dual-Execution Cross-Check**: GPU hits verified by CPU golden reference
3. **Bit-Perfect CI Lock**: 100% parity on test vectors required
4. **No Key Exposure**: Private keys never logged or stored plaintext
5. **Hardened Disclosure**: High-value targets use AES-encrypted fingerprints

### Ethical Guidelines
- ✅ Authorized security research and education
- ✅ White-hat testing with proper authorization
- ✅ Responsible vulnerability disclosure
- ❌ Unauthorized wallet access or fund theft
- ❌ Any illegal activities

## Performance Characteristics

### GPU Acceleration Benefits
- **10-100x speedup** for computationally intensive scanners
- **Automatic device optimization** for NVIDIA/AMD/Intel GPUs
- **Batch processing** for efficient memory usage
- **Bloom filters** for large-scale data filtering

### Optimization Techniques
- Pinned memory for fast CPU-GPU transfers
- Optimal work group sizing per device
- Aggressive compiler optimizations
- Memory access coalescing
- Full compute unit occupancy

## Project Maturity

### Current Status (as of 2025-12-25)
- **Phase 1 (MVP)**: Epics 1-5 complete
- **Phase 13 (Advanced)**: 67% complete (8/12 stories)
- **Overall Progress**: 19% (8/43 stories)
- **Test Coverage**: Tier 1-4 verification gates implemented

### Known Gaps
- Randstorm/BitcoinJS scanner incomplete (high priority)
- Multi-path derivation not fully implemented
- Extended address indices limited
- Electrum seed validation needed
- Some test vectors still failing

## Use Cases

### Primary Users
1. **Security Researchers**: Vulnerability analysis and disclosure
2. **White-Hat Hackers**: Authorized penetration testing
3. **Blockchain Security Teams**: Wallet implementation audits
4. **Academic Researchers**: Cryptographic entropy studies

### Common Workflows
1. **Vulnerability Scanning**: Identify weak wallets
2. **Forensic Recovery**: Reconstruct compromised wallets
3. **Cross-Validation**: Verify against known vulnerabilities
4. **Performance Benchmarking**: Compare GPU vs CPU
5. **Test Vector Generation**: Create reproducible tests

## Documentation Ecosystem

### Available Documentation
- **README.md**: Quick start and overview
- **SECURITY.md**: Security policy and disclosure
- **CONTRIBUTING.md**: Contribution guidelines
- **docs/rag/**: AI model RAG system (this directory)
- **docs/research/**: Vulnerability research papers
- **docs/technical/**: Implementation guides
- **_bmad-output/**: Project management artifacts

### For AI Assistance
This RAG system provides comprehensive context for:
- Code generation following project patterns
- Bug fixing with architectural awareness
- Feature implementation aligned with design
- Security-conscious code review
- Performance optimization guidance

## Getting Started

### Quick Build
```bash
# Clone and build
git clone https://github.com/5n10sndkts-eng/entropy-lab-rs
cd entropy-lab-rs
cargo build --release --all-features

# Run a scanner
cargo run --release -p temporal-planetarium-cli -- help
```

### Quick Test
```bash
# Run tests
cargo test

# Run specific scanner test
cargo test trust_wallet
```

### Development Setup
See [Development Guide](08-development-guide.md) for complete setup instructions.

## Key Metrics

### Codebase Statistics
- **134 Rust source files** total
- **76 source files** in core library
- **51 OpenCL kernel files**
- **32 documentation files**
- **Multiple test suites** (unit + integration)

### Performance
- **GPU Acceleration**: 10-100x faster than CPU
- **Parallel Processing**: Rayon for multi-core CPU
- **Bloom Filters**: Efficient large-scale filtering
- **Optimized Kernels**: Device-specific tuning

## Next Steps for AI Models

To effectively assist with this codebase:
1. Read [Architecture Overview](02-architecture-overview.md) for system design
2. Review [Codebase Structure](03-codebase-structure.md) for file organization
3. Study [Scanner Implementations](04-scanner-implementations.md) for patterns
4. Understand [Security Considerations](10-security-considerations.md) for safety
5. Reference [Cross-Reference Index](16-cross-reference-index.md) for lookups

## Contact and Resources

- **Repository**: https://github.com/5n10sndkts-eng/entropy-lab-rs
- **Issues**: GitHub Issues for bug reports and features
- **Security**: Follow SECURITY.md for vulnerability disclosure
- **Research**: milksad.info for vulnerability details

---

**Status**: ✅ Complete  
**Accuracy**: Reviewed 2026-01-02  
**Next Review**: On major architectural changes
