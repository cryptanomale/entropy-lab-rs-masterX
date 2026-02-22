# Project Documentation Index
# Temporal Planetarium (entropy-lab-rs)

**Last Updated:** 2025-12-23  
**Status:** Phase 10 Complete (CryptoDeepTools Integration)  
**Architecture:** Modular Rust Workspace  

---

## 🏗️ Project Structure

The project is organized into two primary crates:

- **[temporal-planetarium-lib](./crates/temporal-planetarium-lib/src/lib.rs)**: The core security research library.
- **[temporal-planetarium-cli](./crates/temporal-planetarium-cli/src/main.rs)**: The command-line interface.

---

## 📚 Key Documentation

### Project Foundation
- **[Project Context](./project-context.md)**: Executive summary and architecture overview.
- **[Development Guide](./_bmad-output/development-guide.md)**: Setup and contribution instructions.
- **[Architecture (Core Library)](./_bmad-output/architecture.md)**: Detailed breakdown of research logic and GPU usage.

### Research and Vulnerabilities
- **[Randstorm Research](./docs/randstorm-research.md)**: Analysis of the BitcoinJS/Randstorm vulnerability.
- **[Milk Sad Research](./_bmad-output/analysis/research/technical-randstorm-integration-2025-12-17.md)**: Deep dive into Libbitcoin entropy flaws.
- **[Gap Analysis](./_bmad-output/analysis/research/technical-randstorm-coverage-gap-research-2025-12-22.md)**: Comparison of coverage across research tools.

### Verification and Benchmarks
- **[Walkthrough (Current State)](./_bmad-output/walkthrough.md)**: Proof of work and verification results.
- **[Performance Benchmarks](./_bmad-output/project-scan-report.json)**: Results of the `cryptodeeptools_comp` benchmark.

---

## 🛠️ Tooling Integration

- **[Shared Test Vectors](./tests/fixtures/shared_test_vectors.json)**: Standardized test cases for cross-tool validation.
- **[CryptoDeepTools Integration](./_bmad-output/analysis/research/technical-cryptodeeptools-research-2025-12-17.md)**: Parity and validation strategy.

---

## 🚀 Getting Started

To build and run the latest version:

```bash
cargo build --release --all-features
cargo run --release -p temporal-planetarium-cli -- randstorm-scan --help
```

_For detailed information on a specific scanner, refer to its module in the library crate._
