# Development Guide
# Temporal Planetarium - Developer Documentation

**Version:** 1.0  
**Date:** 2025-12-17  
**Audience:** Contributors, Developers, Security Researchers

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Development Environment](#development-environment)
3. [Code Organization](#code-organization)
4. [Development Workflow](#development-workflow)
5. [Adding a New Scanner](#adding-a-new-scanner)
6. [GPU Development](#gpu-development)
7. [Testing Guidelines](#testing-guidelines)
8. [Code Quality Standards](#code-quality-standards)
9. [Documentation Requirements](#documentation-requirements)
10. [Common Patterns](#common-patterns)
11. [Debugging](#debugging)
12. [Performance Optimization](#performance-optimization)

---

## Getting Started

### Prerequisites

**Required:**
- Rust 1.70 or later (2021 edition)
- Git
- Text editor or IDE (VS Code with rust-analyzer recommended)

**Optional (for GPU features):**
- OpenCL development libraries
  - **Ubuntu/Debian:** `sudo apt-get install ocl-icd-opencl-dev`
  - **macOS:** Built-in OpenCL support
  - **Windows:** Install GPU vendor SDK (CUDA Toolkit, AMD APP SDK, or Intel SDK)

**Optional (for RPC features):**
- Bitcoin Core node (for blockchain integration testing)

### Initial Setup

```bash
# Clone the repository
git clone <repository_url>
cd temporal-planetarium

# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Update Rust
rustup update

# Install useful development tools
cargo install cargo-watch    # Auto-rebuild on file changes
cargo install cargo-audit     # Security vulnerability scanning
cargo install cargo-outdated  # Check for outdated dependencies

# Build the project
cargo build

# Run tests
cargo test

# Check formatting
cargo fmt --check

# Run linter
cargo clippy -- -D warnings
```

### First Build

```bash
# Development build (faster compilation, slower runtime)
cargo build

# Release build (optimized)
cargo build --release

# Build with GPU support
cargo build --release --features gpu

# Build with GUI
cargo build --release --features gui

# Build everything
cargo build --release --all-features
```

### Quick Start - Run Your First Scanner

```bash
# See available scanners
cargo run --release -- --help

# Run brainwallet scanner (simplest example)
cargo run --release -- brainwallet --help

# Try a simple scan (example - adjust parameters)
cargo run --release -- brainwallet \
  --wordlist /path/to/wordlist.txt \
  --target-address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
```

---

## Development Environment

### Recommended IDE Setup

**Visual Studio Code:**
```json
// .vscode/extensions.json
{
  "recommendations": [
    "rust-lang.rust-analyzer",
    "tamasfe.even-better-toml",
    "serayuzgur.crates",
    "vadimcn.vscode-lldb"
  ]
}
```

```json
// .vscode/settings.json
{
  "rust-analyzer.checkOnSave.command": "clippy",
  "rust-analyzer.cargo.features": "all",
  "[rust]": {
    "editor.defaultFormatter": "rust-lang.rust-analyzer",
    "editor.formatOnSave": true
  }
}
```

**IntelliJ IDEA / CLion:**
- Install Rust plugin
- Enable "Run Clippy on save"
- Enable "Format on save"

### Environment Variables

Create a `.env` file in the project root:

```bash
# Bitcoin RPC (optional - for RPC-enabled scanners)
RPC_URL=http://localhost:8332
RPC_USER=your_rpc_username
RPC_PASS=your_rpc_password

# Rust logging (optional - if using tracing crate)
RUST_LOG=info

# OpenCL debugging (optional)
CL_DEBUG=1
```

**⚠️ Important:** Never commit `.env` to git. It's already in `.gitignore`.

---

## Code Organization

### Directory Structure

```
temporal-planetarium/
├── src/
│   ├── main.rs              # CLI entry point
│   ├── lib.rs               # Library exports
│   ├── gui.rs               # GUI (optional feature)
│   ├── electrum_mnemonic.rs # Electrum-specific logic
│   │
│   ├── scans/               # Scanner implementations
│   │   ├── mod.rs           # Scanner module exports
│   │   ├── android_securerandom.rs
│   │   ├── cake_wallet*.rs  # Multiple Cake Wallet variants
│   │   ├── trust_wallet*.rs # Multiple Trust Wallet variants
│   │   ├── milk_sad.rs
│   │   ├── profanity.rs
│   │   ├── brainwallet.rs
│   │   └── ...              # Other scanners
│   │
│   ├── utils/               # Utility modules
│   │   ├── mod.rs
│   │   ├── address.rs       # Address generation utilities
│   │   ├── encoding.rs      # Base58, Bech32 encoding
│   │   └── ...
│   │
│   └── bin/                 # Additional binaries
│       ├── benchmark_gpu.rs # GPU benchmarking
│       └── ...
│
├── cl/                      # OpenCL GPU kernels
│   ├── milk_sad_crack.cl
│   ├── trust_wallet_crack.cl
│   └── ...
│
├── tests/                   # Integration tests
│   ├── test_address_generation.rs
│   ├── test_cake_wallet.rs
│   └── ...
│
├── benches/                 # Performance benchmarks
│   └── gpu_optimization_benchmark.rs
│
├── scripts/                 # Utility scripts
├── docs/                    # Documentation (managed separately)
├── _bmad-output/            # BMAD-generated documentation
├── Cargo.toml               # Dependencies and metadata
└── README.md                # Primary documentation
```

### Module Responsibility

**`main.rs`:**
- CLI argument parsing (clap)
- Scanner dispatch
- Error handling and reporting
- Top-level orchestration

**`lib.rs`:**
- Public API exports
- Library interface
- Re-exports for external use

**`scans/`:**
- Each scanner is self-contained
- Scanner-specific logic only
- Use common utilities from `utils/`

**`utils/`:**
- Reusable utility functions
- Cryptographic helpers
- Address generation
- Encoding/decoding

**`bin/`:**
- Standalone executables
- Benchmarks
- Test utilities

---

## Development Workflow

### Feature Development Flow

```
1. Create feature branch
   git checkout -b feature/scanner-name

2. Implement feature
   - Write code
   - Add tests
   - Update documentation

3. Run quality checks
   cargo fmt
   cargo clippy -- -D warnings
   cargo test
   cargo build --release

4. Commit changes
   git add .
   git commit -m "Add scanner for XYZ vulnerability"

5. Push and create PR
   git push origin feature/scanner-name
```

### Daily Development Loop

```bash
# Use cargo-watch for automatic rebuilds
cargo watch -x check -x test -x "clippy -- -D warnings"

# Or manually:
cargo check        # Fast compilation check
cargo test         # Run tests
cargo clippy       # Linting
cargo build        # Full build
```

### Before Committing

**Checklist:**
- [ ] Code compiles: `cargo check`
- [ ] Tests pass: `cargo test`
- [ ] Formatted: `cargo fmt`
- [ ] No clippy warnings: `cargo clippy -- -D warnings`
- [ ] Documentation updated
- [ ] Sensitive data removed (no private keys, no credentials)

---

## Adding a New Scanner

### Step-by-Step Guide

#### 1. Create Scanner Module

Create `src/scans/new_vulnerability.rs`:

```rust
//! Scanner for XYZ vulnerability (CVE-YYYY-XXXXX)
//!
//! Description: Brief description of the vulnerability.
//! 
//! References:
//! - [Vulnerability Disclosure](https://example.com/disclosure)
//! - [CVE Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-YYYY-XXXXX)

use anyhow::{Context, Result};
use bitcoin::Address;
use secp256k1::Secp256k1;

/// Configuration options for the scanner
pub struct ScanOptions {
    pub target_address: String,
    pub gpu_enabled: bool,
    pub batch_size: usize,
}

/// Result of a successful scan
pub struct Finding {
    pub address: String,
    pub private_key: Option<String>, // Handle with care!
    pub derivation_info: String,
}

/// Main scanner function
///
/// # Arguments
/// * `options` - Scanner configuration
///
/// # Returns
/// * `Ok(Vec<Finding>)` - Found vulnerabilities
/// * `Err(_)` - Scanner error
///
/// # Example
/// ```
/// use entropy_lab_rs::scans::new_vulnerability::*;
///
/// let options = ScanOptions {
///     target_address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
///     gpu_enabled: false,
///     batch_size: 1000,
/// };
///
/// let findings = scan_new_vulnerability(&options)?;
/// ```
pub fn scan_new_vulnerability(options: &ScanOptions) -> Result<Vec<Finding>> {
    // 1. Validate inputs
    validate_address(&options.target_address)
        .context("Invalid target address")?;
    
    // 2. Initialize
    let secp = Secp256k1::new();
    let mut findings = Vec::new();
    
    // 3. Choose execution path
    if options.gpu_enabled {
        #[cfg(feature = "gpu")]
        {
            findings = scan_with_gpu(options, &secp)?;
        }
        #[cfg(not(feature = "gpu"))]
        {
            eprintln!("GPU feature not enabled, falling back to CPU");
            findings = scan_with_cpu(options, &secp)?;
        }
    } else {
        findings = scan_with_cpu(options, &secp)?;
    }
    
    Ok(findings)
}

/// CPU-based scanning implementation
fn scan_with_cpu(options: &ScanOptions, secp: &Secp256k1<secp256k1::All>) -> Result<Vec<Finding>> {
    use rayon::prelude::*;
    
    // Parallel CPU implementation using rayon
    let findings: Vec<Finding> = (0..options.batch_size)
        .into_par_iter()
        .filter_map(|i| {
            // Generate candidate
            // Check against target
            // Return Some(finding) if match
            None
        })
        .collect();
    
    Ok(findings)
}

/// GPU-based scanning implementation
#[cfg(feature = "gpu")]
fn scan_with_gpu(options: &ScanOptions, secp: &Secp256k1<secp256k1::All>) -> Result<Vec<Finding>> {
    use crate::scans::gpu_solver;
    
    // GPU implementation using OpenCL
    // See gpu_solver.rs for examples
    
    Ok(vec![])
}

/// Validate Bitcoin address format
fn validate_address(address: &str) -> Result<()> {
    // Validation logic
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_address_validation() {
        assert!(validate_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").is_ok());
        assert!(validate_address("invalid").is_err());
    }
    
    #[test]
    fn test_scanner_basic() {
        let options = ScanOptions {
            target_address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
            gpu_enabled: false,
            batch_size: 10,
        };
        
        let result = scan_new_vulnerability(&options);
        assert!(result.is_ok());
    }
}
```

#### 2. Export from Module Index

Edit `src/scans/mod.rs`:

```rust
pub mod new_vulnerability;
```

#### 3. Add CLI Subcommand

Edit `src/main.rs`:

```rust
use clap::{Parser, Subcommand};

#[derive(Subcommand)]
enum Commands {
    // ... existing commands ...
    
    /// Scan for XYZ vulnerability (CVE-YYYY-XXXXX)
    NewVulnerability {
        /// Target Bitcoin address
        #[arg(long)]
        target_address: String,
        
        /// Enable GPU acceleration
        #[arg(long, default_value = "false")]
        gpu: bool,
        
        /// Batch size for processing
        #[arg(long, default_value = "10000")]
        batch_size: usize,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        // ... existing command handlers ...
        
        Commands::NewVulnerability { target_address, gpu, batch_size } => {
            let options = scans::new_vulnerability::ScanOptions {
                target_address,
                gpu_enabled: gpu,
                batch_size,
            };
            
            let findings = scans::new_vulnerability::scan_new_vulnerability(&options)?;
            
            println!("Found {} potential matches", findings.len());
            for finding in findings {
                println!("  Address: {}", finding.address);
                // Never print private key to stdout!
            }
        }
    }
    
    Ok(())
}
```

#### 4. Create GPU Kernel (If Applicable)

Create `cl/new_vulnerability_crack.cl`:

```c
// OpenCL kernel for XYZ vulnerability scanner

__kernel void crack_kernel(
    __global const uint *search_space,
    __global const uchar *target_hash,
    __global uint *results,
    const uint batch_offset
) {
    int gid = get_global_id(0);
    uint candidate_index = batch_offset + gid;
    
    // 1. Generate candidate from index
    // 2. Perform cryptographic operations
    // 3. Compare against target
    // 4. Write match to results if found
}
```

#### 5. Write Integration Test

Create `tests/test_new_vulnerability.rs`:

```rust
use entropy_lab_rs::scans::new_vulnerability::*;

#[test]
fn test_new_vulnerability_scanner() {
    let options = ScanOptions {
        target_address: "test_address".to_string(),
        gpu_enabled: false,
        batch_size: 100,
    };
    
    let result = scan_new_vulnerability(&options);
    assert!(result.is_ok());
}

#[test]
fn test_known_vulnerable_case() {
    // Test against a known vulnerable example
    // (use test vectors from vulnerability disclosure)
}
```

#### 6. Update Documentation

- Add scanner to `README.md` scanner table
- Update `_bmad-output/index.md` scanner list
- Create scanner-specific documentation if complex
- Add references to CVE/disclosure

---

## GPU Development

### GPU Kernel Development

**Basic Kernel Structure:**

```c
// File: cl/scanner_name_crack.cl

// Helper functions (shared across kernels)
void sha256_hash(__private uchar *data, int len, __private uchar *hash) {
    // SHA256 implementation
}

void generate_address(__private const uchar *pubkey, __private char *address) {
    // Address generation
}

// Main kernel
__kernel void crack_kernel(
    __global const uint *search_space,    // Input: search space parameters
    __global const uchar *target_hash,    // Input: target to find
    __global uint *results,               // Output: found matches
    const uint batch_offset               // Offset for this batch
) {
    // Get thread ID
    int gid = get_global_id(0);
    uint index = batch_offset + gid;
    
    // Generate candidate
    uchar private_key[32];
    generate_private_key_from_index(index, private_key);
    
    // Derive public key
    uchar public_key[65];
    secp256k1_derive_pubkey(private_key, public_key);
    
    // Generate address
    char address[64];
    generate_address(public_key, address);
    
    // Hash address for comparison
    uchar address_hash[32];
    sha256_hash((uchar*)address, 34, address_hash);
    
    // Compare
    if (memcmp(address_hash, target_hash, 32) == 0) {
        // Found match - write to results
        int result_index = atomic_inc(&results[0]);
        if (result_index < MAX_RESULTS) {
            results[result_index + 1] = index;
        }
    }
}
```

### Testing GPU Kernels

```rust
#[cfg(all(test, feature = "gpu"))]
mod gpu_tests {
    use super::*;
    use ocl::{Context, Queue, Device, Platform};
    
    #[test]
    fn test_gpu_kernel_compilation() {
        let platform = Platform::default();
        let device = Device::first(platform).unwrap();
        let context = Context::builder()
            .platform(platform)
            .devices(device)
            .build()
            .unwrap();
        
        let kernel_source = include_str!("../../cl/new_vulnerability_crack.cl");
        
        let program = ocl::Program::builder()
            .src(kernel_source)
            .devices(device)
            .build(&context);
        
        assert!(program.is_ok());
    }
}
```

---

## Testing Guidelines

### Test Organization

**Unit Tests:**
- Located in same file as implementation
- Test individual functions
- Use `#[cfg(test)]` module

**Integration Tests:**
- Located in `tests/` directory
- Test end-to-end scanner functionality
- Test address generation correctness

**GPU Tests:**
- Use `#[cfg(all(test, feature = "gpu"))]`
- May fail in CI (no GPU available)
- Test kernel compilation and basic execution

### Writing Good Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    // Test data as constants
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const EXPECTED_ADDRESS: &str = "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA";
    
    #[test]
    fn test_mnemonic_to_address() {
        let address = generate_address_from_mnemonic(TEST_MNEMONIC).unwrap();
        assert_eq!(address, EXPECTED_ADDRESS);
    }
    
    #[test]
    fn test_invalid_input() {
        let result = generate_address_from_mnemonic("invalid mnemonic");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_derivation_path_bip44() {
        // Test BIP44 derivation
    }
    
    #[test]
    fn test_derivation_path_bip49() {
        // Test BIP49 derivation
    }
}
```

### Running Tests

```bash
# All tests
cargo test

# Specific test
cargo test test_mnemonic_to_address

# With output
cargo test -- --nocapture

# Integration tests only
cargo test --test '*'

# Exclude GPU tests (if no GPU available)
cargo test --lib

# Run with all features
cargo test --all-features
```

---

## Code Quality Standards

### Formatting

```bash
# Check formatting
cargo fmt --check

# Auto-format
cargo fmt
```

### Linting

```bash
# Run clippy (local - strict)
cargo clippy -- -D warnings

# Run clippy (CI - warnings only)
cargo clippy -- -W clippy::all
```

**Common Clippy Fixes:**

```rust
// ❌ Don't use unwrap in production code
let value = risky_operation().unwrap();

// ✅ Use ? operator or expect with context
let value = risky_operation()
    .context("Failed to perform operation")?;

// ❌ Unnecessary clone
let s = string.clone();

// ✅ Use reference when possible
let s = &string;

// ❌ Large types passed by value
fn process(data: LargeStruct) { }

// ✅ Pass by reference
fn process(data: &LargeStruct) { }
```

### Error Handling

```rust
use anyhow::{Context, Result};

// ✅ Good error handling
pub fn scan_addresses(file_path: &str) -> Result<Vec<Address>> {
    let contents = std::fs::read_to_string(file_path)
        .context(format!("Failed to read file: {}", file_path))?;
    
    let addresses = parse_addresses(&contents)
        .context("Failed to parse addresses")?;
    
    Ok(addresses)
}
```

---

## Documentation Requirements

### Code Documentation

```rust
/// Brief one-line description
///
/// More detailed explanation of the function's purpose,
/// behavior, and any important considerations.
///
/// # Arguments
/// * `param1` - Description of param1
/// * `param2` - Description of param2
///
/// # Returns
/// * `Ok(T)` - Success description
/// * `Err(E)` - Error description
///
/// # Example
/// ```
/// use entropy_lab_rs::scans::scanner;
///
/// let result = scanner::scan("target")?;
/// ```
///
/// # Security
/// ⚠️ This function handles private keys. Never log or store the result.
pub fn sensitive_function(param1: &str, param2: usize) -> Result<SecretData> {
    // Implementation
}
```

### README Updates

When adding a scanner, update:
1. Scanner table with CVE/status/GPU support
2. Usage examples
3. Roadmap if applicable
4. Acknowledgments section

---

## Common Patterns

### Pattern: CPU with Rayon Parallelization

```rust
use rayon::prelude::*;

pub fn parallel_scan(candidates: &[Candidate]) -> Vec<Finding> {
    candidates
        .par_chunks(BATCH_SIZE)
        .flat_map(|batch| {
            batch.iter()
                .filter_map(|candidate| check_candidate(candidate))
                .collect::<Vec<_>>()
        })
        .collect()
}
```

### Pattern: GPU with CPU Fallback

```rust
#[cfg(feature = "gpu")]
use crate::scans::gpu_solver;

pub fn scan_with_optional_gpu(options: &ScanOptions) -> Result<Vec<Finding>> {
    if options.gpu_enabled {
        #[cfg(feature = "gpu")]
        {
            match gpu_solver::solve_with_gpu(options) {
                Ok(findings) => return Ok(findings),
                Err(e) => {
                    eprintln!("GPU failed: {}, falling back to CPU", e);
                }
            }
        }
    }
    
    // CPU fallback
    scan_with_cpu(options)
}
```

### Pattern: Progress Reporting

```rust
pub fn scan_with_progress(total: usize) -> Result<Vec<Finding>> {
    let progress = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    
    let findings: Vec<Finding> = (0..total)
        .into_par_iter()
        .filter_map(|i| {
            let count = progress.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if count % 10000 == 0 {
                println!("Progress: {}/{}", count, total);
            }
            check_index(i)
        })
        .collect();
    
    Ok(findings)
}
```

---

## Debugging

### Logging

```rust
// TODO: Migrate to tracing crate
// For now, use println! with prefixes

println!("[INFO] Starting scan...");
println!("[DEBUG] Candidate: {}", candidate);
println!("[WARN] GPU unavailable, using CPU");
println!("[ERROR] Failed to generate address: {}", err);
```

### GPU Debugging

```bash
# Enable OpenCL debugging
export CL_DEBUG=1

# Check available devices
cargo run --release --features gpu -- --list-devices

# Use smaller batch sizes for debugging
cargo run --release --features gpu -- scanner-name --batch-size 100
```

### Common Issues

**Issue: GPU not detected**
```bash
# Check OpenCL installation
clinfo  # Linux
# Or check vendor control panel

# Ensure gpu feature enabled
cargo build --features gpu
```

**Issue: Tests failing**
```bash
# Run with backtrace
RUST_BACKTRACE=1 cargo test

# Run specific test with output
cargo test test_name -- --nocapture --exact
```

---

## Performance Optimization

### Profiling

```bash
# CPU profiling with perf (Linux)
cargo build --release
perf record --call-graph=dwarf ./target/release/entropy-lab-rs scanner-name
perf report

# GPU profiling
# Use vendor tools: NVIDIA Nsight, AMD Radeon GPU Profiler
```

### Benchmarking

```bash
# Run benchmarks
cargo bench

# GPU-specific benchmarks
cargo run --release --bin benchmark_gpu --features gpu
```

### Optimization Tips

1. **Use `--release` for testing performance**
2. **Profile before optimizing** (don't guess)
3. **Batch operations** to reduce overhead
4. **Use parallel processing** (rayon for CPU, OpenCL for GPU)
5. **Minimize allocations** in hot loops
6. **Use efficient data structures** (e.g., bloom filters for set membership)

---

**Version:** 1.0  
**Last Updated:** 2025-12-17  
**For Questions:** Open an issue on GitHub
