# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Temporal Planetarium** (formerly Entropy Lab RS) is a high-performance cryptocurrency security research tool for identifying wallet vulnerabilities caused by weak entropy generation. This is a **modular Rust workspace** with a core library and CLI interface.

**Purpose**: Security research, vulnerability assessment, cross-validation with third-party tools (CryptoDeepTools), and performance testing using GPU acceleration.

**Target Users**: Security researchers, white-hat hackers, blockchain security professionals.

## Build and Test Commands

### Building

```bash
# Build entire workspace (development)
cargo build

# Build optimized release
cargo build --release

# Build with GPU acceleration (OpenCL)
cargo build --release --features gpu

# Build with WebGPU support (for WGSL shaders)
cargo build --release --features wgpu

# Build with all features
cargo build --release --features "gpu,wgpu,gui,z3-solver"

# Build specific crate
cargo build -p temporal-planetarium-lib --release
cargo build -p temporal-planetarium-cli --release
```

### Testing

```bash
# Run all tests
cargo test

# Run tests with specific features
cargo test --features gpu
cargo test --features wgpu
cargo test -p temporal-planetarium-lib --features wgpu test_wgpu_hashing_parity -- --nocapture

# Run single test with output
cargo test test_name -- --nocapture

# Run integration tests from workspace root
cargo test --test test_forensics_vectors
cargo test --test randstorm_cli_integration

# Run GPU parity tests
cargo test --test test_gpu_cpu_parity --features gpu -- --nocapture
```

### Benchmarking

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench --bench randstorm_streaming
cargo bench --bench cryptodeeptools_comp
cargo bench --bench gpu_optimization_benchmark --features gpu
```

### Code Quality

```bash
# Check compilation
cargo check

# Run clippy (linting)
cargo clippy -- -D warnings

# Format code
cargo fmt
```

## Architecture

### Workspace Structure

```
temporal-planetarium/
├── crates/
│   ├── temporal-planetarium-lib/    # Core library - all scanner logic
│   │   ├── src/
│   │   │   ├── scans/              # 19+ vulnerability scanners
│   │   │   │   ├── randstorm/      # BitcoinJS/Randstorm (2011-2015)
│   │   │   │   │   ├── prng/       # PRNG implementations (V8, JavaUtil, Safari)
│   │   │   │   │   ├── fingerprints/ # Browser fingerprinting database
│   │   │   │   │   ├── gpu_integration.rs  # OpenCL integration
│   │   │   │   │   ├── wgpu_integration.rs # WebGPU/WGSL integration
│   │   │   │   │   └── randstorm.wgsl      # GPU shader (WebGPU)
│   │   │   │   ├── milk_sad.rs
│   │   │   │   ├── trust_wallet*.rs
│   │   │   │   ├── cake_wallet*.rs
│   │   │   │   └── [16 more scanners]
│   │   │   └── utils/              # Shared cryptographic utilities
│   │   └── benches/                # Performance benchmarks
│   └── temporal-planetarium-cli/    # Command-line interface
├── cl/                              # OpenCL GPU kernels (46 files)
├── tests/                           # Integration test suite
└── Cargo.toml                       # Workspace configuration
```

### Key Modules

**`scans/randstorm/`** - Critical vulnerability affecting 1.4M+ BTC (2011-2015)
- Multiple PRNG engines: V8 MWC1616, JavaUtil LCG, Safari/Windows CRT
- Browser fingerprinting for timestamp recovery
- Dual GPU backends: OpenCL (`gpu_integration.rs`) and WebGPU (`wgpu_integration.rs`)
- WGSL shader: `randstorm.wgsl` (WebGPU Shading Language)

**`scans/milk_sad.rs`** - Libbitcoin vulnerability (CVE-2023-39910)
- Multi-path derivation support (BIP44/49/84)
- GPU-accelerated scanning

**GPU Architecture**:
- **OpenCL**: 46 kernels in `cl/` directory, feature flag `gpu`
- **WebGPU**: WGSL shaders (e.g., `randstorm.wgsl`), feature flag `wgpu`
- Device-aware work group sizing, pinned memory, aggressive optimizations

## Critical Technical Details

### WGSL/Naga Compiler Limitations

When working with WGSL shaders (`*.wgsl` files):

**Problem**: WGSL/Naga does NOT support non-constant array indexing in loops.

```wgsl
// ❌ FAILS - Non-constant array indexing
for (var i = 0u; i < 64u; i++) {
    let val = K[i];  // ERROR: 'i' is not constant
}

// ✅ WORKS - Manually unrolled
let val0 = K[0];
let val1 = K[1];
// ... (repeat 64 times)
```

**Solution**: Manually unroll ALL loops that use variable array indexing. This applies to:
- SHA256 transform rounds
- Message expansion (m[16..63])
- Any loop accessing arrays with loop variables

**Files Affected**:
- `crates/temporal-planetarium-lib/src/scans/randstorm/randstorm.wgsl`
- Any future WGSL shader implementations

### Feature Flags

- `gpu` - OpenCL acceleration (requires OpenCL drivers)
- `wgpu` - WebGPU/WGSL support (cross-platform GPU)
- `gui` - GUI interface via egui/eframe
- `z3-solver` - Z3 theorem prover for PRNG state recovery

### Test Organization

Integration tests live in workspace root `tests/` but are declared in library `Cargo.toml`:

```toml
[[test]]
name = "randstorm_cli_integration"
path = "../../tests/randstorm_cli_integration.rs"
```

This allows tests to access internal library APIs while living at workspace level.

## Security and Ethics

**White-Hat Research Only**:
- ✅ Authorized security testing
- ✅ Vulnerability research and disclosure
- ✅ Educational purposes
- ❌ Unauthorized wallet access
- ❌ Theft or fund transfers
- ❌ Any illegal activities

**Critical Rules**:
1. Never commit RPC credentials (use environment variables)
2. Never log or export private keys
3. Validate all external inputs (RPC responses, CSV data)
4. Use constant-time operations for cryptographic comparisons
5. Follow responsible disclosure practices

**Environment Variables**:
```bash
RPC_URL=http://127.0.0.1:8332
RPC_USER=your_username
RPC_PASS=your_password
```

## Common Development Tasks

### Adding a New Vulnerability Scanner

1. Create file in `crates/temporal-planetarium-lib/src/scans/new_scanner.rs`
2. Implement scanner logic with `anyhow::Result` error handling
3. Export from `crates/temporal-planetarium-lib/src/scans/mod.rs`
4. Add CLI subcommand in `crates/temporal-planetarium-cli/src/main.rs`
5. Add integration test in `tests/test_new_scanner.rs`
6. Document the CVE/vulnerability reference
7. (Optional) Implement GPU kernel in `cl/new_scanner.cl`

### GPU Kernel Development

**OpenCL** (`cl/*.cl`):
- Use pinned memory for transfers (`CL_MEM_ALLOC_HOST_PTR`)
- Calculate optimal work group sizes based on device
- See `OPENCL_OPTIMIZATIONS.md` for detailed guidance

**WGSL** (`*.wgsl`):
- **CRITICAL**: Manually unroll all loops with variable array indexing
- Use `wgpu` feature flag
- Test with `cargo test --features wgpu test_wgpu_hashing_parity`

### Debugging GPU Code

**OpenCL**:
```bash
# Build and run with verbose GPU output
RUST_LOG=debug cargo run --release --features gpu -- randstorm-scan
```

**WGSL**:
```bash
# Run parity tests with output
cargo test -p temporal-planetarium-lib --features wgpu test_wgpu_hashing_parity -- --nocapture
```

## Reference Documentation

- `README.md` - User guide, installation, usage examples
- `project-context.md` - Executive summary and architecture
- `.github/copilot-instructions.md` - Coding standards and patterns
- `OPENCL_OPTIMIZATIONS.md` - GPU performance optimization guide
- `MILKSAD_GAP_ANALYSIS.md` - Vulnerability coverage analysis
- `RESEARCH_UPDATE_13.md` - Milk Sad research update details

## Important Notes

1. **Workspace Organization**: This is a Rust workspace with two crates (`lib` and `cli`). Always specify `-p` flag when building specific crates.

2. **GPU Tests in CI**: OpenCL tests may fail in CI environments without GPU drivers. Tests use `continue-on-error: true` for GPU features.

3. **Cross-Validation**: Benchmarks compare against CryptoDeepTools for correctness verification (`benches/cryptodeeptools_comp.rs`).

4. **Scanner Patterns**: All scanners follow a similar pattern: entropy generation → key derivation → address generation → balance check (optional RPC).

5. **Multi-Path Support**: Recent scanners support BIP44/49/84 derivation paths simultaneously for comprehensive coverage.
