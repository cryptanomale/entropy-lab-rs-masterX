# GitHub Copilot Instructions for Entropy Lab RS

## Repository Overview

Entropy Lab RS is a Rust-based security research tool designed to identify and analyze cryptocurrency wallet vulnerabilities related to weak entropy generation. This tool is intended for security researchers, white-hat hackers, and blockchain security professionals.

## Working with GitHub Copilot Coding Agent

This repository is configured to work with GitHub Copilot coding agent. When creating issues or providing feedback:

### Good Tasks for Copilot
- ✅ Bug fixes with clear reproduction steps
- ✅ Adding new scanner implementations following existing patterns
- ✅ Writing or expanding unit/integration tests
- ✅ Documentation updates (code comments, README, guides)
- ✅ Refactoring code to improve clarity or performance
- ✅ Adding new CLI commands or options
- ✅ Implementing new GPU kernels based on specifications

### Tasks Requiring Human Expertise
- ❌ Major architectural changes or redesigns
- ❌ Security vulnerability fixes in cryptographic code (requires expert review)
- ❌ Changes to core wallet derivation logic (high risk of fund loss)
- ❌ Decisions about new vulnerability research directions
- ❌ Complex multi-repository coordination

### Creating Issues for Copilot
When writing issues, be specific and include:
- **Clear description** of what needs to be done
- **Acceptance criteria** (e.g., "must pass all existing tests")
- **Files/modules** that likely need changes
- **Example code** or test cases where helpful
- **Security implications** if applicable

### Providing Feedback on Copilot PRs
- Review PRs as you would a teammate's work
- Use `@copilot` in comments to request changes or clarification
- Run tests and linters before approving
- For security-sensitive changes, request human expert review

## Project Structure

This is a **Rust workspace** with two main crates:

```
entropy-lab-rs/
├── crates/
│   ├── temporal-planetarium-lib/     # Core library
│   │   ├── src/
│   │   │   ├── lib.rs                # Library exports
│   │   │   ├── scans/                # Scanner implementations
│   │   │   │   ├── cake_wallet/      # Cake Wallet vulnerability scanners
│   │   │   │   ├── trust_wallet/     # Trust Wallet MT19937 scanners
│   │   │   │   ├── randstorm/        # Browser PRNG vulnerabilities
│   │   │   │   ├── android_securerandom/
│   │   │   │   ├── nonce_reuse/      # ECDSA nonce reuse detection
│   │   │   │   ├── passphrase_recovery.rs
│   │   │   │   └── gpu_solver.rs     # GPU acceleration utilities
│   │   │   └── utils/                # Utilities (RPC, bloom filters, DB)
│   │   ├── benches/                  # Performance benchmarks
│   │   └── tests/                    # Unit tests
│   └── temporal-planetarium-cli/     # CLI application
│       └── src/
│           └── main.rs               # CLI interface with clap
├── cl/                               # OpenCL kernel files (.cl)
├── tests/                            # Workspace-level integration tests
├── docs/                             # Documentation and research
│   ├── technical/                    # Technical guides (GPU, GUI)
│   ├── research/                     # Research findings and audits
│   └── issues/                       # Known issues and tracking
└── .github/workflows/                # CI/CD pipelines
```

## Technology Stack

- **Language**: Rust (edition 2021, minimum version 1.70)
- **Architecture**: Cargo workspace with library + CLI separation
- **GPU Acceleration**: 
  - OpenCL (via `ocl` crate) - Legacy, optional feature `gpu`
  - WGPU (Metal/Vulkan/DX12) - Modern, optional feature `wgpu`
- **CLI Framework**: clap v4.5 with derive macros
- **Cryptography**: secp256k1, bitcoin, bip39, sha2/sha3, hmac, pbkdf2, ripemd
- **RPC Integration**: bitcoincore-rpc for blockchain interactions
- **Performance**: Rayon for parallel processing, bloom filters for optimization
- **Database**: rusqlite for target tracking, optional PostgreSQL support
- **Solver**: Z3 for formal PRNG state recovery (optional feature `z3-solver`)
- **GUI**: eframe/egui for graphical interface (optional feature `gui`)
- **GPU Memory**: bytemuck for zero-copy GPU memory mapping

## Code Style and Quality

### Formatting
- Use `cargo fmt` for all Rust code (enforced in CI)
- Follow standard Rust naming conventions (snake_case for functions/variables, CamelCase for types)

### Linting
- Run `cargo clippy --all-targets --all-features -- -D warnings` before committing
- CI enforces clippy warnings as errors
- Prefer using `Result` and `?` operator over `unwrap()`/`expect()`

### Error Handling
- Use `anyhow::Result` for error propagation
- Provide descriptive error messages
- Avoid panics in production code paths
- Use `expect()` only for internal consistency checks with clear messages

### Comments
- Add doc comments (`///`) for all public APIs
- Document security implications of sensitive operations
- Explain complex cryptographic or mathematical operations
- Include examples in doc comments where helpful

### Module Organization
- **Hardware Parity**: Use module-level separation for CPU vs GPU backends
  - Pattern: `cpu::module_name` for CPU reference, `gpu::module_name` for GPU optimized
  - Example: See `crates/temporal-planetarium-lib/src/scans/randstorm/` structure
- **Kernel Files**: All OpenCL kernel files (`.cl`) must be in the root `cl/` directory
- **Memory Layout**: Use `#[repr(C)]` with `bytemuck` for GPU-shared structs

## Security Best Practices

### Critical Security Rules (Zero-Tolerance)
1. **Never commit credentials**: Use environment variables or `.env` files (gitignored)
2. **Never log or store private keys**: Handle sensitive data in memory only. Private keys MUST NEVER be logged or exported to plain text
3. **Validate all external inputs**: Especially user-provided data and RPC responses
4. **Use constant-time operations**: For cryptographic comparisons
5. **Follow responsible disclosure**: This is a research tool for authorized testing only
6. **Integer-only GPU kernels**: Floating-point math is STRICTLY PROHIBITED in OpenCL/WGPU kernels to prevent driver-specific rounding divergence
7. **Dual-execution verification**: Every GPU "hit" MUST be verified by CPU golden reference before reporting
8. **No key exposure**: Vulnerability fingerprints for high-value targets are stored as AES-encrypted blobs with remote key management

### GPU Kernel Requirements
**CRITICAL**: All PRNG logic in GPU kernels must use:
- Fixed-point bitwise integers only (`u32`, `u64`)
- Explicit wrapping arithmetic
- NO floating-point operations (`float`, `double`) - this causes non-deterministic results across GPU drivers

### Environment Variables
The project uses these environment variables for sensitive configuration:
- `RPC_URL`: Bitcoin RPC endpoint
- `RPC_USER`: Bitcoin RPC username
- `RPC_PASS`: Bitcoin RPC password

Always use `clap`'s `env` attribute for environment variable support in CLI arguments.

### Credential Handling
```rust
// Good: Using environment variables with clap
#[arg(long, env = "RPC_USER")]
rpc_user: String,

// Bad: Hardcoded credentials
let user = "hardcoded_username"; // NEVER DO THIS
```

## Building and Testing

### Build Commands
```bash
# Check compilation (workspace)
cargo check --workspace

# Build for development
cargo build --workspace

# Build with specific features
cargo build -p temporal-planetarium-lib --features gpu
cargo build -p temporal-planetarium-lib --features wgpu
cargo build -p temporal-planetarium-lib --features gui
cargo build -p temporal-planetarium-cli --features gpu,gui

# Build optimized release
cargo build --workspace --release
```

### Feature Flags
- `gpu`: OpenCL GPU acceleration (legacy)
- `wgpu`: WGPU GPU acceleration (Metal/Vulkan/DX12, recommended for macOS)
- `gui`: Graphical user interface with eframe/egui
- `z3-solver`: Z3 SMT solver for PRNG state recovery
- `postgres`: PostgreSQL database support (requires tokio runtime)

### Testing
```bash
# Run all tests in workspace
cargo test --workspace

# Run tests for specific crate
cargo test -p temporal-planetarium-lib
cargo test -p temporal-planetarium-cli

# Run specific test
cargo test test_name

# Run with output
cargo test -- --nocapture

# Run with nextest (used in CI)
cargo nextest run --workspace
```

**Note**: GPU tests may fail in CI environments without OpenCL/WGPU support. The CI uses `continue-on-error: true` for GPU-dependent tests.

### GPU Dependencies
- **WGPU** (recommended for macOS): Uses native Metal, Vulkan, or DX12
- **OpenCL** (legacy): Requires OpenCL drivers
  - Ubuntu/Debian: `sudo apt-get install ocl-icd-opencl-dev`
  - Tests may be skipped if GPU runtime is unavailable
- Consider using feature flags to make GPU support optional for broader compatibility

## Common Patterns

### Scanner Implementation
When adding new vulnerability scanners in `crates/temporal-planetarium-lib/src/scans/`:
1. Create a new module directory (e.g., `new_vulnerability/`)
2. Implement the scanner logic with proper error handling
3. Use the `Scanner` trait pattern with `UnboundedSender<ScanProgress>` for progress reporting
4. Implement CPU reference implementation first (in `cpu::` module if GPU variant planned)
5. Add GPU-optimized version in `gpu::` module if needed
6. Place OpenCL kernel files in the root `cl/` directory
7. Add CLI subcommand in `crates/temporal-planetarium-cli/src/main.rs`
8. Export from scanner module's `mod.rs`
9. Add integration tests in workspace `tests/` directory
10. Document the vulnerability being scanned with CVE references
11. Ensure bit-perfect parity between CPU and GPU implementations

### GPU Optimization
- **Unified Shader Bridge**: Use only fixed-point bitwise integers in kernels
- **Memory Management**: Use pinned memory (`bytemuck`) for CPU-GPU transfers
- **Work Group Sizing**: Calculate optimal sizes based on device capabilities
- **Device-Aware Batching**: Implement batch sizing based on GPU memory
- **Dual Verification**: Always verify GPU results with CPU golden reference
- **Zero-Allocation Hot Loops**: Minimize allocations in scanning loops
- See `docs/technical/GPU_OPTIMIZATION_GUIDE.md` and `docs/technical/OPENCL_OPTIMIZATIONS.md` for detailed guidance

### CLI Design
- Use clap's derive macros for argument parsing
- Provide sensible defaults where possible
- Support both CLI args and environment variables for configuration
- Include helpful descriptions and examples in `--help` output
- Implement progress bars with `indicatif` for long-running operations

### Progressive Scanning Pattern
Implement the `Scanner` trait:
```rust
pub trait Scanner {
    fn scan(&self, progress_tx: UnboundedSender<ScanProgress>) -> anyhow::Result<ScanResults>;
}
```
This enables real-time ETA and progress reporting to CLI/GUI.

## CI/CD Pipeline

The project uses GitHub Actions with these checks:
- **Lint & Check**: Fast formatting and clippy checks
  - `cargo fmt --all -- --check` (must pass)
  - `cargo clippy --all-targets --all-features -- -D warnings` (must pass)
  - Security audit with `cargo audit`
- **Test**: Parallel test shards (4-way partitioning with cargo-nextest)
  - OpenCL setup for GPU tests
  - Partition-based test execution for speed
- **Burn-In**: Flaky test detection (weekly or with `[burn-in]` in commit message)
  - Runs tests 10 times to catch intermittent failures
- **GPU Check**: Build verification with GPU features
  - Tests with pocl-opencl-icd software implementation
- **Mathematical Parity**: Cross-platform validation
  - Generates 10,000 test vectors
  - Validates Rust implementation against Python reference

All PRs must pass the CI pipeline before merging. GPU-specific tests use `continue-on-error` where hardware is unavailable.

## Documentation Standards

### Code Documentation
- Document all public functions, structs, and enums
- Include usage examples in module-level documentation
- Document security implications and edge cases
- Reference relevant CVEs or security advisories
- Explain cryptographic algorithms and mathematical operations
- Document GPU kernel behavior and memory requirements

### Project Documentation
- Update `README.md` when adding features or scanners
- Maintain `SECURITY.md` for security-related changes
- Follow `CONTRIBUTING.md` guidelines
- Document configuration options and environment variables
- Update `project-context.md` for architectural changes
- Add technical documentation in `docs/technical/` for complex implementations
- Document research findings in `docs/research/`

### Required Documentation for New Scanners
1. Scanner purpose and vulnerability description
2. CVE references or security advisories
3. Expected entropy space size
4. Derivation paths used
5. Performance characteristics (CPU vs GPU)
6. Example usage in CLI
7. Known limitations or edge cases

## Performance Considerations

- Use `--release` flag for performance testing
- Profile with `cargo bench` or `perf` for optimization
- Consider GPU acceleration (WGPU or OpenCL) for computationally intensive operations
- Use Rayon for CPU parallelization where appropriate
- Implement bloom filters for large-scale data filtering
- Use `bytemuck` for zero-copy GPU memory transfers
- Minimize allocations in hot loops (scanning operations)
- Prefer WGPU over OpenCL on macOS for native Metal performance

### Benchmarking
The library includes comprehensive benchmarks in `crates/temporal-planetarium-lib/benches/`:
- `gpu_optimization_benchmark.rs` - GPU vs CPU performance comparison
- `trust_wallet_benchmark.rs` - Trust Wallet scanner performance
- `brainwallet_benchmark.rs` - Brainwallet attack performance
- `wgpu_metal_benchmark.rs` - WGPU backend performance
- Run with: `cargo bench -p temporal-planetarium-lib`

## Ethical Guidelines

This tool is for **authorized security research only**:
- ✅ Security research and education
- ✅ White-hat testing with proper authorization
- ✅ Responsible vulnerability disclosure
- ❌ Unauthorized wallet access
- ❌ Theft or unauthorized fund transfers
- ❌ Any illegal activities

Always follow local laws and responsible disclosure practices.

## When Contributing

1. Check existing issues and PRs to avoid duplicate work
2. Create a feature branch from `main` or `develop`
3. Write tests for new functionality (unit tests in library, integration in `tests/`)
4. Implement CPU reference implementation first, then GPU optimization
5. Ensure GPU and CPU implementations have bit-perfect parity
6. Run full test suite and linters locally:
   ```bash
   cargo fmt --all
   cargo clippy --all-targets --all-features -- -D warnings
   cargo test --workspace
   ```
7. Update documentation as needed
8. Reference related issues in PR description
9. Be prepared to address code review feedback

### Workspace Development Tips
- The library crate (`temporal-planetarium-lib`) contains all core logic
- The CLI crate (`temporal-planetarium-cli`) is a thin wrapper around the library
- Integration tests in `tests/` are shared across the workspace
- Use `cargo test -p <crate-name>` to test specific crates
- Feature flags are defined in library; CLI re-exports them

## Useful Resources

- <a href="https://doc.rust-lang.org/book/">Rust Book</a>
- <a href="https://rust-lang.github.io/api-guidelines/">Rust API Guidelines</a>
- <a href="https://docs.rs/secp256k1/">secp256k1 Documentation</a>
- <a href="https://developer.bitcoin.org/reference/">Bitcoin Developer Reference</a>
- <a href="https://www.khronos.org/opencl/">OpenCL Programming Guide</a>
- <a href="https://wgpu.rs/">WGPU Documentation</a>
- Project-specific documentation in `docs/`:
  - `docs/technical/GPU_OPTIMIZATION_GUIDE.md` - GPU performance optimization
  - `docs/technical/OPENCL_OPTIMIZATIONS.md` - OpenCL-specific optimizations
  - `docs/technical/GUI_GUIDE.md` - GUI development guide
  - `docs/research/` - Research findings and audits
  - `project-context.md` - Current project architecture and status

## Questions or Issues?

- Check existing documentation in the repository:
  - `README.md` - General overview and usage
  - `CONTRIBUTING.md` - Contribution guidelines
  - `SECURITY.md` - Security policies and best practices
  - `project-context.md` - Current architecture and roadmap
  - `docs/` - Technical guides and research findings
- Review security audit reports (files matching `docs/*AUDIT*.md`)
- Check known issues in `docs/issues/`
- Open an issue with the appropriate label
- Follow the issue template if provided

## Important Files for Contributors

Before making changes, review these key files:
- `project-context.md` - Project architecture, status, and critical implementation rules
- `.github/copilot-instructions.md` - This file (coding guidelines)
- `docs/technical/GPU_OPTIMIZATION_GUIDE.md` - GPU development requirements
- Test files in `tests/` - Expected behavior and integration patterns
