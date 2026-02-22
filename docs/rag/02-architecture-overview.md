# Architecture Overview

**Version:** 1.0.0  
**Last Updated:** 2026-01-02  
**Document Type:** RAG - System Architecture

## System Architecture

### High-Level Design

Entropy Lab RS follows a **modular workspace architecture** with clear separation between:
1. **Core Library** (`temporal-planetarium-lib`): All security research logic
2. **CLI Interface** (`temporal-planetarium-cli`): Command-line user interface
3. **GPU Kernels** (`cl/`): OpenCL acceleration code

```
┌─────────────────────────────────────────────────────┐
│                  CLI Interface                       │
│           (temporal-planetarium-cli)                 │
└────────────────────┬────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────┐
│              Core Library                            │
│         (temporal-planetarium-lib)                   │
│  ┌────────────┐  ┌──────────┐  ┌────────────────┐  │
│  │  Scanners  │  │ Utils    │  │  GPU/CPU Exec  │  │
│  └────────────┘  └──────────┘  └────────────────┘  │
└────────────────────┬────────────────────────────────┘
                     │
      ┌──────────────┴──────────────┐
      ▼                             ▼
┌─────────────┐              ┌─────────────┐
│  CPU Path   │              │  GPU Path   │
│  (Rayon)    │              │  (OpenCL)   │
└─────────────┘              └─────────────┘
```

### Workspace Structure

The project uses Cargo workspace with resolver="2":

```toml
[workspace]
members = [
    "crates/temporal-planetarium-lib",
    "crates/temporal-planetarium-cli",
]
```

**Benefits**:
- Shared dependencies across crates
- Unified build and test execution
- Clean separation of concerns
- Reusable library for integration

### Core Library Organization

```
temporal-planetarium-lib/src/
├── lib.rs                    # Public API exports
├── scans/                    # Vulnerability scanners
│   ├── mod.rs
│   ├── randstorm/           # Randstorm/BitcoinJS scanner
│   ├── trust_wallet/        # Trust Wallet scanners
│   ├── cake_wallet/         # Cake Wallet scanners
│   ├── android_securerandom/# Android vulnerability
│   ├── milk_sad.rs          # Libbitcoin Milk Sad
│   ├── profanity.rs         # Profanity vanity addresses
│   ├── brainwallet.rs       # Brainwallet analysis
│   └── ...
├── utils/                   # Shared utilities
│   ├── bitcoin_rpc.rs       # Bitcoin Core RPC client
│   ├── bloom_filter.rs      # CPU bloom filter
│   ├── gpu_bloom_filter.rs  # GPU bloom filter
│   ├── db.rs                # SQLite database
│   ├── electrum.rs          # Electrum integration
│   └── ...
├── bin/                     # Helper binaries
│   ├── benchmark_gpu.rs
│   ├── generate_test_vectors.rs
│   └── ...
└── gui.rs                   # GUI interface (egui)
```

## Design Patterns

### 1. Module-Level Hardware Parity

**Pattern**: Separate CPU and GPU implementations in distinct modules.

```rust
// CPU implementation
pub mod cpu {
    pub fn scan_entropy(seed: &[u8]) -> Result<bool> {
        // CPU-optimized SIMD or sequential logic
    }
}

// GPU implementation
pub mod gpu {
    pub fn scan_entropy_opencl(seeds: &[Vec<u8>]) -> Result<Vec<bool>> {
        // OpenCL kernel dispatch
    }
}
```

**Benefits**:
- Clean separation of concerns
- Easy to test and benchmark separately
- Fallback path when GPU unavailable

### 2. Unified Shader Bridge (Critical)

**Law**: All PRNG logic uses **fixed-point bitwise integers only**.

```c
// ✅ CORRECT: Integer-only operations
__kernel void generate_seed(__global uint* output) {
    uint state = get_global_id(0);
    state = (state * 1103515245u + 12345u) & 0x7FFFFFFFu;
    output[0] = state;
}

// ❌ FORBIDDEN: Floating-point causes driver divergence
__kernel void bad_kernel(__global float* output) {
    float val = sin(get_global_id(0));  // NEVER USE FLOATS
    output[0] = val;
}
```

**Rationale**: Floating-point math has driver-specific rounding, causing GPU/CPU divergence.

### 3. Progressive Scanning Trait

All scanners implement a common interface:

```rust
pub trait Scanner {
    fn scan(&self, progress_tx: UnboundedSender<ScanProgress>) -> anyhow::Result<()>;
}

pub struct ScanProgress {
    pub current: u64,
    pub total: u64,
    pub found: Vec<Finding>,
}
```

**Benefits**:
- Real-time ETA and progress reporting
- Consistent UI across all scanners
- Cancelable long-running scans

### 4. Zero-Allocation Hot Paths

Performance-critical loops avoid allocations:

```rust
// ✅ GOOD: Pre-allocated buffer
let mut buffer = vec![0u8; BATCH_SIZE * 32];
for batch in batches {
    process_batch_inplace(&mut buffer, batch);
}

// ❌ BAD: Allocation per iteration
for item in items {
    let result = vec![0u8; 32];  // Allocates every loop
    process(result);
}
```

### 5. Dual-Execution Cross-Check

**Critical Security Pattern**: Every GPU hit must be verified by CPU.

```rust
// GPU finds candidate
let gpu_candidates = opencl_scan(seeds)?;

// CPU golden reference verifies
for candidate in gpu_candidates {
    let cpu_result = cpu_verify(&candidate)?;
    if cpu_result != candidate.gpu_result {
        panic!("GPU/CPU divergence detected!");
    }
}
```

## Data Flow

### Typical Scanner Flow

```
Input (Target Addresses)
         │
         ▼
  Load into Memory
         │
    ┌────┴────┐
    │         │
    ▼         ▼
CPU Path   GPU Path
    │         │
    │    ┌────┴────┐
    │    │ Batch   │
    │    │ OpenCL  │
    │    │ Kernel  │
    │    └────┬────┘
    │         │
    │    Candidates
    │         │
    └────┬────┘
         ▼
   CPU Verify
         │
         ▼
   Store Results
         │
         ▼
    Report to UI
```

### GPU Execution Flow

```
Host (CPU)                  Device (GPU)
    │                            │
    ├──── Allocate Buffers ─────>
    │                            │
    ├──── Copy Input Data ──────>
    │                            │
    ├──── Enqueue Kernel ───────>
    │                            │
    │                       Execute
    │                       Parallel
    │                       Threads
    │                            │
    <──── Copy Results Back ─────┤
    │                            │
    ▼                            ▼
Verify                       Complete
```

## Component Responsibilities

### Scanners (`src/scans/`)
- Implement vulnerability-specific logic
- Handle both CPU and GPU execution
- Report findings with full context
- Follow security best practices

### Utils (`src/utils/`)
- **bitcoin_rpc.rs**: Blockchain interaction
- **bloom_filter.rs**: Fast set membership testing
- **db.rs**: Persistent storage (SQLite)
- **electrum.rs**: Electrum wallet integration
- **encryption.rs**: AES-GCM for sensitive data

### GPU Kernels (`cl/`)
- **secp256k1*.cl**: Elliptic curve operations
- **sha2.cl, ripemd.cl**: Hash functions
- **mt19937.cl**: Mersenne Twister PRNG
- **bip39*.cl**: Mnemonic handling
- **randstorm*.cl**: Randstorm scanner kernels

### Binaries (`src/bin/`)
- **benchmark_gpu.rs**: Performance benchmarking
- **generate_test_vectors.rs**: Test data creation
- **verify_forensics.rs**: Forensic validation

## Concurrency Model

### CPU Parallelism (Rayon)

```rust
use rayon::prelude::*;

seeds.par_iter()
    .map(|seed| derive_address(seed))
    .collect()
```

### GPU Parallelism (OpenCL)

```rust
let kernel = pro_que.kernel_builder("scan_kernel")
    .arg(&input_buffer)
    .arg(&output_buffer)
    .arg(batch_size)
    .build()?;

kernel.cmd()
    .global_work_size(work_size)
    .enq()?;
```

### Async I/O (Tokio - Optional)

```rust
#[cfg(feature = "postgres")]
use tokio::runtime::Runtime;

let rt = Runtime::new()?;
rt.block_on(async {
    pool.get().await?.query(...).await?
});
```

## Error Handling Strategy

### Cascading Errors with Context

```rust
use anyhow::{Context, Result};

pub fn scan_wallet(path: &Path) -> Result<Wallet> {
    let data = fs::read(path)
        .context("Failed to read wallet file")?;
    
    let wallet = parse_wallet(&data)
        .context("Failed to parse wallet data")?;
    
    Ok(wallet)
}
```

### GPU Error Recovery

```rust
match opencl_scan(seeds) {
    Ok(results) => results,
    Err(e) if e.is_device_error() => {
        warn!("GPU failed, falling back to CPU");
        cpu_scan(seeds)?
    }
    Err(e) => return Err(e),
}
```

## Configuration Management

### Environment Variables

```rust
use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(long, env = "RPC_URL")]
    rpc_url: String,
    
    #[arg(long, env = "RPC_USER")]
    rpc_user: String,
}
```

### Feature Flags

```toml
[features]
default = []
gpu = ["dep:ocl"]
gui = ["dep:eframe", "dep:egui"]
z3-solver = ["dep:z3"]
wgpu = ["dep:wgpu"]
```

## Testing Architecture

### Tier System

1. **Tier 1 (Unit)**: <30s, local only
2. **Tier 2 (Integration)**: ~5m, CI runs
3. **Tier 4 (Golden)**: 100% parity with known vectors

### Test Organization

```
tests/
├── randstorm_integration.rs      # Tier 2
├── test_gpu_cpu_parity.rs        # Tier 4
├── cake_wallet_unit.rs           # Tier 1
└── fixtures/
    └── shared_test_vectors.json
```

## Security Architecture

### Layered Security

```
┌─────────────────────────────┐
│  Input Validation Layer     │  ← Sanitize all inputs
├─────────────────────────────┤
│  Cryptographic Operations   │  ← Constant-time ops
├─────────────────────────────┤
│  Private Key Handling       │  ← In-memory only, never log
├─────────────────────────────┤
│  Result Verification        │  ← Dual CPU/GPU check
└─────────────────────────────┘
```

### Defense in Depth

1. **Input Validation**: Reject malformed data early
2. **Type Safety**: Rust's type system prevents errors
3. **Memory Safety**: No buffer overflows or use-after-free
4. **Constant-Time**: Timing-attack resistant crypto
5. **Verification**: Cross-check all critical results

## Performance Architecture

### Optimization Hierarchy

1. **Algorithm Choice**: O(n) vs O(n²) matters most
2. **Batch Processing**: Amortize overhead
3. **GPU Acceleration**: 10-100x for parallel work
4. **SIMD/Rayon**: Multi-core CPU parallelism
5. **Memory Layout**: Cache-friendly data structures

### Profiling Points

```rust
use std::time::Instant;

let start = Instant::now();
let result = expensive_operation();
tracing::info!("Operation took {:?}", start.elapsed());
```

## Extensibility

### Adding New Scanners

1. Create module in `src/scans/`
2. Implement `Scanner` trait
3. Add GPU kernel in `cl/` if needed
4. Add integration tests
5. Export from `src/scans/mod.rs`
6. Add CLI subcommand

### Adding New Utils

1. Create module in `src/utils/`
2. Add public API
3. Document with examples
4. Export from `src/utils/mod.rs`

---

**Related Documents**:
- [Codebase Structure](03-codebase-structure.md)
- [Scanner Implementations](04-scanner-implementations.md)
- [GPU Acceleration](05-gpu-acceleration.md)
- [Security Considerations](10-security-considerations.md)
