# Architecture Documentation
# Temporal Planetarium - System Architecture

**Version:** 1.0  
**Date:** 2025-12-17  
**Project:** entropy-lab-rs (Temporal Planetarium)

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [System Components](#system-components)
3. [Scanner Architecture](#scanner-architecture)
4. [GPU Acceleration Architecture](#gpu-acceleration-architecture)
5. [Cryptographic Layer](#cryptographic-layer)
6. [Data Flow](#data-flow)
7. [Integration Points](#integration-points)
8. [Deployment Architecture](#deployment-architecture)
9. [Security Architecture](#security-architecture)
10. [Performance Architecture](#performance-architecture)

---

## Architecture Overview

### System Type
**Hybrid CLI + Library with Optional GPU Acceleration**

### Key Architectural Principles

1. **Modularity** - Each scanner is self-contained
2. **Extensibility** - Easy to add new vulnerability scanners
3. **Performance** - GPU acceleration where it matters
4. **Safety** - Rust's memory safety guarantees
5. **Flexibility** - Works as CLI tool or library
6. **Graceful Degradation** - CPU fallback when GPU unavailable

### High-Level Architecture Diagram

```
┌───────────────────────────────────────────────────────────────┐
│                     User Interface Layer                      │
├───────────────────────────────────────────────────────────────┤
│  CLI (clap)          │  GUI (egui)         │  Library API     │
│  main.rs             │  gui.rs             │  lib.rs          │
└──────────────┬───────┴──────────┬──────────┴──────────────────┘
               │                  │
               └──────────┬───────┘
                          ▼
┌───────────────────────────────────────────────────────────────┐
│                    Scanner Dispatcher                         │
│              (Routes to appropriate scanner)                  │
└──────────────┬────────────────────────────────────────────────┘
               │
               ▼
┌───────────────────────────────────────────────────────────────┐
│                     Scanner Layer                             │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  Individual Scanners (src/scans/)                       │ │
│  │                                                          │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │ │
│  │  │   Cake       │  │   Trust      │  │   Milk       │ │ │
│  │  │   Wallet     │  │   Wallet     │  │   Sad        │ │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘ │ │
│  │                                                          │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │ │
│  │  │  Android     │  │  Profanity   │  │  Brain       │ │ │
│  │  │  SecRandom   │  │              │  │  Wallet      │ │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘ │ │
│  │                                                          │ │
│  │  ... (12 more scanners)                                 │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────┬────────────────────────────────────────────────┘
               │
               ├──────────────┬──────────────┐
               ▼              ▼              ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │   GPU Path   │  │   CPU Path   │  │   Hybrid     │
    │              │  │              │  │              │
    │ gpu_solver.rs│  │ Rayon        │  │ Auto-select  │
    │      ↓       │  │ Parallel     │  │              │
    │ OpenCL       │  │              │  │              │
    │ Kernels      │  │              │  │              │
    └──────────────┘  └──────────────┘  └──────────────┘
               │              │              │
               └──────────────┴──────────────┘
                          ▼
┌───────────────────────────────────────────────────────────────┐
│                  Cryptographic Layer                          │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  secp256k1  │  bitcoin  │  bip39  │  sha2/3  │  hmac  │ │
│  └─────────────────────────────────────────────────────────┘ │
└──────────────┬────────────────────────────────────────────────┘
               │
               ▼
┌───────────────────────────────────────────────────────────────┐
│                   External Integration                        │
│  Bitcoin RPC  │  File I/O  │  Bloom Filters  │  CSV          │
└───────────────────────────────────────────────────────────────┘
```

---

## System Components

### 1. User Interface Layer

#### CLI (main.rs)
**Responsibilities:**
- Parse command-line arguments using clap
- Validate user input
- Dispatch to appropriate scanner
- Display results
- Handle errors and logging

**Key Features:**
- Subcommand-based interface (one per scanner)
- Environment variable support for sensitive data
- Help text and usage examples
- Error reporting

**Technology:** `clap` v4.5 with derive macros

#### GUI (gui.rs)
**Responsibilities:**
- Provide graphical interface using egui
- Scanner selection
- Parameter configuration
- Real-time progress display
- Results visualization

**Key Features:**
- Auto-detect GPU availability
- Scanner configuration forms
- Progress bars and status
- Result tables

**Technology:** `egui` v0.29 + `eframe` v0.29 (optional feature)

#### Library API (lib.rs)
**Responsibilities:**
- Export public scanner interfaces
- Provide programmatic access
- Enable integration into other tools

**Key Features:**
- Clean, documented API
- Result types for error handling
- Reusable scanner functions

---

### 2. Scanner Layer

#### Scanner Module Structure
Each scanner follows a consistent pattern:

```rust
// Scanner module template
pub fn scan_vulnerability(
    target: &Target,
    options: &ScanOptions,
) -> Result<Vec<Finding>> {
    // 1. Validate inputs
    // 2. Initialize scanner
    // 3. Choose GPU or CPU path
    // 4. Execute scan
    // 5. Return findings
}
```

#### Scanner Types

**1. Blockchain-Connected Scanners:**
- Android SecureRandom (requires RPC)
- Cake Wallet RPC
- Verify CSV (reads blockchain data)

**2. Brute-Force Scanners:**
- Cake Wallet variants
- Trust Wallet variants
- Milk Sad
- Profanity
- Mobile Sensor

**3. Dictionary/Pattern Scanners:**
- Brainwallet (wordlist-based)
- Passphrase Recovery

**4. Direct Analysis Scanners:**
- Direct Key
- EC_NEW
- Malicious Extension

---

### 3. GPU Acceleration Layer

#### GPU Solver (gpu_solver.rs)
**Responsibilities:**
- Manage OpenCL context and devices
- Load and compile kernels
- Transfer data between CPU and GPU
- Execute kernels with optimal work group sizes
- Handle errors and fallback to CPU

**Key Components:**

```rust
pub struct GpuSolver {
    context: ocl::Context,
    queue: ocl::Queue,
    device: ocl::Device,
    work_group_size: usize,
}

impl GpuSolver {
    pub fn new(device_id: Option<usize>) -> Result<Self>;
    pub fn solve(&self, kernel: &str, data: &[u8]) -> Result<Vec<u8>>;
    pub fn optimize_work_group_size(&mut self) -> Result<()>;
}
```

**Optimization Features:**
- Device-aware work group sizing
- Pinned memory allocation
- Kernel compilation caching
- Asynchronous execution
- Error recovery

#### OpenCL Kernels (cl/*.cl)
**Organization:**
- One kernel per scanner (base)
- Multipath variants (_multipath.cl)
- Optimization variants (_optimized.cl)

**Kernel Families:**
1. **milk_sad_*.cl** - Milk Sad scanners
2. **trust_wallet_*.cl** - Trust Wallet scanners  
3. **cake_wallet_*.cl** - Cake Wallet scanners
4. **mobile_sensor_*.cl** - Mobile sensor scanners
5. **profanity_*.cl** - Profanity scanners
6. **minstd_rand_*.cl** - LCG scanners

**Common Kernel Structure:**
```c
__kernel void crack_kernel(
    __global const uint *search_space,
    __global const uchar *target_hash,
    __global uint *results,
    const uint batch_offset
) {
    // 1. Get global thread ID
    // 2. Generate candidate from thread ID
    // 3. Perform cryptographic operations
    // 4. Compare against target
    // 5. Write match to results buffer
}
```

---

## Cryptographic Layer

### Core Cryptographic Components

#### 1. Elliptic Curve Operations (secp256k1)
**Used For:**
- Private key to public key conversion
- ECDSA signature verification
- Point multiplication

**Library:** `secp256k1` v0.29

#### 2. Address Generation (bitcoin)
**Supported Formats:**
- **P2PKH** (Legacy) - Starts with `1`
- **P2WPKH** (SegWit) - Starts with `bc1q`
- **P2SH-P2WPKH** (SegWit wrapped) - Starts with `3`

**Derivation Paths:**
- BIP44: `m/44'/0'/0'/0/0` (Legacy)
- BIP49: `m/49'/0'/0'/0/0` (SegWit wrapped)
- BIP84: `m/84'/0'/0'/0/0` (Native SegWit)

**Library:** `bitcoin` v0.32

#### 3. Mnemonic Handling (bip39)
**Operations:**
- Mnemonic to seed conversion (PBKDF2-HMAC-SHA512)
- Seed to master key derivation
- Child key derivation (BIP32)

**Library:** `bip39` v2.0

#### 4. Hashing & HMAC
**Algorithms:**
- SHA256 (`sha2` crate)
- SHA512 (`sha2` crate)
- SHA3 (`sha3` crate)
- RIPEMD160 (`ripemd` crate)
- HMAC (`hmac` crate)

#### 5. Key Derivation
**Functions:**
- PBKDF2 (`pbkdf2` crate)
- HMAC-SHA512 (for BIP32)

---

## Data Flow

### Typical Scanner Execution Flow

```
1. User Input (CLI/GUI)
   ↓
2. Input Validation
   ↓
3. Scanner Selection
   ↓
4. Scanner Initialization
   ↓
5. Execution Path Selection
   ├─→ GPU Available? ──Yes→ GPU Path
   │                     ├─→ Load Kernel
   │                     ├─→ Transfer Data
   │                     ├─→ Execute Kernel
   │                     ├─→ Retrieve Results
   │                     └─→ Process Results
   └─→ No ──→ CPU Path
               ├─→ Rayon Parallel Processing
               ├─→ Batch Processing
               └─→ Collect Results
   ↓
6. Results Aggregation
   ↓
7. Output Formatting
   ↓
8. Display/Save Results
```

### GPU Data Flow (Detailed)

```
CPU                          GPU
 │                            │
 ├─→ Allocate Buffers        │
 │                            │
 ├─→ Transfer Search Space ─→│
 │                            │
 ├─→ Transfer Target Hash ──→│
 │                            │
 ├─→ Enqueue Kernel          │
 │                            ├─→ Execute Threads
 │                            ├─→ Generate Candidates
 │                            ├─→ Hash & Compare
 │                            └─→ Write Matches
 │                            │
 ├←─ Retrieve Results ───────┤
 │                            │
 └─→ Process Matches         │
```

---

## Integration Points

### 1. Bitcoin Core RPC Integration

**Purpose:** Query blockchain for transaction data

**Scanners Using RPC:**
- Android SecureRandom (fetch previous transactions)
- Cake Wallet RPC (verify addresses on-chain)
- Verify CSV (validate addresses)

**Configuration:**
```bash
RPC_URL=http://localhost:8332
RPC_USER=your_username
RPC_PASS=your_password
```

**Library:** `bitcoincore-rpc` v0.19

**Key Operations:**
- `getblock()` - Fetch block data
- `getrawtransaction()` - Fetch transaction data
- `getaddressinfo()` - Validate addresses
- `listunspent()` - Check UTXO set

### 2. File I/O Integration

**CSV Files:**
- Input: Target addresses, known hashes
- Output: Findings, results

**Data Files:**
- `cakewallet_vulnerable_hashes.txt`
- `android_securerandom_hits.txt`
- `trust_wallet_ms_sample.csv`

**Libraries:** `csv` v1.3, `serde` v1.0

### 3. Bloom Filter Integration

**Purpose:** Memory-efficient large-scale address set membership testing

**Use Cases:**
- Checking against millions of known addresses
- Fast negative lookups
- Memory-constrained environments

**Library:** `bloomfilter` v3.0.1, `siphasher` v1.0.1

---

## Deployment Architecture

### Build Configurations

#### 1. CLI-Only Build (Default)
```bash
cargo build --release
```
**Features:** Core scanners, CPU processing
**Size:** ~5-10 MB

#### 2. GPU-Enabled Build
```bash
cargo build --release --features gpu
```
**Features:** Core + GPU acceleration
**Size:** ~10-20 MB
**Requirements:** OpenCL runtime

#### 3. GUI Build
```bash
cargo build --release --features gui
```
**Features:** Core + GUI interface
**Size:** ~15-25 MB

#### 4. Full Build
```bash
cargo build --release --all-features
```
**Features:** All features enabled
**Size:** ~20-30 MB
**Requirements:** OpenCL runtime

### Platform Support

**Linux:**
- ✅ Fully supported
- OpenCL: `apt-get install ocl-icd-opencl-dev`

**macOS:**
- ✅ Fully supported
- OpenCL: Built-in support

**Windows:**
- ✅ Supported
- OpenCL: Install GPU vendor SDK

### Containerization (Optional)

```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ocl-icd-libopencl1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/entropy-lab-rs /usr/local/bin/
CMD ["entropy-lab-rs"]
```

---

## Security Architecture

### Defense in Depth

**Layer 1: Input Validation**
- Validate all user inputs
- Sanitize file paths
- Check address formats
- Verify numeric ranges

**Layer 2: Memory Safety**
- Rust's ownership system
- Bounds checking
- No null pointer dereferences
- No buffer overflows

**Layer 3: Cryptographic Safety**
- Use audited libraries
- Constant-time comparisons
- Secure random number generation
- Proper key derivation

**Layer 4: Operational Security**
- Never log private keys
- Environment variables for secrets
- Secure file permissions
- Minimal attack surface

### Secrets Management

**Environment Variables:**
```rust
use std::env;

let rpc_user = env::var("RPC_USER")
    .context("RPC_USER not set")?;
```

**Never in Code:**
```rust
// ❌ NEVER DO THIS
const RPC_PASSWORD: &str = "hardcoded_password";

// ✅ DO THIS
let rpc_password = env::var("RPC_PASS")?;
```

### Audit Trail

**Logging Strategy:**
- ✅ Log operations (scan started/completed)
- ✅ Log errors and warnings
- ✅ Log configuration (sanitized)
- ❌ Never log private keys
- ❌ Never log mnemonics
- ⚠️ Log addresses (if necessary for research)

---

## Performance Architecture

### CPU Optimization

**Parallelization:**
- Uses `rayon` v1.10 for data parallelism
- Thread pool size = CPU cores
- Work-stealing scheduler

**Batch Processing:**
- Process candidates in batches
- Minimize memory allocations
- Cache hot data

**Example:**
```rust
use rayon::prelude::*;

candidates
    .par_chunks(BATCH_SIZE)
    .for_each(|batch| {
        // Process batch in parallel
    });
```

### GPU Optimization

**Work Group Sizing:**
- NVIDIA: 256-512 threads
- AMD: 128-256 threads
- Intel: 64-128 threads

**Memory Optimization:**
- Pinned memory for transfers
- Constant memory for lookup tables
- Coalesced memory access

**Kernel Optimization:**
- Fast math optimizations
- Instruction fusion
- Loop unrolling

See `OPENCL_OPTIMIZATIONS.md` for comprehensive GPU optimization guide.

---

## Future Architecture Considerations

### Planned Improvements

**1. Microservice Architecture (Long-term)**
- Scanner as separate services
- API gateway
- Result aggregation service
- Scalable deployment

**2. Distributed Computing**
- Multiple GPU nodes
- Work distribution
- Result collection

**3. Plugin System**
- Dynamic scanner loading
- Third-party scanner integration
- Hot-swappable kernels

**4. Enhanced Monitoring**
- Prometheus metrics
- Grafana dashboards
- Performance profiling

---

**Version:** 1.0  
**Last Updated:** 2025-12-17  
**Maintained By:** Temporal Planetarium Team
