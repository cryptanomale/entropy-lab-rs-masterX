# Architecture Document - Randstorm/BitcoinJS Scanner

**Project:** Temporal Planetarium (entropy-lab-rs)  
**Feature:** Randstorm/BitcoinJS Vulnerability Scanner  
**Author:** Winston (Architect)  
**Date:** 2025-12-17  
**Version:** 1.0  
**Status:** Ready for Implementation

---

## Executive Summary

This architecture document defines the technical design for the Randstorm/BitcoinJS Scanner, a GPU-accelerated vulnerability detection system for Bitcoin wallets generated with weak JavaScript PRNGs (2011-2015). The design leverages temporal-planetarium's existing 46 GPU kernels and 18 scanner patterns while introducing JavaScript PRNG reconstruction capabilities.

**Key Architectural Decisions:**
- **Modular Design:** Follows established scanner patterns (`src/scans/randstorm.rs`)
- **GPU-First Architecture:** OpenCL acceleration with CPU fallback
- **Phased Implementation:** Week 1 MVP → Week 2 Expansion → Week 3+ Optimization
- **Responsible by Design:** No private key export, disclosure framework built-in
- **Performance Target:** 10-100x GPU speedup, 60-95% vulnerability coverage

---

## System Context

### Integration with Existing Platform

**Temporal Planetarium Current State:**
- 18 existing vulnerability scanners (Milk Sad, Cake Wallet, Trust Wallet, Profanity, etc.)
- 46 OpenCL GPU kernels with proven 10-100x speedup
- Rust 2021 codebase (minimum 1.70) with established patterns
- CLI interface using clap v4.5
- Comprehensive crypto stack (secp256k1, bitcoin, bip39)

**New Scanner Positioning:**
- Scanner #19 in the suite
- Addresses critical gap: $1B+ Randstorm vulnerability
- Reuses existing GPU infrastructure (`gpu_solver.rs`)
- Follows modular scanner architecture
- Integrates seamlessly with existing CLI

### Brownfield Integration Points

```
temporal-planetarium/
├── src/
│   ├── scans/
│   │   ├── [18 existing scanners]
│   │   └── randstorm.rs          ← NEW MODULE
│   │       ├── mod.rs
│   │       ├── prng/
│   │       ├── fingerprints/
│   │       └── integration.rs
│   ├── gpu_solver.rs             ← REUSE (device detection, work groups)
│   └── main.rs                   ← EXTEND (add subcommand)
├── cl/
│   ├── [46 existing kernels]
│   └── randstorm_crack.cl        ← NEW KERNEL
└── tests/
    └── randstorm_tests.rs        ← NEW TESTS
```

---

## Architectural Principles

### 1. Boring Technology That Works

**Philosophy:** Leverage proven patterns, avoid novel complexity.

**Application:**
- Rust (memory safety, existing codebase language)
- OpenCL (established GPU framework, 46 kernels already working)
- Modular scanners (18 successful implementations to learn from)
- CLI (no GUI complexity in MVP)

**Rationale:** $1B vulnerability requires fast, reliable delivery. Proven tech reduces risk.

### 2. User Journeys Drive Technical Decisions

**Primary Journey:** Security researcher validates Randstorm findings
```
Input: Bitcoin address list (CSV)
  ↓
Browser config iteration (GPU-accelerated)
  ↓
PRNG state reconstruction
  ↓
Private key candidates generation
  ↓
Address comparison
  ↓
Output: Vulnerability report (CSV)
```

**Technical Implications:**
- Batch processing required (not single-address focus)
- Progress reporting essential (long-running scans)
- GPU optimization critical (performance determines usefulness)
- Clear result format (security professionals need data, not prose)

### 3. Simple Solutions That Scale When Needed

**Phase 1 (Week 1):** Simple, working scanner
- Single PRNG (Chrome V8)
- Top 100 configs
- Basic GPU kernel
- 60-70% coverage

**Phase 2 (Week 2):** Scale coverage
- All PRNGs (Firefox, Safari, IE)
- 500 configs
- Optimized GPU
- 85-90% coverage

**Phase 3 (Week 3+):** Scale performance
- Probabilistic search
- Multi-GPU
- 95%+ coverage

**Rationale:** Ship fast, beat attackers, iterate based on real data.

### 4. Developer Productivity IS Architecture

**Decisions for Productivity:**
- Follow existing patterns (copy-paste from successful scanners)
- Comprehensive error handling (anyhow::Result everywhere)
- Unit testable components (PRNG, fingerprints separate from GPU)
- Clear separation of concerns (PRNG logic ≠ GPU kernel ≠ CLI)

**Anti-Patterns to Avoid:**
- ❌ Premature GPU optimization (Phase 1 just needs 10x)
- ❌ Complex abstraction layers (direct, clear code)
- ❌ Clever algorithms (boring, proven algorithms)

---

## Component Architecture

### High-Level Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                      CLI Interface                           │
│                   (clap v4.5 parser)                        │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│                  Randstorm Scanner                           │
│                 (src/scans/randstorm.rs)                    │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ PRNG Module  │  │ Fingerprint  │  │ Integration  │     │
│  │              │  │  Database    │  │   Module     │     │
│  │ • Chrome V8  │  │              │  │              │     │
│  │ • Firefox    │  │ • Top 100    │  │ • GPU Bridge │     │
│  │ • Safari     │  │ • Priority   │  │ • Results    │     │
│  │ • IE         │  │   Sorting    │  │   Collector  │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└────────────┬────────────────────────────────┬──────────────┘
             │                                │
             ▼                                ▼
┌─────────────────────────┐    ┌────────────────────────────┐
│   GPU Solver (Reused)   │    │   Crypto Libraries         │
│                         │    │                            │
│ • Device Detection      │    │ • secp256k1 (pub keys)    │
│ • Work Group Sizing     │    │ • bitcoin (addresses)     │
│ • Memory Management     │    │ • bip39 (HD wallets)      │
│ • Kernel Dispatch       │    │                            │
└────────────┬────────────┘    └────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────────┐
│                 OpenCL GPU Kernel                            │
│              (cl/randstorm_crack.cl)                        │
│                                                              │
│  Input: Browser configs, timestamp ranges                   │
│  Process: PRNG state → Private key → Public key → Address  │
│  Output: Match buffer (vulnerable addresses)                │
└─────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

#### 1. CLI Interface (`src/main.rs` extension)

**Responsibility:** Parse user input, validate arguments, dispatch to scanner.

**Interface:**
```rust
// Add to main.rs clap derive
#[derive(Subcommand)]
enum Commands {
    // ... existing 18 scanners ...
    
    #[command(about = "Scan for Randstorm/BitcoinJS vulnerabilities")]
    RandstormScan {
        #[arg(long, help = "Target addresses CSV file")]
        target_addresses: PathBuf,
        
        #[arg(long, default_value = "1", help = "Scanner phase (1, 2, or 3)")]
        phase: u8,
        
        #[arg(long, help = "Force GPU acceleration")]
        gpu: bool,
        
        #[arg(long, help = "Force CPU fallback")]
        cpu: bool,
        
        #[arg(long, help = "Output file (default: stdout)")]
        output: Option<PathBuf>,
    },
}
```

**Error Handling:**
- Invalid CSV format → clear error with line number
- GPU unavailable → warning + auto CPU fallback
- Invalid phase number → error with valid options

#### 2. Randstorm Scanner Module (`src/scans/randstorm/mod.rs`)

**Responsibility:** Orchestrate scanning workflow, manage state, coordinate components.

**Public API:**
```rust
pub struct RandstormScanner {
    phase: Phase,
    gpu_enabled: bool,
    fingerprint_db: FingerprintDatabase,
    prng_engines: HashMap<BrowserType, Box<dyn PrngEngine>>,
}

impl RandstormScanner {
    pub fn new(phase: Phase, force_cpu: bool) -> Result<Self>;
    
    pub fn scan_addresses(
        &self,
        addresses: &[BitcoinAddress],
        progress: impl ProgressReporter,
    ) -> Result<Vec<VulnerabilityFinding>>;
    
    fn scan_single_address(
        &self,
        address: &BitcoinAddress,
    ) -> Result<Option<VulnerabilityFinding>>;
}

pub struct VulnerabilityFinding {
    pub address: BitcoinAddress,
    pub confidence: ConfidenceLevel,
    pub browser_config: BrowserConfig,
    pub timestamp_range: (DateTime, DateTime),
    pub derivation_path: DerivationPath,
}
```

**Internal Flow:**
```rust
fn scan_single_address(&self, address: &BitcoinAddress) -> Result<Option<VulnerabilityFinding>> {
    // 1. Load browser configs for current phase
    let configs = self.fingerprint_db.get_configs_for_phase(self.phase);
    
    // 2. Estimate timestamp range from blockchain data (if available)
    let timestamp_range = estimate_creation_time(address)?;
    
    // 3. Dispatch to GPU or CPU
    let result = if self.gpu_enabled {
        self.scan_gpu(address, &configs, timestamp_range)?
    } else {
        self.scan_cpu(address, &configs, timestamp_range)?
    };
    
    Ok(result)
}
```

#### 3. PRNG Module (`src/scans/randstorm/prng/`)

**Responsibility:** Implement JavaScript PRNG algorithms for each browser.

**File Structure:**
```
prng/
├── mod.rs              # Public API, PRNG trait
├── chrome_v8.rs        # MWC1616 algorithm
├── firefox.rs          # LCG variant (Phase 2)
├── safari.rs           # Xorshift128+ (Phase 2)
└── ie_chakra.rs        # Mersenne Twister (Phase 2)
```

**PRNG Trait:**
```rust
pub trait PrngEngine {
    /// Generate PRNG state from seed components
    fn generate_state(&self, seed: &SeedComponents) -> PrngState;
    
    /// Generate random bytes from PRNG state
    fn generate_bytes(&self, state: &PrngState, count: usize) -> Vec<u8>;
    
    /// Browser/version this PRNG applies to
    fn applicable_to(&self) -> &[BrowserVersion];
}

pub struct SeedComponents {
    pub timestamp_ms: u64,      // Date.now()
    pub user_agent: String,
    pub screen_width: u32,
    pub screen_height: u32,
    pub timezone_offset: i32,
    // ... other fingerprint components
}
```

**Chrome V8 Implementation (Phase 1 Priority):**
```rust
pub struct ChromeV8Prng {
    // MWC1616 constants
}

impl PrngEngine for ChromeV8Prng {
    fn generate_state(&self, seed: &SeedComponents) -> PrngState {
        // Implement MWC1616 seeding from timestamp + fingerprint
        // This is THE critical algorithm - must match V8 exactly
        
        let mut state = PrngState::default();
        
        // Combine timestamp with fingerprint hash
        let fingerprint_hash = hash_fingerprint(seed);
        let combined_seed = seed.timestamp_ms ^ fingerprint_hash;
        
        // Initialize MWC1616 state
        state.state1 = (combined_seed & 0xFFFFFFFF) as u32;
        state.state2 = ((combined_seed >> 32) & 0xFFFFFFFF) as u32;
        
        state
    }
    
    fn generate_bytes(&self, state: &PrngState, count: usize) -> Vec<u8> {
        // MWC1616 algorithm
        let mut result = Vec::with_capacity(count);
        let mut s1 = state.state1;
        let mut s2 = state.state2;
        
        for _ in 0..count {
            // MWC1616 next()
            s1 = 18000 * (s1 & 0xFFFF) + (s1 >> 16);
            s2 = 30903 * (s2 & 0xFFFF) + (s2 >> 16);
            let r = ((s1 << 16) + s2) & 0xFFFFFFFF;
            result.push((r & 0xFF) as u8);
        }
        
        result
    }
    
    fn applicable_to(&self) -> &[BrowserVersion] {
        &[
            BrowserVersion::new("Chrome", 14..=45),
            // V8-based browsers in 2011-2015
        ]
    }
}
```

**Testing Requirements:**
- Unit tests with known test vectors from Randstorm disclosure
- 100% match requirement for state generation
- Fuzz testing with random seeds

#### 4. Fingerprint Database (`src/scans/randstorm/fingerprints/`)

**Responsibility:** Store and prioritize browser configurations from 2011-2015.

**File Structure:**
```
fingerprints/
├── mod.rs                    # Database struct, loading logic
├── data/
│   ├── phase1_top100.csv     # Top 100 configs (60-70% coverage)
│   ├── phase2_top500.csv     # Extended 500 configs (85-90% coverage)
│   └── phase3_longtail.csv   # Probabilistic configs (95%+ coverage)
```

**Database Schema (CSV):**
```csv
priority,user_agent,screen_width,screen_height,color_depth,timezone_offset,language,platform,market_share_est,year_min,year_max
1,Mozilla/5.0 (Windows NT 6.1) Chrome/25.0,1366,768,24,-300,en-US,Win32,0.082,2011,2015
2,Mozilla/5.0 (Windows NT 6.1) Chrome/30.0,1920,1080,24,-300,en-US,Win32,0.065,2012,2015
...
```

**API:**
```rust
pub struct FingerprintDatabase {
    configs: Vec<BrowserConfig>,
    phase1_cutoff: usize,  // Index where phase 1 ends (top 100)
    phase2_cutoff: usize,  // Index where phase 2 ends (top 500)
}

impl FingerprintDatabase {
    pub fn load() -> Result<Self>;
    
    pub fn get_configs_for_phase(&self, phase: Phase) -> &[BrowserConfig] {
        match phase {
            Phase::One => &self.configs[..self.phase1_cutoff],
            Phase::Two => &self.configs[..self.phase2_cutoff],
            Phase::Three => &self.configs,
        }
    }
    
    pub fn get_config_by_priority(&self, priority: usize) -> Option<&BrowserConfig>;
}

#[derive(Clone, Debug)]
pub struct BrowserConfig {
    pub priority: u32,
    pub user_agent: String,
    pub screen_width: u32,
    pub screen_height: u32,
    pub color_depth: u8,
    pub timezone_offset: i32,
    pub language: String,
    pub platform: String,
    pub market_share_estimate: f32,
    pub year_range: (u16, u16),
}
```

**Data Sources:**
- StatCounter historical data (2011-2015)
- NetMarketShare archives
- EFF Panopticlick studies
- Manual curation for accuracy

**Prioritization Algorithm:**
```rust
impl FingerprintDatabase {
    fn load_and_sort() -> Result<Vec<BrowserConfig>> {
        let mut configs = Self::load_from_csv()?;
        
        // Sort by market share (descending)
        // Higher market share = higher priority
        configs.sort_by(|a, b| {
            b.market_share_estimate
                .partial_cmp(&a.market_share_estimate)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        
        // Assign priorities
        for (idx, config) in configs.iter_mut().enumerate() {
            config.priority = idx as u32 + 1;
        }
        
        Ok(configs)
    }
}
```

#### 5. GPU Integration (`src/scans/randstorm/integration.rs`)

**Responsibility:** Bridge Rust code to GPU kernel, manage CPU-GPU transfers.

**Reuse Existing Infrastructure:**
```rust
use crate::gpu_solver::{GpuSolver, DeviceInfo, WorkGroupConfig};

pub struct GpuIntegration {
    solver: GpuSolver,
    kernel: CompiledKernel,
    device_info: DeviceInfo,
}

impl GpuIntegration {
    pub fn new() -> Result<Self> {
        // Reuse existing gpu_solver.rs initialization
        let solver = GpuSolver::new()?;
        let device_info = solver.get_device_info()?;
        
        // Compile Randstorm kernel
        let kernel_source = include_str!("../../../cl/randstorm_crack.cl");
        let kernel = solver.compile_kernel("randstorm_crack", kernel_source)?;
        
        Ok(Self {
            solver,
            kernel,
            device_info,
        })
    }
    
    pub fn scan_batch(
        &self,
        configs: &[BrowserConfig],
        timestamp_range: (u64, u64),
        target_address: &BitcoinAddress,
    ) -> Result<Option<VulnerabilityFinding>> {
        // 1. Prepare input buffers
        let config_buffer = self.prepare_config_buffer(configs)?;
        let timestamp_buffer = self.prepare_timestamp_buffer(timestamp_range)?;
        let target_hash = target_address.to_hash160();
        
        // 2. Calculate work group size (reuse existing logic)
        let work_group_config = self.solver.calculate_work_groups(
            configs.len() * 1000, // configs × timestamps per config
            &self.device_info,
        )?;
        
        // 3. Execute kernel
        let result_buffer = self.solver.execute_kernel(
            &self.kernel,
            &[config_buffer, timestamp_buffer, target_hash.into()],
            work_group_config,
        )?;
        
        // 4. Read results
        self.parse_results(result_buffer)
    }
}
```

**Memory Management:**
- Pinned memory for transfers (reuse existing pattern)
- Batch size auto-tuning based on GPU VRAM
- Result buffer sizing (small - only matches returned)

#### 6. GPU Kernel (`cl/randstorm_crack.cl`)

**Responsibility:** Parallel PRNG state generation and address checking.

**Kernel Signature:**
```c
__kernel void randstorm_crack(
    __global const BrowserConfig* configs,
    __global const uint64* timestamp_range,
    __constant const uchar* target_hash160,
    __global Result* results,
    __global uint* result_count
)
```

**Kernel Logic (Pseudocode):**
```c
// Each thread handles one config × timestamp combination
uint gid = get_global_id(0);
uint config_idx = gid / TIMESTAMPS_PER_CONFIG;
uint timestamp_idx = gid % TIMESTAMPS_PER_CONFIG;

// Load config from global memory
BrowserConfig config = configs[config_idx];

// Calculate timestamp
uint64 timestamp = timestamp_range[0] + timestamp_idx * TIMESTAMP_STEP;

// Generate PRNG seed
PRNGState state = generate_prng_state(&config, timestamp);

// Generate private key bytes from PRNG
uchar privkey[32];
generate_bytes_from_prng(&state, privkey, 32);

// Generate public key (secp256k1)
uchar pubkey[65];
secp256k1_generate_pubkey(privkey, pubkey);

// Generate address hash160
uchar hash160[20];
bitcoin_hash160(pubkey, 65, hash160);

// Compare with target
if (memcmp(hash160, target_hash160, 20) == 0) {
    // MATCH FOUND!
    uint idx = atomic_inc(result_count);
    results[idx].config_idx = config_idx;
    results[idx].timestamp = timestamp;
    // Don't store private key (security!)
}
```

**Performance Optimizations:**
- Inline PRNG (no function call overhead)
- Constant memory for target hash
- Precomputed secp256k1 tables (if feasible)
- Coalesced memory access (config struct layout)

**Phase 1 Simplifications:**
- Only Chrome V8 PRNG (single algorithm path)
- No derivation paths (direct private key only)
- Basic secp256k1 (no optimizations yet)

**Phase 2 Enhancements:**
- Multi-PRNG support (switch statement on config.browser_type)
- Multi-path derivation (check multiple BIP paths per seed)

---

## Data Flow Architecture

### End-to-End Scan Flow

```
1. User Input
   ├─ CSV file: address1, address2, ...
   └─ Phase selection: 1, 2, or 3

2. Scanner Initialization
   ├─ Load fingerprint database
   ├─ Initialize PRNG engines
   ├─ Detect GPU capability
   └─ Compile kernel (if GPU)

3. Per-Address Scan Loop
   FOR EACH address IN addresses:
   
   4. Config Iteration (Prioritized)
      ├─ Load configs for phase
      └─ Sort by priority (market share)
      
      FOR EACH config IN configs:
      
      5. Timestamp Range Estimation
         ├─ Query blockchain for first tx
         ├─ Set range: first_tx - 30 days to first_tx
         └─ Generate timestamp candidates
         
      6. GPU Batch Processing
         ├─ Batch size: 1M config×timestamp combinations
         ├─ Transfer to GPU (pinned memory)
         ├─ Execute kernel
         ├─ Read results
         └─ Check for matches
         
      7. Match Handling
         IF match found:
            ├─ Confidence = f(market_share, timestamp_proximity)
            ├─ Store finding
            └─ BREAK (don't test more configs for this address)
         
      END FOR (configs)
      
   8. Progress Reporting
      ├─ Update progress bar
      ├─ Log current config being tested
      └─ Estimate time remaining
      
   END FOR (addresses)

9. Results Output
   ├─ Generate CSV report
   ├─ Sort by confidence (HIGH → LOW)
   └─ Write to file or stdout
```

### Memory Flow (GPU Path)

```
CPU Side:
┌─────────────────────────┐
│ Fingerprint Database    │
│ (Vec<BrowserConfig>)    │
└──────────┬──────────────┘
           │ Select phase configs
           ▼
┌─────────────────────────┐
│ Config Buffer           │
│ (Serialized structs)    │
└──────────┬──────────────┘
           │ Pin memory
           ▼
┌─────────────────────────┐
│ GPU Transfer (DMA)      │
└──────────┬──────────────┘
           │
           ▼
GPU Side:
┌─────────────────────────┐
│ Global Memory           │
│ (Config array)          │
└──────────┬──────────────┘
           │ Each thread reads one
           ▼
┌─────────────────────────┐
│ Thread Execution        │
│ • PRNG state gen        │
│ • secp256k1 ops         │
│ • Hash comparison       │
└──────────┬──────────────┘
           │ If match
           ▼
┌─────────────────────────┐
│ Result Buffer           │
│ (Small - only matches)  │
└──────────┬──────────────┘
           │ Transfer back
           ▼
CPU Side:
┌─────────────────────────┐
│ VulnerabilityFinding    │
└─────────────────────────┘
```

### Error Flow

```
Error Categories:
1. Input Errors (User Fixable)
   ├─ Invalid CSV format
   ├─ Invalid Bitcoin address
   └─ Invalid phase number
   → Return clear error message

2. System Errors (Environmental)
   ├─ GPU unavailable
   ├─ Insufficient memory
   └─ File I/O errors
   → Log warning, attempt graceful degradation

3. Logic Errors (Bugs)
   ├─ PRNG mismatch vs test vector
   ├─ Address generation incorrect
   └─ GPU kernel failure
   → Panic with diagnostic info (fail fast)

Error Handling Pattern:
fn scan_address(addr: &str) -> Result<Option<Finding>> {
    // Validate input
    let parsed = BitcoinAddress::from_str(addr)
        .context("Invalid Bitcoin address format")?;
    
    // Attempt operation with context
    let configs = self.fingerprint_db.get_configs_for_phase(self.phase)
        .context("Failed to load browser configurations")?;
    
    // GPU path with fallback
    let result = match self.scan_gpu(&parsed, &configs) {
        Ok(finding) => finding,
        Err(e) if e.is_gpu_error() => {
            warn!("GPU scan failed: {}, falling back to CPU", e);
            self.scan_cpu(&parsed, &configs)?
        }
        Err(e) => return Err(e),
    };
    
    Ok(result)
}
```

---

## Deployment Architecture

### Build & Distribution

**Build Configuration:**
```toml
# Cargo.toml additions

[features]
default = ["gpu"]
gpu = ["ocl"]  # OpenCL GPU acceleration (optional)

[dependencies]
# Existing temporal-planetarium deps
secp256k1 = "0.27"
bitcoin = "0.30"
bip39 = "2.0"
clap = { version = "4.5", features = ["derive"] }
anyhow = "1.0"
rayon = "1.7"

# Optional GPU
ocl = { version = "0.19", optional = true }

[dev-dependencies]
criterion = "0.5"  # Benchmarking

[[bench]]
name = "randstorm_bench"
harness = false
```

**Platform Support:**
- **Linux:** Primary development and testing platform
  - OpenCL via NVIDIA/AMD/Intel drivers
  - CPU fallback always available
  
- **macOS:** Full support
  - OpenCL via Apple drivers
  - Metal backend (future consideration)
  
- **Windows:** Supported
  - OpenCL via GPU vendor drivers
  - CPU fallback

**Distribution:**
```bash
# Release builds
cargo build --release                    # With GPU support
cargo build --release --no-default-features  # CPU only

# Binaries
target/release/entropy-lab  # Main executable
```

### Runtime Environment

**System Requirements:**
- **Minimum (CPU only):**
  - 4GB RAM
  - 1GB disk space
  - Rust 1.70+
  
- **Recommended (GPU):**
  - 8GB RAM
  - NVIDIA/AMD/Intel GPU with OpenCL support
  - 4GB GPU VRAM
  - OpenCL development libraries

**GPU Detection Logic:**
```rust
pub fn initialize_scanner(force_cpu: bool) -> Result<RandstormScanner> {
    let gpu_available = !force_cpu && GpuSolver::is_available();
    
    if gpu_available {
        match GpuIntegration::new() {
            Ok(gpu) => {
                info!("GPU detected: {}", gpu.device_info.name);
                info!("GPU VRAM: {} MB", gpu.device_info.vram_mb);
                Ok(RandstormScanner::with_gpu(gpu))
            }
            Err(e) => {
                warn!("GPU initialization failed: {}", e);
                warn!("Falling back to CPU mode");
                Ok(RandstormScanner::cpu_only())
            }
        }
    } else {
        info!("Running in CPU-only mode");
        Ok(RandstormScanner::cpu_only())
    }
}
```

---

## Security Architecture

### Threat Model

**Threats We Defend Against:**

1. **Accidental Private Key Leakage**
   - **Threat:** Developer accidentally logs/stores private keys
   - **Mitigation:** Never materialize private keys in Rust code (GPU only), no export capability
   
2. **Malicious Code Injection**
   - **Threat:** Attacker modifies scanner to steal keys
   - **Mitigation:** Open source (public audit), no network calls, Rust memory safety
   
3. **Supply Chain Attack**
   - **Threat:** Compromised dependency includes backdoor
   - **Mitigation:** `cargo audit` in CI, minimal dependencies, vendor popular crates

**Threats We Acknowledge But Don't Mitigate:**

1. **Malicious User**
   - Scanner can identify vulnerable wallets
   - User could use findings maliciously
   - **Response:** Responsible disclosure framework, ethical guidelines, legal disclaimers
   
2. **Quantum Computing**
   - Not relevant to this vulnerability (weak entropy, not crypto break)
   - **Response:** None needed

### Secure Design Patterns

**Pattern 1: No Private Key Materialization**
```rust
// ❌ NEVER DO THIS
struct VulnerabilityFinding {
    address: String,
    private_key: Vec<u8>,  // ❌ FORBIDDEN
}

// ✅ CORRECT PATTERN
struct VulnerabilityFinding {
    address: String,
    confidence: ConfidenceLevel,
    browser_config: BrowserConfig,  // Can be used to reconstruct, but requires deliberate effort
    timestamp: DateTime,
}
```

**Pattern 2: GPU-Only Cryptographic Operations**
```rust
// Private keys never leave GPU memory
// GPU kernel:
__kernel void randstorm_crack(...) {
    uchar privkey[32];  // Local memory only
    generate_privkey_from_prng(privkey);
    
    uchar pubkey[65];
    secp256k1_generate_pubkey(privkey, pubkey);  // Use immediately
    
    // privkey disposed when thread exits
    // Never returned to CPU
}
```

**Pattern 3: Secure Memory Clearing**
```rust
impl Drop for PrngState {
    fn drop(&mut self) {
        // Zero sensitive data on drop
        use zeroize::Zeroize;
        self.state.zeroize();
    }
}
```

### Responsible Disclosure Framework

**Architecture Integration:**

```rust
pub struct VulnerabilityFinding {
    pub address: BitcoinAddress,
    pub confidence: ConfidenceLevel,
    pub discovered_at: DateTime,
    pub disclosure_status: DisclosureStatus,
}

pub enum DisclosureStatus {
    Initial,                                    // Just discovered
    NotificationAttempted(DateTime),           // Tried to contact owner
    CoordinatedWithExchange(DateTime, String), // Exchange notified
    PublicDisclosure(DateTime),                // After 90 days
}

impl VulnerabilityFinding {
    pub fn can_disclose_publicly(&self) -> bool {
        match self.disclosure_status {
            DisclosureStatus::PublicDisclosure(_) => true,
            _ => {
                let elapsed = Utc::now() - self.discovered_at;
                elapsed.num_days() >= 90
            }
        }
    }
}
```

**Workflow Support:**
```rust
// Findings management
pub struct FindingsManager {
    findings: Vec<VulnerabilityFinding>,
    disclosure_config: DisclosureConfig,
}

impl FindingsManager {
    pub fn add_finding(&mut self, finding: VulnerabilityFinding) -> Result<()> {
        // Auto-check if high-value
        if self.is_high_value(&finding)? {
            self.notify_exchanges(&finding)?;
        }
        
        self.findings.push(finding);
        self.persist_findings()?;
        Ok(())
    }
    
    pub fn generate_disclosure_report(&self) -> Result<DisclosureReport> {
        let ready_to_disclose: Vec<_> = self.findings.iter()
            .filter(|f| f.can_disclose_publicly())
            .collect();
        
        Ok(DisclosureReport::new(ready_to_disclose))
    }
}
```

---

## Performance Architecture

### Performance Budget

**Phase 1 (Week 1) Targets:**
- **GPU Speedup:** 10x minimum vs CPU baseline
- **Scan Time:** <30 minutes per address (common configs)
- **Throughput:** 100M-1B seeds/second (single GPU)
- **Memory:** <8GB RAM, <4GB GPU VRAM

**Phase 2 (Week 2) Targets:**
- **GPU Speedup:** 50x vs CPU baseline
- **Scan Time:** <10 minutes per address
- **Throughput:** 1B-10B seeds/second
- **Memory:** <16GB RAM, <4GB GPU VRAM

**Phase 3 (Week 3+) Targets:**
- **GPU Speedup:** 100x vs CPU (multi-GPU)
- **Scan Time:** <5 minutes per address
- **Throughput:** 10B+ seeds/second (multi-GPU)
- **Memory:** Scales with GPU count

### Performance Optimization Strategy

**Phase 1: Get It Working**
- Basic GPU kernel (no fancy optimizations)
- Simple work group sizing (reuse existing logic)
- Target: 10x speedup (proof of concept)

**Phase 2: Make It Fast**
- Device-specific tuning (NVIDIA vs AMD vs Intel)
- Constant memory for fingerprint database
- Coalesced memory access
- Target: 50x speedup (production ready)

**Phase 3: Make It Scale**
- Multi-GPU support
- Async kernel execution
- Advanced memory management
- Target: 100x speedup (professional use)

### Benchmarking Architecture

**Benchmark Suite:**
```rust
// benches/randstorm_bench.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_prng_generation(c: &mut Criterion) {
    let prng = ChromeV8Prng::new();
    let seed = SeedComponents::default();
    
    c.bench_function("chrome_v8_state_gen", |b| {
        b.iter(|| prng.generate_state(black_box(&seed)))
    });
}

fn bench_gpu_vs_cpu(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan_performance");
    
    group.bench_function("gpu_1M_seeds", |b| {
        b.iter(|| scan_gpu(black_box(1_000_000)))
    });
    
    group.bench_function("cpu_1M_seeds", |b| {
        b.iter(|| scan_cpu(black_box(1_000_000)))
    });
    
    group.finish();
}

criterion_group!(benches, bench_prng_generation, bench_gpu_vs_cpu);
criterion_main!(benches);
```

**Performance Monitoring:**
```rust
pub struct PerformanceMetrics {
    pub seeds_per_second: f64,
    pub gpu_utilization: f32,
    pub memory_usage_mb: usize,
    pub kernel_execution_time_ms: f64,
    pub transfer_overhead_ms: f64,
}

impl RandstormScanner {
    pub fn get_metrics(&self) -> PerformanceMetrics {
        // Collect from GPU profiler
        PerformanceMetrics {
            seeds_per_second: self.total_seeds / self.elapsed_time.as_secs_f64(),
            gpu_utilization: self.gpu_profiler.utilization(),
            memory_usage_mb: self.gpu_profiler.memory_used_mb(),
            kernel_execution_time_ms: self.gpu_profiler.last_kernel_time_ms(),
            transfer_overhead_ms: self.gpu_profiler.last_transfer_time_ms(),
        }
    }
}
```

---

## Testing Architecture

### Test Pyramid

```
                    ▲
                   / \
                  /   \
                 /  E2E \          Integration Tests (10)
                /       \          • Full scan workflow
               /    INT  \         • GPU-CPU parity
              /___________\        • Multi-phase validation
             /             \
            /               \      Unit Tests (50+)
           /      UNIT       \     • PRNG algorithms
          /___________________\    • Fingerprint DB
                                   • Address generation
```

### Unit Tests (50+ tests)

**PRNG Tests:**
```rust
#[cfg(test)]
mod prng_tests {
    use super::*;
    
    #[test]
    fn test_chrome_v8_known_vectors() {
        let prng = ChromeV8Prng::new();
        
        // Test vectors from Randstorm disclosure
        let test_cases = vec![
            (
                SeedComponents {
                    timestamp_ms: 1357891234567,
                    user_agent: "Mozilla/5.0 (Windows NT 6.1) Chrome/25.0".into(),
                    screen_width: 1366,
                    screen_height: 768,
                    timezone_offset: -300,
                    // ... complete fingerprint
                },
                // Expected private key (first 32 bytes from PRNG)
                hex::decode("a1b2c3d4...").unwrap(),
            ),
            // ... more test vectors
        ];
        
        for (seed, expected_privkey) in test_cases {
            let state = prng.generate_state(&seed);
            let generated = prng.generate_bytes(&state, 32);
            assert_eq!(generated, expected_privkey, "PRNG output mismatch for test vector");
        }
    }
    
    #[test]
    fn test_prng_deterministic() {
        let prng = ChromeV8Prng::new();
        let seed = SeedComponents::default();
        
        let state1 = prng.generate_state(&seed);
        let state2 = prng.generate_state(&seed);
        
        assert_eq!(state1, state2, "PRNG must be deterministic");
    }
}
```

**Fingerprint Database Tests:**
```rust
#[test]
fn test_fingerprint_db_loading() {
    let db = FingerprintDatabase::load().expect("Failed to load fingerprint DB");
    
    // Validate structure
    assert!(db.configs.len() >= 100, "Phase 1 requires at least 100 configs");
    assert!(db.configs.len() <= 1000, "Unreasonably large config database");
    
    // Validate prioritization
    for i in 1..db.configs.len() {
        assert!(
            db.configs[i-1].market_share_estimate >= db.configs[i].market_share_estimate,
            "Configs must be sorted by market share descending"
        );
    }
}

#[test]
fn test_phase_config_counts() {
    let db = FingerprintDatabase::load().unwrap();
    
    let phase1 = db.get_configs_for_phase(Phase::One);
    let phase2 = db.get_configs_for_phase(Phase::Two);
    
    assert_eq!(phase1.len(), 100, "Phase 1 should have exactly 100 configs");
    assert_eq!(phase2.len(), 500, "Phase 2 should have exactly 500 configs");
}
```

### Integration Tests (10 tests)

**End-to-End Scan Test:**
```rust
#[test]
fn test_full_scan_workflow() {
    // Load known vulnerable address from test vectors
    let test_address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
    let expected_config = BrowserConfig {
        user_agent: "Mozilla/5.0 (Windows NT 6.1) Chrome/25.0".into(),
        screen_width: 1366,
        screen_height: 768,
        // ... complete config from test vector
    };
    let expected_timestamp = 1357891234567u64;
    
    // Initialize scanner
    let scanner = RandstormScanner::new(Phase::One, false).unwrap();
    
    // Scan address
    let result = scanner.scan_addresses(
        &[BitcoinAddress::from_str(test_address).unwrap()],
        NullProgress,
    ).unwrap();
    
    // Validate finding
    assert_eq!(result.len(), 1, "Should find exactly one vulnerability");
    let finding = &result[0];
    assert_eq!(finding.address.to_string(), test_address);
    assert_eq!(finding.browser_config.user_agent, expected_config.user_agent);
    assert_eq!(finding.confidence, ConfidenceLevel::High);
}
```

**GPU-CPU Parity Test:**
```rust
#[test]
fn test_gpu_cpu_parity() {
    let test_address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
    
    // Scan with GPU
    let scanner_gpu = RandstormScanner::new(Phase::One, false).unwrap();
    let result_gpu = scanner_gpu.scan_single_address(
        &BitcoinAddress::from_str(test_address).unwrap()
    ).unwrap();
    
    // Scan with CPU
    let scanner_cpu = RandstormScanner::new(Phase::One, true).unwrap();
    let result_cpu = scanner_cpu.scan_single_address(
        &BitcoinAddress::from_str(test_address).unwrap()
    ).unwrap();
    
    // Results must match
    assert_eq!(result_gpu, result_cpu, "GPU and CPU implementations must produce identical results");
}
```

### Validation Tests (Critical)

**Randstorm Disclosure Validation:**
```rust
#[test]
fn test_randstorm_disclosure_examples() {
    // Load ALL examples from 2023 Randstorm disclosure
    let test_vectors = load_randstorm_test_vectors();
    
    let scanner = RandstormScanner::new(Phase::Two, false).unwrap();
    
    let mut found_count = 0;
    for vector in &test_vectors {
        let result = scanner.scan_single_address(&vector.address).unwrap();
        
        if let Some(finding) = result {
            found_count += 1;
            assert_eq!(
                finding.browser_config, vector.expected_config,
                "Config mismatch for {}", vector.address
            );
        }
    }
    
    let detection_rate = found_count as f64 / test_vectors.len() as f64;
    assert!(
        detection_rate >= 0.85,
        "Phase 2 must detect at least 85% of Randstorm examples (got {:.1}%)",
        detection_rate * 100.0
    );
}
```

---

## Operational Architecture

### Logging & Observability

**Logging Strategy:**
```rust
use tracing::{info, warn, error, debug, instrument};

#[instrument(skip(self))]
pub fn scan_addresses(&self, addresses: &[BitcoinAddress]) -> Result<Vec<Finding>> {
    info!("Starting Randstorm scan for {} addresses", addresses.len());
    info!("Phase: {:?}, GPU: {}", self.phase, self.gpu_enabled);
    
    let mut findings = Vec::new();
    
    for (idx, address) in addresses.iter().enumerate() {
        debug!("Scanning address {}/{}: {}", idx + 1, addresses.len(), address);
        
        if let Some(finding) = self.scan_single_address(address)? {
            warn!("VULNERABILITY FOUND: {} (confidence: {:?})", address, finding.confidence);
            findings.push(finding);
        }
    }
    
    info!("Scan complete. Found {} vulnerabilities", findings.len());
    Ok(findings)
}
```

**Progress Reporting:**
```rust
pub trait ProgressReporter {
    fn update(&mut self, current: usize, total: usize, message: &str);
    fn set_message(&mut self, message: &str);
}

pub struct CliProgress {
    bar: ProgressBar,
}

impl ProgressReporter for CliProgress {
    fn update(&mut self, current: usize, total: usize, message: &str) {
        self.bar.set_position(current as u64);
        self.bar.set_message(message.to_string());
        
        // Estimate time remaining
        let elapsed = self.bar.elapsed();
        let rate = current as f64 / elapsed.as_secs_f64();
        let remaining = ((total - current) as f64 / rate) as u64;
        
        self.bar.set_message(format!(
            "{} | {:.0} configs/sec | ETA: {}",
            message,
            rate,
            format_duration(Duration::from_secs(remaining))
        ));
    }
}
```

### Error Recovery

**Checkpoint System (Phase 3):**
```rust
#[derive(Serialize, Deserialize)]
pub struct ScanCheckpoint {
    pub addresses_scanned: Vec<BitcoinAddress>,
    pub addresses_remaining: Vec<BitcoinAddress>,
    pub findings_so_far: Vec<VulnerabilityFinding>,
    pub current_config_idx: usize,
    pub timestamp: DateTime<Utc>,
}

impl RandstormScanner {
    pub fn save_checkpoint(&self, path: &Path) -> Result<()> {
        let checkpoint = ScanCheckpoint {
            addresses_scanned: self.completed_addresses.clone(),
            addresses_remaining: self.remaining_addresses.clone(),
            findings_so_far: self.findings.clone(),
            current_config_idx: self.current_config_idx,
            timestamp: Utc::now(),
        };
        
        let json = serde_json::to_string_pretty(&checkpoint)?;
        std::fs::write(path, json)?;
        
        info!("Checkpoint saved to {}", path.display());
        Ok(())
    }
    
    pub fn resume_from_checkpoint(path: &Path) -> Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let checkpoint: ScanCheckpoint = serde_json::from_str(&json)?;
        
        info!("Resuming scan from checkpoint (saved {})", checkpoint.timestamp);
        info!("Progress: {}/{} addresses completed",
              checkpoint.addresses_scanned.len(),
              checkpoint.addresses_scanned.len() + checkpoint.addresses_remaining.len());
        
        // Reconstruct scanner state
        let mut scanner = Self::new(Phase::Three, false)?;
        scanner.completed_addresses = checkpoint.addresses_scanned;
        scanner.remaining_addresses = checkpoint.addresses_remaining;
        scanner.findings = checkpoint.findings_so_far;
        scanner.current_config_idx = checkpoint.current_config_idx;
        
        Ok(scanner)
    }
}

// Auto-checkpoint on SIGTERM/SIGINT
fn setup_signal_handlers(scanner: &Arc<Mutex<RandstormScanner>>) {
    let scanner_clone = Arc::clone(scanner);
    ctrlc::set_handler(move || {
        info!("Interrupt received, saving checkpoint...");
        let scanner = scanner_clone.lock().unwrap();
        if let Err(e) = scanner.save_checkpoint(Path::new("scan.checkpoint")) {
            error!("Failed to save checkpoint: {}", e);
        }
        std::process::exit(0);
    }).expect("Error setting Ctrl-C handler");
}
```

---

## Architecture Decision Records (ADRs)

### ADR-001: Use OpenCL for GPU Acceleration

**Status:** Accepted

**Context:**
Need GPU acceleration for 10-100x performance. Options: CUDA (NVIDIA only), OpenCL (multi-vendor), or Vulkan Compute.

**Decision:**
Use OpenCL via `ocl` crate.

**Rationale:**
- Temporal Planetarium already has 46 OpenCL kernels (proven working)
- Multi-vendor support (NVIDIA, AMD, Intel)
- Reuse existing `gpu_solver.rs` infrastructure
- Team has OpenCL experience

**Consequences:**
- ✅ Leverage existing code (faster development)
- ✅ Works on more hardware than CUDA
- ❌ Slightly slower than CUDA on NVIDIA (acceptable trade-off)
- ❌ Requires OpenCL drivers (documented in README)

---

### ADR-002: No Private Key Materialization in Rust

**Status:** Accepted

**Context:**
Private keys are sensitive. Accidental logging/storage could compromise security.

**Decision:**
Private keys only exist in GPU kernel local memory. Never transferred to CPU/Rust code.

**Rationale:**
- Prevents accidental leakage (logging, debug output, etc.)
- Aligns with responsible disclosure goals
- Makes malicious modification harder (would require GPU kernel changes)

**Consequences:**
- ✅ Improved security posture
- ✅ Clearer ethical stance
- ❌ Debugging harder (can't inspect private keys)
- ❌ Can't verify private key correctness directly (must test via address generation)

**Mitigation for Debugging:**
Test suite uses known test vectors where expected address is known. If address matches, private key was correct.

---

### ADR-003: Phased Implementation Strategy

**Status:** Accepted

**Context:**
$1B vulnerability with active attacker exploitation. Time pressure vs completeness.

**Decision:**
Ship Phase 1 (60-70% coverage) in Week 1, iterate based on real findings.

**Rationale:**
- Week 1 delivery beats attackers
- Real data informs Phase 2/3 optimizations
- Risk: shipping incomplete scanner
- Bigger risk: waiting 3 weeks while attackers sweep wallets

**Consequences:**
- ✅ Faster time to value (60-70% vs 0% in Week 1)
- ✅ Real-world validation of approach
- ✅ Community can contribute findings to improve coverage
- ❌ Initial version misses 30-40% of wallets (documented limitation)

---

### ADR-004: CPU Fallback Always Available

**Status:** Accepted

**Context:**
Not all users have GPUs. CI environments often lack GPU.

**Decision:**
Maintain functionally complete CPU implementation. GPU is an optimization, not a requirement.

**Rationale:**
- Broader accessibility (any Rust-capable system)
- CI/testing easier (no GPU required)
- Graceful degradation (GPU fails → CPU continues)

**Consequences:**
- ✅ Works everywhere Rust works
- ✅ Testing doesn't require GPU
- ❌ CPU implementation slower (10-100x)
- ❌ Maintenance burden (two code paths)

**Mitigation:**
Extensive tests ensure CPU and GPU produce identical results. GPU is performance layer over CPU logic.

---

### ADR-005: Follow Existing Scanner Patterns

**Status:** Accepted

**Context:**
18 existing scanners with established patterns. Could redesign or reuse.

**Decision:**
Strictly follow existing scanner architecture patterns.

**Rationale:**
- Consistency across codebase (easier maintenance)
- Proven patterns (18 successful implementations)
- Team familiarity (faster development)
- Integration simpler (same interfaces)

**Consequences:**
- ✅ Fast development (copy-paste existing patterns)
- ✅ Consistent user experience
- ✅ Reuse existing utilities (CSV parsing, progress bars, etc.)
- ❌ Inherits any existing pattern limitations (acceptable for consistency)

---

## Implementation Roadmap

### Phase 1: MVP (Week 1)

**Day 1-2: Foundation**
- [ ] Create `src/scans/randstorm/` module structure
- [ ] Implement Chrome V8 PRNG (`prng/chrome_v8.rs`)
- [ ] Create fingerprint database schema
- [ ] Load top 100 browser configs from CSV

**Day 3-4: GPU Integration**
- [ ] Create `cl/randstorm_crack.cl` kernel
- [ ] Implement basic GPU integration (`integration.rs`)
- [ ] Reuse `gpu_solver.rs` for device detection
- [ ] Basic work group sizing

**Day 5-6: CLI & Testing**
- [ ] Add `randstorm-scan` subcommand to `main.rs`
- [ ] Implement progress reporting
- [ ] Write unit tests (PRNG, fingerprint DB)
- [ ] Integration test with test vectors

**Day 7: Validation & Documentation**
- [ ] Validate against Randstorm disclosure examples (100% match required)
- [ ] Performance benchmarks (10x GPU speedup minimum)
- [ ] README documentation
- [ ] Usage examples

**Phase 1 Exit Criteria:**
- ✅ 100% validation on test vectors
- ✅ 10x+ GPU speedup demonstrated
- ✅ 60-70% estimated coverage
- ✅ Zero regressions in existing scanners
- ✅ Documentation complete

### Phase 2: Expansion (Week 2)

**Day 8-9: Additional PRNGs**
- [ ] Firefox SpiderMonkey PRNG
- [ ] Safari JavaScriptCore PRNG
- [ ] IE Chakra PRNG
- [ ] GPU kernel multi-PRNG support

**Day 10-11: Extended Coverage**
- [ ] Expand fingerprint DB to 500 configs
- [ ] Multi-path derivation (BIP32/44/49/84)
- [ ] Batch processing optimization

**Day 12-13: GPU Optimization**
- [ ] Device-specific tuning (NVIDIA/AMD/Intel)
- [ ] Constant memory for fingerprint DB
- [ ] Coalesced memory access

**Day 14: Validation & Release**
- [ ] 85-90% coverage validation
- [ ] 50x+ GPU speedup benchmark
- [ ] Security audit
- [ ] Phase 2 release

**Phase 2 Exit Criteria:**
- ✅ All browser PRNGs implemented
- ✅ 500 configs loaded and tested
- ✅ 50x+ GPU speedup
- ✅ 85-90% estimated coverage
- ✅ Security audit complete (zero critical findings)

### Phase 3: Optimization (Week 3+)

**Week 3: Advanced Features**
- [ ] Probabilistic search algorithms
- [ ] ML-based config prediction (if data available)
- [ ] Adaptive search based on findings

**Week 4: Professional Features**
- [ ] Multi-GPU support
- [ ] Checkpoint/resume functionality
- [ ] PDF report generation
- [ ] 95%+ coverage validation

**Phase 3 Exit Criteria:**
- ✅ 95%+ coverage demonstrated
- ✅ Multi-GPU scaling works
- ✅ Professional features complete
- ✅ Community validation of methodology

---

## Appendix A: Technology Stack

### Core Languages & Frameworks
- **Rust 1.70+** - Primary implementation language (memory safety, performance)
- **OpenCL 1.2+** - GPU acceleration framework

### Rust Crates (Dependencies)
```toml
[dependencies]
# Cryptography
secp256k1 = "0.27"          # Elliptic curve operations
bitcoin = "0.30"            # Bitcoin address generation
bip39 = "2.0"               # HD wallet support

# CLI & I/O
clap = { version = "4.5", features = ["derive"] }  # Command-line parsing
serde = { version = "1.0", features = ["derive"] } # Serialization
serde_json = "1.0"          # JSON support
csv = "1.2"                 # CSV parsing

# Error Handling & Logging
anyhow = "1.0"              # Error handling
tracing = "0.1"             # Structured logging
tracing-subscriber = "0.3"  # Logging subscriber

# GPU (Optional)
ocl = { version = "0.19", optional = true }  # OpenCL bindings

# Parallelism
rayon = "1.7"               # CPU parallelization

# Utilities
chrono = "0.4"              # Date/time handling
hex = "0.4"                 # Hex encoding
zeroize = "1.6"             # Secure memory clearing
```

### Development Tools
```toml
[dev-dependencies]
criterion = "0.5"           # Benchmarking
proptest = "1.2"            # Property-based testing
tempfile = "3.7"            # Temporary files for tests
```

### Build & Deployment
- **cargo** - Rust build system
- **cargo-audit** - Security vulnerability scanning
- **cargo-clippy** - Linting
- **cargo-fmt** - Code formatting

---

## Appendix B: Glossary

**Bitcoin Address:** Public identifier for receiving Bitcoin (derived from public key via hash160)

**BIP (Bitcoin Improvement Proposal):** Standard for Bitcoin features (BIP32 = HD wallets, BIP44 = derivation paths)

**Browser Fingerprint:** Collection of browser/system characteristics that reduce entropy

**Derivation Path:** Sequence defining how to derive child keys from master key (e.g., m/44'/0'/0'/0/0)

**Entropy:** Measure of randomness/unpredictability (256 bits required for Bitcoin private keys)

**GPU Kernel:** Function executed in parallel on GPU (written in OpenCL C)

**Hash160:** RIPEMD160(SHA256(data)) - used in Bitcoin address generation

**HD Wallet:** Hierarchical Deterministic wallet (BIP32) - generates multiple addresses from single seed

**OpenCL:** Open Computing Language - framework for GPU programming

**PRNG:** Pseudo-Random Number Generator - algorithm generating random-like numbers from seed

**Randstorm:** Vulnerability in JavaScript-based Bitcoin wallet generators (2011-2015)

**secp256k1:** Elliptic curve used by Bitcoin for public key cryptography

**Work Group:** Batch of threads executed together on GPU (OpenCL concept)

---

**ARCHITECTURE DOCUMENT COMPLETE**

**Status:** APPROVED FOR IMPLEMENTATION  
**Next Step:** Generate Epics & User Stories (Product Manager)  
**Architect:** Winston  
**Date:** 2025-12-17

---

*This architecture provides a complete technical blueprint for implementing the Randstorm/BitcoinJS Scanner as defined in the PRD. All architectural decisions prioritize pragmatism, security, and rapid delivery to address the critical $1B+ vulnerability before attackers exhaust the search space.*
