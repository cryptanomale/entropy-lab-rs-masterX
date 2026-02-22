# Scanner Implementations

**Version:** 1.0.0  
**Last Updated:** 2026-01-02  
**Document Type:** RAG - Scanner Documentation

## Overview

Entropy Lab RS implements 15+ vulnerability scanners targeting different cryptocurrency wallet vulnerabilities. Each scanner follows consistent patterns while implementing vulnerability-specific logic.

## Scanner Catalog

### 1. Randstorm/BitcoinJS Scanner

**CVE/Disclosure**: 2011-2015 vulnerability, disclosed 2023  
**Affected**: Blockchain.info, CoinPunk, BrainWallet, other BitcoinJS users  
**Impact**: 1.4M+ BTC at risk ($1B+)  
**Status**: Partially implemented (67% complete)

**Location**: `crates/temporal-planetarium-lib/src/scans/randstorm/`

**Architecture** (26 files):
- `engines/`: JavaScript PRNG implementations (V8, ChakraCore, Safari, SpiderMonkey)
- `prng/`: Specific PRNGs (BitcoinJS v0.1.3, LCG, LFSR, Safari/Windows)
- `cpu/`: CPU reference implementation
- `fingerprints/`: AES-encrypted target fingerprints
- Core modules: attack_estimator, checkpoint, cli, config, forensics, GPU/WGPU integration, heuristics, validator, z3_solver

**Key Features**:
- Bit-perfect JavaScript PRNG reconstruction
- Z3 SMT solver for state recovery
- Multiple engine support (V8, ChakraCore, Safari, SpiderMonkey)
- Checkpoint/resume capability
- GPU/CPU dual execution
- Encrypted fingerprint matching

**Example Usage**:
```rust
use temporal_planetarium_lib::scans::randstorm::{RandstormScanner, ScanConfig};

let config = ScanConfig {
    engine: Engine::V8,
    start_timestamp: 1293840000,
    end_timestamp: 1420070400,
    ..Default::default()
};

let scanner = RandstormScanner::new(config)?;
scanner.scan(progress_tx)?;
```

### 2. Trust Wallet Scanner

**CVE**: CVE-2023-31290 (MT19937), CVE-2024-23660 (LCG)  
**Affected**: Trust Wallet (Android/iOS)  
**Impact**: Deterministic wallet generation from timestamps  
**Status**: ✅ Complete

**Location**: `crates/temporal-planetarium-lib/src/scans/trust_wallet/`

**Variants**:
- **MT19937 (Android)**: Mersenne Twister PRNG seeded with millisecond timestamp
- **minstd_rand0 (iOS)**: Linear Congruential Generator (LCG) with `a=16807, m=2^31-1`

**GPU Kernels**: `trust_wallet_crack.cl`, `trust_wallet_multipath.cl`

**Example Usage**:
```rust
use temporal_planetarium_lib::scans::trust_wallet;

// Android (MT19937)
trust_wallet::standard::run(target_address, start_ts, end_ts)?;

// iOS (LCG)
trust_wallet::lcg::run(target_address, start_ts, end_ts)?;
```

**Implementation Pattern**:
```rust
// MT19937 state generation
let mut mt = Mt19937::new(timestamp_ms);
let entropy = mt.generate_words(8); // 256 bits

// LCG state generation (minstd_rand0)
let mut state = timestamp_sec as u64;
for _ in 0..256 {
    state = (state * 16807) % 0x7FFFFFFF;
    // Use state for entropy
}
```

### 3. Cake Wallet Scanner

**CVE/Disclosure**: 2024 vulnerability  
**Affected**: Cake Wallet (2020-2021)  
**Impact**: ~8,717 vulnerable wallets (20-bit entropy)  
**Status**: ✅ Complete

**Location**: `crates/temporal-planetarium-lib/src/scans/cake_wallet/`

**Modules**:
- `standard.rs`: Basic 20-bit entropy scan
- `prng.rs`: Dart PRNG time-based reconstruction
- `targeted.rs`: Hash matching against known vulnerables
- `crack.rs`: GPU-accelerated address cracking
- `rpc.rs`: RPC balance checking

**GPU Kernels**: `cake_wallet_crack.cl`, `batch_cake_full.cl`, `cake_hash.cl`

**Dart PRNG Implementation**:
```dart
// Original Dart PRNG weakness
final random = Random(DateTime.now().millisecondsSinceEpoch);
final entropy = List.generate(32, (_) => random.nextInt(256));
```

**Scanner Implementation**:
```rust
// Reconstruct Dart Random state
let timestamp_ms = ...; // 2020-2021 range
let mut prng = DartRandom::new(timestamp_ms as u64);
let entropy: Vec<u8> = (0..32).map(|_| prng.next_u8()).collect();

// Generate Electrum mnemonic
let mnemonic = electrum::create_electrum_seed(&entropy)?;
```

### 4. Libbitcoin Milk Sad Scanner

**CVE**: CVE-2023-39910  
**Affected**: Libbitcoin Explorer (bx) 3.0.0 - 3.6.0  
**Impact**: Deterministic seed generation from weak entropy  
**Status**: ✅ Complete

**Location**: `crates/temporal-planetarium-lib/src/scans/milk_sad.rs`

**GPU Kernels**: `milk_sad_crack.cl`, `milk_sad_multipath.cl`

**Vulnerability Pattern**:
```cpp
// Libbitcoin weakness: insufficient entropy from system source
bc::data_chunk entropy(16);
bc::pseudo_random_fill(entropy); // Weak on some systems
auto mnemonic = bc::wallet::create_mnemonic(entropy);
```

**Scanner Features**:
- Multi-path derivation (BIP44/49/84)
- GPU-accelerated address generation
- Bloom filter for fast lookups
- RPC balance checking

### 5. Android SecureRandom Scanner

**CVE/Advisory**: 2013 Bitcoin wallet vulnerability  
**Affected**: Android Bitcoin wallets (pre-4.4)  
**Impact**: Duplicate R values allow private key recovery  
**Status**: ✅ Complete with nonce reuse detection

**Location**: `crates/temporal-planetarium-lib/src/scans/android_securerandom/`

**Vulnerability**: Insufficient SecureRandom entropy led to ECDSA nonce reuse (duplicate R values).

**Two-Phase Approach**:
1. **Nonce Reuse Detection**: Scan blockchain for duplicate R values
2. **Private Key Recovery**: Compute private key from two signatures with same R

**Implementation**:
```rust
// Phase 1: Detect duplicate R values
pub struct RValueIndex {
    r_values: HashMap<[u8; 32], Vec<SignatureInfo>>,
}

// Phase 2: Recover private key
pub fn recover_private_key(
    r: &[u8; 32],
    s1: &[u8; 32],
    s2: &[u8; 32],
    z1: &[u8; 32], // sighash
    z2: &[u8; 32],
) -> Result<SecretKey> {
    // k = (z1 - z2) / (s1 - s2) mod n
    // private_key = (s1 * k - z1) / r mod n
}
```

### 6. Profanity Scanner

**CVE**: CVE-2022-40769  
**Affected**: Profanity vanity address generator  
**Impact**: Private keys can be brute-forced from vanity addresses  
**Status**: Partially implemented

**Location**: `crates/temporal-planetarium-lib/src/scans/profanity.rs`

**GPU Kernels**: `batch_profanity.cl`

**Vulnerability**: Profanity used only 32 bits of entropy for private key generation, making brute-force feasible.

### 7. Brainwallet Scanner

**Category**: Weak passphrase analysis  
**Affected**: Any brainwallet implementation  
**Impact**: Dictionary/common phrase attacks  
**Status**: ✅ Complete

**Location**: `crates/temporal-planetarium-lib/src/scans/brainwallet.rs`

**Features**:
- Dictionary-based passphrase testing
- Common phrase patterns
- GPU-accelerated hash computation
- Integration with known compromised wallets

**GPU Kernels**: Multiple SHA-256 implementations

### 8. Mobile Sensor Scanner

**Category**: Sensor-based entropy attacks  
**Affected**: Mobile wallets using device sensors for entropy  
**Impact**: Predictable entropy from accelerometer/gyroscope  
**Status**: ✅ Complete

**Location**: `crates/temporal-planetarium-lib/src/scans/mobile_sensor.rs`

**GPU Kernels**: `mobile_sensor_crack.cl`, `mobile_sensor_hash.cl`

### 9. Additional Scanners

**BIP3x PCG Scanner** (`bip3x.rs`): Tests bip3x PCG PRNG implementation  
**Direct Key** (`direct_key.rs`): Direct private key import/analysis  
**EC_NEW** (`ec_new.rs`): OpenSSL EC_KEY_new vulnerability  
**Malicious Extension** (`malicious_extension.rs`): Browser extension attacks  
**Passphrase Recovery** (`passphrase_recovery.rs`): BIP39 passphrase brute-force  
**Verify CSV** (`verify_csv.rs`): CSV data validation

## Common Scanner Patterns

### Scanner Trait

All scanners can implement:
```rust
pub trait Scanner {
    fn scan(&self, progress_tx: UnboundedSender<ScanProgress>) -> anyhow::Result<()>;
}
```

### Progress Reporting

```rust
use tokio::sync::mpsc::unbounded_channel;

let (tx, mut rx) = unbounded_channel();

// Scanner sends progress
tx.send(ScanProgress {
    current: 1000,
    total: 1000000,
    found: vec![finding],
})?;

// UI receives progress
while let Some(progress) = rx.recv().await {
    println!("Progress: {}/{}", progress.current, progress.total);
}
```

### GPU Acceleration Pattern

```rust
#[cfg(feature = "gpu")]
pub fn scan_gpu(targets: &[Address]) -> Result<Vec<Finding>> {
    use crate::scans::gpu_solver::GpuSolver;
    
    let mut solver = GpuSolver::new()?;
    solver.load_kernel("scanner_kernel")?;
    solver.scan_batch(targets)
}

#[cfg(not(feature = "gpu"))]
pub fn scan_gpu(_targets: &[Address]) -> Result<Vec<Finding>> {
    anyhow::bail!("GPU support not enabled. Recompile with --features gpu")
}
```

### CPU Fallback Pattern

```rust
pub fn scan(targets: &[Address], use_gpu: bool) -> Result<Vec<Finding>> {
    if use_gpu {
        match scan_gpu(targets) {
            Ok(results) => return Ok(results),
            Err(e) => {
                warn!("GPU scan failed: {}, falling back to CPU", e);
            }
        }
    }
    
    scan_cpu(targets)
}
```

## Scanner Configuration

### Common Configuration Options

```rust
pub struct ScanConfig {
    pub start_timestamp: u64,      // Start of time range
    pub end_timestamp: u64,        // End of time range
    pub batch_size: usize,         // Batch processing size
    pub use_gpu: bool,             // Enable GPU acceleration
    pub checkpoint_interval: u64,  // Checkpoint frequency
    pub target_addresses: Vec<Address>, // Addresses to search for
}
```

### Feature-Specific Configuration

**Randstorm**:
```rust
pub struct RandstormConfig {
    pub engine: JavaScriptEngine,  // V8, ChakraCore, Safari, SM
    pub use_z3: bool,              // Enable Z3 solver
    pub fingerprint_path: PathBuf, // Encrypted fingerprints
}
```

**Trust Wallet**:
```rust
pub struct TrustWalletConfig {
    pub prng_type: PrngType,       // MT19937 or LCG
    pub network: Network,          // Bitcoin, Ethereum, etc.
    pub derivation_path: DerivationPath,
}
```

## Testing Scanners

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_scanner_basic() {
        let config = ScanConfig::default();
        let scanner = Scanner::new(config).unwrap();
        // Test scanner logic
    }
}
```

### Integration Tests

Located in `tests/` directory:
- `cake_wallet_unit.rs`
- `trust_wallet_unit.rs`
- `randstorm_integration.rs`
- `test_gpu_cpu_parity.rs`

### Test Vectors

Golden test data in `tests/fixtures/shared_test_vectors.json`:
```json
{
  "trust_wallet_mt19937": [
    {
      "timestamp": 1609459200000,
      "expected_mnemonic": "abandon abandon...",
      "expected_address": "bc1q..."
    }
  ]
}
```

## Performance Characteristics

### Scanner Complexity

| Scanner | CPU Complexity | GPU Speedup | Typical Runtime |
|---------|---------------|-------------|-----------------|
| Trust Wallet | O(n) | 50-100x | Minutes |
| Cake Wallet | O(n) | 50-100x | Minutes |
| Randstorm | O(n²) | 10-50x | Hours |
| Milk Sad | O(n) | 50-100x | Minutes |
| Brainwallet | O(n) | 100x+ | Varies |
| Android SecureRandom | O(n²) | N/A | Hours |

### Optimization Strategies

1. **Bloom Filters**: Fast set membership testing
2. **Batch Processing**: Amortize GPU overhead
3. **Early Exit**: Stop on first match (if applicable)
4. **Checkpointing**: Resume interrupted scans
5. **Multi-Path Derivation**: Check multiple addresses per seed

---

**Related Documents**:
- [GPU Acceleration](05-gpu-acceleration.md)
- [Cryptographic Operations](06-cryptographic-operations.md)
- [Performance Optimization](14-performance-optimization.md)
- [Testing Strategy](09-testing-strategy.md)
