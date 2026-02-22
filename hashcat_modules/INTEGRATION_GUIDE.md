# Hashcat Module Integration Guide

## Overview

This document explains how the C module files in this directory integrate with the OpenCL kernels from the `cl/` directory to create complete hashcat modules.

## Architecture

### Two-Part System

Hashcat modules consist of two components:

1. **C Module (Host-side)** - This directory
   - Parses hash input format
   - Decodes Bitcoin addresses (Base58/Bech32)
   - Validates parameters
   - Populates esalt structure
   - Manages module metadata

2. **OpenCL Kernel (Device-side)** - `../cl/` directory
   - Runs on GPU
   - Performs cryptographic operations
   - Derives wallets from timestamps/entropy
   - Compares against target address

## Module Mapping

### Module 30501 (Milk Sad)

**C Module:** `module_30501.c`
- Parses: `$milksad$<purpose>$<timestamp>$<address>`
- Decodes addresses (P2PKH, P2SH, P2WPKH)
- Validates purpose (44/49/84) and timestamp range
- Populates `milksad_t` esalt structure

**OpenCL Kernel:** `../cl/milk_sad_multipath.cl`
- Implements MT19937 PRNG (MSB extraction)
- BIP39 entropy to mnemonic conversion
- BIP32 derivation for BIP44/49/84 paths
- Address generation and comparison
- Uses: `mt19937.cl`, `bip39_full.cl`, `secp256k1*.cl`, `sha2.cl`, `ripemd.cl`

**esalt Structure:**
```c
typedef struct milksad {
  u32 purpose;              // 44, 49, or 84
  u32 timestamp;            // Seed for MT19937
  u8  target_hash160[20];   // Decoded from address
  u8  padding[4];
} milksad_t;
```

### Module 30502 (Trust Wallet)

**C Module:** `module_30502.c`
- Parses: `$trustwallet$<purpose>$<timestamp>$<address>`
- Decodes addresses (P2PKH, P2SH, P2WPKH)
- Validates purpose (44/49/84) and timestamp range (Nov 2022)
- Populates `trustwallet_t` esalt structure

**OpenCL Kernel:** `../cl/trust_wallet_multipath.cl`
- Implements MT19937 PRNG (LSB extraction - KEY DIFFERENCE)
- BIP39 entropy to mnemonic conversion
- BIP32 derivation for BIP44/49/84 paths
- Address generation and comparison
- Uses: Same dependencies as Milk Sad

**esalt Structure:**
```c
typedef struct trustwallet {
  u32 purpose;
  u32 timestamp;
  u8  target_hash160[20];
  u8  padding[4];
} trustwallet_t;
```

**Critical Difference:**
- Milk Sad: `entropy[i] = (mt19937() >> 24) & 0xFF` (MSB)
- Trust Wallet: `entropy[i] = mt19937() & 0xFF` (LSB)

### Module 30503 (Cake Wallet)

**C Module:** `module_30503.c`
- Parses: `$cakewallet$<address>`
- Decodes Bech32 P2WPKH addresses only
- No purpose or timestamp fields
- Populates `cakewallet_t` esalt structure

**OpenCL Kernel:** `../cl/cake_wallet_crack.cl` or `../cl/batch_address_electrum.cl`
- Implements weak PRNG (2^20 entropy space)
- Electrum seed format (not BIP39)
- Derives m/0'/0/0 (Electrum-style)
- P2WPKH address generation only
- Uses: `bip39_full.cl`, `secp256k1*.cl`, `sha2.cl`, `ripemd.cl`

**esalt Structure:**
```c
typedef struct cakewallet {
  u8  target_hash160[20];
  u8  padding[12];
} cakewallet_t;
```

## Integration Steps

### 1. Copy Files to Hashcat

Assuming hashcat is cloned at `/path/to/hashcat`:

```bash
# Copy C modules
cp hashcat_modules/module_30501.c /path/to/hashcat/src/modules/
cp hashcat_modules/module_30502.c /path/to/hashcat/src/modules/
cp hashcat_modules/module_30503.c /path/to/hashcat/src/modules/

# Copy OpenCL kernels (rename to hashcat convention)
cp cl/milk_sad_multipath.cl /path/to/hashcat/OpenCL/m30501_a3-pure.cl
cp cl/trust_wallet_multipath.cl /path/to/hashcat/OpenCL/m30502_a3-pure.cl
cp cl/cake_wallet_crack.cl /path/to/hashcat/OpenCL/m30503_a3-pure.cl

# Copy dependencies
cp cl/common.cl /path/to/hashcat/OpenCL/
cp cl/mt19937.cl /path/to/hashcat/OpenCL/
cp cl/sha2.cl /path/to/hashcat/OpenCL/
cp cl/ripemd.cl /path/to/hashcat/OpenCL/
cp cl/sha512.cl /path/to/hashcat/OpenCL/
cp cl/secp256k1_*.cl /path/to/hashcat/OpenCL/
cp cl/bip39_*.cl /path/to/hashcat/OpenCL/
```

### 2. Kernel Naming Convention

Hashcat uses a specific naming pattern for kernels:

- `m<MODE>_a<ATTACK>-<TYPE>.cl`
  - `<MODE>`: Module number (30501, 30502, 30503)
  - `<ATTACK>`: Attack mode (0=straight, 1=combination, 3=brute-force)
  - `<TYPE>`: pure (OpenCL only) or optimized (device-specific)

For these modules:
- `m30501_a3-pure.cl` - Milk Sad, brute-force attack, pure kernel
- `m30502_a3-pure.cl` - Trust Wallet, brute-force attack, pure kernel
- `m30503_a3-pure.cl` - Cake Wallet, brute-force attack, pure kernel

### 3. Build Hashcat

```bash
cd /path/to/hashcat
make clean
make
```

### 4. Verify Modules

```bash
# Check if modules are recognized
./hashcat --version
./hashcat -m 30501 --help
./hashcat -m 30502 --help
./hashcat -m 30503 --help

# Run self-test
./hashcat --self-test-disable -m 30501
./hashcat --self-test-disable -m 30502
./hashcat --self-test-disable -m 30503

# Benchmark
./hashcat -m 30501 --benchmark
./hashcat -m 30502 --benchmark
./hashcat -m 30503 --benchmark
```

## Data Flow

### Milk Sad / Trust Wallet Flow

```
User Input: $milksad$49$1514764800$3HERnjC6RDwg6UYx1hHiAKUp6gz1217h2U
    ↓
module_hash_decode():
    ├─ Parse purpose: 49
    ├─ Parse timestamp: 1514764800
    └─ Decode address: 3HERn... → hash160[20]
    ↓
esalt structure:
    {
      purpose: 49,
      timestamp: 1514764800,
      target_hash160: [0x12, 0x34, ...]
    }
    ↓
GPU Kernel (milk_sad_multipath.cl):
    ├─ MT19937(1514764800) → entropy
    ├─ BIP39(entropy) → mnemonic → seed
    ├─ BIP32 derive m/49'/0'/0'/0/0
    ├─ Generate P2SH-P2WPKH address
    └─ Compare hash160 with target
    ↓
Match found: timestamp 1514764800 generates target address
```

### Cake Wallet Flow

```
User Input: $cakewallet$bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c
    ↓
module_hash_decode():
    └─ Decode Bech32: bc1q... → hash160[20]
    ↓
esalt structure:
    {
      target_hash160: [0xab, 0xcd, ...]
    }
    ↓
GPU Kernel (cake_wallet_crack.cl):
    ├─ Loop i = 0 to 2^20
    ├─ Generate Electrum seed from i
    ├─ Derive m/0'/0/0
    ├─ Generate P2WPKH address
    └─ Compare hash160 with target
    ↓
Match found: entropy value generates target address
```

## Kernel Requirements

### Required Include Files

All kernels need access to:

1. **Common Utilities** (`common.cl`)
   - Type definitions
   - Utility functions

2. **Cryptographic Primitives**
   - `sha2.cl` - SHA256
   - `ripemd.cl` - RIPEMD160
   - `sha512.cl` - SHA512 for BIP32/39

3. **BIP39 Implementation**
   - `bip39_full.cl` - Main BIP39 logic
   - `bip39_helpers.cl` - Helper functions
   - `bip39_pbkdf2.cl` - PBKDF2 for seed derivation
   - `bip39_wordlist.cl` - BIP39 word list

4. **Secp256k1 Implementation**
   - `secp256k1_common.cl` - Common definitions
   - `secp256k1_field.cl` - Field operations
   - `secp256k1_group.cl` - Point operations
   - `secp256k1_scalar.cl` - Scalar operations
   - `secp256k1_prec.cl` - Precomputation tables

5. **PRNG Implementations**
   - `mt19937.cl` - Mersenne Twister (for Milk Sad/Trust Wallet)

### Kernel Entry Points

Each kernel must implement:

```c
// Main search kernel (attack mode 3 - brute force)
KERNEL_FQ void m30501_mxx (KERN_ATTR_BASIC ())
{
  // 1. Get work item ID
  // 2. Generate candidate (from timestamp/entropy)
  // 3. Derive wallet address
  // 4. Compare with target
  // 5. Report match if found
}

// Additional kernel for attack mode optimization
KERNEL_FQ void m30501_sxx (KERN_ATTR_BASIC ())
{
  // Similar to mxx but for specific attack modes
}
```

## Performance Considerations

### Expected Performance (RTX 3090)

- **Milk Sad (30501)**: 5-10 GH/s
  - Full 2018 scan: ~3 seconds
  - Bottleneck: BIP32 derivation + secp256k1

- **Trust Wallet (30502)**: 5-10 GH/s
  - Full vulnerable window: <1 second
  - Same bottleneck as Milk Sad

- **Cake Wallet (30503)**: 30-60 GH/s
  - Full 2^20 space: <1 second
  - Faster due to Electrum (simpler than BIP39)

### Optimization Opportunities

1. **Precomputation Tables**
   - Store common secp256k1 points in constant memory
   - ~60KB for significant speedup

2. **Work Group Size**
   - Optimal: 64-256 threads per workgroup
   - Depends on GPU architecture

3. **Memory Coalescing**
   - Align data structures to 128-byte boundaries
   - Use proper memory access patterns

## Debugging

### Common Issues

1. **Kernel Compilation Errors**
   - Check that all include files are present
   - Verify OpenCL syntax compatibility
   - Use `--force` to skip kernel cache

2. **Incorrect Results**
   - Verify address decoding (Base58/Bech32)
   - Check endianness in hash160 comparison
   - Validate PRNG implementation

3. **Performance Problems**
   - Profile with hashcat's `-O` flag
   - Check kernel_loops and kernel_accel settings
   - Monitor GPU utilization

### Testing Strategy

1. **Unit Tests**
   - Test each address decoder separately
   - Verify checksum calculations
   - Validate parameter ranges

2. **Integration Tests**
   - Use known test vectors
   - Verify against reference implementations
   - Test all address types

3. **Performance Tests**
   - Benchmark against expected speeds
   - Compare with similar hashcat modules
   - Test on different GPU architectures

## References

- Hashcat Module Development: https://github.com/hashcat/hashcat/blob/master/docs/hashcat-plugin-development-guide.md
- Milk Sad: https://milksad.info/
- Entropy Lab RS: https://github.com/5n10sndkts-eng/entropy-lab-rs
- BIP39: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
- BIP32: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

## License

MIT (same as hashcat and entropy-lab-rs)
