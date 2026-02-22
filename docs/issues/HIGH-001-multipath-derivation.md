# HIGH-001: Implement Multi-Path Derivation (BIP44/49/84/86)

**Priority**: 🟡 HIGH  
**Type**: Feature Enhancement  
**Epic**: Epic 1 - Core Scanning Engine  
**Story**: Story 1.3 (partial) - Extended coverage  
**Estimated Effort**: 1 week  
**Assigned**: TBD  

---

## Problem Statement

Current scanner implementations only check a **single derivation path** (typically `m/44'/0'/0'/0/0` or similar). This misses approximately **75% of potential addresses** per seed that use different BIP standards.

## Current Behavior

Example from milk_sad.rs:
```rust
// Only checks one path
let path = "m/44'/0'/0'/0/0";
let address = derive_address(&seed, path);
check_if_match(address);
```

## Desired Behavior

Should check all common derivation paths:

```rust
let paths = vec![
    "m/44'/0'/0'/0/0",  // BIP44 (Legacy)
    "m/49'/0'/0'/0/0",  // BIP49 (SegWit-wrapped)
    "m/84'/0'/0'/0/0",  // BIP84 (Native SegWit)
    "m/86'/0'/0'/0/0",  // BIP86 (Taproot)
];

for path in paths {
    let address = derive_address(&seed, path);
    check_if_match(address);
}
```

## Impact of Current Limitation

**Coverage Gap**: Missing 75% of addresses
- Many wallets default to BIP49 or BIP84 instead of BIP44
- Taproot (BIP86) wallets growing in adoption
- Multi-coin wallets use different paths per coin

**Example Scenario**:
- Vulnerable seed generated with weak entropy
- User creates BIP84 wallet (native SegWit)
- Scanner only checks BIP44 path
- **Vulnerability missed!**

## Technical Details

### BIP Standards Overview

| BIP | Path Template | Address Type | Example Prefix |
|-----|--------------|--------------|----------------|
| 44 | m/44'/0'/0'/0/x | P2PKH (Legacy) | `1...` |
| 49 | m/49'/0'/0'/0/x | P2SH-P2WPKH (Wrapped SegWit) | `3...` |
| 84 | m/84'/0'/0'/0/x | P2WPKH (Native SegWit) | `bc1q...` |
| 86 | m/86'/0'/0'/0/x | P2TR (Taproot) | `bc1p...` |

### Implementation Strategy

#### Phase 1: Add Multi-Path Support to Core Derivation

Modify `derive_address()` functions to support path array:

```rust
pub fn derive_addresses_multipath(
    seed: &[u8],
    account: u32,
    index: u32,
) -> Vec<(String, String)> {  // (path, address)
    let paths = [
        (44, AddressType::P2PKH),
        (49, AddressType::P2SH_P2WPKH),
        (84, AddressType::P2WPKH),
        (86, AddressType::P2TR),
    ];
    
    paths.iter().map(|(purpose, addr_type)| {
        let path = format!("m/{}'/{}'/{}'/{}/{}", purpose, 0, account, 0, index);
        let address = derive_address_typed(seed, &path, *addr_type);
        (path, address)
    }).collect()
}
```

#### Phase 2: Update Scanners

Update each scanner to use multi-path:

**Before**:
```rust
let address = derive_p2pkh_address(&seed);
if target_addresses.contains(&address) {
    println!("Match found!");
}
```

**After**:
```rust
let addresses = derive_addresses_multipath(&seed, 0, 0);
for (path, address) in addresses {
    if target_addresses.contains(&address) {
        println!("Match found at path {}: {}", path, address);
    }
}
```

#### Phase 3: GPU Kernels

Update OpenCL kernels to generate all path types:

```c
// In kernel
__kernel void scan_multipath(
    __global const uint* timestamps,
    __global const char* target_addresses,
    __global uint* results
) {
    // Generate seed
    uint8_t seed[64];
    generate_seed(timestamp, seed);
    
    // Derive for each BIP path
    derive_and_check_bip44(seed, target_addresses, results);
    derive_and_check_bip49(seed, target_addresses, results);
    derive_and_check_bip84(seed, target_addresses, results);
    derive_and_check_bip86(seed, target_addresses, results);
}
```

## Affected Scanners

All vulnerability scanners should support multi-path:

- [x] Milk Sad (`milk_sad.rs`) - **Already has `milk_sad_multipath.cl` kernel!**
- [x] Trust Wallet (`trust_wallet/`) - **Already has `trust_wallet_multipath.cl`!**
- [ ] Cake Wallet (`cake_wallet/`)
- [ ] Randstorm (`randstorm/`)
- [ ] Direct Key (`direct_key.rs`)
- [ ] Mobile Sensor (`mobile_sensor.rs`)
- [ ] Brainwallet (`brainwallet.rs`)
- [ ] Profanity (`profanity.rs`)

**Good news**: Multi-path kernels already exist for Milk Sad and Trust Wallet!

## Implementation Checklist

### Week 1: Core Implementation

- [ ] Day 1: Add multi-path support to CPU derivation utilities
  - [ ] Implement `derive_addresses_multipath()` helper
  - [ ] Support all 4 BIP standards (44/49/84/86)
  - [ ] Add unit tests for each path type

- [ ] Day 2-3: Update Cake Wallet scanner
  - [ ] Add `--multipath` CLI flag
  - [ ] Use existing `cake_wallet_crack.cl` as template
  - [ ] Update GPU kernel for multi-path
  - [ ] Add integration test

- [ ] Day 4-5: Update Randstorm scanner
  - [ ] Modify `randstorm/derivation.rs` for multi-path
  - [ ] Update WGSL shader `randstorm.wgsl`
  - [ ] Update OpenCL kernel (if exists)
  - [ ] Add integration test

### Testing

- [ ] Verify multi-path derivation with known test vectors
- [ ] Ensure BIP49 addresses use correct P2SH-P2WPKH format
- [ ] Test with existing Milk Sad multi-path kernel
- [ ] GPU/CPU parity check for all paths

### Documentation

- [ ] Update scanner documentation explaining multi-path support
- [ ] Add `--multipath` flag to CLI help text
- [ ] Update README examples
- [ ] Document performance implications (4x more derivations)

## Performance Considerations

**Computational Cost**: 4x increase (4 paths vs 1 path)

**Mitigation**:
- GPU parallelization handles this well (still faster than CPU single-path)
- Can make multi-path optional via CLI flag
- Bloom filter optimization becomes more important

**Expected Performance**:
- CPU: ~1,500 seeds/sec (down from ~6,000) - still acceptable
- GPU: ~50,000 seeds/sec (down from ~200,000) - still excellent

## Acceptance Criteria

- [ ] All scanners support `--multipath` flag (or enabled by default)
- [ ] Addresses generated for BIP44, BIP49, BIP84, and BIP86
- [ ] GPU kernels updated for multi-path (where GPU support exists)
- [ ] Integration tests validate multi-path derivation
- [ ] Documentation updated
- [ ] Performance benchmarks run (acceptable degradation)

## Additional Context

See:
- Audit Report: `docs/CODEBASE_AUDIT_2026-01.md` Section 6.3.3
- Existing multi-path kernels: `cl/milk_sad_multipath.cl`, `cl/trust_wallet_multipath.cl`
- BIP specs: BIP32, BIP44, BIP49, BIP84, BIP86

## Related Issues

- Depends on: Extended address index scanning (HIGH-002)
- Blocks: Complete coverage of vulnerable wallets

## Labels

`high-priority`, `feature`, `enhancement`, `multipath`, `epic-1`, `coverage`
