# HIGH-002: Implement Extended Address Index Scanning (0-100+)

**Priority**: 🟡 HIGH  
**Type**: Feature Enhancement  
**Epic**: Epic 1 - Core Scanning Engine  
**Story**: Story 1.3 - Extended coverage  
**Estimated Effort**: 2-3 days  
**Assigned**: TBD  

---

## Problem Statement

Current scanner implementations only check **address index 0** (e.g., `m/44'/0'/0'/0/0`). This misses **95%+ of addresses** that use higher indices (e.g., `m/44'/0'/0'/0/1` through `m/44'/0'/0'/0/100`).

## Current Behavior

```rust
// Only checks index 0
let path = "m/44'/0'/0'/0/0";
let address = derive_address(&seed, path);
```

## Desired Behavior

```rust
// Check indices 0 through 100 (configurable)
for index in 0..=100 {
    let path = format!("m/44'/0'/0'/0/{}", index);
    let address = derive_address(&seed, &path);
    check_if_match(address);
}
```

## Impact of Current Limitation

**Coverage Gap**: Missing 95%+ of addresses

**Real-World Scenario**:
1. User generates wallet with weak entropy
2. Receives payment to address #5 (`m/44'/0'/0'/0/5`)
3. Scanner only checks address #0
4. **Vulnerability missed!**

**Typical Usage Patterns**:
- Most wallets generate 20-100 addresses by default
- HD wallets generate new address for each transaction (privacy)
- Business wallets may use hundreds of addresses

## Technical Details

### HD Wallet Index Convention

BIP32 derivation path format:
```
m / purpose' / coin_type' / account' / change / address_index
```

**Key Point**: `address_index` is NOT hardened (no `'`)

**Common ranges**:
- **Minimal scan**: 0-20 (covers most casual users)
- **Standard scan**: 0-100 (covers 99% of users)
- **Comprehensive scan**: 0-1000 (businesses, heavy users)
- **Exhaustive scan**: 0-1,000,000+ (impractical for brute-force)

### Implementation Strategy

#### Option A: Fixed Range (Simple)

Add CLI flag for index range:

```rust
#[arg(long, default_value = "100")]
max_address_index: u32,
```

```rust
for index in 0..=max_address_index {
    let address = derive_address_at_index(&seed, index);
    check_if_match(address);
}
```

**Pros**: Simple, predictable, easy to benchmark
**Cons**: May scan too many (slow) or too few (miss addresses)

#### Option B: Gap Limit Strategy (Smarter)

Use "gap limit" heuristic (like Electrum):

```rust
const GAP_LIMIT: u32 = 20;  // Stop after 20 consecutive unused addresses

let mut gap_count = 0;
let mut index = 0;

while gap_count < GAP_LIMIT {
    let address = derive_address_at_index(&seed, index);
    
    if check_if_match(address) {
        gap_count = 0;  // Reset gap
        // Continue scanning
    } else {
        gap_count += 1;
    }
    
    index += 1;
}
```

**Pros**: Adapts to actual usage, stops early if no matches
**Cons**: More complex, requires tracking state

#### Option C: Hybrid (Recommended)

Combine both approaches:

```rust
--max-index <N>      // Hard limit (default: 100)
--gap-limit <N>      // Stop after N misses (default: 20)
--min-index <N>      // Always check at least N (default: 10)
```

**Pros**: Flexible, efficient, covers edge cases
**Cons**: More CLI options

### GPU Optimization

Extended index scanning is **perfect for GPU parallelization**:

**Naive approach** (sequential):
```
for index in 0..100:
    derive(seed, index)  # 100 sequential operations
```

**GPU approach** (parallel):
```
Launch 100 threads in parallel
Each thread derives one index
All complete in ~same time as one derivation
```

**Expected speedup**: ~100x for index scanning on GPU!

## Implementation Checklist

### Day 1: Core Infrastructure

- [ ] Add `max_address_index` parameter to derivation functions
- [ ] Update `derive_address()` to accept index parameter
- [ ] Add helper `derive_addresses_range(seed, start, end) -> Vec<Address>`
- [ ] Add unit tests for index range derivation

### Day 2: Scanner Integration

- [ ] Update Milk Sad scanner for index range
- [ ] Update Trust Wallet scanner
- [ ] Update Cake Wallet scanner
- [ ] Update CLI flags

### Day 3: GPU Kernels

- [ ] Update OpenCL kernels to support index ranges
- [ ] Optimize for parallel index derivation
- [ ] Add GPU/CPU parity tests

### Testing & Documentation

- [ ] Integration test with known seed at index 50
- [ ] Performance benchmark (index 0 only vs 0-100)
- [ ] Update README with index scanning explanation
- [ ] Document performance implications

## Performance Analysis

### CPU Performance

**Single index** (baseline): ~6,000 seeds/sec

**100 indices**: 
- Naive: ~60 seeds/sec (100x slower)
- With early termination (gap limit): ~200-500 seeds/sec
- Still acceptable for targeted scans

### GPU Performance

**Single index** (baseline): ~200,000 seeds/sec

**100 indices** (parallel):
- ~150,000-180,000 seeds/sec (minimal overhead!)
- GPU can handle 100+ threads per seed easily
- Memory bandwidth becomes limiting factor, not compute

### Optimization Strategies

1. **Batch Processing**: Derive multiple indices per GPU dispatch
2. **Early Termination**: Stop scanning if no matches in first 20 indices
3. **Selective Scanning**: Only scan extended range for "hot" seeds (RPC balance check)

## Acceptance Criteria

- [ ] All scanners support `--max-address-index` flag
- [ ] Default range: 0-100 (configurable)
- [ ] Optional `--gap-limit` for smart termination
- [ ] GPU kernels optimized for parallel index scanning
- [ ] Integration tests validate index > 0 addresses found
- [ ] Documentation explains index scanning
- [ ] Performance benchmarks show acceptable overhead

## Example Usage

```bash
# Scan first 10 addresses only (fast)
cargo run --release -- milk-sad --target bc1qXXX --max-address-index 10

# Comprehensive scan (slower but thorough)
cargo run --release -- milk-sad --target bc1qXXX --max-address-index 1000

# Smart scan with gap limit
cargo run --release -- milk-sad --target bc1qXXX --gap-limit 20
```

## Combined with Multi-Path

When combined with multi-path derivation (HIGH-001):

```
4 paths × 100 indices = 400 addresses per seed

CPU:  ~15 seeds/sec (acceptable)
GPU:  ~50,000 seeds/sec (excellent)
```

## Additional Context

See:
- Audit Report: `docs/CODEBASE_AUDIT_2026-01.md` Section 6.3.4
- BIP32: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
- Electrum gap limit: https://electrum.readthedocs.io/en/latest/
- Related: HIGH-001 (Multi-path derivation)

## Labels

`high-priority`, `feature`, `enhancement`, `address-scanning`, `epic-1`, `coverage`

## Notes

**Quick Win**: This is relatively easy to implement and provides huge coverage increase. Should be done alongside multi-path (HIGH-001) as they complement each other.
