# CRITICAL-003: Electrum Seed Validation Missing in Cake Wallet Scanner

**Priority**: 🔴 CRITICAL  
**Type**: Bug / Correctness Issue  
**Epic**: Epic 1 - Core Scanning Engine  
**Story**: Related to Cake Wallet scanner  
**Estimated Effort**: 2 days  
**Assigned**: TBD  

---

## Problem Statement

The Cake Wallet scanner generates BIP39 mnemonic words and derives them as Electrum seeds, but does NOT validate the Electrum version prefix. This may generate **invalid Electrum seeds** that would fail in actual wallet software.

## Technical Background

### Electrum Seed Validation

Electrum seeds require specific version prefixes after HMAC-SHA512 hashing:

```
seed = PBKDF2(mnemonic, "electrum" + passphrase, iterations=2048)
version = HMAC-SHA512(key="Seed version", data=seed)

Valid versions:
- Standard wallet: version must start with "01"
- SegWit wallet:   version must start with "100"  
- 2FA wallet:      version must start with "101"
```

If version doesn't match, the seed is **invalid** and will be rejected by Electrum wallet software.

### Current Implementation

From `crates/temporal-planetarium-lib/src/utils/electrum.rs`:

```rust
pub fn derive_electrum_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    let mut seed = [0u8; 64];
    let salt = format!("electrum{}", passphrase);
    pbkdf2::<HmacSha512>(mnemonic.as_bytes(), salt.as_bytes(), 2048, &mut seed);
    seed
}
```

But **NO VALIDATION** of version prefix!

### Impact on Cake Wallet Scanner

The Cake Wallet scanner:
1. Uses weak PRNG to generate entropy
2. Converts entropy to BIP39 mnemonic words
3. Derives as Electrum seed using `derive_electrum_seed()`
4. **Assumes seed is valid** (may not be!)

## Impact

- ❌ **False positives**: Scanner may report "found" seeds that don't work in Electrum
- ❌ **Wasted computation**: GPU cycles spent on invalid seeds
- ❌ **Incorrect results**: Users test recovered seed and it fails
- ⚠️ **Research validity**: Results may not match actual vulnerable wallets

## Root Cause

Electrum seed generation is **probabilistic**. Only ~1 in 16 random mnemonics produce valid Electrum seeds (for "01" prefix).

The Cake Wallet vulnerability generates weak entropy → BIP39 words, but these may not satisfy Electrum's version requirement.

## Proposed Solution

### Option A: Add Validation Check (Recommended)

Modify Cake Wallet scanner to validate seeds before reporting:

```rust
pub fn is_valid_electrum_seed(mnemonic: &str) -> bool {
    let seed = derive_electrum_seed(mnemonic, "");
    let mut mac = HmacSha512::new_from_slice(b"Seed version").unwrap();
    mac.update(&seed);
    let version = hex::encode(mac.finalize().into_bytes());
    
    // Check for valid prefixes
    version.starts_with("01") ||    // Standard
    version.starts_with("100") ||   // SegWit
    version.starts_with("101")      // 2FA
}
```

In scanner:
```rust
if derive_as_electrum && !is_valid_electrum_seed(&mnemonic) {
    continue; // Skip invalid Electrum seeds
}
```

**Pros**:
- Filters out invalid seeds
- Reduces false positives
- Matches actual Electrum behavior

**Cons**:
- Slightly more computation per seed
- May miss some edge cases

### Option B: Generate Until Valid (More Accurate)

If Cake Wallet vulnerability specifically targets Electrum wallets, the vulnerable implementation may have **regenerated** seeds until valid:

```rust
loop {
    let mnemonic = generate_weak_mnemonic();
    if is_valid_electrum_seed(&mnemonic) {
        break; // Use this seed
    }
}
```

This would require modifying the scanner to match this behavior.

**Pros**:
- More accurate to actual vulnerable wallet behavior
- No false positives

**Cons**:
- Need to verify if Cake Wallet actually did this
- More complex implementation

### Option C: Document Limitation

If validation is too complex, at minimum document that not all generated seeds are valid Electrum seeds.

**Pros**:
- No code changes
- Quick fix

**Cons**:
- Doesn't solve the problem
- Users may be confused

## Recommended Approach

**Use Option A** (Add Validation Check):

1. Implement `is_valid_electrum_seed()` helper in `electrum.rs`
2. Add validation to Cake Wallet scanner before reporting results
3. Add counter for "seeds generated" vs "valid Electrum seeds"
4. Update documentation explaining the validation

## Acceptance Criteria

- [ ] `is_valid_electrum_seed()` function implemented in `electrum.rs`
- [ ] Cake Wallet scanner validates seeds before reporting
- [ ] Unit test for Electrum seed validation with known valid/invalid seeds
- [ ] Scanner reports both total seeds checked and valid Electrum seeds found
- [ ] Documentation updated explaining Electrum validation requirement

## Test Cases

```rust
#[test]
fn test_electrum_validation() {
    // Known valid Electrum seed (prefix "01")
    let valid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert!(is_valid_electrum_seed(valid));
    
    // Known invalid seed
    let invalid = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
    assert!(!is_valid_electrum_seed(invalid));
}
```

## Additional Context

See:
- Audit Report: `docs/CODEBASE_AUDIT_2026-01.md` Section 6.3.5
- Electrum documentation: https://electrum.readthedocs.io/en/latest/seedphrase.html
- Existing implementation: `crates/temporal-planetarium-lib/src/utils/electrum.rs`
- Existing tests: `tests/` (various Electrum tests)

## Related Issues

- Affects all Cake Wallet scanner variants (standard, targeted, crack, RPC)
- May affect other scanners if they use Electrum derivation

## Labels

`critical`, `bug`, `correctness`, `cake-wallet`, `electrum`, `epic-1`

## Priority Justification

Marked CRITICAL because:
1. Affects correctness of scanner results
2. May produce false positives in production use
3. Relatively easy fix (2 days)
4. Blockedfor production release
