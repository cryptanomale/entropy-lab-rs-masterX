# Research Update #13: Discovery of 224,000+ Vulnerable Wallets

**Date:** July 2025  
**Source:** https://milksad.info/posts/research-update-13/  
**Vulnerability:** Milk Sad (CVE-2023-39910) - Libbitcoin Explorer weak PRNG

## Overview

Research Update #13 from the Milk Sad team documents the discovery of over 224,000 new Bitcoin wallets vulnerable to the Libbitcoin Explorer entropy weakness. This represents an **85x increase** from the initially documented ~2,600 vulnerable wallets, making it one of the largest clusters of weak wallets discovered to date.

## Technical Characteristics

The Update #13 wallet cluster has the following distinctive characteristics:

### Entropy Generation
- **PRNG:** Mersenne Twister MT19937
- **Seeding:** 32-bit system timestamp (insufficient entropy)
- **Extraction:** Most Significant Byte (MSB) from each MT19937 output
- **Entropy Size:** 256-bit (32 bytes)
- **Mnemonic:** 24-word BIP39 phrases

### Address Type
- **Standard:** BIP49 P2SH-SegWit
- **Derivation Path:** `m/49'/0'/0'/0/0`
- **Address Prefix:** Starts with '3'
- **Format:** P2WPKH nested in P2SH

### Activity Pattern
- **Time Period:** Primarily 2018
- **Transaction Pattern:** Small deposits around 2018
- **Characteristics:** Highly patterned activity suggesting automated creation
- **Suspected Use:** Possible mixer experiment or large-scale service

### Impact
- **Total Wallets:** 224,000+ vulnerable addresses
- **Previous Scale:** ~2,600 wallets (85x increase)
- **Risk Level:** Critical - all funds recoverable by anyone with this knowledge

## How This Implementation Supports Update #13

This `entropy-lab-rs` implementation **fully supports** all requirements for detecting Update #13 wallets:

### ✅ Complete Feature Coverage

1. **256-bit Entropy (24-word mnemonics)**
   - Implemented via `EntropySize::Bits256`
   - Test: `test_entropy_generation_256bit()`
   - Generates exactly 32 bytes from MT19937 with MSB extraction

2. **MT19937 PRNG with MSB Extraction**
   - Core implementation in `generate_entropy_msb()`
   - Takes only bits 31:24 (MSB) from each 32-bit MT19937 output
   - Test: `test_validate_milk_sad_mnemonic()` validates "milk sad" canonical output

3. **BIP49 P2SH-SegWit Addresses**
   - Implemented via `AddressType::P2SHWPKH`
   - Generates addresses with prefix '3'
   - Test: `test_address_types()` validates prefix
   - Test: `test_update_13_wallet_generation()` specifically validates Update #13 pattern

4. **Derivation Path m/49'/0'/0'/0/0**
   - Path determined by `AddressType::purpose()` returning 49
   - Full path: `m/49'/0'/0'/0/0` (purpose/coin/account/change/index)
   - Change = 0 (external), Index = 0 (first address)

5. **Time Range Scanning**
   - Constants provided: `UPDATE_13_START_TIMESTAMP`, `UPDATE_13_END_TIMESTAMP`
   - Covers full year 2018: Jan 1 - Dec 31
   - Configurable via CLI: `--start-timestamp` and `--end-timestamp`

### Usage Examples

#### Scan for Update #13 Wallets (2018, 24-word, BIP49)

```bash
# Using predefined 2018 time range
cargo run --release -- milk-sad \
  --start-timestamp 1514764800 \
  --end-timestamp 1546300799 \
  --multipath \
  --rpc-url http://127.0.0.1:8332 \
  --rpc-user your_username \
  --rpc-pass your_password
```

#### Target-Based Scan (Known Address)

```bash
# If you have a specific address to check
cargo run --release -- milk-sad \
  --target 3HERnjC6RDwg6UYx1hHiAKUp6gz1217h2U \
  --start-timestamp 1514764800 \
  --end-timestamp 1546300799
```

#### Full Coverage Scan

The scanner automatically checks:
- All three entropy sizes (128, 192, 256-bit) by default in RPC mode
- All three address types (BIP44, BIP49, BIP84)
- Both external (0) and change (1) address chains
- Multiple address indices with `--multipath` flag

## Technical Implementation Details

### Entropy Generation Algorithm

```rust
pub fn generate_entropy_msb(timestamp: u32, size: EntropySize) -> Vec<u8> {
    let byte_len = size.byte_len(); // 32 bytes for Bits256
    let mut rng = Mt19937GenRand32::new(timestamp);
    let mut entropy = vec![0u8; byte_len];
    
    // MSB extraction: take ONLY the most significant byte
    for byte in entropy.iter_mut().take(byte_len) {
        let val = rng.next_u32();
        *byte = ((val >> 24) & 0xFF) as u8; // Bits 31:24
    }
    
    entropy
}
```

### BIP49 Address Generation

```rust
// BIP49: m/49'/0'/0'/0/0
let purpose = 49;
let path = format!("m/{}'/{}'/{}'/{}/{}", purpose, 0, 0, 0, 0);
let derived_key = root.derive_priv(&secp, &path)?;
let pubkey = private_key.public_key(&secp);
let address = Address::p2shwpkh(&compressed_pubkey, Network::Bitcoin);
// Result: Address starting with '3'
```

## Validation Tests

The following tests validate Update #13 support:

### Unit Tests (src/scans/milk_sad.rs)
```rust
#[test]
fn test_update_13_time_constants() {
    // Verifies 2018 time range constants
}

#[test]
fn test_update_13_wallet_generation() {
    // Validates 24-word + BIP49 generation
}

#[test]
fn test_validate_milk_sad_mnemonic() {
    // Canonical "milk sad wage cup..." test
}
```

### Integration Tests (tests/integration_tests.rs)
```rust
#[test]
fn test_research_update_13_requirements() {
    // End-to-end validation of all requirements
}
```

Run all tests:
```bash
cargo test --lib scans::milk_sad::tests
cargo test --test integration_tests test_research_update_13
```

## Security Implications

### For Wallet Users
If you created a Bitcoin wallet between 2011-2023 using any of these tools, your funds may be at risk:
- Libbitcoin Explorer (`bx seed` command)
- Any wallet software using Libbitcoin for key generation
- Web-based wallets from the 2011-2018 era
- Automated wallet generation services around 2018

**Immediate Action Required:**
1. Check if your wallet matches the vulnerable pattern (24-word, starts with '3', created ~2018)
2. If vulnerable, immediately transfer funds to a securely-generated wallet
3. Use a modern wallet with proper CSPRNG (cryptographically secure PRNG)

### For Security Researchers
This tool allows you to:
- Identify vulnerable wallets for responsible disclosure
- Verify your own research implementations
- Understand the scale of the vulnerability
- Test address generation correctness

### Ethical Guidelines
- **Do:** Use for security research and vulnerability assessment
- **Do:** Report findings to affected parties
- **Do:** Help users move funds to secure wallets
- **Don't:** Use for unauthorized fund access or theft
- **Don't:** Exploit vulnerabilities for personal gain

## Timeline

- **2011-2023:** Libbitcoin Explorer versions 3.0.0-3.6.0 vulnerable
- **July 2023:** Original Milk Sad vulnerability disclosed (~$900K stolen)
- **2018:** Peak activity period for Update #13 wallet cluster
- **July 2025:** Research Update #13 published, 224k+ wallets identified
- **Present:** All vulnerable patterns fully reproducible in entropy-lab-rs

## References

1. **Milk Sad Main Disclosure:** https://milksad.info/disclosure.html
2. **Research Update #13:** https://milksad.info/posts/research-update-13/
3. **CVE-2023-39910:** Libbitcoin Explorer PRNG vulnerability
4. **BIP39:** Mnemonic code for generating deterministic keys
5. **BIP49:** Derivation scheme for P2WPKH-nested-in-P2SH addresses
6. **Mersenne Twister:** MT19937 pseudorandom number generator

## Contributing

To enhance Update #13 support:

1. **Add GPU Acceleration:** Implement BIP49 path in GPU kernels
2. **Bloom Filter Integration:** Speed up large-scale scanning
3. **Database Support:** Track found wallets systematically
4. **Extended Indices:** Scan addresses beyond index 0
5. **Parallel RPC:** Optimize network balance checking

See `CONTRIBUTING.md` for guidelines.

## Disclaimer

This tool is for **research and educational purposes only**. The authors are not responsible for misuse. Always:
- Obtain proper authorization before testing
- Follow responsible disclosure practices
- Respect local laws and regulations
- Report vulnerabilities ethically

---

**Last Updated:** 2025-12-06  
**Implementation Status:** ✅ Complete  
**Test Coverage:** ✅ Validated  
**Documentation:** ✅ Comprehensive
