# Hashcat Module Recommendations for Entropy Lab RS

## Executive Summary

This document provides recommendations for creating hashcat-compatible modules for the vulnerability scanners in entropy-lab-rs. While we have functional OpenCL kernels that work with our Rust implementation, creating standard hashcat modules would:

1. **Increase adoption** - Security researchers already know hashcat
2. **Enable integration** - Works with existing security workflows
3. **Provide standardization** - Industry-standard tool compatibility
4. **Enable distribution** - Hashcat-utils for distributed cracking

## Current Status

### ✅ What We Have
- Complete OpenCL GPU kernels for all major vulnerabilities
- Correct address generation for P2PKH, P2SH-P2WPKH, and P2WPKH
- Full BIP32/BIP39/BIP44/49/84 implementation
- MT19937, minstd_rand, and other PRNG implementations
- Functional Rust-based scanners

### ❌ What We're Missing
- Hashcat module wrapper code (`.c` files)
- Hash format specifications
- Integration with hashcat build system
- Official mode numbers
- Example hash files
- Documentation for hashcat users

## Recommended Hashcat Modules

### Module 1: Milk Sad P2SH-P2WPKH (Priority: CRITICAL)

**Suggested Mode:** 30500  
**Name:** Bitcoin Milk Sad P2SH-P2WPKH (CVE-2023-39910, Research Update #13)

**Hash Format:**
```
$milksad$<purpose>$<timestamp>$<target_address>
```

**Examples:**
```
$milksad$49$1514764800$3HERnjC6RDwg6UYx1hHiAKUp6gz1217h2U
$milksad$44$1514764800$1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
$milksad$84$1514764800$bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
```

**Parameters:**
- `purpose`: 44 (P2PKH), 49 (P2SH-P2WPKH), or 84 (P2WPKH)
- `timestamp`: Unix timestamp (32-bit, 10 digits)
- `target_address`: Bitcoin address to find

**Attack Type:** Timestamp brute-force
- Min timestamp: 1293840000 (2011-01-01)
- Max timestamp: 1704067199 (2023-12-31)
- Research Update #13: 1514764800-1546300799 (2018)

**Expected Performance:**
- ~1-10 GH/s on modern GPUs
- Full 2018 scan: ~1-10 seconds on RTX 4090

**Implementation:**
```c
// modules/module_30500.c
typedef struct milksad {
    u32 purpose;     // 44, 49, or 84
    u32 timestamp;
    u8  target_hash160[20];
} milksad_t;

int module_hash_decode(...)
{
    // Parse format: $milksad$<purpose>$<timestamp>$<address>
    // 1. Extract purpose
    // 2. Extract timestamp
    // 3. Decode address to Hash160 (base58 or bech32)
    // 4. Store in esalt
}

// Use our existing milk_sad_multipath.cl kernel
```

**Why This Matters:**
- Affects 224,000+ wallets worth significant value
- Largest known cluster of vulnerable wallets
- Most critical vulnerability to detect

---

### Module 2: Trust Wallet MT19937 (Priority: HIGH)

**Suggested Mode:** 30501  
**Name:** Trust Wallet Browser Extension MT19937 (CVE-2023-31290)

**Hash Format:**
```
$trustwallet$<purpose>$<timestamp>$<target_address>
```

**Examples:**
```
$trustwallet$49$1668384000$3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN
$trustwallet$44$1668384000$1JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN
$trustwallet$84$1668384000$bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c
```

**Parameters:**
- `purpose`: 44, 49, or 84
- `timestamp`: Unix timestamp during vulnerable period
- `target_address`: Bitcoin address to find

**Attack Type:** Timestamp brute-force
- Vulnerable window: Nov 14-23, 2022
- Min: 1668384000 (Nov 14, 2022)
- Max: 1669247999 (Nov 23, 2022)
- Only ~864,000 timestamps to check

**Expected Performance:**
- ~1-10 GH/s on modern GPUs
- Full scan: <1 second on RTX 4090

**Implementation:**
```c
// modules/module_30501.c
// Similar to Milk Sad but uses LSB extraction instead of MSB
// Critical difference: Trust Wallet uses entropy[i] = mt19937() & 0xFF
```

**Key Difference from Milk Sad:**
- Trust Wallet uses **LSB** (Least Significant Byte) extraction
- Milk Sad uses **MSB** (Most Significant Byte) extraction
- Cannot reuse same kernel without modification

---

### Module 3: Cake Wallet Electrum (Priority: MEDIUM)

**Suggested Mode:** 30502  
**Name:** Cake Wallet Electrum Weak PRNG (2024)

**Hash Format:**
```
$cakewallet$<target_address>
```

**Example:**
```
$cakewallet$bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c
```

**Parameters:**
- `target_address`: Bitcoin P2WPKH address (bc1q...)

**Attack Type:** Entropy space brute-force
- Only 2^20 (1,048,576) possible seeds
- Very small search space

**Expected Performance:**
- ~10-100 GH/s on modern GPUs
- Full scan: <1 second on any modern GPU

**Implementation:**
```c
// modules/module_30502.c
// Scans 2^20 entropy space
// Uses Electrum seed format (not BIP39)
// Derives m/0'/0/0 (Electrum-style)
// Generates P2WPKH addresses
```

**Special Considerations:**
- Electrum seed validation required
- Must check "100" prefix in HMAC-SHA512 output
- Only ~1M valid seeds (not all entropy values work)

---

### Module 4: Trust Wallet iOS minstd_rand (Priority: MEDIUM)

**Suggested Mode:** 30503  
**Name:** Trust Wallet iOS minstd_rand0 LCG (CVE-2024-23660)

**Hash Format:**
```
$trustwallet-ios$<purpose>$<seed>$<target_address>
```

**Examples:**
```
$trustwallet-ios$44$123456789$1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
$trustwallet-ios$49$123456789$3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN
```

**Parameters:**
- `purpose`: 44, 49, or 84
- `seed`: 32-bit LCG seed
- `target_address`: Bitcoin address

**Attack Type:** LCG seed brute-force
- 2^32 possible seeds
- But many duplicates due to LCG properties

**Expected Performance:**
- ~1-10 GH/s on modern GPUs
- Full 2^32 scan: Minutes to hours depending on GPU

**Implementation:**
```c
// modules/module_30503.c
// Uses minstd_rand0 LCG: seed = seed * 16807 % 2147483647
// LSB extraction like Trust Wallet browser
```

---

## Implementation Plan

### Phase 1: Core Modules (Weeks 1-2)

1. **Create Module Skeletons**
   - [ ] `modules/module_30500.c` (Milk Sad)
   - [ ] `modules/module_30501.c` (Trust Wallet)
   - [ ] `modules/module_30502.c` (Cake Wallet)
   - [ ] `modules/module_30503.c` (Trust Wallet iOS)

2. **Implement Hash Parsers**
   - [ ] Base58 address decoder
   - [ ] Bech32 address decoder
   - [ ] Parameter extraction
   - [ ] Validation logic

3. **Port OpenCL Kernels**
   - [ ] Adapt include structure for hashcat
   - [ ] Test kernel compilation
   - [ ] Verify correctness

### Phase 2: Integration (Weeks 3-4)

1. **Build System Integration**
   - [ ] Add modules to Makefile
   - [ ] Test compilation on Linux/Windows/macOS
   - [ ] Resolve dependencies

2. **Testing**
   - [ ] Create test vectors
   - [ ] Validate against known addresses
   - [ ] Performance benchmarking

3. **Documentation**
   - [ ] Write module README files
   - [ ] Create example hash files
   - [ ] Usage documentation

### Phase 3: Publication (Week 5)

1. **Pull Request to Hashcat**
   - [ ] Fork hashcat repository
   - [ ] Create feature branch
   - [ ] Submit PR with documentation
   - [ ] Address review feedback

2. **Community Release**
   - [ ] Blog post announcement
   - [ ] GitHub release
   - [ ] Security advisory update

## Hash Format Specifications

### Address Decoding Logic

**Base58 (P2PKH and P2SH):**
```c
int decode_base58_address(const char *address, u8 *hash160, u8 *version)
{
    // 1. Base58 decode to 25 bytes
    u8 decoded[25];
    base58_decode(address, decoded);
    
    // 2. Extract version byte
    *version = decoded[0];
    
    // 3. Verify checksum (last 4 bytes)
    u8 checksum[32];
    sha256d(decoded, 21, checksum);
    if (memcmp(checksum, decoded + 21, 4) != 0)
        return -1;
    
    // 4. Extract hash160 (bytes 1-20)
    memcpy(hash160, decoded + 1, 20);
    
    return 0;
}
```

**Bech32 (P2WPKH):**
```c
int decode_bech32_address(const char *address, u8 *hash160)
{
    // 1. Verify HRP ("bc" for mainnet)
    if (strncmp(address, "bc1", 3) != 0)
        return -1;
    
    // 2. Bech32 decode
    u8 witness_version;
    u8 witness_program[40];
    int witness_program_len;
    
    bech32_decode(&witness_version, witness_program, &witness_program_len, address);
    
    // 3. Verify version 0 and length 20 (P2WPKH)
    if (witness_version != 0 || witness_program_len != 20)
        return -1;
    
    // 4. Extract hash160
    memcpy(hash160, witness_program, 20);
    
    return 0;
}
```

### Timestamp to Hash160 Logic

**Common Steps (All Modules):**
```c
u8 hash160[20];

// 1. Generate entropy from timestamp/seed using PRNG
u8 entropy[16];  // or 24/32 for longer mnemonics
generate_entropy(timestamp, entropy);

// 2. BIP39: Entropy → Mnemonic → Seed
u8 bip39_seed[64];
bip39_entropy_to_seed(entropy, bip39_seed);

// 3. BIP32: Derive to target path
derive_bip32_path(bip39_seed, purpose, hash160);

// 4. Apply address-type-specific hashing
if (purpose == 49) {
    // P2SH-P2WPKH: Hash160(witness_script)
    create_and_hash_witness_script(hash160);
}

// 5. Compare with target
if (memcmp(hash160, target_hash160, 20) == 0) {
    found = true;
}
```

## Performance Expectations

### Theoretical Performance

Based on GPU architecture and similar hashcat modes:

| GPU Model | Milk Sad (GH/s) | Trust Wallet (GH/s) | Cake Wallet (GH/s) |
|-----------|-----------------|---------------------|---------------------|
| RTX 4090  | 8-15           | 8-15               | 50-100             |
| RTX 4080  | 6-12           | 6-12               | 40-80              |
| RTX 3090  | 5-10           | 5-10               | 30-60              |
| RTX 3080  | 4-8            | 4-8                | 25-50              |

**Scan Time Estimates:**

| Vulnerability | Time Range | Timestamps | RTX 4090 Time |
|--------------|------------|------------|---------------|
| Milk Sad Update #13 | 2018 | 31.5M | ~3 seconds |
| Trust Wallet | Nov 2022 | 864K | <1 second |
| Cake Wallet | All | 1M | <1 second |

### Bottlenecks

1. **BIP32 Derivation** - Most expensive operation
   - Multiple HMAC-SHA512 operations
   - Secp256k1 point multiplication
   - ~70% of compute time

2. **Address Type Handling** - Moderate cost
   - P2SH-P2WPKH: Additional Hash160
   - ~20% of compute time

3. **Memory Transfer** - Minor cost
   - CPU→GPU: Minimal (just target hash)
   - GPU→CPU: Minimal (only results)
   - ~10% of compute time

## Testing Strategy

### Unit Tests

Create test vectors for each module:

```bash
# Milk Sad P2SH-P2WPKH
echo '$milksad$49$0$3HERnjC6RDwg6UYx1hHiAKUp6gz1217h2U' > test_milksad.hash
./hashcat -m 30500 test_milksad.hash -a 3 '0' --self-test-disable

# Expected: Found timestamp 0 generates this address

# Trust Wallet
echo '$trustwallet$44$1668384000$1ExampleAddressXXXXXXXXXXXXXXXXX' > test_tw.hash
./hashcat -m 30501 test_tw.hash -a 3 '1668384000'

# Cake Wallet
echo '$cakewallet$bc1qExampleAddressXXXXXXXXXXXXXXXXX' > test_cake.hash
./hashcat -m 30502 test_cake.hash -a 3 '?d?d?d?d?d?d'
```

### Integration Tests

Test against known vulnerable addresses:

```bash
# Test with known Milk Sad addresses from Research Update #13
./hashcat -m 30500 update13_addresses.hash -a 3 \
  --increment --increment-min=10 --increment-max=10 \
  '?d?d?d?d?d?d?d?d?d?d' \
  --skip=1514764800000000000 --limit=1546300799999999999
```

### Performance Tests

Benchmark against other cryptocurrency modes:

```bash
./hashcat -m 30500 -b  # Milk Sad
./hashcat -m 11300 -b  # Bitcoin wallet.dat (comparison)
./hashcat -m 28500 -b  # Bitcoin WIF (comparison)
```

## Documentation Requirements

### For Each Module

1. **README.md**
   ```markdown
   # Hashcat Module 30500: Milk Sad P2SH-P2WPKH
   
   ## Description
   [CVE, vulnerability details, impact]
   
   ## Hash Format
   [Specification]
   
   ## Examples
   [Usage examples]
   
   ## Performance
   [Benchmarks]
   
   ## References
   [Links to research, advisories]
   ```

2. **Example Hash Files**
   - `example.30500.hash` - Sample hashes
   - `example.30500.cmd` - Sample commands

3. **Test Vectors**
   - `test.30500.hash` - Known plaintext/hash pairs
   - For validation and testing

## Contributing to Hashcat

### Submission Checklist

- [ ] Module compiles on Linux, Windows, macOS
- [ ] Self-tests pass
- [ ] Benchmarks work
- [ ] Documentation complete
- [ ] Example hashes provided
- [ ] No proprietary code
- [ ] MIT or similar license
- [ ] Clean code style (follow hashcat conventions)
- [ ] No compiler warnings

### PR Description Template

```markdown
## New Module: Milk Sad P2SH-P2WPKH (Mode 30500)

This PR adds support for detecting Bitcoin wallets vulnerable to the Milk Sad 
vulnerability (CVE-2023-39910), specifically targeting Research Update #13 
which identified 224,000+ affected wallets.

### Vulnerability Background
- Libbitcoin Explorer versions 3.0.0-3.6.0
- MT19937 PRNG seeded with 32-bit timestamp
- Primarily affects 2018 wallets using BIP49 (P2SH-P2WPKH)

### Implementation Details
- Hash format: `$milksad$<purpose>$<timestamp>$<address>`
- Supports BIP44 (P2PKH), BIP49 (P2SH-P2WPKH), BIP84 (P2WPKH)
- OpenCL kernel included
- Full BIP32/BIP39 derivation

### Testing
- Self-tests pass on NVIDIA/AMD GPUs
- Validated against known vulnerable addresses
- Performance: ~10 GH/s on RTX 4090

### References
- https://milksad.info/
- https://milksad.info/posts/research-update-13/
- https://github.com/5n10sndkts-eng/entropy-lab-rs
```

## Maintenance

### Version Compatibility

- Test with hashcat 6.2.6+ (current stable)
- Ensure backward compatibility
- Document any version-specific features

### Updates

- Monitor for hashcat API changes
- Update kernels for new GPU architectures
- Add support for new attack modes

## Conclusion

Creating hashcat modules for entropy-lab-rs would:

1. **Maximize Impact** - Reach the widest security researcher audience
2. **Enable Discovery** - Help identify and recover vulnerable wallets
3. **Standardize Tools** - Professional security workflow integration
4. **Build Community** - Contribute to open-source security tools

**Recommended Next Steps:**
1. Start with Milk Sad module (highest impact)
2. Test thoroughly with known addresses
3. Submit PR to hashcat
4. Create follow-up modules for other vulnerabilities

**Estimated Effort:**
- Initial development: 2-3 weeks
- Testing and refinement: 1-2 weeks  
- PR submission and review: 1-2 weeks
- **Total: 4-7 weeks for full integration**

**Resources Needed:**
- Access to GPU hardware for testing
- Time for hashcat codebase familiarization
- Coordination with hashcat maintainers

## References

- Hashcat: https://hashcat.net/
- Plugin Guide: https://github.com/hashcat/hashcat/blob/master/docs/hashcat-plugin-development-guide.md
- Milk Sad: https://milksad.info/
- This Project: https://github.com/5n10sndkts-eng/entropy-lab-rs
