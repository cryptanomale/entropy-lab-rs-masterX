# Address Format Quick Reference

## Overview

This document provides a quick reference for Bitcoin address generation in the entropy-lab-rs project, specifically focusing on the differences between address types and how they are generated in GPU kernels.

## Bitcoin Address Types

### P2PKH (Pay-to-PubKey-Hash) - Legacy

**Prefix:** `1...`  
**Example:** `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`  
**BIP:** BIP44  
**Derivation Path:** `m/44'/0'/0'/0/0`

**Generation:**
```c
// 1. Get compressed public key (33 bytes)
uchar pubkey[33];
secp256k1_serialize_pubkey(pubkey, &public_key);

// 2. Hash160 (SHA256 + RIPEMD160)
uchar hash160[20];
identifier_for_public_key(&public_key, hash160);

// 3. Add version byte (0x00 for mainnet)
// 4. Add checksum (first 4 bytes of SHA256d)
// 5. Base58 encode
```

**In GPU Kernel:**
```c
identifier_for_public_key(&address_pub, hash160);
// hash160 can be used directly for P2PKH addresses
```

---

### P2SH-P2WPKH (Pay-to-Script-Hash wrapping SegWit) - Nested SegWit

**Prefix:** `3...`  
**Example:** `3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy`  
**BIP:** BIP49  
**Derivation Path:** `m/49'/0'/0'/0/0`

**Generation:**
```c
// 1. Get compressed public key (33 bytes)
uchar pubkey[33];

// 2. Hash160 of public key (pubkey hash)
uchar pubkey_hash[20];
identifier_for_public_key(&public_key, pubkey_hash);

// 3. Create witness program (redeem script)
// Structure: OP_0 (0x00) + PUSH20 (0x14) + pubkey_hash
uchar witness_script[22];
witness_script[0] = 0x00;  // OP_0 (witness version 0)
witness_script[1] = 0x14;  // Push next 20 bytes
memcpy(witness_script + 2, pubkey_hash, 20);

// 4. Hash160 of witness script (script hash)
uchar script_hash[20];
sha256(witness_script, 22, temp);
ripemd160(temp, 32, script_hash);

// 5. Add version byte (0x05 for P2SH)
// 6. Add checksum (first 4 bytes of SHA256d)
// 7. Base58 encode
```

**In GPU Kernel:**
```c
// CRITICAL: This is different from P2PKH!
uchar pubkey_hash[20];
identifier_for_public_key(&address_pub, pubkey_hash);

// Create witness script
uchar witness_script[22];
witness_script[0] = 0x00;
witness_script[1] = 0x14;
for (int i = 0; i < 20; i++) {
    witness_script[i + 2] = pubkey_hash[i];
}

// Hash160 the witness script
uchar sha256_result[32] __attribute__((aligned(4)));
sha256((__private uint*)witness_script, 22, (__private uint*)sha256_result);
ripemd160(sha256_result, 32, (__private uchar*)hash160);

// Now hash160 contains script_hash for P2SH address
```

---

### P2WPKH (Pay-to-Witness-PubKey-Hash) - Native SegWit

**Prefix:** `bc1q...` (mainnet), `tb1q...` (testnet)  
**Example:** `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4`  
**BIP:** BIP84  
**Derivation Path:** `m/84'/0'/0'/0/0`

**Generation:**
```c
// 1. Get compressed public key (33 bytes)
uchar pubkey[33];

// 2. Hash160 of public key (witness program)
uchar hash160[20];
identifier_for_public_key(&public_key, hash160);

// 3. Bech32 encode with:
//    - HRP: "bc" (mainnet) or "tb" (testnet)
//    - Version: 0
//    - Program: hash160 (20 bytes)
```

**In GPU Kernel:**
```c
// Same as P2PKH - just Hash160(pubkey)
identifier_for_public_key(&address_pub, hash160);

// Bech32 encoding is done on CPU side
// GPU only needs to match against hash160
```

---

## Comparison Table

| Address Type | Prefix | BIP | Purpose | Hash160 Value | Encoding |
|--------------|--------|-----|---------|---------------|----------|
| P2PKH | 1... | BIP44 | 44 | Hash160(pubkey) | Base58 |
| P2SH-P2WPKH | 3... | BIP49 | 49 | Hash160(witness_script) | Base58 |
| P2WPKH | bc1q... | BIP84 | 84 | Hash160(pubkey) | Bech32 |

**Key Insight:** P2SH-P2WPKH requires an **additional Hash160 operation** on the witness script!

---

## GPU Kernel Implementation

### Correct Multi-Path Implementation

```c
// Get public key
extended_public_key_t address_pub;
public_from_private(&address_key, &address_pub);

// Generate Hash160 based on address type
uchar hash160[20];

if (purpose == 49) {
    // P2SH-P2WPKH: Need to hash the witness script
    uchar pubkey_hash[20];
    identifier_for_public_key(&address_pub, pubkey_hash);
    
    // Create witness script: OP_0 (0x00) + PUSH20 (0x14) + pubkey_hash
    uchar witness_script[22];
    witness_script[0] = 0x00;
    witness_script[1] = 0x14;
    for (int i = 0; i < 20; i++) {
        witness_script[i + 2] = pubkey_hash[i];
    }
    
    // Hash160 the witness script for P2SH
    uchar sha256_result[32] __attribute__((aligned(4)));
    sha256((__private uint*)witness_script, 22, (__private uint*)sha256_result);
    ripemd160(sha256_result, 32, (__private uchar*)hash160);
} else {
    // P2PKH (BIP44) and P2WPKH (BIP84): Use pubkey hash directly
    identifier_for_public_key(&address_pub, hash160);
}

// Now hash160 can be compared against target
```

### Incorrect Implementation (Bug)

```c
// ❌ WRONG: This only works for P2PKH and P2WPKH
uchar hash160[20];
identifier_for_public_key(&address_pub, hash160);

// This will NOT match P2SH-P2WPKH addresses!
// P2SH requires hashing the witness script, not the pubkey
```

---

## Testing Address Generation

### Test Vectors

**Known Private Key:**
```
Private Key: 0x0000000000000000000000000000000000000000000000000000000000000001
Public Key:  0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
```

**Expected Addresses:**

```
P2PKH (m/44'/0'/0'/0/0):
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

P2SH-P2WPKH (m/49'/0'/0'/0/0):
3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN

P2WPKH (m/84'/0'/0'/0/0):
bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
```

**Hash160 Values:**

```
P2PKH hash160:
62e907b15cbf27d5425399ebf6f0fb50ebb88f18

P2SH-P2WPKH witness script:
001462e907b15cbf27d5425399ebf6f0fb50ebb88f18

P2SH-P2WPKH script hash (hash160 of witness script):
8f55563b9a19f321c211e9b9f38cdf686ea07845

P2WPKH hash160 (same as P2PKH):
62e907b15cbf27d5425399ebf6f0fb50ebb88f18
```

**Note:** P2PKH and P2WPKH use the same hash160 value, just different encoding!

### CPU Validation Code

```rust
use bitcoin::{Address, CompressedPublicKey, Network};

// For P2PKH
let addr_p2pkh = Address::p2pkh(pubkey, Network::Bitcoin);

// For P2SH-P2WPKH
let compressed = CompressedPublicKey(pubkey.inner);
let addr_p2shwpkh = Address::p2shwpkh(&compressed, Network::Bitcoin);

// For P2WPKH
let addr_p2wpkh = Address::p2wpkh(&compressed, Network::Bitcoin);
```

---

## Debugging Checklist

When GPU kernel doesn't find expected addresses:

- [ ] Check if address type matches derivation path (purpose)
- [ ] Verify Hash160 calculation based on address type
- [ ] For P2SH addresses: Confirm witness script is created correctly
- [ ] For P2SH addresses: Confirm witness script is hashed
- [ ] Check address encoding (Base58 vs Bech32) doesn't affect hash160
- [ ] Validate public key compression (should always be compressed)
- [ ] Verify derivation path is correct for address type
- [ ] Test with known test vectors first

---

## Common Mistakes

### Mistake 1: Using P2PKH hash for P2SH addresses
```c
// ❌ WRONG
identifier_for_public_key(&address_pub, hash160);
// This won't work for P2SH-P2WPKH addresses!
```

### Mistake 2: Forgetting witness script version
```c
// ❌ WRONG
witness_script[0] = 0x14;  // Missing OP_0
witness_script[1] = pubkey_hash[0];
```

### Mistake 3: Wrong hash function
```c
// ❌ WRONG
sha256(witness_script, 22, hash160);
// Should be: SHA256 then RIPEMD160 (Hash160)
```

### Mistake 4: Confusing address encoding with hash value
```c
// P2PKH and P2WPKH use SAME hash160 value
// Only difference is encoding (Base58 vs Bech32)
// Don't try to "convert" between them at hash level
```

---

## Quick Lookup: Purpose → Address Type

```c
uint purpose = ...;

if (purpose == 44) {
    // P2PKH (Legacy)
    // hash160 = Hash160(pubkey)
    // prefix: 1...
}
else if (purpose == 49) {
    // P2SH-P2WPKH (Nested SegWit)
    // hash160 = Hash160(witness_script)
    // witness_script = 0x00 + 0x14 + Hash160(pubkey)
    // prefix: 3...
}
else if (purpose == 84) {
    // P2WPKH (Native SegWit)
    // hash160 = Hash160(pubkey)
    // prefix: bc1q...
}
```

---

## Files Updated

### Fixed Files:
- ✅ `cl/milk_sad_multipath.cl` - Now correctly generates P2SH-P2WPKH addresses
- ✅ `cl/trust_wallet_multipath.cl` - New kernel with full address type support

### Still Using Simple Hash160:
- `cl/milk_sad_crack.cl` - Only generates P2PKH (BIP44) - This is correct for its purpose
- `cl/trust_wallet_crack.cl` - Only generates P2PKH (BIP44) - Should use multipath kernel for full coverage

---

## Summary

**The Critical Fix:**

P2SH-P2WPKH addresses (prefix "3", BIP49) require:
1. Hash160(pubkey) → pubkey_hash
2. Create witness_script: `0x00 + 0x14 + pubkey_hash`
3. Hash160(witness_script) → script_hash
4. Use script_hash for address comparison

This is different from P2PKH and P2WPKH which directly use Hash160(pubkey).

**Research Update #13 Impact:**

The 224,000+ vulnerable Milk Sad wallets use P2SH-P2WPKH (BIP49). Without this fix, the scanner would miss all of them!

