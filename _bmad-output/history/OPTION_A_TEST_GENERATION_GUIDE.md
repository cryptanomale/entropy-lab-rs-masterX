# Option A: Randstorm Test Vector Generation & Validation Guide

## Executive Summary

Generate 1,000+ synthetic test vectors replicating the Randstorm vulnerability with known timestamps, create a controlled testnet environment, and validate scanner accuracy.

---

## Phase 1: Generate Test Vectors (10 minutes)

### Method 1: Python (Fastest - Recommended)

```bash
cd /Users/moe/temporal-planetarium/scripts
python3 generate_test_vectors_option_a.py
```

**Output:**
- `randstorm_test_vectors.csv` (1,000 keys)
- `randstorm_test_addresses.txt` (addresses only)
- `randstorm_test_private_keys.txt` (WIF format)

**CSV Format:**
```csv
timestamp_ms,seed,private_key_hex,wif,address,vulnerability
1325376000000,1325376000,deadbeef...,5J...,1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa,randstorm
```

### Method 2: Rust (More Production-Like)

```bash
cd /Users/moe/temporal-planetarium
cargo run --bin generate_randstorm_test_vectors --release
```

---

## Phase 2: Select Test Target (5 minutes)

### Strategy: One Funded Address

From the 1,000 generated addresses:

1. **Select Address:**
   ```bash
   head -1 randstorm_test_addresses.txt
   ```
   Example: `1RandStormTest123456789ABCDEF`

2. **Fund on Testnet:**
   - Use Bitcoin Testnet Faucet: https://testnet-faucet.mempool.co/
   - Send **0.001 tBTC** to selected address
   - Wait for 1 confirmation (~10 minutes)

3. **Verify Balance:**
   ```bash
   curl "https://blockstream.info/testnet/api/address/1RandStormTest123456789ABCDEF"
   ```

---

## Phase 3: Configure Scanner (2 minutes)

### Update Scanner Config

Edit `src/scans/randstorm.rs`:

```rust
// Add test mode
pub fn scan_with_test_vectors(
    test_vectors_path: &str,
    target_address: &str,
) -> Result<Vec<Match>> {
    let vectors = load_test_vectors(test_vectors_path)?;
    
    for vector in vectors {
        let derived_address = derive_address_from_weak_prng(vector.timestamp_ms)?;
        
        if derived_address == target_address {
            return Ok(vec![Match {
                address: target_address.to_string(),
                private_key: vector.private_key_hex,
                timestamp_ms: vector.timestamp_ms,
                vulnerability: "randstorm".to_string(),
            }]);
        }
    }
    
    Ok(vec![])
}
```

### Test Mode CLI Flag

```rust
// src/main.rs
#[command(name = "randstorm")]
pub struct RandstormArgs {
    #[arg(long)]
    test_mode: bool,
    
    #[arg(long)]
    test_vectors: Option<PathBuf>,
    
    #[arg(long)]
    target_address: Option<String>,
}
```

---

## Phase 4: Run Validation Test (5 minutes)

### Test 1: Known Address Match

```bash
cargo run --release -- randstorm \
  --test-mode \
  --test-vectors scripts/randstorm_test_vectors.csv \
  --target-address 1RandStormTest123456789ABCDEF
```

**Expected Output:**
```
✓ Match found!
  Address: 1RandStormTest123456789ABCDEF
  Private Key: 5J...
  Timestamp: 2012-01-01 00:00:00 UTC
  Vulnerability: Randstorm (BitcoinJS v0.1.3)
```

### Test 2: Full Sweep (All 1,000 Vectors)

```bash
cargo run --release -- randstorm \
  --test-mode \
  --test-vectors scripts/randstorm_test_vectors.csv \
  --sweep-all
```

**Expected Output:**
```
Scanned: 1,000 addresses
Found: 1 match (funded address)
Time: 0.234 seconds
Rate: 4,273 addr/sec
```

### Test 3: Balance Verification

```bash
python3 scripts/validate_scanner.py \
  --test-vectors scripts/randstorm_test_vectors.csv \
  --match-output randstorm_match.json
```

**Expected Output:**
```
✓ Address derivation: PASS
✓ Balance check: 0.001 tBTC (PASS)
✓ Private key validity: PASS
✓ Signature verification: PASS

Overall: 4/4 tests PASSED
```

---

## Phase 5: Production Readiness Checklist

### Before Mainnet Deployment

- [ ] **Test Mode Works:** All 3 validation tests pass
- [ ] **Performance Target:** >1,000 addr/sec on CPU
- [ ] **Memory Efficient:** <500 MB for 1M address scan
- [ ] **RPC Integration:** Tested against Bitcoin Core testnet
- [ ] **Error Handling:** Graceful failures logged
- [ ] **Bloom Filter:** False positive rate <0.1%

### Safety Checks

- [ ] **No Mainnet Keys in Code:** Remove all test private keys
- [ ] **Audit Trail:** Log all scans with timestamps
- [ ] **Rate Limiting:** Respect RPC node limits
- [ ] **Ethical Compliance:** README warning present

---

## Expected Timeline

| Phase | Duration | Cumulative |
|-------|----------|------------|
| Generate Vectors | 10 min | 10 min |
| Fund Testnet Address | 15 min | 25 min |
| Configure Scanner | 5 min | 30 min |
| Run Validation | 10 min | 40 min |
| Iterate/Fix Bugs | 20 min | 60 min |

**Total: ~1 hour** to production-ready validation.

---

## Troubleshooting

### Issue: Scanner Doesn't Find Match

**Diagnosis:**
```bash
# Verify address derivation manually
python3 -c "
import hashlib
timestamp_ms = 1325376000000
# ... derive address
print(f'Expected: 1RandStormTest...')
print(f'Got: {derived_address}')
"
```

**Fix:** Ensure ARC4 cipher state matches exact BitcoinJS v0.1.3 implementation.

### Issue: Balance Check Fails

**Diagnosis:**
```bash
curl https://blockstream.info/testnet/api/address/1RandStormTest.../utxo
```

**Fix:** Confirm testnet faucet transaction confirmed (≥1 block).

### Issue: Performance Too Slow

**Current:** 1,000 addr/sec (CPU fallback)  
**Target:** 10,000+ addr/sec

**Optimization Path:**
1. Implement GPU kernel (Story 1.9) - 100x speedup
2. Batch RPC calls - 10x speedup
3. Bloom filter pre-scan - 50x speedup

---

## Next Steps After Validation

1. **Document Results:**
   - Screenshot of successful match
   - Performance metrics
   - Update `IMPLEMENTATION_SUMMARY.md`

2. **Implement GPU Acceleration (Story 1.9):**
   - Expected speedup: 100-1000x
   - Target: 1M+ addr/sec

3. **Production Deployment:**
   - Mainnet RPC configuration
   - Legal/ethical review
   - Public announcement (if applicable)

---

## Contact & Support

- **Issue Tracker:** [GitHub Issues](https://github.com/your-repo/temporal-planetarium/issues)
- **Randstorm Disclosure:** [Unciphered Blog](https://www.unciphered.com/blog/randstorm)
- **BitcoinJS Archive:** [v0.1.3 Source](https://github.com/bitcoinjs/bitcoinjs-lib/releases/tag/v0.1.3)

---

**Status:** ✅ Ready for Execution  
**Risk Level:** LOW (Testnet only)  
**Estimated Success Rate:** 95%+ (if ARC4 implementation exact)

---

*Generated by BMAD Master Agent*  
*Last Updated: 2025-01-17*
