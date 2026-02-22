# Hashcat Module Files

This directory contains the C module files for three Bitcoin wallet vulnerability scanners to be used with hashcat.

## Files

- `module_30501.c` - **Milk Sad Vulnerability** (CVE-2023-39910)
  - Hash format: `$milksad$<purpose>$<timestamp>$<address>`
  - Supports BIP44/49/84 address types (P2PKH, P2SH-P2WPKH, P2WPKH)
  - Priority: CRITICAL (224,000+ affected wallets)

- `module_30502.c` - **Trust Wallet MT19937 Vulnerability** (CVE-2023-31290)
  - Hash format: `$trustwallet$<purpose>$<timestamp>$<address>`
  - Supports BIP44/49/84 address types
  - Time-limited vulnerability (Nov 14-23, 2022)
  - Priority: HIGH

- `module_30503.c` - **Cake Wallet Electrum Weak PRNG** (2024)
  - Hash format: `$cakewallet$<address>`
  - Only supports P2WPKH (bc1q...) addresses
  - Simpler format (no purpose/timestamp fields)
  - Priority: MEDIUM

## Installation

To install these modules in hashcat:

1. Clone the hashcat repository:
   ```bash
   git clone https://github.com/hashcat/hashcat.git
   cd hashcat
   ```

2. Copy the module files:
   ```bash
   cp /path/to/entropy-lab-rs/hashcat_modules/module_30501.c src/modules/
   cp /path/to/entropy-lab-rs/hashcat_modules/module_30502.c src/modules/
   cp /path/to/entropy-lab-rs/hashcat_modules/module_30503.c src/modules/
   ```

3. Copy the OpenCL kernels (from entropy-lab-rs/cl/):
   ```bash
   cp /path/to/entropy-lab-rs/cl/milk_sad_multipath.cl OpenCL/m30501_a3-pure.cl
   cp /path/to/entropy-lab-rs/cl/trust_wallet_multipath.cl OpenCL/m30502_a3-pure.cl
   cp /path/to/entropy-lab-rs/cl/cake_wallet_crack.cl OpenCL/m30503_a3-pure.cl
   ```

4. Copy the dependency kernels:
   ```bash
   cp /path/to/entropy-lab-rs/cl/common.cl OpenCL/
   cp /path/to/entropy-lab-rs/cl/mt19937.cl OpenCL/
   cp /path/to/entropy-lab-rs/cl/sha2.cl OpenCL/
   cp /path/to/entropy-lab-rs/cl/ripemd.cl OpenCL/
   cp /path/to/entropy-lab-rs/cl/sha512.cl OpenCL/
   cp /path/to/entropy-lab-rs/cl/secp256k1*.cl OpenCL/
   cp /path/to/entropy-lab-rs/cl/bip39*.cl OpenCL/
   ```

5. Build hashcat:
   ```bash
   make clean
   make
   ```

## Usage Examples

### Module 30501 (Milk Sad)

```bash
# Test with example hash
echo '$milksad$49$1514764800$3HERnjC6RDwg6UYx1hHiAKUp6gz1217h2U' > test.hash

# Run hashcat (kernel will brute-force timestamps)
./hashcat -m 30501 test.hash

# Benchmark
./hashcat -m 30501 --benchmark
```

### Module 30502 (Trust Wallet)

```bash
# Test with example hash
echo '$trustwallet$49$1668384000$3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN' > test.hash

# Run hashcat
./hashcat -m 30502 test.hash

# Benchmark
./hashcat -m 30502 --benchmark
```

### Module 30503 (Cake Wallet)

```bash
# Test with example hash
echo '$cakewallet$bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c' > test.hash

# Run hashcat
./hashcat -m 30503 test.hash

# Benchmark
./hashcat -m 30503 --benchmark
```

## Implementation Details

### Features Implemented

- ✅ Full Base58Check decoder for P2PKH and P2SH addresses
- ✅ Full Bech32 decoder for P2WPKH addresses
- ✅ SHA256 checksum verification for Base58Check
- ✅ Bech32 checksum verification
- ✅ Parameter validation (purpose, timestamp ranges)
- ✅ esalt structures for passing data to GPU kernels
- ✅ Complete module registration with hashcat

### Address Format Support

**Module 30501 & 30502 (Milk Sad & Trust Wallet):**
- P2PKH (purpose=44): Addresses starting with "1", Base58, version 0x00
- P2SH-P2WPKH (purpose=49): Addresses starting with "3", Base58, version 0x05
- P2WPKH (purpose=84): Addresses starting with "bc1q", Bech32, witness version 0

**Module 30503 (Cake Wallet):**
- P2WPKH only: Addresses starting with "bc1q", Bech32, witness version 0

### Timestamp Ranges

- **Milk Sad**: 1293840000 to 1704067199 (2011-01-01 to 2023-12-31)
- **Trust Wallet**: 1668384000 to 1669247999 (2022-11-14 to 2022-11-23)
- **Cake Wallet**: No timestamp (uses entropy space brute-force)

## Testing

Test vectors are provided in the ST_HASH constants in each module:

- Module 30501: `$milksad$49$1514764800$3HERnjC6RDwg6UYx1hHiAKUp6gz1217h2U`
- Module 30502: `$trustwallet$49$1668384000$3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN`
- Module 30503: `$cakewallet$bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c`

## Security Notice

These modules are designed for:
- ✅ Security research and education
- ✅ White-hat testing with proper authorization
- ✅ Responsible vulnerability disclosure
- ❌ NOT for unauthorized wallet access
- ❌ NOT for theft or unauthorized fund transfers
- ❌ NOT for any illegal activities

Always follow local laws and responsible disclosure practices.

## References

- **Milk Sad**: https://milksad.info/
- **CVE-2023-39910**: Milk Sad vulnerability
- **CVE-2023-31290**: Trust Wallet vulnerability
- **Hashcat**: https://hashcat.net/
- **entropy-lab-rs**: https://github.com/5n10sndkts-eng/entropy-lab-rs

## License

MIT License (same as hashcat)

## Author

Created for the entropy-lab-rs project
See docs/credits.txt for contributors
