# Hashcat Module Creation Task

## Overview

Create three hashcat modules (C wrapper files) for Bitcoin wallet vulnerability scanners. The OpenCL kernels already exist and are located in the hashcat source tree. You need to create the module wrapper C files that parse hash formats and interface with these kernels.

## Context

- **Target Hashcat Version**: 7.1.2+
- **Module Numbers**: 30501, 30502, 30503 (Note: 30500 is already taken)
- **OpenCL Kernels**: Already present in hashcat/OpenCL/:
  - `m30501_a3-pure.cl` (Milk Sad)
  - `m30502_a3-pure.cl` (Trust Wallet)
  - `m30503_a3-pure.cl` (Cake Wallet)
- **Dependencies**: MT19937, BIP39, BIP32, Secp256k1, SHA256, RIPEMD160 kernels already copied

## Research Summary

### Hashcat Module Structure

Based on analysis of existing hashcat modules (module_11300.c for Bitcoin wallet.dat, module_16600.c for Electrum wallet), a typical cryptocurrency module includes:

1. **Module Metadata**: Hash name, category, kernel type, attack execution mode
2. **Hash Parser**: `module_hash_decode()` - parses input hash format
3. **Hash Encoder**: `module_hash_encode()` - formats output (optional)
4. **esalt Structure**: Extra data passed to GPU kernels
5. **Module Registration**: `module_init()` - registers all callbacks

### Key Patterns from Existing Modules

```c
// From module_11300.c (Bitcoin wallet.dat)
static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;

// esalt is used to pass additional data to GPU
typedef struct bitcoin_wallet {
  u32 cry_master_buf[64];
  u32 ckey_buf[64];
  u32 public_key_buf[64];
  u32 cry_master_len;
  u32 ckey_len;
  u32 public_key_len;
} bitcoin_wallet_t;
```

### Bitcoin Address Encoding

**Base58Check** (for P2PKH "1..." and P2SH "3..." addresses):
- 25 bytes total: [1 version byte][20 hash160][4 checksum]
- Checksum = first 4 bytes of SHA256(SHA256(version + hash160))
- Base58 alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz (no 0, O, I, l)

**Bech32** (for P2WPKH "bc1q..." addresses):
- Format: hrp + separator + data + checksum
- HRP = "bc" for mainnet
- Witness version 0 + 20-byte hash160 for P2WPKH
- Uses custom Bech32 alphabet and checksum algorithm

---

## Module 1: module_30501.c - Milk Sad

### Specifications

- **Module Number**: 30501
- **Hash Name**: "Bitcoin Milk Sad Vulnerability (CVE-2023-39910)"
- **Hash Category**: HASH_CATEGORY_CRYPTOCURRENCY_WALLET
- **Attack Exec**: ATTACK_EXEC_INSIDE_KERNEL
- **Kernel Type**: 30501
- **Salt Type**: SALT_TYPE_EMBEDDED
- **Digest Size**: DGST_SIZE_4_4 (16 bytes, though we use 20 for hash160)

### Hash Format

```
$milksad$<purpose>$<timestamp>$<address>
```

**Parameters:**
- `purpose`: Integer, one of 44 (P2PKH), 49 (P2SH-P2WPKH), or 84 (P2WPKH)
- `timestamp`: 32-bit Unix timestamp (10 digits, range: 1293840000-1704067199)
- `address`: Bitcoin address corresponding to the purpose:
  - purpose=44: P2PKH address starting with "1"
  - purpose=49: P2SH address starting with "3"
  - purpose=84: P2WPKH address starting with "bc1q"

**Examples:**
```
$milksad$49$1514764800$3HERnjC6RDwg6UYx1hHiAKUp6gz1217h2U
$milksad$44$1514764800$1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
$milksad$84$1514764800$bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
```

### esalt Structure

```c
typedef struct milksad
{
  u32 purpose;              // 44, 49, or 84
  u32 timestamp;            // Unix timestamp seed for MT19937
  u8  target_hash160[20];   // Hash160 extracted from address
  u8  padding[4];           // Align to 32 bytes
} milksad_t;
```

### Implementation Requirements

#### module_hash_decode() Pseudocode

```c
int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, 
                        MAYBE_UNUSED void *digest_buf, 
                        MAYBE_UNUSED salt_t *salt, 
                        MAYBE_UNUSED void *esalt_buf, 
                        MAYBE_UNUSED void *hook_salt_buf, 
                        MAYBE_UNUSED hashinfo_t *hash_info, 
                        const char *line_buf, 
                        MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;
  milksad_t *milksad = (milksad_t *) esalt_buf;

  // 1. Tokenize the input: $milksad$<purpose>$<timestamp>$<address>
  hc_token_t token;
  memset (&token, 0, sizeof (hc_token_t));
  
  token.token_cnt = 4;
  token.signatures_cnt = 1;
  token.signatures_buf[0] = "$milksad$";
  
  // Token 0: signature "$milksad$"
  token.len[0] = 9;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_SIGNATURE;
  
  // Token 1: purpose (1-2 digits)
  token.len_min[1] = 2;
  token.len_max[1] = 2;
  token.attr[1] = TOKEN_ATTR_VERIFY_LENGTH;
  token.sep[1] = '$';
  
  // Token 2: timestamp (10 digits)
  token.len_min[2] = 10;
  token.len_max[2] = 10;
  token.attr[2] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;
  token.sep[2] = '$';
  
  // Token 3: address (25-62 characters for Base58, 42-62 for Bech32)
  token.len_min[3] = 25;
  token.len_max[3] = 62;
  token.attr[3] = TOKEN_ATTR_VERIFY_LENGTH;
  
  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);
  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);
  
  // 2. Parse purpose
  const u8 *purpose_pos = (const u8 *) line_buf + token.len[0];
  const int purpose = atoi ((const char *) purpose_pos);
  
  if (purpose != 44 && purpose != 49 && purpose != 84) {
    return (PARSER_SIGNATURE_UNMATCHED);
  }
  milksad->purpose = purpose;
  
  // 3. Parse timestamp
  const u8 *timestamp_pos = (const u8 *) line_buf + token.len[0] + token.len[1] + 1;
  const u32 timestamp = atoi ((const char *) timestamp_pos);
  
  // Validate timestamp range (2011-01-01 to 2023-12-31)
  if (timestamp < 1293840000 || timestamp > 1704067199) {
    return (PARSER_HASH_VALUE);
  }
  milksad->timestamp = timestamp;
  
  // 4. Parse address
  const u8 *address_pos = (const u8 *) line_buf + token.len[0] + token.len[1] + 1 + token.len[2] + 1;
  const int address_len = token.len[3];
  
  // 5. Decode address based on purpose
  if (purpose == 44 && address_pos[0] == '1') {
    // P2PKH - decode Base58, expect version 0x00
    // TODO: Implement base58_decode()
    // Extract milksad->target_hash160[20]
  }
  else if (purpose == 49 && address_pos[0] == '3') {
    // P2SH - decode Base58, expect version 0x05
    // TODO: Implement base58_decode()
    // Extract milksad->target_hash160[20]
  }
  else if (purpose == 84 && address_pos[0] == 'b' && address_pos[1] == 'c' && address_pos[2] == '1') {
    // Bech32 - decode Bech32
    // TODO: Implement bech32_decode()
    // Extract milksad->target_hash160[20]
  }
  else {
    return (PARSER_HASH_ENCODING);
  }
  
  // 6. Set fake digest (not used, but required by hashcat)
  memcpy (digest, milksad->target_hash160, 16);
  
  // 7. Set fake salt (not used, but required by hashcat)
  salt->salt_buf[0] = milksad->timestamp;
  salt->salt_len = 4;
  
  return (PARSER_OK);
}
```

### Base58 Decoder Implementation

```c
// Helper function to decode Base58Check address
static bool base58_decode_address (const u8 *address_str, const int address_len, 
                                    u8 expected_version, u8 *hash160_out)
{
  // Base58 alphabet (Bitcoin uses this specific ordering)
  static const char base58_alphabet[] = 
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  
  // Decode Base58 to binary (25 bytes: version + hash160 + checksum)
  u8 decoded[25];
  memset (decoded, 0, 25);
  
  // Convert Base58 string to big integer, then to bytes
  // (Implementation details: use standard Base58 algorithm)
  for (int i = 0; i < address_len; i++) {
    const char *p = strchr (base58_alphabet, address_str[i]);
    if (p == NULL) return false;
    
    int digit = p - base58_alphabet;
    
    // Multiply existing value by 58 and add new digit
    int carry = digit;
    for (int j = 24; j >= 0; j--) {
      carry += 58 * decoded[j];
      decoded[j] = carry % 256;
      carry /= 256;
    }
  }
  
  // Verify version byte
  if (decoded[0] != expected_version) return false;
  
  // Verify checksum (double SHA256 of first 21 bytes)
  sha256_ctx_t sha256_ctx;
  u8 hash[32];
  
  sha256_init (&sha256_ctx);
  sha256_update (&sha256_ctx, decoded, 21);
  sha256_final (&sha256_ctx);
  memcpy (hash, sha256_ctx.h, 32);
  
  sha256_init (&sha256_ctx);
  sha256_update (&sha256_ctx, hash, 32);
  sha256_final (&sha256_ctx);
  
  if (memcmp (sha256_ctx.h, decoded + 21, 4) != 0) return false;
  
  // Extract hash160 (bytes 1-20)
  memcpy (hash160_out, decoded + 1, 20);
  
  return true;
}
```

### Bech32 Decoder Implementation

```c
// Helper function to decode Bech32 address (P2WPKH)
static bool bech32_decode_address (const u8 *address_str, const int address_len, 
                                    u8 *hash160_out)
{
  // Bech32 alphabet
  static const char bech32_alphabet[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  
  // Verify HRP ("bc" for mainnet)
  if (address_str[0] != 'b' || address_str[1] != 'c' || address_str[2] != '1') {
    return false;
  }
  
  // Find separator position (last '1')
  int sep_pos = -1;
  for (int i = address_len - 1; i >= 3; i--) {
    if (address_str[i] == '1') {
      sep_pos = i;
      break;
    }
  }
  if (sep_pos == -1) return false;
  
  // Decode data part
  u8 data[64];
  int data_len = 0;
  
  for (int i = sep_pos + 1; i < address_len; i++) {
    const char *p = strchr (bech32_alphabet, tolower(address_str[i]));
    if (p == NULL) return false;
    data[data_len++] = p - bech32_alphabet;
  }
  
  // Verify checksum (last 6 characters)
  if (!bech32_verify_checksum (address_str, sep_pos, data, data_len)) {
    return false;
  }
  
  // Remove checksum
  data_len -= 6;
  
  // Convert from 5-bit to 8-bit encoding
  u8 decoded[40];
  int decoded_len = 0;
  
  if (!convert_bits (decoded, &decoded_len, 8, data, data_len, 5, false)) {
    return false;
  }
  
  // First byte is witness version (should be 0 for P2WPKH)
  if (decoded[0] != 0) return false;
  
  // Next 20 bytes are hash160
  if (decoded_len != 21) return false;
  
  memcpy (hash160_out, decoded + 1, 20);
  
  return true;
}

// Helper: Convert bits between different bit groups
static bool convert_bits (u8 *out, int *outlen, int outbits, 
                          const u8 *in, int inlen, int inbits, bool pad)
{
  u32 val = 0;
  int bits = 0;
  int maxv = (1 << outbits) - 1;
  int out_pos = 0;
  
  for (int i = 0; i < inlen; i++) {
    val = (val << inbits) | in[i];
    bits += inbits;
    
    while (bits >= outbits) {
      bits -= outbits;
      out[out_pos++] = (val >> bits) & maxv;
    }
  }
  
  if (pad && bits > 0) {
    out[out_pos++] = (val << (outbits - bits)) & maxv;
  }
  else if (bits >= inbits || ((val << (outbits - bits)) & maxv)) {
    return false;
  }
  
  *outlen = out_pos;
  return true;
}

// Helper: Verify Bech32 checksum
static bool bech32_verify_checksum (const u8 *hrp, int hrp_len, 
                                     const u8 *data, int data_len)
{
  // Bech32 checksum algorithm
  // (Implementation of polymod function for Bech32)
  u32 c = 1;
  
  // Process HRP
  for (int i = 0; i < hrp_len; i++) {
    c = bech32_polymod_step (c) ^ (hrp[i] >> 5);
  }
  c = bech32_polymod_step (c);
  for (int i = 0; i < hrp_len; i++) {
    c = bech32_polymod_step (c) ^ (hrp[i] & 0x1f);
  }
  
  // Process data
  for (int i = 0; i < data_len; i++) {
    c = bech32_polymod_step (c) ^ data[i];
  }
  
  return c == 1;
}

static u32 bech32_polymod_step (u32 pre)
{
  u8 b = pre >> 25;
  return ((pre & 0x1FFFFFF) << 5) ^
         (-((b >> 0) & 1) & 0x3b6a57b2UL) ^
         (-((b >> 1) & 1) & 0x26508e6dUL) ^
         (-((b >> 2) & 1) & 0x1ea119faUL) ^
         (-((b >> 3) & 1) & 0x3d4233ddUL) ^
         (-((b >> 4) & 1) & 0x2a1462b3UL);
}
```

### SHA256 Checksum Verification

```c
// Note: Use hashcat's existing sha256_ctx_t and functions
#include "inc_hash_sha256.h"

// Example usage in base58_decode:
sha256_ctx_t sha256_ctx;

sha256_init (&sha256_ctx);
sha256_update (&sha256_ctx, data, 21);
sha256_final (&sha256_ctx);

u8 hash1[32];
memcpy (hash1, sha256_ctx.h, 32);

sha256_init (&sha256_ctx);
sha256_update (&sha256_ctx, hash1, 32);
sha256_final (&sha256_ctx);

// First 4 bytes of sha256_ctx.h are the checksum
```

### Additional Required Functions

```c
u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, 
                       MAYBE_UNUSED const user_options_t *user_options, 
                       MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (milksad_t);
  return esalt_size;
}

const char *ST_HASH = "$milksad$49$1514764800$3HERnjC6RDwg6UYx1hHiAKUp6gz1217h2U";
const char *ST_PASS = ""; // Not used for timestamp brute-force
```

### Complete Module Template

```c
/**
 * Author....: See docs/credits.txt
 * License...: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "memory.h"
#include "emu_inc_hash_sha256.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "Bitcoin Milk Sad Vulnerability (CVE-2023-39910)";
static const u64   KERN_TYPE      = 30501;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "";
static const char *ST_HASH        = "$milksad$49$1514764800$3HERnjC6RDwg6UYx1hHiAKUp6gz1217h2U";

typedef struct milksad
{
  u32 purpose;
  u32 timestamp;
  u8  target_hash160[20];
  u8  padding[4];
} milksad_t;

u32 module_attack_exec    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC;     }
u32 module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;       }
u32 module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;       }
u32 module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;       }
u32 module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;       }
u32 module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;       }
u32 module_hash_category  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY;   }
const char *module_hash_name (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;   }
u64 module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;       }
u32 module_opti_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE;       }
u64 module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;       }
u32 module_salt_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE;       }
const char *module_st_hash(MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH;         }
const char *module_st_pass(MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS;         }

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (milksad_t);
  return esalt_size;
}

// TODO: Implement module_hash_decode() with Base58/Bech32 decoders

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_deprecated_notice        = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_dictstat_disable         = MODULE_DEFAULT;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
  module_ctx->module_extra_tuningdb_block     = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_decode_postprocess  = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_encode              = MODULE_DEFAULT;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hashes_count_min         = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max         = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable            = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_size    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_init    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_term    = MODULE_DEFAULT;
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size           = MODULE_DEFAULT;
  module_ctx->module_hook_size                = MODULE_DEFAULT;
  module_ctx->module_jit_build_options        = MODULE_DEFAULT;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max       = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
  module_ctx->module_potfile_disable          = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
  module_ctx->module_pwdump_column            = MODULE_DEFAULT;
  module_ctx->module_pw_max                   = MODULE_DEFAULT;
  module_ctx->module_pw_min                   = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = MODULE_DEFAULT;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
```

---

## Module 2: module_30502.c - Trust Wallet

### Specifications

- **Module Number**: 30502
- **Hash Name**: "Trust Wallet MT19937 Vulnerability (CVE-2023-31290)"
- **Hash Category**: HASH_CATEGORY_CRYPTOCURRENCY_WALLET
- **Attack Exec**: ATTACK_EXEC_INSIDE_KERNEL
- **Kernel Type**: 30502
- **Salt Type**: SALT_TYPE_EMBEDDED

### Hash Format

```
$trustwallet$<purpose>$<timestamp>$<address>
```

**Parameters:**
- Same as Milk Sad: purpose (44/49/84), timestamp, address

**Examples:**
```
$trustwallet$49$1668384000$3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN
$trustwallet$44$1668384000$1JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN
$trustwallet$84$1668384000$bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c
```

### esalt Structure

```c
typedef struct trustwallet
{
  u32 purpose;
  u32 timestamp;
  u8  target_hash160[20];
  u8  padding[4];
} trustwallet_t;
```

### Implementation Notes

**Nearly identical to Milk Sad module**, with these changes:
- Signature: `$trustwallet$` instead of `$milksad$`
- Hash name: "Trust Wallet MT19937 Vulnerability (CVE-2023-31290)"
- Timestamp range: 1668384000-1669247999 (Nov 14-23, 2022)
- ST_HASH: `$trustwallet$49$1668384000$3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN`

**Key Difference:**
- Trust Wallet uses LSB (Least Significant Byte) extraction: `entropy[i] = mt19937() & 0xFF`
- Milk Sad uses MSB extraction
- This difference is handled in the OpenCL kernel, not in the C module

---

## Module 3: module_30503.c - Cake Wallet

### Specifications

- **Module Number**: 30503
- **Hash Name**: "Cake Wallet Electrum Weak PRNG (2024)"
- **Hash Category**: HASH_CATEGORY_CRYPTOCURRENCY_WALLET
- **Attack Exec**: ATTACK_EXEC_INSIDE_KERNEL
- **Kernel Type**: 30503
- **Salt Type**: SALT_TYPE_NONE

### Hash Format

```
$cakewallet$<address>
```

**Parameters:**
- `address`: Bitcoin P2WPKH (bech32) address only (bc1q...)

**Example:**
```
$cakewallet$bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c
```

### esalt Structure

```c
typedef struct cakewallet
{
  u8  target_hash160[20];
  u8  padding[12];  // Align to 32 bytes
} cakewallet_t;
```

### Implementation Requirements

#### module_hash_decode() Pseudocode

```c
int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, 
                        MAYBE_UNUSED void *digest_buf, 
                        MAYBE_UNUSED salt_t *salt, 
                        MAYBE_UNUSED void *esalt_buf, 
                        MAYBE_UNUSED void *hook_salt_buf, 
                        MAYBE_UNUSED hashinfo_t *hash_info, 
                        const char *line_buf, 
                        MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;
  cakewallet_t *cakewallet = (cakewallet_t *) esalt_buf;

  // 1. Tokenize: $cakewallet$<address>
  hc_token_t token;
  memset (&token, 0, sizeof (hc_token_t));
  
  token.token_cnt = 2;
  token.signatures_cnt = 1;
  token.signatures_buf[0] = "$cakewallet$";
  
  // Token 0: signature
  token.len[0] = 12;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_SIGNATURE;
  
  // Token 1: bech32 address (42-62 characters)
  token.len_min[1] = 42;
  token.len_max[1] = 62;
  token.attr[1] = TOKEN_ATTR_VERIFY_LENGTH;
  
  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);
  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);
  
  // 2. Parse address (must be bc1q)
  const u8 *address_pos = (const u8 *) line_buf + token.len[0];
  const int address_len = token.len[1];
  
  // Verify it's a bech32 address
  if (address_pos[0] != 'b' || address_pos[1] != 'c' || address_pos[2] != '1') {
    return (PARSER_SIGNATURE_UNMATCHED);
  }
  
  // 3. Decode Bech32 to hash160
  if (!bech32_decode_address (address_pos, address_len, cakewallet->target_hash160)) {
    return (PARSER_HASH_ENCODING);
  }
  
  // 4. Set fake digest
  memcpy (digest, cakewallet->target_hash160, 16);
  
  // 5. No salt needed (SALT_TYPE_NONE)
  salt->salt_len = 0;
  
  return (PARSER_OK);
}
```

### Implementation Notes

**Simpler than Milk Sad/Trust Wallet:**
- No purpose field
- No timestamp field
- Only supports Bech32 P2WPKH addresses
- Uses SALT_TYPE_NONE instead of SALT_TYPE_EMBEDDED
- ST_HASH: `$cakewallet$bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c`

---

## Testing Requirements

### Test Vectors

Create test hash files for each module:

**test_30501.hash** (Milk Sad):
```
$milksad$49$1514764800$3HERnjC6RDwg6UYx1hHiAKUp6gz1217h2U
$milksad$44$1514764800$1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
$milksad$84$1514764800$bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
```

**test_30502.hash** (Trust Wallet):
```
$trustwallet$49$1668384000$3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN
$trustwallet$44$1668384000$1JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN
$trustwallet$84$1668384000$bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c
```

**test_30503.hash** (Cake Wallet):
```
$cakewallet$bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c
$cakewallet$bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
```

### Validation Checks

1. **Parse Test**: Verify each module correctly parses test hashes
   ```bash
   ./hashcat -m 30501 test_30501.hash --self-test-disable
   ./hashcat -m 30502 test_30502.hash --self-test-disable
   ./hashcat -m 30503 test_30503.hash --self-test-disable
   ```

2. **Address Validation**:
   - P2PKH addresses start with '1', version byte 0x00
   - P2SH addresses start with '3', version byte 0x05
   - P2WPKH addresses start with 'bc1q', witness version 0
   - Checksums must verify (Base58Check and Bech32)

3. **Range Validation**:
   - Milk Sad: timestamps 1293840000-1704067199
   - Trust Wallet: timestamps 1668384000-1669247999
   - Purpose: only 44, 49, or 84

---

## Build Integration

### Files to Create

1. `/path/to/hashcat/src/modules/module_30501.c` - Milk Sad module
2. `/path/to/hashcat/src/modules/module_30502.c` - Trust Wallet module
3. `/path/to/hashcat/src/modules/module_30503.c` - Cake Wallet module

### Already Copied to Hashcat

**OpenCL Kernels:**
- `hashcat/OpenCL/m30501_a3-pure.cl` (Milk Sad)
- `hashcat/OpenCL/m30502_a3-pure.cl` (Trust Wallet)
- `hashcat/OpenCL/m30503_a3-pure.cl` (Cake Wallet)

**Dependencies:**
- `hashcat/OpenCL/mt19937.cl`
- `hashcat/OpenCL/bip39_full.cl`, `bip39_helpers.cl`, `bip39_pbkdf2.cl`, `bip39_wordlist.cl`
- `hashcat/OpenCL/secp256k1*.cl` (common, field, group, prec, scalar)
- `hashcat/OpenCL/sha2.cl`, `ripemd.cl`, `sha512.cl`
- `hashcat/OpenCL/common.cl`

### Build Command

```bash
cd /path/to/hashcat
make clean
make
```

### Testing

```bash
# Verify module loads
./hashcat --version
./hashcat -m 30501 --help
./hashcat -m 30502 --help
./hashcat -m 30503 --help

# Self-test (will fail until kernels are fully working)
./hashcat -m 30501 --benchmark
./hashcat -m 30502 --benchmark
./hashcat -m 30503 --benchmark
```

---

## Priority Order

1. **Module 30501 (Milk Sad)** - CRITICAL
   - Affects 224,000+ wallets
   - Highest impact
   - Most complex (supports all 3 address types)

2. **Module 30502 (Trust Wallet)** - HIGH
   - Time-sensitive vulnerability (Nov 2022)
   - Nearly identical to Milk Sad
   - Can reuse most code

3. **Module 30503 (Cake Wallet)** - MEDIUM
   - Simpler implementation
   - Only Bech32 support
   - Lower impact (smaller entropy space)

---

## References

- Hashcat source: https://github.com/hashcat/hashcat
- Existing module examples:
  - `src/modules/module_11300.c` - Bitcoin wallet.dat
  - `src/modules/module_16600.c` - Electrum wallet
  - `src/modules/module_18800.c` - Ethereum pre-sale wallet
- Entropy-lab-rs documentation:
  - `HASHCAT_MODULES_RECOMMENDED.md`
  - `HASHCAT_MODULE_IMPLEMENTATION.md`
  - `ADDRESS_FORMAT_REFERENCE.md`
- CVE references:
  - CVE-2023-39910 (Milk Sad)
  - CVE-2023-31290 (Trust Wallet)

---

## Expected Output

Three complete, production-ready C module files that:
- ✅ Parse the specified hash formats correctly
- ✅ Decode Base58 and Bech32 Bitcoin addresses
- ✅ Verify checksums (SHA256 for Base58Check, Bech32 checksum)
- ✅ Populate esalt structures for GPU kernels
- ✅ Follow hashcat coding conventions
- ✅ Include proper error handling
- ✅ Pass validation tests
- ✅ Compile without warnings in hashcat

---

**Status**: Ready for implementation  
**Document Version**: 1.0  
**Created**: 2025-12-11
