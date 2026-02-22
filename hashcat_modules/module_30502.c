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
static const char *HASH_NAME      = "Trust Wallet MT19937 Vulnerability (CVE-2023-31290)";
static const u64   KERN_TYPE      = 30502;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "";
static const char *ST_HASH        = "$trustwallet$49$1668384000$3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN";

// Timestamp validation constants (Trust Wallet vulnerability window)
#define TRUSTWALLET_MIN_TIMESTAMP 1668384000  // 2022-11-14
#define TRUSTWALLET_MAX_TIMESTAMP 1669247999  // 2022-11-23

typedef struct trustwallet
{
  u32 purpose;
  u32 timestamp;
  u8  target_hash160[20];
  u8  padding[4];
} trustwallet_t;

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
  const u64 esalt_size = (const u64) sizeof (trustwallet_t);
  return esalt_size;
}

// Helper: Bech32 polymod step
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

// Helper: Convert bits between different bit groups
static bool convert_bits (u8 *out, int *outlen, int outbits, const u8 *in, int inlen, int inbits, bool pad)
{
  u32 val = 0;
  int bits = 0;
  int maxv = (1 << outbits) - 1;
  int out_pos = 0;
  
  for (int i = 0; i < inlen; i++)
  {
    val = (val << inbits) | in[i];
    bits += inbits;
    
    while (bits >= outbits)
    {
      bits -= outbits;
      out[out_pos++] = (val >> bits) & maxv;
    }
  }
  
  if (pad && bits > 0)
  {
    out[out_pos++] = (val << (outbits - bits)) & maxv;
  }
  else if (bits >= inbits || ((val << (outbits - bits)) & maxv))
  {
    return false;
  }
  
  *outlen = out_pos;
  return true;
}

// Helper: Verify Bech32 checksum
static bool bech32_verify_checksum (const u8 *hrp, int hrp_len, const u8 *data, int data_len)
{
  u32 c = 1;
  
  // Process HRP
  for (int i = 0; i < hrp_len; i++)
  {
    c = bech32_polymod_step (c) ^ (hrp[i] >> 5);
  }
  c = bech32_polymod_step (c);
  for (int i = 0; i < hrp_len; i++)
  {
    c = bech32_polymod_step (c) ^ (hrp[i] & 0x1f);
  }
  
  // Process data
  for (int i = 0; i < data_len; i++)
  {
    c = bech32_polymod_step (c) ^ data[i];
  }
  
  return c == 1;
}

// Helper function to decode Bech32 address (P2WPKH)
static bool bech32_decode_address (const u8 *address_str, const int address_len, u8 *hash160_out)
{
  // Bech32 alphabet
  static const char bech32_alphabet[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  
  // Verify HRP ("bc" for mainnet)
  if (address_str[0] != 'b' || address_str[1] != 'c' || address_str[2] != '1')
  {
    return false;
  }
  
  // Find separator position (last '1')
  int sep_pos = -1;
  for (int i = address_len - 1; i >= 3; i--)
  {
    if (address_str[i] == '1')
    {
      sep_pos = i;
      break;
    }
  }
  if (sep_pos == -1) return false;
  
  // Decode data part
  u8 data[64];
  int data_len = 0;
  
  for (int i = sep_pos + 1; i < address_len; i++)
  {
    const char *p = strchr (bech32_alphabet, tolower(address_str[i]));
    if (p == NULL) return false;
    data[data_len++] = p - bech32_alphabet;
  }
  
  // Verify checksum (last 6 characters)
  const u8 hrp[] = {'b', 'c'};
  if (!bech32_verify_checksum (hrp, 2, data, data_len))
  {
    return false;
  }
  
  // Remove checksum
  data_len -= 6;
  
  // Convert from 5-bit to 8-bit encoding
  u8 decoded[40];
  int decoded_len = 0;
  
  if (!convert_bits (decoded, &decoded_len, 8, data, data_len, 5, false))
  {
    return false;
  }
  
  // First byte is witness version (should be 0 for P2WPKH)
  if (decoded[0] != 0) return false;
  
  // Next 20 bytes are hash160
  if (decoded_len != 21) return false;
  
  memcpy (hash160_out, decoded + 1, 20);
  
  return true;
}

// Helper function to decode Base58Check address
static bool base58_decode_address (const u8 *address_str, const int address_len, u8 expected_version, u8 *hash160_out)
{
  // Base58 alphabet (Bitcoin uses this specific ordering)
  static const char base58_alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  
  // Decode Base58 to binary (25 bytes: version + hash160 + checksum)
  u8 decoded[25];
  memset (decoded, 0, 25);
  
  // Convert Base58 string to big integer, then to bytes
  for (int i = 0; i < address_len; i++)
  {
    const char *p = strchr (base58_alphabet, address_str[i]);
    if (p == NULL) return false;
    
    int digit = p - base58_alphabet;
    
    // Multiply existing value by 58 and add new digit
    int carry = digit;
    for (int j = 24; j >= 0; j--)
    {
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

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;
  trustwallet_t *trustwallet = (trustwallet_t *) esalt_buf;

  // Tokenize the input: $trustwallet$<purpose>$<timestamp>$<address>
  hc_token_t token;
  memset (&token, 0, sizeof (hc_token_t));
  
  token.token_cnt = 4;
  token.signatures_cnt = 1;
  token.signatures_buf[0] = "$trustwallet$";
  
  // Token 0: signature "$trustwallet$"
  token.len[0] = 13;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_SIGNATURE;
  
  // Token 1: purpose (2 digits)
  token.len_min[1] = 2;
  token.len_max[1] = 2;
  token.attr[1] = TOKEN_ATTR_VERIFY_LENGTH;
  token.sep[1] = '$';
  
  // Token 2: timestamp (10 digits)
  token.len_min[2] = 10;
  token.len_max[2] = 10;
  token.attr[2] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;
  token.sep[2] = '$';
  
  // Token 3: address (25-62 characters)
  token.len_min[3] = 25;
  token.len_max[3] = 62;
  token.attr[3] = TOKEN_ATTR_VERIFY_LENGTH;
  
  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);
  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);
  
  // Parse purpose
  const u8 *purpose_pos = (const u8 *) line_buf + token.len[0];
  const int purpose = atoi ((const char *) purpose_pos);
  
  if (purpose != 44 && purpose != 49 && purpose != 84)
  {
    return (PARSER_SIGNATURE_UNMATCHED);
  }
  trustwallet->purpose = purpose;
  
  // Parse timestamp
  const u8 *timestamp_pos = (const u8 *) line_buf + token.len[0] + token.len[1] + 1;
  const u32 timestamp = atoi ((const char *) timestamp_pos);
  
  // Validate timestamp range
  if (timestamp < TRUSTWALLET_MIN_TIMESTAMP || timestamp > TRUSTWALLET_MAX_TIMESTAMP)
  {
    return (PARSER_HASH_VALUE);
  }
  trustwallet->timestamp = timestamp;
  
  // Parse address
  const u8 *address_pos = (const u8 *) line_buf + token.len[0] + token.len[1] + 1 + token.len[2] + 1;
  const int address_len = token.len[3];
  
  // Decode address based on purpose
  bool decode_success = false;
  
  if (purpose == 44 && address_pos[0] == '1')
  {
    // P2PKH - decode Base58, expect version 0x00
    decode_success = base58_decode_address (address_pos, address_len, 0x00, trustwallet->target_hash160);
  }
  else if (purpose == 49 && address_pos[0] == '3')
  {
    // P2SH - decode Base58, expect version 0x05
    decode_success = base58_decode_address (address_pos, address_len, 0x05, trustwallet->target_hash160);
  }
  else if (purpose == 84 && address_pos[0] == 'b' && address_pos[1] == 'c' && address_pos[2] == '1')
  {
    // Bech32 - decode Bech32
    decode_success = bech32_decode_address (address_pos, address_len, trustwallet->target_hash160);
  }
  else
  {
    return (PARSER_HASH_ENCODING);
  }
  
  if (!decode_success)
  {
    return (PARSER_HASH_ENCODING);
  }
  
  // Set fake digest (not used, but required by hashcat)
  memcpy (digest, trustwallet->target_hash160, 16);
  
  // Set fake salt (not used, but required by hashcat)
  salt->salt_buf[0] = trustwallet->timestamp;
  salt->salt_len = 4;
  
  return (PARSER_OK);
}

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
