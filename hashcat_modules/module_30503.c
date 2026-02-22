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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "Cake Wallet Electrum Weak PRNG (2024)";
static const u64   KERN_TYPE      = 30503;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_NONE;
static const char *ST_PASS        = "";
static const char *ST_HASH        = "$cakewallet$bc1q34aq5drpuwy3wgl9lhup9892qp6svr8ldzyy7c";

typedef struct cakewallet
{
  u8  target_hash160[20];
  u8  padding[12];
} cakewallet_t;

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
  const u64 esalt_size = (const u64) sizeof (cakewallet_t);
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

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;
  cakewallet_t *cakewallet = (cakewallet_t *) esalt_buf;

  // Tokenize: $cakewallet$<address>
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
  
  // Parse address (must be bc1q)
  const u8 *address_pos = (const u8 *) line_buf + token.len[0];
  const int address_len = token.len[1];
  
  // Verify it's a bech32 address
  if (address_pos[0] != 'b' || address_pos[1] != 'c' || address_pos[2] != '1')
  {
    return (PARSER_SIGNATURE_UNMATCHED);
  }
  
  // Decode Bech32 to hash160
  if (!bech32_decode_address (address_pos, address_len, cakewallet->target_hash160))
  {
    return (PARSER_HASH_ENCODING);
  }
  
  // Set fake digest
  memcpy (digest, cakewallet->target_hash160, 16);
  
  // Note: SALT_TYPE_NONE means we don't use salt for this module,
  // but we still need to access the salt structure safely.
  // Setting salt_len to 0 is safe even with SALT_TYPE_NONE.
  salt->salt_len = 0;
  
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
