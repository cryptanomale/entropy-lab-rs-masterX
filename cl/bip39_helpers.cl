// Helper functions for BIP39 mnemonic generation
// These are used by batch_address.cl for Milk Sad and Dart PRNG paths

// Generate BIP39 mnemonic from entropy
// Returns the length of the mnemonic string
static inline int generate_mnemonic(__private uchar* entropy, int entropy_len, __private uchar* mnemonic) {
    // Hash entropy for checksum
    uint entropy_hash_buf[8] __attribute__((aligned(4)));
    sha256((__private const uint*)entropy, entropy_len, entropy_hash_buf);
    uchar checksum = (((uchar*)entropy_hash_buf)[0] >> 4) & 0xF;
    
    // BIP39 entropy (128 bits) + 4-bit checksum = 132 bits
    // We need 12 words of 11 bits each.
    
    // Create a 17-byte buffer for entropy + checksum
    uchar buf[17];
    for(int i=0; i<16; i++) buf[i] = entropy[i];
    buf[16] = checksum << 4; // Checksum is the 4 most significant bits of the last byte
    
    // Extract 11-bit chunks
    ushort indices[12];
    for (int i = 0; i < 12; i++) {
        int bit_pos = i * 11;
        int byte_pos = bit_pos / 8;
        int bit_offset = bit_pos % 8;
        
        // Read 16 bits starting at byte_pos
        uint val = ((uint)buf[byte_pos] << 8) | (uint)buf[byte_pos + 1];
        if (bit_offset > 5) {
             // Need one more byte if 11 bits span across 3 bytes
             val = (val << 8) | (uint)buf[byte_pos + 2];
             indices[i] = (val >> (16 - 11 - bit_offset)) & 0x7FF;
        } else {
             indices[i] = (val >> (16 - 11 - bit_offset)) & 0x7FF;
        }
    }
    
    // Build mnemonic string
    int mnemonic_index = 0;
    for (int i=0; i < 12; i++) {
        int word_index = indices[i];
        int word_length = word_lengths[word_index];
        
        for(int j=0; j<word_length; j++) {
            mnemonic[mnemonic_index++] = words[word_index][j];
        }
        mnemonic[mnemonic_index++] = 32; // space
    }
    mnemonic[mnemonic_index - 1] = 0; // null terminate
    
    // Calculate actual length
    int len = 11; // 11 spaces
    for(int i=0; i<12; i++) len += word_lengths[indices[i]];
    
    return len;
}

// BIP39 Mnemonic to Seed (PBKDF2-HMAC-SHA512)
// Optimized with state memoization and unrolling
static inline void mnemonic_to_seed(__private uchar* mnemonic, int mnemonic_len, __private uchar* salt, int salt_len, __private uchar* seed_output) {
    uchar current_hash[64];
    uchar last_hash[64];
    uchar seed[64];
    for(int i=0; i<64; i++) seed[i] = 0;
    
    // T1 = HMAC(mnemonic, salt || 0001)
    uchar salt_with_index[128];
    for(int i=0; i<salt_len; i++) salt_with_index[i] = salt[i];
    salt_with_index[salt_len] = 0x00;
    salt_with_index[salt_len+1] = 0x00;
    salt_with_index[salt_len+2] = 0x00;
    salt_with_index[salt_len+3] = 0x01;
    
    hmac_sha512(mnemonic, mnemonic_len, salt_with_index, salt_len + 4, last_hash);
    for(int i=0; i<64; i++) seed[i] = last_hash[i];
    
    // Memoize HMAC states for mnemonic
    // HMAC(K, m) = H((K ^ opad) || H((K ^ ipad) || m))
    // mnemonic is the key (K)
    uchar ipad[128], opad[128];
    uchar key_buf[128];
    for(int i=0; i<128; i++) key_buf[i] = 0;
    for(int i=0; i<mnemonic_len && i<128; i++) key_buf[i] = mnemonic[i];
    
    for(int i=0; i<128; i++) {
        ipad[i] = key_buf[i] ^ 0x36;
        opad[i] = key_buf[i] ^ 0x5c;
    }
    
    ulong ipad_state[8], opad_state[8];
    for(int i=0; i<8; i++) ipad_state[i] = k_sha512_iv[i];
    sha512_compress(ipad_state, (const __private ulong*)ipad);
    
    for(int i=0; i<8; i++) opad_state[i] = k_sha512_iv[i];
    sha512_compress(opad_state, (const __private ulong*)opad);
    
    // PBKDF2 rounds (2047 remaining)
    // Unrolled by factor 4
    for (int j=1; j<2048; j+=4) {
        for(int r=0; r<4; r++) {
            // Inner hash: H((K^ipad) || last_hash)
            ulong state[8];
            for(int i=0; i<8; i++) state[i] = ipad_state[i];
            
            // last_hash is 64 bytes, fits in 1 block with padding
            ulong block[16];
            for(int i=0; i<16; i++) block[i] = 0;
            for(int i=0; i<64; i++) ((uchar*)block)[i] = last_hash[i];
            ((uchar*)block)[64] = 0x80;
            block[15] = SWAP512((ulong)(128 + 64) * 8);
            
            sha512_compress(state, block);
            
            uchar inner_hash[64];
            for(int i=0; i<8; i++) ((ulong*)inner_hash)[i] = SWAP512(state[i]);
            
            // Outer hash: H((K^opad) || inner_hash)
            for(int i=0; i<8; i++) state[i] = opad_state[i];
            for(int i=0; i<16; i++) block[i] = 0;
            for(int i=0; i<64; i++) ((uchar*)block)[i] = inner_hash[i];
            ((uchar*)block)[64] = 0x80;
            block[15] = SWAP512((ulong)(128 + 64) * 8);
            
            sha512_compress(state, block);
            
            for(int i=0; i<8; i++) ((ulong*)last_hash)[i] = SWAP512(state[i]);
            for(int i=0; i<64; i++) seed[i] ^= last_hash[i];
        }
    }
    
    for(int i=0; i<64; i++) seed_output[i] = seed[i];
}
