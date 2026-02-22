// Complete BIP39 Implementation for GPU
// Includes: Wordlist, Entropy→Mnemonic, PBKDF2-HMAC-SHA512

// Include the complete wordlist
// Note: This will be included from bip39_wordlist_complete.cl

// BIP39 Helper Functions
static void bip39_get_word(uint index, __private uchar* word_out) {
    if (index >= 2048) {
        for (int i = 0; i < 8; i++) word_out[i] = 0;
        return;
    }
    
    for (int i = 0; i < 8; i++) {
        word_out[i] = bip39_wordlist[index][i];
    }
}

// Extract 11-bit index from entropy at bit position
static uint bip39_extract_11bits(const __private uchar* data, uint bit_pos) {
    // Need to read up to 3 bytes to get 11 bits spanning byte boundaries
    uint byte_pos = bit_pos / 8;
    uint bit_offset = bit_pos % 8;
    
    // Read 3 bytes starting at byte_pos and combine into a 24-bit value
    uint val = ((uint)data[byte_pos] << 16);
    if (byte_pos + 1 < 17) val |= ((uint)data[byte_pos + 1] << 8);
    if (byte_pos + 2 < 17) val |= ((uint)data[byte_pos + 2]);
    
    // Shift to get the 11 bits we need at the correct position
    // bit_offset tells us how many bits to skip from the start of the first byte
    // We want bits starting at bit_offset, for 11 bits
    uint shift = 24 - 11 - bit_offset;  // Shift right to align 11 bits at LSB
    
    return (val >> shift) & 0x7FF;  // Mask to 11 bits
}

// Convert 128-bit entropy to 12 BIP39 words
static void bip39_entropy_to_words(
    const __private uchar entropy[16],
    __private uchar words[12][8]
) {
    // Calculate checksum
    uchar entropy_hash[32];
    sha256((__private const uint*)entropy, 16, (__private uint*)entropy_hash);
    
    // Create entropy + checksum (128 bits + 4 bits)
    uchar entropy_with_checksum[17];
    for (int i = 0; i < 16; i++) {
        entropy_with_checksum[i] = entropy[i];
    }
    entropy_with_checksum[16] = entropy_hash[0]; // First 4 bits are checksum
    
    // Extract 12 words (11 bits each = 132 bits total)
    for (int i = 0; i < 12; i++) {
        uint bit_pos = i * 11;
        uint word_index = bip39_extract_11bits(entropy_with_checksum, bit_pos);
        bip39_get_word(word_index, words[i]);
    }
}

// PBKDF2-HMAC-SHA512 with iterations
static void pbkdf2_bip39(
    const __private uchar* password, uint pass_len,
    const __private uchar* salt, uint salt_len,
    uint iterations,
    __private uchar* output
) {
    // PBKDF2 for one block
    uchar salt_block[256];
    for (uint i = 0; i < salt_len && i < 252; i++) {
        salt_block[i] = salt[i];
    }
    // Append block number (1 for first block)
    salt_block[salt_len] = 0;
    salt_block[salt_len + 1] = 0;
    salt_block[salt_len + 2] = 0;
    salt_block[salt_len + 3] = 1;
    
    uchar u[64];
    uchar result[64];
    
    // First iteration
    hmac_sha512(password, pass_len, salt_block, salt_len + 4, u);
    for (int i = 0; i < 64; i++) {
        result[i] = u[i];
    }
    
    // Remaining iterations
    for (uint iter = 1; iter < iterations; iter++) {
        uchar u_next[64];
        hmac_sha512(password, pass_len, u, 64, u_next);
        
        for (int i = 0; i < 64; i++) {
            result[i] ^= u_next[i];
            u[i] = u_next[i];
        }
    }
    
    // Copy result
    for (int i = 0; i < 64; i++) {
        output[i] = result[i];
    }
}

// Complete BIP39: Mnemonic words → Seed
static void bip39_words_to_seed(
    const __private uchar words[12][8],
    __private uchar seed[64]
) {
    // Build mnemonic string
    uchar mnemonic[128];
    uint mnem_len = 0;
    
    for (int i = 0; i < 12; i++) {
        // Copy word
        for (int j = 0; j < 8; j++) {
            if (words[i][j] == 0) break;
            mnemonic[mnem_len++] = words[i][j];
        }
        // Add space (except after last word)
        if (i < 11 && mnem_len < 127) {
            mnemonic[mnem_len++] = ' ';
        }
    }
    
    // Build salt: "mnemonic" + passphrase (empty for no passphrase)
    uchar salt[16] = {'m','n','e','m','o','n','i','c',0,0,0,0,0,0,0,0};
    uint salt_len = 8;
    
    // PBKDF2-HMAC-SHA512 with 2048 iterations
    pbkdf2_bip39(mnemonic, mnem_len, salt, salt_len, 2048, seed);
}

// Master function: Entropy → Seed (Complete BIP39)
static void bip39_entropy_to_seed_complete(
    const __private uchar entropy[16],
    __private uchar seed[64]
) {
    // Step 1: Entropy → Mnemonic words
    uchar words[12][8];
    bip39_entropy_to_words(entropy, words);
    
    // Step 2: Mnemonic → Seed (PBKDF2)
    bip39_words_to_seed(words, seed);
}

// ============================================================================
// 192-bit (18-word) BIP39 support
// ============================================================================

// Extract 11-bit index from entropy at bit position (extended for larger arrays)
static uint bip39_extract_11bits_ext(const __private uchar* data, uint data_len, uint bit_pos) {
    uint byte_pos = bit_pos / 8;
    uint bit_offset = bit_pos % 8;
    
    uint val = ((uint)data[byte_pos] << 16);
    if (byte_pos + 1 < data_len) val |= ((uint)data[byte_pos + 1] << 8);
    if (byte_pos + 2 < data_len) val |= ((uint)data[byte_pos + 2]);
    
    uint shift = 24 - 11 - bit_offset;
    return (val >> shift) & 0x7FF;
}

// Convert 192-bit entropy to 18 BIP39 words
static void bip39_entropy_to_words_18(
    const __private uchar entropy[24],
    __private uchar words[18][8]
) {
    // Calculate checksum (192 bits = 6 bit checksum)
    uchar entropy_hash[32];
    sha256((__private const uint*)entropy, 24, (__private uint*)entropy_hash);
    
    // Create entropy + checksum (192 bits + 6 bits = 198 bits = 25 bytes)
    uchar entropy_with_checksum[25];
    for (int i = 0; i < 24; i++) {
        entropy_with_checksum[i] = entropy[i];
    }
    entropy_with_checksum[24] = entropy_hash[0]; // First 6 bits are checksum
    
    // Extract 18 words (11 bits each = 198 bits total)
    for (int i = 0; i < 18; i++) {
        uint bit_pos = i * 11;
        uint word_index = bip39_extract_11bits_ext(entropy_with_checksum, 25, bit_pos);
        bip39_get_word(word_index, words[i]);
    }
}

// Mnemonic words → Seed (18 words)
static void bip39_words_to_seed_18(
    const __private uchar words[18][8],
    __private uchar seed[64]
) {
    uchar mnemonic[192];
    uint mnem_len = 0;
    
    for (int i = 0; i < 18; i++) {
        for (int j = 0; j < 8; j++) {
            if (words[i][j] == 0) break;
            mnemonic[mnem_len++] = words[i][j];
        }
        if (i < 17 && mnem_len < 191) {
            mnemonic[mnem_len++] = ' ';
        }
    }
    
    uchar salt[16] = {'m','n','e','m','o','n','i','c',0,0,0,0,0,0,0,0};
    uint salt_len = 8;
    
    pbkdf2_bip39(mnemonic, mnem_len, salt, salt_len, 2048, seed);
}

// Master function: 192-bit Entropy → Seed
static void bip39_entropy_to_seed_complete_24(
    const __private uchar entropy[24],
    __private uchar seed[64]
) {
    uchar words[18][8];
    bip39_entropy_to_words_18(entropy, words);
    bip39_words_to_seed_18(words, seed);
}

// ============================================================================
// 256-bit (24-word) BIP39 support
// ============================================================================

// Convert 256-bit entropy to 24 BIP39 words
static void bip39_entropy_to_words_24(
    const __private uchar entropy[32],
    __private uchar words[24][8]
) {
    // Calculate checksum (256 bits = 8 bit checksum)
    uchar entropy_hash[32];
    sha256((__private const uint*)entropy, 32, (__private uint*)entropy_hash);
    
    // Create entropy + checksum (256 bits + 8 bits = 264 bits = 33 bytes)
    uchar entropy_with_checksum[33];
    for (int i = 0; i < 32; i++) {
        entropy_with_checksum[i] = entropy[i];
    }
    entropy_with_checksum[32] = entropy_hash[0]; // First 8 bits are checksum
    
    // Extract 24 words (11 bits each = 264 bits total)
    for (int i = 0; i < 24; i++) {
        uint bit_pos = i * 11;
        uint word_index = bip39_extract_11bits_ext(entropy_with_checksum, 33, bit_pos);
        bip39_get_word(word_index, words[i]);
    }
}

// Mnemonic words → Seed (24 words)
static void bip39_words_to_seed_24(
    const __private uchar words[24][8],
    __private uchar seed[64]
) {
    uchar mnemonic[256];
    uint mnem_len = 0;
    
    for (int i = 0; i < 24; i++) {
        for (int j = 0; j < 8; j++) {
            if (words[i][j] == 0) break;
            mnemonic[mnem_len++] = words[i][j];
        }
        if (i < 23 && mnem_len < 255) {
            mnemonic[mnem_len++] = ' ';
        }
    }
    
    uchar salt[16] = {'m','n','e','m','o','n','i','c',0,0,0,0,0,0,0,0};
    uint salt_len = 8;
    
    pbkdf2_bip39(mnemonic, mnem_len, salt, salt_len, 2048, seed);
}

// Master function: 256-bit Entropy → Seed
static void bip39_entropy_to_seed_complete_32(
    const __private uchar entropy[32],
    __private uchar seed[64]
) {
    uchar words[24][8];
    bip39_entropy_to_words_24(entropy, words);
    bip39_words_to_seed_24(words, seed);
}

