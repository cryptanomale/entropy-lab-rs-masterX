// BIP39 Wordlist - 2048 English words
// Each word is max 8 characters, stored as 8 bytes
// Total: 2048 * 8 = 16KB constant memory

__constant uchar bip39_wordlist[2048][8] = {
    // Index 0-9
    "abandon\0", "ability\0", "able\0\0\0\0", "about\0\0\0", "above\0\0\0",
    "absent\0\0", "absorb\0\0", "abstract", "absurd\0\0", "abuse\0\0\0",
    // Index 10-19
    "access\0\0", "accident", "account\0", "accuse\0\0", "achieve\0",
    "acid\0\0\0\0", "acoustic", "acquire\0", "across\0\0", "act\0\0\0\0\0",
    // Index 20-29
    "action\0\0", "actor\0\0\0", "actress\0", "actual\0\0", "adapt\0\0\0",
    "add\0\0\0\0\0", "addict\0\0", "address\0", "adjust\0\0", "admit\0\0\0",
    // Index 30-39
    "adult\0\0\0", "advance\0", "advice\0\0", "aerobic\0", "affair\0\0",
    "afford\0\0", "afraid\0\0", "again\0\0\0", "age\0\0\0\0\0", "agent\0\0\0",
    // Index 40-49
    "agree\0\0\0", "ahead\0\0\0", "aim\0\0\0\0\0", "air\0\0\0\0\0", "airport\0",
    "aisle\0\0\0", "alarm\0\0\0", "album\0\0\0", "alcohol\0", "alert\0\0\0",
    // Index 50-59
    "alien\0\0\0", "all\0\0\0\0\0", "alley\0\0\0", "allow\0\0\0", "almost\0\0",
    "alone\0\0\0", "alpha\0\0\0", "already\0", "also\0\0\0\0", "alter\0\0\0",
    
    // TODO: Add remaining 1988 words
    // This is a LARGE file - for proof of concept, showing structure
    // Full wordlist needs all 2048 words
    
    // Placeholder for remaining words (will be filled)
};

// Helper: Get word from wordlist by index
static void bip39_get_word(uint index, __private uchar* word_out) {
    if (index >= 2048) return;
    
    for (int i = 0; i < 8; i++) {
        word_out[i] = bip39_wordlist[index][i];
    }
}

// Convert 11 bits to word index
static uint bip39_bits_to_index(const uchar* entropy, uint bit_offset) {
    uint byte_offset = bit_offset / 8;
    uint bit_in_byte = bit_offset % 8;
    
    // Extract 11 bits across byte boundaries
    uint index = 0;
    
    // Get bits from current byte
    uint bits_in_first = 8 - bit_in_byte;
    if (bits_in_first >= 11) {
        // All 11 bits in one byte
        index = (entropy[byte_offset] >> (bits_in_first - 11)) & 0x7FF;
    } else {
        // Split across multiple bytes
        index = (entropy[byte_offset] & ((1 << bits_in_first) - 1)) << (11 - bits_in_first);
        
        uint remaining_bits = 11 - bits_in_first;
        uint next_byte = byte_offset + 1;
        
        if (remaining_bits <= 8) {
            index |= entropy[next_byte] >> (8 - remaining_bits);
        } else {
            // Need third byte
            index |= entropy[next_byte] << (remaining_bits - 8);
            index |= entropy[next_byte + 1] >> (16 - remaining_bits);
        }
    }
    
    return index & 0x7FF; // 11 bits = 0-2047
}

// Convert 128-bit entropy to 12 BIP39 words
static void bip39_entropy_to_mnemonic(
    const uchar entropy[16],
    __private uchar mnemonic[12][8]
) {
    // Add checksum
    uchar entropy_with_checksum[17];
    for (int i = 0; i < 16; i++) {
        entropy_with_checksum[i] = entropy[i];
    }
    
    // SHA256 for checksum (first 4 bits)
    uchar hash[32];
    sha256((const uint*)entropy, 16, (uint*)hash);
    entropy_with_checksum[16] = hash[0];
    
    // Extract 12 words (11 bits each)
    for (int word_idx = 0; word_idx < 12; word_idx++) {
        uint bit_offset = word_idx * 11;
        uint index = bip39_bits_to_index(entropy_with_checksum, bit_offset);
        bip39_get_word(index, mnemonic[word_idx]);
    }
}
