// Test kernel - extract MT19937 entropy from GPU for validation
__kernel void test_mt19937(
    __global uint* seeds,
    __global uchar* results,
    uint count
) {
    uint gid = get_global_id(0);
    if (gid >= count) return;
    
    uint seed = seeds[gid];
    
    // Generate 128-bit entropy using MT19937
    uint entropy_words[4];
    mt19937_extract_128(seed, entropy_words);
    
    // Extract bytes (MSB first - Libbitcoin style)
    uchar entropy[16];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            entropy[i*4 + j] = (entropy_words[i] >> (24 - j*8)) & 0xFF;
        }
    }
    
    // Copy to results
    for (int i = 0; i < 16; i++) {
        results[gid * 16 + i] = entropy[i];
    }
}
