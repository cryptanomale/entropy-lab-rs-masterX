// Cake Wallet Full GPU Scanner
// Dependencies: dart_prng, sha2, mnemonic_constants

// OPTIMIZATION: Inline hint for frequently called function
inline int compare_hashes(uchar* a, __global const uchar* b) {
    // OPTIMIZATION: Unroll comparison loop for better performance
    #pragma unroll 8
    for (int i = 0; i < 32; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

// OPTIMIZATION: Use restrict and const for read-only buffers
__kernel void cake_hash(
    __global const ulong * restrict timestamps,
    __global const uchar * restrict target_hashes,
    uint target_count,
    __global ulong * restrict results,
    __global uint * restrict result_count
) {
    ulong gid = get_global_id(0);
    
    // OPTIMIZATION: Coalesced memory read
    ulong timestamp_us = timestamps[gid];
    
    // 1. Dart PRNG -> Entropy
    DartRandom dart_rng;
    dart_random_init(&dart_rng, timestamp_us);
    
    uchar entropy[16];
    dart_random_generate_bytes(&dart_rng, entropy, 16);
    
    // 2. Entropy -> Mnemonic Indices
    // (Logic copied from batch_address.cl / int_to_address.cl)
    // We need to handle the 16 bytes entropy manually
    
    // Need SHA256 of entropy for checksum
    uchar entropy_aligned[16] __attribute__((aligned(4)));
    for (int i = 0; i < 16; i++) {
        entropy_aligned[i] = entropy[i];
    }
    
    uchar entropy_hash[32] __attribute__((aligned(4)));
    sha256((__private const uint*)entropy_aligned, 16, (__private uint*)entropy_hash);
    uchar checksum = (entropy_hash[0] >> 4) & 0xF;
    
    // Convert 16 bytes to two ulongs for bit manipulation
    ulong mnemonic_lo = 0;
    ulong mnemonic_hi = 0;
    
    // Load bytes into ulongs (Little Endian)
    for(int i=0; i<8; i++) mnemonic_lo |= ((ulong)entropy[i]) << (i*8);
    for(int i=0; i<8; i++) mnemonic_hi |= ((ulong)entropy[i+8]) << (i*8);
    
    ushort indices[12];
    indices[0] = (mnemonic_hi >> 53) & 2047;
    indices[1] = (mnemonic_hi >> 42) & 2047;
    indices[2] = (mnemonic_hi >> 31) & 2047;
    indices[3] = (mnemonic_hi >> 20) & 2047;
    indices[4] = (mnemonic_hi >> 9)  & 2047;
    indices[5] = ((mnemonic_hi & ((1 << 9)-1)) << 2) | ((mnemonic_lo >> 62) & 3);
    indices[6] = (mnemonic_lo >> 51) & 2047;
    indices[7] = (mnemonic_lo >> 40) & 2047;
    indices[8] = (mnemonic_lo >> 29) & 2047;
    indices[9] = (mnemonic_lo >> 18) & 2047;
    indices[10] = (mnemonic_lo >> 7) & 2047;
    indices[11] = ((mnemonic_lo & ((1 << 7)-1)) << 4) | checksum;
    
    // 3. Construct Mnemonic String
    uchar mnemonic[256];
    int pos = 0;
    for (int i=0; i < 12; i++) {
        int word_index = indices[i];
        int word_length = word_lengths[word_index];
        
        if (i > 0) mnemonic[pos++] = ' ';
        
        for(int j=0; j<word_length; j++) {
            mnemonic[pos++] = words[word_index][j];
        }
    }
    
    // 4. SHA256 Hash of Mnemonic
    uchar mnemonic_aligned[256] __attribute__((aligned(4)));
    for (int i = 0; i < pos; i++) {
        mnemonic_aligned[i] = mnemonic[i];
    }
    
    uchar hash[32] __attribute__((aligned(4)));
    sha256((__private const uint*)mnemonic_aligned, pos, (__private uint*)hash);
    
    // 5. Binary Search in Target Hashes
    int l = 0;
    int r = target_count - 1;
    
    while (l <= r) {
        int m = l + (r - l) / 2;
        int cmp = compare_hashes(hash, &target_hashes[m * 32]);
        
        if (cmp == 0) {
            // Found!
            uint idx = atomic_inc(result_count);
            if (idx < 1024) { // Limit results to avoid overflow
                results[idx] = timestamp_us;
            }
            return;
        }
        
        if (cmp < 0) {
            // hash < target, so target is in right half? 
            // No, if hash < target[m], then we need smaller targets?
            // Wait, array is sorted ascending.
            // If hash < target[m], then hash is to the left.
            r = m - 1;
        } else {
            l = m + 1;
        }
    }
}
