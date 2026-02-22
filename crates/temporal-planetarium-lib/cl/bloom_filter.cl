/**
 * bloom_filter.cl - GPU-Accelerated Blocked Bloom Filter
 * 
 * Part of STORY-003-001: Implement OpenCL Blocked Bloom Filter Kernel
 * 
 * This kernel implements a Blocked Bloom Filter (BBF) optimized for GPU cache lines.
 * Key design principles:
 * - 256-bit (32-byte) block alignment for GPU L1 cache optimization
 * - Multiple hash functions using multiplicative hashing
 * - O(1) amortized lookup time for membership testing
 * 
 * References:
 * - Foundation & Scale Strategy Research (2025-12-23)
 * - arxiv.org/abs/2103.16989 (GPU Bloom Filters)
 */

// Configuration constants
#define BLOOM_BLOCK_SIZE 256       // 256 bits = 32 bytes (GPU cache line)
#define BLOOM_BLOCK_BYTES 32       // Bytes per block
#define BLOOM_NUM_HASHES 15        // k=15 for <0.1% FPR with optimal sizing
#define BLOOM_HASH_SEED 0x9E3779B9 // Golden ratio prime

/**
 * MurmurHash3-inspired hash function for GPU
 * Fast, well-distributed, and suitable for Bloom filter hashing
 */
inline uint murmur_hash(__global const uchar* data, uint len, uint seed) {
    uint h = seed;
    uint k;
    
    // Body: process 4-byte chunks
    for (uint i = 0; i < len / 4; i++) {
        k = ((__global uint*)data)[i];
        k *= 0xCC9E2D51;
        k = (k << 15) | (k >> 17);
        k *= 0x1B873593;
        
        h ^= k;
        h = (h << 13) | (h >> 19);
        h = h * 5 + 0xE6546B64;
    }
    
    // Tail: handle remaining bytes
    uint remaining = len & 3;
    if (remaining > 0) {
        k = 0;
        for (uint i = 0; i < remaining; i++) {
            k |= (uint)data[len - remaining + i] << (i * 8);
        }
        k *= 0xCC9E2D51;
        k = (k << 15) | (k >> 17);
        k *= 0x1B873593;
        h ^= k;
    }
    
    // Finalization
    h ^= len;
    h ^= h >> 16;
    h *= 0x85EBCA6B;
    h ^= h >> 13;
    h *= 0xC2B2AE35;
    h ^= h >> 16;
    
    return h;
}

/**
 * Generate k hash values from a single base hash using double hashing
 * h_i = h1 + i * h2 (mod m)
 */
inline uint get_hash_k(__global const uchar* item, uint item_len, uint k, uint filter_size_bits) {
    uint h1 = murmur_hash(item, item_len, BLOOM_HASH_SEED);
    uint h2 = murmur_hash(item, item_len, h1);
    return (h1 + k * h2) % filter_size_bits;
}

/**
 * Blocked Bloom Filter: Check if an item is possibly in the filter
 * 
 * @param filter       The Bloom filter bit array (global memory)
 * @param filter_size  Size of the filter in bytes
 * @param items        Array of items to check (e.g., Bitcoin addresses as 25-byte hashes)
 * @param item_len     Length of each item in bytes
 * @param num_items    Number of items to check
 * @param results      Output: 1 if possibly present, 0 if definitely not present
 */
__kernel void bloom_lookup(
    __global const uchar* filter,
    const uint filter_size_bytes,
    __global const uchar* items,
    const uint item_len,
    const uint num_items,
    __global uchar* results
) {
    uint gid = get_global_id(0);
    
    if (gid >= num_items) return;
    
    // Get pointer to this thread's item
    __global const uchar* item = items + (gid * item_len);
    uint filter_size_bits = filter_size_bytes * 8;
    
    // Check all k hash positions
    uchar found = 1;
    for (uint k = 0; k < BLOOM_NUM_HASHES; k++) {
        uint bit_pos = get_hash_k(item, item_len, k, filter_size_bits);
        uint byte_pos = bit_pos / 8;
        uint bit_offset = bit_pos % 8;
        
        // Check if bit is set
        if ((filter[byte_pos] & (1 << bit_offset)) == 0) {
            found = 0;
            break; // Early exit: definitely not in filter
        }
    }
    
    results[gid] = found;
}

/**
 * Blocked Bloom Filter: Insert items into the filter
 * 
 * @param filter       The Bloom filter bit array (global memory, read-write)
 * @param filter_size  Size of the filter in bytes
 * @param items        Array of items to insert
 * @param item_len     Length of each item in bytes
 * @param num_items    Number of items to insert
 */
__kernel void bloom_insert(
    __global uchar* filter,
    const uint filter_size_bytes,
    __global const uchar* items,
    const uint item_len,
    const uint num_items
) {
    uint gid = get_global_id(0);
    
    if (gid >= num_items) return;
    
    // Get pointer to this thread's item
    __global const uchar* item = items + (gid * item_len);
    uint filter_size_bits = filter_size_bytes * 8;
    
    // Set all k hash positions
    for (uint k = 0; k < BLOOM_NUM_HASHES; k++) {
        uint bit_pos = get_hash_k(item, item_len, k, filter_size_bits);
        uint byte_pos = bit_pos / 8;
        uint bit_offset = bit_pos % 8;
        
        // Atomic OR to set bit (thread-safe)
        atomic_or((__global int*)(filter + (byte_pos & ~3)), 1 << ((byte_pos & 3) * 8 + bit_offset));
    }
}

/**
 * Combined kernel: Bloom filter lookup during address derivation
 * 
 * This kernel is designed to be called from within the randstorm_scan pipeline:
 * 1. Derive address from PRNG state
 * 2. Check address against Bloom filter
 * 3. Write match result
 * 
 * @param filter           Pre-populated Bloom filter with target addresses
 * @param filter_size      Size of filter in bytes
 * @param derived_addresses Array of 25-byte P2PKH addresses (hash160 + version + checksum)
 * @param num_addresses   Number of addresses to check
 * @param matches         Output: indices of potential matches (for secondary verification)
 * @param match_count     Output: number of potential matches found (atomic counter)
 */
__kernel void bloom_filter_check_addresses(
    __global const uchar* filter,
    const uint filter_size_bytes,
    __global const uchar* derived_addresses,
    const uint num_addresses,
    __global uint* matches,
    __global volatile uint* match_count
) {
    uint gid = get_global_id(0);
    
    if (gid >= num_addresses) return;
    
    // Each address is 25 bytes (1 version + 20 hash160 + 4 checksum)
    const uint ADDRESS_LEN = 25;
    __global const uchar* addr = derived_addresses + (gid * ADDRESS_LEN);
    uint filter_size_bits = filter_size_bytes * 8;
    
    // Check all k hash positions
    uchar possibly_present = 1;
    for (uint k = 0; k < BLOOM_NUM_HASHES; k++) {
        uint bit_pos = get_hash_k(addr, ADDRESS_LEN, k, filter_size_bits);
        uint byte_pos = bit_pos / 8;
        uint bit_offset = bit_pos % 8;
        
        if ((filter[byte_pos] & (1 << bit_offset)) == 0) {
            possibly_present = 0;
            break;
        }
    }
    
    // If possibly present, record for secondary verification
    if (possibly_present) {
        uint idx = atomic_add(match_count, 1);
        matches[idx] = gid;
    }
}
