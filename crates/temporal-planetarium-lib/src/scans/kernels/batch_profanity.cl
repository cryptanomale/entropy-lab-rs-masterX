// Profanity Vanity Address Cracker
// Brute-forces 32-bit seeds used by Profanity's mt19937_64 RNG

__kernel void batch_profanity(
    __global ulong* results,
    __global uint* result_count,
    ulong target_addr_part1, // First 8 bytes of address
    ulong target_addr_part2, // Next 8 bytes
    uint target_addr_part3,  // Last 4 bytes
    ulong offset
) {
    ulong gid = get_global_id(0) + offset;
    
    // Seed is simply the GID (iterating 0..2^32)
    ulong seed = gid;
    
    // Initialize MT19937-64
    mt19937_64_state state;
    mt19937_64_init(&state, seed);
    
    // Generate Private Key (192 bits from 3x 64-bit extractions?)
    // Profanity uses std::uniform_int_distribution<uint64_t> which calls the generator.
    // It generates 32 bytes (256 bits) for the private key.
    // Since mt19937_64 produces 64 bits, we need 4 calls.
    
    ulong priv_parts[4];
    priv_parts[0] = mt19937_64_extract(&state);
    priv_parts[1] = mt19937_64_extract(&state);
    priv_parts[2] = mt19937_64_extract(&state);
    priv_parts[3] = mt19937_64_extract(&state);
    
    uchar private_key[32] __attribute__((aligned(4)));
    // Copy to uchar array (Little Endian?)
    // std::mt19937_64 output is native endian.
    // We assume Little Endian for now (x86/GPU).
    
    for(int i=0; i<8; i++) {
        private_key[i]    = (priv_parts[0] >> (i*8)) & 0xFF;
        private_key[i+8]  = (priv_parts[1] >> (i*8)) & 0xFF;
        private_key[i+16] = (priv_parts[2] >> (i*8)) & 0xFF;
        private_key[i+24] = (priv_parts[3] >> (i*8)) & 0xFF;
    }
    
    // Generate Public Key
    public_key_t pub_key;
    if (!secp256k1_ec_pubkey_create(&pub_key.key, (const __private unsigned char*)private_key)) {
        return; // Invalid private key
    }
    
    // Serialize Uncompressed Public Key (65 bytes: 0x04 + X + Y)
    // Ethereum uses Keccak-256 of the uncompressed public key (minus the 0x04 prefix)
    uchar serialized_pubkey[65] __attribute__((aligned(4)));
    secp256k1_ec_pubkey_serialize(serialized_pubkey, 65, &pub_key.key, SECP256K1_EC_UNCOMPRESSED);
    
    // Keccak-256 of bytes 1..65 (64 bytes)
    uchar address_hash[32];
    keccak256(&serialized_pubkey[1], 64, address_hash);
    
    // Address is last 20 bytes of hash
    // Check match
    
    // Pack address for comparison
    ulong a1 = 0, a2 = 0;
    uint a3 = 0;
    
    // Address starts at index 12 of hash (32 - 20 = 12)
    for(int i=0; i<8; i++) a1 |= ((ulong)address_hash[12+i]) << (i*8);
    for(int i=0; i<8; i++) a2 |= ((ulong)address_hash[20+i]) << (i*8);
    for(int i=0; i<4; i++) a3 |= ((uint)address_hash[28+i]) << (i*8);
    
    if (a1 == target_addr_part1 && a2 == target_addr_part2 && a3 == target_addr_part3) {
        uint idx = atomic_inc(result_count);
        if (idx < 1024) {
            results[idx] = seed;
        }
    }
}
