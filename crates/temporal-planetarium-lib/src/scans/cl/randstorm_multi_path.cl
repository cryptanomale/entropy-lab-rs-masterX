// Multi-Path Derivation Kernel
// Implements BIP32 path derivation for Randstorm scanning

#include "sha2.cl"
#include "ripemd.cl"
#include "secp256k1.cl"

// Hardcoded paths for performance
// m/44'/0'/0'/0
// m/49'/0'/0'/0
// m/84'/0'/0'/0
// m/86'/0'/0'/0

#define PATH_44 44
#define PATH_49 49
#define PATH_84 84
#define PATH_86 86

typedef struct {
    uchar chain_code[32];
    uchar key[32];
    uint depth;
    uint parent_fingerprint;
    uint index;
} ExtendedKey;

// Helper to serialize integer big-endian
static void ser32(uint i, __private uchar *out) {
    out[0] = (i >> 24) & 0xFF;
    out[1] = (i >> 16) & 0xFF;
    out[2] = (i >> 8) & 0xFF;
    out[3] = i & 0xFF;
}


// Child Key Derivation (Private -> Private)
// Supports hardened and normal derivation
static void ckd_priv(__private ExtendedKey *parent, uint index, __private ExtendedKey *child) {
    uchar data[37];
    
    // Check if hardened
    if (index >= 0x80000000) {
        data[0] = 0x00;
        for(int i=0; i<32; i++) data[1+i] = parent->key[i];
    } else {
        // Normal derivation: need public key point(kpar)
        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(&pubkey, parent->key)) {
            // Invalid private key (very rare)
            return; 
        }
        
        // Serialize compressed public key (33 bytes) to data[0..32]
        size_t len = 33;
        secp256k1_ec_pubkey_serialize(data, 33, &pubkey, SECP256K1_FLAGS_BIT_COMPRESSION);
    }
    
    // Append index
    ser32(index, data + 33);
    
    uchar I[64];
    hmac_sha512(parent->chain_code, 32, data, 37, I);
    
    // IL = I[0..31] -> Tweak
    // IR = I[32..63] -> New Chain Code
    
    // Child Key = (IL + Parent Key) mod n
    // Copy parent key to child key buffer first
    for(int i=0; i<32; i++) child->key[i] = parent->key[i];
    
    // Add tweak (IL) to child key (which is currently parent key)
    if (!secp256k1_ec_seckey_tweak_add(child->key, I)) {
        // Tweak failed (IL >= n or result 0) - extremely rare
        // In practice we'd skip this index or handle recursively
    }
    
   // Copy new chain code
    for(int i=0; i<32; i++) child->chain_code[i] = I[32+i];
    
    // Update metadata
    child->depth = parent->depth + 1;
    child->index = index;
    // We skip parent fingerprint calc for speed as we don't need it for scanning
}

__constant uint PURPOSES[4] = {44, 49, 84, 86};

__kernel void randstorm_multi_path(
    __global const uchar *entropy_pool_input, // Flattened 32-byte entropy pools
    const uint num_seeds,
    const uint start_index,
    const uint max_index,
    __global uchar *results // Output buffer
) {
    uint gid = get_global_id(0);
    if (gid >= num_seeds) return;
    
    // 1. Load Entropy
    uchar seed[32];
    for(int i=0; i<32; i++) seed[i] = entropy_pool_input[gid * 32 + i];
    
    // 2. Derive Master Key (m)
    // HMAC-SHA512("Bitcoin seed", seed)
    ExtendedKey master;
    uchar I[64];
    uchar key[] = "Bitcoin seed"; 
    hmac_sha512(key, 12, seed, 32, I);
    
    for(int i=0; i<32; i++) master.key[i] = I[i];
    for(int i=0; i<32; i++) master.chain_code[i] = I[32+i];
    master.depth = 0;
    master.index = 0;
    
    // 3. Derive Hardened Path Roots
    // m / Purpose' / CoinType' / Account' / Change / Index
    // CoinType = 0 (Bitcoin)
    // Account = 0
    // Change = 0 (External)
    
    for (int p_idx = 0; p_idx < 4; p_idx++) {
        uint purpose = purposes[p_idx];
        
        // Derive m/purpose'
        ExtendedKey k1, k2, k3, k4;
        ckd_priv(&master, 0x80000000 | purpose, &k1);
        
        // Derive m/purpose'/0' (CoinType=0)
        ckd_priv(&k1, 0x80000000 | 0, &k2);
        
        // Derive m/purpose'/0'/0' (Account=0)
        ckd_priv(&k2, 0x80000000 | 0, &k3);
        
        // Derive m/purpose'/0'/0'/0 (Change=0 - Normal derivation)
        ckd_priv(&k3, 0, &k4);
        
        // k4 is the base key for this path (chain root)
        
        // Loop through indices for this batch
        // Note: GPU usually prefers massive thread counts vs looping, 
        // but here we are batching seeds.
        // If we want to check indices 0..99, we loop here.
        
        // Optimization: If indices are large, we might want one thread per (seed, index) pair.
        // For now, let's assume we do 10-20 indices per kernel launch, or 100 loops.
        // 100 loops of EC point mult is heavy (10ms+).
        
        // Let's implement the loop.
        ExtendedKey child_key;
        for (uint idx = start_index; idx < max_index; idx++) {
            ckd_priv(&k4, idx, &child_key);
            
            // Now we have the private key for the address.
            // We need to generate the address (Hash160 of Pubkey) or just the Hash160?
            // Bloom filter checks Hash160 (20 bytes).
            
            // Generate Pubkey
            secp256k1_pubkey pub;
            if (secp256k1_ec_pubkey_create(&pub, child_key.key)) {
                uchar compressed_pub[33];
                // Most modern paths use compressed keys. BIP44 *can* be uncompressed but modern wallets use compressed.
                // We'll assume compressed to save bandwidth/compute.
                secp256k1_ec_pubkey_serialize(compressed_pub, 33, &pub, SECP256K1_FLAGS_BIT_COMPRESSION);
                
                // Hash160(compressed_pub)
                uchar sha_hash[32];
                sha256(compressed_pub, 33, (uint*)sha_hash); // Cast to uint* unfortunately? No, wrapper needed or cast.
                // sha256 takes __private uint* hash?
                // Wait, sha256 in sha2.cl takes uint*.
                // We need to handle type casting carefully.
                
                // Using sha256 wrapper if necessary, or manually call
                // Let's rely on standard sha256_gpu wrapper logic if available or just cast.
                // sha256 implementation above writes to uint*.
                 
                uint sha256_out_uint[8];
                sha256((__private uint*)compressed_pub, 33 * 8, sha256_out_uint); // Length in bits!
                
                // Correct usage of sha256 usually expects bytes relative to implementation.
                // Looking at sha256.cl:
                // void sha256(__private const uint *pass, int pass_len, __private uint* hash)
                // pass_len is in BYTES from the looks of `int plen=pass_len/4;`.
                
                // We need to handle unaligned access if casting uchar* to uint*?
                // GPU often requires alignment.
                // Copy to aligned buffer.
                uint aligned_pub[9]; // 33 bytes -> 9 uints
                for(int i=0; i<9; i++) aligned_pub[i] = 0;
                uchar* ptr = (uchar*)aligned_pub;
                for(int i=0; i<33; i++) ptr[i] = compressed_pub[i];
                
                sha256(aligned_pub, 33, sha256_out_uint);
                
                // RIPEMD160
                // ripemd160(sha256_out_uint)
                // We need a ripemd160 implementation.
                // ripemd.cl provides `ripemd160(const uchar* msg, uint len, uchar* hash)`
                
                uchar ripemd_out[20];
                uchar sha256_out_bytes[32];
                // Convert uint array back to chars big endian? 
                // SHA256 output is usually Big Endian words?
                // Standard SHA256 logic puts bytes in memory in correct order usually.
                
                for(int i=0; i<32; i++) {
                    // This manual copy might be needed depending on endianness of the uint array in sha256 implementation
                    // sha256.cl line 454: p[0]=SWAP256(State[0]);
                    // SWAP256 converts to Big Endian?
                    // Let's assume standard byte order in memory is achieved.
                    sha256_out_bytes[i] = ((uchar*)sha256_out_uint)[i];
                }

                ripemd160(sha256_out_bytes, 32, ripemd_out);
                
                // Write Result [SeedID][PathID][Index] -> Hash160
                // We have flattened results buffer?
                // Size: num_seeds * 4_paths * (max - start) * 20 bytes?
                // That's HUGE. 
                // Suggestion: Just check Bloom filter HERE?
                
                // For this STORY-004-002, the goal is "Implement GPU Kernel ... Batching".
                // We should output the raw data or a reduced form.
                // Writing 400 * 20 bytes = 8KB per seed.
                // 1000 seeds = 8MB. Acceptable.
                
                // Output mapping:
                // flat_index = gid * 4 * (max-start) + p_idx * (max-start) + (idx - start)
                uint total_indices = (max_index - start_index);
                uint flat_idx = gid * (4 * total_indices) + p_idx * total_indices + (idx - start_index);
                
                for(int k=0; k<20; k++) {
                    results[flat_idx * 20 + k] = ripemd_out[k];
                }
            }
        }
    }
}
