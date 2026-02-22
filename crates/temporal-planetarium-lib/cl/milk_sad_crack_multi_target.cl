// Milk Sad Multi-Target Kernels
// Scans a timestamp range against N target Hash160s simultaneously.
//
// Each GPU thread = one timestamp.
// For each timestamp: generate entropy → derive address → compare against all N targets.
//
// Result encoding per hit (two u64 words):
//   word0 = timestamp | (addr_idx << 32)
//   word1 = target_idx

// ============================================================================
// Helper: compare derived hash160 against target buffer, record hit if match
// ============================================================================
static void check_and_record(
    ulong h1, ulong h2, uint h3,           // derived Hash160 packed
    uint timestamp, uint addr_idx,
    __global const uchar* targets,          // flat N×20 buffer
    __global const uint* purposes_buf,      // per-target purpose (unused here, for reference)
    uint target_count,
    __global ulong* results,
    __global uint* result_count,
    uint max_results
) {
    for (uint t = 0; t < target_count; t++) {
        // Unpack target Hash160
        __global const uchar* tgt = targets + t * 20;
        ulong th1 = 0, th2 = 0;
        uint  th3 = 0;
        for (int i = 0; i < 8; i++) th1 |= ((ulong)tgt[i])    << (i*8);
        for (int i = 0; i < 8; i++) th2 |= ((ulong)tgt[i+8])  << (i*8);
        for (int i = 0; i < 4; i++) th3 |= ((uint) tgt[i+16]) << (i*8);

        if (h1 == th1 && h2 == th2 && h3 == th3) {
            uint idx = atomic_inc(result_count);
            if (idx < max_results) {
                results[idx * 2]     = ((ulong)addr_idx << 32) | timestamp;
                results[idx * 2 + 1] = t;
            }
        }
    }
}

// ============================================================================
// Helper: compute Hash160 for a given public key depending on purpose
// purpose=49 (BIP49/P2SH-P2WPKH) needs witness-script hashing
// ============================================================================
static void hash160_for_purpose(
    __private extended_public_key_t* pub_key,
    uint purpose,
    __private uchar* hash160_out
) {
    if (purpose == 49) {
        uchar pubkey_hash[20];
        identifier_for_public_key(pub_key, pubkey_hash);
        uchar witness_script[22];
        witness_script[0] = 0x00;
        witness_script[1] = 0x14;
        for (int i = 0; i < 20; i++) witness_script[i+2] = pubkey_hash[i];
        uchar sha256_result[32] __attribute__((aligned(4)));
        sha256((__private uint*)witness_script, 22, (__private uint*)sha256_result);
        ripemd160(sha256_result, 32, (__private uchar*)hash160_out);
    } else {
        identifier_for_public_key(pub_key, hash160_out);
    }
}

// ============================================================================
// Derive key chain down to m/purpose'/0'/0'/0 and return external_key
// ============================================================================
static void derive_external_key(
    __private extended_private_key_t* master,
    uint purpose,
    __private extended_private_key_t* external_key_out
) {
    extended_private_key_t k1, k2, k3;
    hardened_private_child_from_private(master, &k1, purpose);
    hardened_private_child_from_private(&k1,    &k2, 0);
    hardened_private_child_from_private(&k2,    &k3, 0);
    normal_private_child_from_private(&k3, external_key_out, 0);
}

// ============================================================================
// MACRO-like pattern: generate entropy, seed, master — used in all 6 kernels
// ============================================================================

// 128-bit single-address (index 0 only) — multi-target
__kernel void milk_sad_mt(
    __global ulong* results,
    __global uint* result_count,
    __global const uchar* targets,
    __global const uint* purposes,
    uint target_count,
    uint offset,
    uint max_results
) {
    uint ts = get_global_id(0) + offset;

    uchar entropy[16] __attribute__((aligned(4)));
    mt19937_extract_msb_128(ts, entropy);
    uchar seed[64] __attribute__((aligned(8)));
    bip39_entropy_to_seed_complete(entropy, seed);

    extended_private_key_t master;
    new_master_from_seed(0, seed, &master);

    // For each unique purpose among targets, derive and check
    // (We check all targets; same derivation reused if purpose repeats)
    uint last_purpose = 0xFFFFFFFF;
    extended_private_key_t ext_key;
    for (uint t = 0; t < target_count; t++) {
        uint purpose = purposes[t];
        if (purpose != last_purpose) {
            derive_external_key(&master, purpose, &ext_key);
            last_purpose = purpose;
        }
        extended_private_key_t addr_key;
        normal_private_child_from_private(&ext_key, &addr_key, 0);
        extended_public_key_t addr_pub;
        public_from_private(&addr_key, &addr_pub);
        uchar h160[20];
        hash160_for_purpose(&addr_pub, purpose, h160);

        ulong h1 = 0, h2 = 0; uint h3 = 0;
        for (int i = 0; i < 8; i++) h1 |= ((ulong)h160[i])    << (i*8);
        for (int i = 0; i < 8; i++) h2 |= ((ulong)h160[i+8])  << (i*8);
        for (int i = 0; i < 4; i++) h3 |= ((uint) h160[i+16]) << (i*8);

        // Compare against just this one target
        __global const uchar* tgt = targets + t * 20;
        ulong th1=0, th2=0; uint th3=0;
        for (int i=0;i<8;i++) th1|=((ulong)tgt[i])<<(i*8);
        for (int i=0;i<8;i++) th2|=((ulong)tgt[i+8])<<(i*8);
        for (int i=0;i<4;i++) th3|=((uint)tgt[i+16])<<(i*8);
        if (h1==th1 && h2==th2 && h3==th3) {
            uint idx = atomic_inc(result_count);
            if (idx < max_results) {
                results[idx*2]   = (ulong)ts;
                results[idx*2+1] = t;
            }
        }
    }
}

// 128-bit — 30 addresses per timestamp — multi-target
__kernel void milk_sad_mt_multi30(
    __global ulong* results,
    __global uint* result_count,
    __global const uchar* targets,
    __global const uint* purposes,
    uint target_count,
    uint offset,
    uint max_results
) {
    uint ts = get_global_id(0) + offset;

    uchar entropy[16] __attribute__((aligned(4)));
    mt19937_extract_msb_128(ts, entropy);
    uchar seed[64] __attribute__((aligned(8)));
    bip39_entropy_to_seed_complete(entropy, seed);

    extended_private_key_t master;
    new_master_from_seed(0, seed, &master);

    for (uint t = 0; t < target_count; t++) {
        uint purpose = purposes[t];
        extended_private_key_t ext_key;
        derive_external_key(&master, purpose, &ext_key);

        __global const uchar* tgt = targets + t * 20;
        ulong th1=0, th2=0; uint th3=0;
        for (int i=0;i<8;i++) th1|=((ulong)tgt[i])<<(i*8);
        for (int i=0;i<8;i++) th2|=((ulong)tgt[i+8])<<(i*8);
        for (int i=0;i<4;i++) th3|=((uint)tgt[i+16])<<(i*8);

        for (uint ai = 0; ai < 30; ai++) {
            extended_private_key_t addr_key;
            normal_private_child_from_private(&ext_key, &addr_key, ai);
            extended_public_key_t addr_pub;
            public_from_private(&addr_key, &addr_pub);
            uchar h160[20];
            hash160_for_purpose(&addr_pub, purpose, h160);

            ulong h1=0, h2=0; uint h3=0;
            for (int i=0;i<8;i++) h1|=((ulong)h160[i])<<(i*8);
            for (int i=0;i<8;i++) h2|=((ulong)h160[i+8])<<(i*8);
            for (int i=0;i<4;i++) h3|=((uint)h160[i+16])<<(i*8);

            if (h1==th1 && h2==th2 && h3==th3) {
                uint idx = atomic_inc(result_count);
                if (idx < max_results) {
                    results[idx*2]   = ((ulong)ai << 32) | ts;
                    results[idx*2+1] = t;
                }
            }
        }
    }
}

// 192-bit single-address — multi-target
__kernel void milk_sad_mt_192(
    __global ulong* results,
    __global uint* result_count,
    __global const uchar* targets,
    __global const uint* purposes,
    uint target_count,
    uint offset,
    uint max_results
) {
    uint ts = get_global_id(0) + offset;

    uchar entropy[24] __attribute__((aligned(4)));
    mt19937_extract_msb_192(ts, entropy);
    uchar seed[64] __attribute__((aligned(8)));
    bip39_entropy_to_seed_complete_24(entropy, seed);

    extended_private_key_t master;
    new_master_from_seed(0, seed, &master);

    for (uint t = 0; t < target_count; t++) {
        uint purpose = purposes[t];
        extended_private_key_t ext_key;
        derive_external_key(&master, purpose, &ext_key);
        extended_private_key_t addr_key;
        normal_private_child_from_private(&ext_key, &addr_key, 0);
        extended_public_key_t addr_pub;
        public_from_private(&addr_key, &addr_pub);
        uchar h160[20];
        hash160_for_purpose(&addr_pub, purpose, h160);

        __global const uchar* tgt = targets + t * 20;
        ulong th1=0,th2=0; uint th3=0;
        for(int i=0;i<8;i++) th1|=((ulong)tgt[i])<<(i*8);
        for(int i=0;i<8;i++) th2|=((ulong)tgt[i+8])<<(i*8);
        for(int i=0;i<4;i++) th3|=((uint)tgt[i+16])<<(i*8);
        ulong h1=0,h2=0; uint h3=0;
        for(int i=0;i<8;i++) h1|=((ulong)h160[i])<<(i*8);
        for(int i=0;i<8;i++) h2|=((ulong)h160[i+8])<<(i*8);
        for(int i=0;i<4;i++) h3|=((uint)h160[i+16])<<(i*8);

        if (h1==th1&&h2==th2&&h3==th3) {
            uint idx=atomic_inc(result_count);
            if(idx<max_results){ results[idx*2]=(ulong)ts; results[idx*2+1]=t; }
        }
    }
}

// 192-bit — 30 addresses — multi-target
__kernel void milk_sad_mt_multi30_192(
    __global ulong* results,
    __global uint* result_count,
    __global const uchar* targets,
    __global const uint* purposes,
    uint target_count,
    uint offset,
    uint max_results
) {
    uint ts = get_global_id(0) + offset;

    uchar entropy[24] __attribute__((aligned(4)));
    mt19937_extract_msb_192(ts, entropy);
    uchar seed[64] __attribute__((aligned(8)));
    bip39_entropy_to_seed_complete_24(entropy, seed);

    extended_private_key_t master;
    new_master_from_seed(0, seed, &master);

    for (uint t = 0; t < target_count; t++) {
        uint purpose = purposes[t];
        extended_private_key_t ext_key;
        derive_external_key(&master, purpose, &ext_key);

        __global const uchar* tgt = targets + t * 20;
        ulong th1=0,th2=0; uint th3=0;
        for(int i=0;i<8;i++) th1|=((ulong)tgt[i])<<(i*8);
        for(int i=0;i<8;i++) th2|=((ulong)tgt[i+8])<<(i*8);
        for(int i=0;i<4;i++) th3|=((uint)tgt[i+16])<<(i*8);

        for (uint ai = 0; ai < 30; ai++) {
            extended_private_key_t addr_key;
            normal_private_child_from_private(&ext_key, &addr_key, ai);
            extended_public_key_t addr_pub;
            public_from_private(&addr_key, &addr_pub);
            uchar h160[20];
            hash160_for_purpose(&addr_pub, purpose, h160);
            ulong h1=0,h2=0; uint h3=0;
            for(int i=0;i<8;i++) h1|=((ulong)h160[i])<<(i*8);
            for(int i=0;i<8;i++) h2|=((ulong)h160[i+8])<<(i*8);
            for(int i=0;i<4;i++) h3|=((uint)h160[i+16])<<(i*8);
            if(h1==th1&&h2==th2&&h3==th3){
                uint idx=atomic_inc(result_count);
                if(idx<max_results){ results[idx*2]=((ulong)ai<<32)|ts; results[idx*2+1]=t; }
            }
        }
    }
}

// 256-bit single-address — multi-target
__kernel void milk_sad_mt_256(
    __global ulong* results,
    __global uint* result_count,
    __global const uchar* targets,
    __global const uint* purposes,
    uint target_count,
    uint offset,
    uint max_results
) {
    uint ts = get_global_id(0) + offset;

    uchar entropy[32] __attribute__((aligned(4)));
    mt19937_extract_msb_256(ts, entropy);
    uchar seed[64] __attribute__((aligned(8)));
    bip39_entropy_to_seed_complete_32(entropy, seed);

    extended_private_key_t master;
    new_master_from_seed(0, seed, &master);

    for (uint t = 0; t < target_count; t++) {
        uint purpose = purposes[t];
        extended_private_key_t ext_key;
        derive_external_key(&master, purpose, &ext_key);
        extended_private_key_t addr_key;
        normal_private_child_from_private(&ext_key, &addr_key, 0);
        extended_public_key_t addr_pub;
        public_from_private(&addr_key, &addr_pub);
        uchar h160[20];
        hash160_for_purpose(&addr_pub, purpose, h160);

        __global const uchar* tgt = targets + t * 20;
        ulong th1=0,th2=0; uint th3=0;
        for(int i=0;i<8;i++) th1|=((ulong)tgt[i])<<(i*8);
        for(int i=0;i<8;i++) th2|=((ulong)tgt[i+8])<<(i*8);
        for(int i=0;i<4;i++) th3|=((uint)tgt[i+16])<<(i*8);
        ulong h1=0,h2=0; uint h3=0;
        for(int i=0;i<8;i++) h1|=((ulong)h160[i])<<(i*8);
        for(int i=0;i<8;i++) h2|=((ulong)h160[i+8])<<(i*8);
        for(int i=0;i<4;i++) h3|=((uint)h160[i+16])<<(i*8);

        if(h1==th1&&h2==th2&&h3==th3){
            uint idx=atomic_inc(result_count);
            if(idx<max_results){ results[idx*2]=(ulong)ts; results[idx*2+1]=t; }
        }
    }
}

// 256-bit — 30 addresses — multi-target  (primary kernel for Update #13 batch scan)
__kernel void milk_sad_mt_multi30_256(
    __global ulong* results,
    __global uint* result_count,
    __global const uchar* targets,
    __global const uint* purposes,
    uint target_count,
    uint offset,
    uint max_results
) {
    uint ts = get_global_id(0) + offset;

    uchar entropy[32] __attribute__((aligned(4)));
    mt19937_extract_msb_256(ts, entropy);
    uchar seed[64] __attribute__((aligned(8)));
    bip39_entropy_to_seed_complete_32(entropy, seed);

    extended_private_key_t master;
    new_master_from_seed(0, seed, &master);

    for (uint t = 0; t < target_count; t++) {
        uint purpose = purposes[t];
        extended_private_key_t ext_key;
        derive_external_key(&master, purpose, &ext_key);

        __global const uchar* tgt = targets + t * 20;
        ulong th1=0,th2=0; uint th3=0;
        for(int i=0;i<8;i++) th1|=((ulong)tgt[i])<<(i*8);
        for(int i=0;i<8;i++) th2|=((ulong)tgt[i+8])<<(i*8);
        for(int i=0;i<4;i++) th3|=((uint)tgt[i+16])<<(i*8);

        for (uint ai = 0; ai < 30; ai++) {
            extended_private_key_t addr_key;
            normal_private_child_from_private(&ext_key, &addr_key, ai);
            extended_public_key_t addr_pub;
            public_from_private(&addr_key, &addr_pub);
            uchar h160[20];
            hash160_for_purpose(&addr_pub, purpose, h160);
            ulong h1=0,h2=0; uint h3=0;
            for(int i=0;i<8;i++) h1|=((ulong)h160[i])<<(i*8);
            for(int i=0;i<8;i++) h2|=((ulong)h160[i+8])<<(i*8);
            for(int i=0;i<4;i++) h3|=((uint)h160[i+16])<<(i*8);
            if(h1==th1&&h2==th2&&h3==th3){
                uint idx=atomic_inc(result_count);
                if(idx<max_results){ results[idx*2]=((ulong)ai<<32)|ts; results[idx*2+1]=t; }
            }
        }
    }
}
