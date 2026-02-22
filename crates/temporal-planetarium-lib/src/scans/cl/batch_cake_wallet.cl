// Cake Wallet GPU Kernel — Batch Address Derivation
// Input:  32-bit seed indices (0..N)
// Output: 20-byte P2WPKH witness program (Hash160) per seed
//
// FIXED: The previous version had a fatal stub:
//     "For now, we skip word creation and go straight to seed from entropy"
//     "Simplified: Use entropy directly as seed"
// Those two stubs meant the kernel did neither BIP39 PBKDF2 nor BIP32
// derivation correctly — it just copied raw entropy bytes into the seed
// buffer and derived an address from garbage. Every address produced was
// wrong and would never correspond to a real Cake Wallet key.
//
// This version:
//   1. Generates entropy from seed index (via Dart PRNG — see generate_dart_entropy)
//   2. Derives the BIP39 mnemonic (word indices from entropy + checksum)
//   3. Converts word indices to the mnemonic string using the embedded wordlist
//   4. Runs full BIP39 PBKDF2-HMAC-SHA512 with salt "mnemonic" (2048 iters)
//   5. Derives m/0'/0/0 and outputs the P2WPKH Hash160

// ─── Dart PRNG (same SplitMix64 + xorshift128+ as other kernels) ─────────

static ulong batchcw_splitmix64(ulong *sm) {
    *sm += 0x9e3779b97f4a7c15UL;
    ulong z = *sm;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
    return z ^ (z >> 31);
}

static uchar batchcw_dart_byte(ulong *s0, ulong *s1) {
    ulong v0 = *s0, v1 = *s1;
    ulong result = v0 + v1;
    ulong s1x = v1 ^ v0;
    *s0 = rotate(v0, 55UL) ^ s1x ^ (s1x << 14);
    *s1 = rotate(s1x, 36UL);
    ulong x_hi = result >> 32;
    ulong x_lo = result & 0xFFFFFFFFUL;
    ulong res  = (x_hi * 256UL) + ((x_lo * 256UL) >> 32);
    return (uchar)(res >> 32);
}
// ─────────────────────────────────────────────────────────────────────────────

__kernel void batch_cake_wallet(
    __global const uint *seed_indices,   // 32-bit seed indices (0..N)
    __global uchar      *output_h160     // 20-byte Hash160 per seed
) {
    int gid = get_global_id(0);
    uint seed_idx = seed_indices[gid];

    // 1. Generate 16 bytes of entropy via Dart PRNG (FIXED: was just copying seed_idx bytes)
    ulong sm = (ulong)seed_idx;
    ulong s0 = batchcw_splitmix64(&sm);
    ulong s1 = batchcw_splitmix64(&sm);
    if (s0 == 0UL && s1 == 0UL) {
        s0 = 0x9e3779b97f4a7c15UL;
        s1 = 0x6c62272e07bb0142UL;
    }

    uchar entropy[16];
    for (int i = 0; i < 16; i++) entropy[i] = batchcw_dart_byte(&s0, &s1);

    // 2. BIP39 checksum (SHA256 of entropy, top 4 bits)
    uchar entropy_hash[32] __attribute__((aligned(4)));
    sha256((__private const uint*)entropy, 16, (__private uint*)entropy_hash);
    uchar checksum = (entropy_hash[0] >> 4) & 0x0F;

    // 3. Extract 12 × 11-bit word indices
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

    // 4. Build mnemonic string from word indices using embedded BIP39 wordlist
    //    (FIXED: was stubbed out with "skip word creation")
    uchar mnemonic[256] = {0};
    int mnemonic_len = 0;
    for (int i = 0; i < 12; i++) {
        int w = widx[i];
        int l = word_lengths[w];
        for (int j = 0; j < l; j++) mnemonic[mnemonic_len++] = words[w][j];
        if (i < 11) mnemonic[mnemonic_len++] = ' ';
    }

    // 5. BIP39 PBKDF2-HMAC-SHA512 with salt "mnemonic" (2048 iterations)
    //    (FIXED: was `for (i < 16) seed[i] = entropy[i]` — completely wrong)
    //
    //    Password = mnemonic string
    //    Salt     = "mnemonic"  (8 bytes) || \x00\x00\x00\x01 (block counter)
    uchar ipad_key[128] __attribute__((aligned(4)));
    uchar opad_key[128] __attribute__((aligned(4)));
    for (int x = 0; x < 128; x++) {
        ipad_key[x] = (x < mnemonic_len) ? (mnemonic[x] ^ 0x36) : 0x36;
        opad_key[x] = (x < mnemonic_len) ? (mnemonic[x] ^ 0x5C) : 0x5C;
    }

    // "mnemonic" = 0x6d,6e,65,6d,6f,6e,69,63
    uchar salt[12] = {0x6d,0x6e,0x65,0x6d,0x6f,0x6e,0x69,0x63, 0,0,0,1};
    uchar sha512_result[64] __attribute__((aligned(8)));
    uchar buf[256] __attribute__((aligned(4)));

    // U1
    for (int x = 0; x < 128; x++) buf[x] = ipad_key[x];
    for (int x = 0; x < 12;  x++) buf[128+x] = salt[x];
    sha512((__private ulong*)buf, 140, (__private ulong*)sha512_result);

    for (int x = 0; x < 128; x++) buf[x] = opad_key[x];
    for (int x = 0; x < 64;  x++) buf[128+x] = sha512_result[x];
    sha512((__private ulong*)buf, 192, (__private ulong*)sha512_result);

    uchar seed[64] __attribute__((aligned(8)));
    for (int x = 0; x < 64; x++) seed[x] = sha512_result[x];

    // U2 … U2048
    for (int iter = 1; iter < 2048; iter++) {
        for (int x = 0; x < 128; x++) buf[x] = ipad_key[x];
        for (int x = 0; x < 64;  x++) buf[128+x] = sha512_result[x];
        sha512((__private ulong*)buf, 192, (__private ulong*)sha512_result);

        for (int x = 0; x < 128; x++) buf[x] = opad_key[x];
        for (int x = 0; x < 64;  x++) buf[128+x] = sha512_result[x];
        sha512((__private ulong*)buf, 192, (__private ulong*)sha512_result);

        for (int x = 0; x < 64; x++) seed[x] ^= sha512_result[x];
    }

    // 6. BIP32 m/0'/0/0
    extended_private_key_t master_key;
    new_master_from_seed(0, seed, &master_key);

    extended_private_key_t account_key;
    hardened_private_child_from_private(&master_key, &account_key, 0); // m/0'

    extended_private_key_t change_key;
    normal_private_child_from_private(&account_key, &change_key, 0);   // m/0'/0

    extended_private_key_t address_key;
    normal_private_child_from_private(&change_key, &address_key, 0);   // m/0'/0/0

    extended_public_key_t address_pub;
    public_from_private(&address_key, &address_pub);

    // 7. P2WPKH Hash160 → output (20 bytes)
    __global uchar *output = output_h160 + (gid * 20);
    uchar pubkey_hash[20];
    identifier_for_public_key(&address_pub, pubkey_hash);
    for (int i = 0; i < 20; i++) output[i] = pubkey_hash[i];
}
