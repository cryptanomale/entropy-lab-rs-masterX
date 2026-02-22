// Dart Random() PRNG Implementation (xorshift128+)
// Based on Dart SDK: runtime/lib/math.cc

typedef struct {
    ulong state0;
    ulong state1;
} DartRandom;

void dart_random_init(DartRandom* rng, ulong seed) {
    rng->state0 = seed;
    rng->state1 = seed ^ 0x5DEECE66DUL;
}

ulong dart_random_next_u64(DartRandom* rng) {
    ulong s0 = rng->state0;
    ulong s1 = rng->state1;
    ulong result = s0 + s1;
    
    s1 ^= s0;
    rng->state0 = ((s0 << 55) | (s0 >> 9)) ^ s1 ^ (s1 << 14);
    rng->state1 = (s1 << 36) | (s1 >> 28);
    
    return result;
}

uint dart_random_next_int(DartRandom* rng, uint max) {
    ulong x = dart_random_next_u64(rng);
    // Dart's nextInt uses: (x * max) >> 64
    // Implement 64x32 -> 96-bit multiplication manually
    // (x * max) >> 64 = (x_hi * max) + ((x_lo * max) >> 32) >> 32
    ulong x_hi = x >> 32;
    ulong x_lo = x & 0xFFFFFFFFUL;
    ulong result = (x_hi * max) + ((x_lo * max) >> 32);
    return (uint)(result >> 32);
}

void dart_random_generate_bytes(DartRandom* rng, uchar* output, int length) {
    for (int i = 0; i < length; i++) {
        output[i] = (uchar)dart_random_next_int(rng, 256);
    }
}
