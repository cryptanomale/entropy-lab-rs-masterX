// Dart VM Random() — xorshift128+ with SplitMix64 initialisation
//
// BUG HISTORY:
//   Original code used: state0 = seed; state1 = seed ^ 0x5DEECE66DUL
//   0x5DEECE66D is java.util.Random's LCG multiplier — completely unrelated
//   to Dart. This caused every timestamp to produce wrong entropy, so no
//   real Cake Wallet key could ever be found.
//
// CORRECT ALGORITHM (Dart SDK runtime/lib/math.cc, _Random._setupSeed):
//   Both xorshift128+ state words are derived via two successive SplitMix64
//   steps from the user seed (= DateTime.now().microsecondsSinceEpoch).

typedef struct {
    ulong state0;
    ulong state1;
} DartRandom;

// One SplitMix64 step — matches Dart's internal _Random._nextSeed().
static ulong dart_splitmix64_step(ulong *state) {
    *state += 0x9e3779b97f4a7c15UL;
    ulong z = *state;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9UL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebUL;
    return z ^ (z >> 31);
}

// Initialize from a 64-bit seed (microseconds since epoch for Cake Wallet).
// FIX: Replaces the old broken: state0=seed; state1=seed^0x5DEECE66D
void dart_random_init(DartRandom *rng, ulong seed) {
    ulong sm = seed;
    rng->state0 = dart_splitmix64_step(&sm);
    rng->state1 = dart_splitmix64_step(&sm);

    // xorshift128+ must not start in the all-zero state
    if (rng->state0 == 0UL && rng->state1 == 0UL) {
        rng->state0 = 0x9e3779b97f4a7c15UL;
        rng->state1 = 0x6c62272e07bb0142UL;
    }
}

// One xorshift128+ step — matches Dart VM _Random._nextState().
ulong dart_random_next_u64(DartRandom *rng) {
    ulong s0 = rng->state0;
    ulong s1 = rng->state1;
    ulong result = s0 + s1;          // output = sum BEFORE update

    ulong s1x = s1 ^ s0;
    rng->state0 = rotate(s0, 55UL) ^ s1x ^ (s1x << 14);
    rng->state1 = rotate(s1x, 36UL);

    return result;
}

// Dart nextInt(max) via 128-bit multiply reduction.
uint dart_random_next_int(DartRandom *rng, uint max) {
    ulong x = dart_random_next_u64(rng);
    ulong x_hi = x >> 32;
    ulong x_lo = x & 0xFFFFFFFFUL;
    ulong result = (x_hi * (ulong)max) + ((x_lo * (ulong)max) >> 32);
    return (uint)(result >> 32);
}

// Generate `length` bytes via successive nextInt(256) calls.
void dart_random_generate_bytes(DartRandom *rng, uchar *output, int length) {
    for (int i = 0; i < length; i++) {
        output[i] = (uchar)dart_random_next_int(rng, 256);
    }
}
