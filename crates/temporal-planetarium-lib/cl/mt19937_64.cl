// MT19937-64 implementation for OpenCL
// Based on C++11 std::mt19937_64

#define NN 312
#define MM 156
#define MATRIX_A 0xB5026F5AA96619E9UL
#define UM 0xFFFFFFFF80000000UL /* Most significant 33 bits */
#define LM 0x7FFFFFFFUL /* Least significant 31 bits */

typedef struct {
    ulong mt[NN];
    int mti;
} mt19937_64_state;

void mt19937_64_init(mt19937_64_state *state, ulong seed) {
    state->mt[0] = seed;
    for (state->mti = 1; state->mti < NN; state->mti++) {
        state->mt[state->mti] = 
            (6364136223846793005UL * (state->mt[state->mti - 1] ^ (state->mt[state->mti - 1] >> 62)) + state->mti);
    }
}

ulong mt19937_64_extract(mt19937_64_state *state) {
    int i;
    ulong x;
    ulong mag01[2] = {0UL, MATRIX_A};

    if (state->mti >= NN) { /* generate NN words at one time */
        for (i = 0; i < NN - MM; i++) {
            x = (state->mt[i] & UM) | (state->mt[i + 1] & LM);
            state->mt[i] = state->mt[i + MM] ^ (x >> 1) ^ mag01[(int)(x & 1UL)];
        }
        for (; i < NN - 1; i++) {
            x = (state->mt[i] & UM) | (state->mt[i + 1] & LM);
            state->mt[i] = state->mt[i + (MM - NN)] ^ (x >> 1) ^ mag01[(int)(x & 1UL)];
        }
        x = (state->mt[NN - 1] & UM) | (state->mt[0] & LM);
        state->mt[NN - 1] = state->mt[MM - 1] ^ (x >> 1) ^ mag01[(int)(x & 1UL)];

        state->mti = 0;
    }

    x = state->mt[state->mti++];

    x ^= (x >> 29) & 0x5555555555555555UL;
    x ^= (x << 17) & 0x71D67FFFEDA60000UL;
    x ^= (x << 37) & 0xFFF7EEE000000000UL;
    x ^= (x >> 43);

    return x;
}
