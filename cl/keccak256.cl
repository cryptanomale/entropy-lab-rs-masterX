// Keccak-256 implementation for OpenCL
// Based on standard Keccak-f[1600] permutation

#define KECCAK_ROUNDS 24

constant ulong KeccakRoundConstants[KECCAK_ROUNDS] = {
    0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL,
    0x8000000080008000UL, 0x000000000000808bUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL, 0x000000000000008aUL,
    0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
    0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL,
    0x8000000000008003UL, 0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800aUL, 0x800000008000000aUL, 0x8000000080008081UL,
    0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
};

#define ROL64(a, offset) ((((ulong)a) << offset) ^ (((ulong)a) >> (64-offset)))

void KeccakF1600(ulong *st) {
    int i;
    ulong t, bc[5];

    for (int round = 0; round < KECCAK_ROUNDS; round++) {

        // Theta
        for (i = 0; i < 5; i++)
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROL64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5)
                st[j + i] ^= t;
        }

        // Rho Pi
        t = st[1];
        st[1] = ROL64(st[6], 44);
        st[6] = ROL64(st[9], 20);
        st[9] = ROL64(st[22], 61);
        st[22] = ROL64(st[14], 39);
        st[14] = ROL64(st[20], 18);
        st[20] = ROL64(st[2], 62);
        st[2] = ROL64(st[12], 43);
        st[12] = ROL64(st[13], 25);
        st[13] = ROL64(st[19], 8);
        st[19] = ROL64(st[23], 56);
        st[23] = ROL64(st[15], 41);
        st[15] = ROL64(st[4], 27);
        st[4] = ROL64(st[24], 14);
        st[24] = ROL64(st[21], 2);
        st[21] = ROL64(st[8], 55);
        st[8] = ROL64(st[16], 45);
        st[16] = ROL64(st[5], 36);
        st[5] = ROL64(st[3], 28);
        st[3] = ROL64(st[18], 21);
        st[18] = ROL64(st[17], 15);
        st[17] = ROL64(st[11], 10);
        st[11] = ROL64(st[7], 6);
        st[7] = ROL64(st[10], 3);
        st[10] = ROL64(st[1], 1);
        st[1] = t;

        // Chi
        for (int j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++)
                bc[i] = st[j + i];
            for (i = 0; i < 5; i++)
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        // Iota
        st[0] ^= KeccakRoundConstants[round];
    }
}

void keccak256(const uchar *in, int inLen, uchar *out) {
    ulong st[25];
    for (int i = 0; i < 25; i++) st[i] = 0;

    int rsiz = 136; // rate = 1600 - 2*256 = 1088 bits = 136 bytes

    int offset = 0;
    while (inLen >= rsiz) {
        for (int i = 0; i < rsiz / 8; i++) {
            st[i] ^= ((ulong *)in)[offset / 8 + i];
        }
        KeccakF1600(st);
        offset += rsiz;
        inLen -= rsiz;
    }

    // Padding
    uchar lastBlock[136];
    for(int i=0; i<136; i++) lastBlock[i] = 0;
    for(int i=0; i<inLen; i++) lastBlock[i] = in[offset + i];
    
    lastBlock[inLen] = 0x01;
    lastBlock[rsiz - 1] |= 0x80;

    for (int i = 0; i < rsiz / 8; i++) {
        st[i] ^= ((ulong *)lastBlock)[i];
    }
    KeccakF1600(st);

    // Output
    for (int i = 0; i < 4; i++) {
        ((ulong *)out)[i] = st[i];
    }
}
