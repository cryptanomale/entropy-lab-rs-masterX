struct Fingerprint {
    timestamp_lo: u32,
    timestamp_hi: u32,
    screen_width: u32,
    screen_height: u32,
};

@group(0) @binding(0) var<storage, read> fingerprints: array<Fingerprint>;
@group(0) @binding(1) var<storage, read> bloom_filter: array<u32>;
@group(0) @binding(2) var<storage, read_write> results: array<u32>;

const BLOOM_NUM_HASHES: u32 = 15u;
const BLOOM_HASH_SEED: u32 = 0x9E3779B9u;

// --- SHA256 Implementation ---
struct Sha256State {
    state: array<u32, 8>,
    count_lo: u32,
    count_hi: u32,
    buffer: array<u32, 16>, // 64 bytes
};

fn sha256_init(ctx: ptr<function, Sha256State>) {
    (*ctx).state[0] = 0x6a09e667u;
    (*ctx).state[1] = 0xbb67ae85u;
    (*ctx).state[2] = 0x3c6ef372u;
    (*ctx).state[3] = 0xa54ff53au;
    (*ctx).state[4] = 0x510e527fu;
    (*ctx).state[5] = 0x9b05688cu;
    (*ctx).state[6] = 0x1f83d9abu;
    (*ctx).state[7] = 0x5be0cd19u;
    (*ctx).count_lo = 0u;
    (*ctx).count_hi = 0u;
    for (var i = 0u; i < 16u; i++) {
        (*ctx).buffer[i] = 0u;
    }
}

fn rotr(x: u32, n: u32) -> u32 {
    return (x >> n) | (x << (32u - n));
}

fn ch(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) ^ ((~x) & z);
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) ^ (x & z) ^ (y & z);
}

fn sigma0(x: u32) -> u32 {
    return rotr(x, 2u) ^ rotr(x, 13u) ^ rotr(x, 22u);
}

fn sigma1(x: u32) -> u32 {
    return rotr(x, 6u) ^ rotr(x, 11u) ^ rotr(x, 25u);
}

fn delta0(x: u32) -> u32 {
    return rotr(x, 7u) ^ rotr(x, 18u) ^ (x >> 3u);
}

fn delta1(x: u32) -> u32 {
    return rotr(x, 17u) ^ rotr(x, 19u) ^ (x >> 10u);
}

fn sha256_transform(ctx: ptr<function, Sha256State>, data: ptr<function, array<u32, 16>>) {
    var m: array<u32, 64>;
    m[0] = (*data)[0]; m[1] = (*data)[1]; m[2] = (*data)[2]; m[3] = (*data)[3];
    m[4] = (*data)[4]; m[5] = (*data)[5]; m[6] = (*data)[6]; m[7] = (*data)[7];
    m[8] = (*data)[8]; m[9] = (*data)[9]; m[10] = (*data)[10]; m[11] = (*data)[11];
    m[12] = (*data)[12]; m[13] = (*data)[13]; m[14] = (*data)[14]; m[15] = (*data)[15];

    m[16] = delta1(m[14]) + m[9] + delta0(m[1]) + m[0];
    m[17] = delta1(m[15]) + m[10] + delta0(m[2]) + m[1];
    m[18] = delta1(m[16]) + m[11] + delta0(m[3]) + m[2];
    m[19] = delta1(m[17]) + m[12] + delta0(m[4]) + m[3];
    m[20] = delta1(m[18]) + m[13] + delta0(m[5]) + m[4];
    m[21] = delta1(m[19]) + m[14] + delta0(m[6]) + m[5];
    m[22] = delta1(m[20]) + m[15] + delta0(m[7]) + m[6];
    m[23] = delta1(m[21]) + m[16] + delta0(m[8]) + m[7];
    m[24] = delta1(m[22]) + m[17] + delta0(m[9]) + m[8];
    m[25] = delta1(m[23]) + m[18] + delta0(m[10]) + m[9];
    m[26] = delta1(m[24]) + m[19] + delta0(m[11]) + m[10];
    m[27] = delta1(m[25]) + m[20] + delta0(m[12]) + m[11];
    m[28] = delta1(m[26]) + m[21] + delta0(m[13]) + m[12];
    m[29] = delta1(m[27]) + m[22] + delta0(m[14]) + m[13];
    m[30] = delta1(m[28]) + m[23] + delta0(m[15]) + m[14];
    m[31] = delta1(m[29]) + m[24] + delta0(m[16]) + m[15];
    m[32] = delta1(m[30]) + m[25] + delta0(m[17]) + m[16];
    m[33] = delta1(m[31]) + m[26] + delta0(m[18]) + m[17];
    m[34] = delta1(m[32]) + m[27] + delta0(m[19]) + m[18];
    m[35] = delta1(m[33]) + m[28] + delta0(m[20]) + m[19];
    m[36] = delta1(m[34]) + m[29] + delta0(m[21]) + m[20];
    m[37] = delta1(m[35]) + m[30] + delta0(m[22]) + m[21];
    m[38] = delta1(m[36]) + m[31] + delta0(m[23]) + m[22];
    m[39] = delta1(m[37]) + m[32] + delta0(m[24]) + m[23];
    m[40] = delta1(m[38]) + m[33] + delta0(m[25]) + m[24];
    m[41] = delta1(m[39]) + m[34] + delta0(m[26]) + m[25];
    m[42] = delta1(m[40]) + m[35] + delta0(m[27]) + m[26];
    m[43] = delta1(m[41]) + m[36] + delta0(m[28]) + m[27];
    m[44] = delta1(m[42]) + m[37] + delta0(m[29]) + m[28];
    m[45] = delta1(m[43]) + m[38] + delta0(m[30]) + m[29];
    m[46] = delta1(m[44]) + m[39] + delta0(m[31]) + m[30];
    m[47] = delta1(m[45]) + m[40] + delta0(m[32]) + m[31];
    m[48] = delta1(m[46]) + m[41] + delta0(m[33]) + m[32];
    m[49] = delta1(m[47]) + m[42] + delta0(m[34]) + m[33];
    m[50] = delta1(m[48]) + m[43] + delta0(m[35]) + m[34];
    m[51] = delta1(m[49]) + m[44] + delta0(m[36]) + m[35];
    m[52] = delta1(m[50]) + m[45] + delta0(m[37]) + m[36];
    m[53] = delta1(m[51]) + m[46] + delta0(m[38]) + m[37];
    m[54] = delta1(m[52]) + m[47] + delta0(m[39]) + m[38];
    m[55] = delta1(m[53]) + m[48] + delta0(m[40]) + m[39];
    m[56] = delta1(m[54]) + m[49] + delta0(m[41]) + m[40];
    m[57] = delta1(m[55]) + m[50] + delta0(m[42]) + m[41];
    m[58] = delta1(m[56]) + m[51] + delta0(m[43]) + m[42];
    m[59] = delta1(m[57]) + m[52] + delta0(m[44]) + m[43];
    m[60] = delta1(m[58]) + m[53] + delta0(m[45]) + m[44];
    m[61] = delta1(m[59]) + m[54] + delta0(m[46]) + m[45];
    m[62] = delta1(m[60]) + m[55] + delta0(m[47]) + m[46];
    m[63] = delta1(m[61]) + m[56] + delta0(m[48]) + m[47];

    var a = (*ctx).state[0];
    var b = (*ctx).state[1];
    var c = (*ctx).state[2];
    var d = (*ctx).state[3];
    var e = (*ctx).state[4];
    var f = (*ctx).state[5];
    var g = (*ctx).state[6];
    var h = (*ctx).state[7];

    var t1: u32; var t2: u32;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x428a2f98u + m[0]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x71374491u + m[1]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0xb5c0fbcfu + m[2]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0xe9b5dba5u + m[3]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x3956c25bu + m[4]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x59f111f1u + m[5]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x923f82a4u + m[6]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0xab1c5ed5u + m[7]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0xd807aa98u + m[8]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x12835b01u + m[9]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x243185beu + m[10]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x550c7dc3u + m[11]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x72be5d74u + m[12]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x80deb1feu + m[13]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x9bdc06a7u + m[14]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0xc19bf174u + m[15]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0xe49b69c1u + m[16]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0xefbe4786u + m[17]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x0fc19dc6u + m[18]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x240ca1ccu + m[19]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x2de92c6fu + m[20]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x4a7484aau + m[21]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x5cb0a9dcu + m[22]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x76f988dau + m[23]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x983e5152u + m[24]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0xa831c66du + m[25]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0xb00327c8u + m[26]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0xbf597fc7u + m[27]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0xc6e00bf3u + m[28]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0xd5a79147u + m[29]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x06ca6351u + m[30]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x14292967u + m[31]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x27b70a85u + m[32]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x2e1b2138u + m[33]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x4d2c6dfcu + m[34]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x53380d13u + m[35]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x650a7354u + m[36]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x766a0abbu + m[37]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x81c2c92eu + m[38]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x92722c85u + m[39]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0xa2bfe8a1u + m[40]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0xa81a664bu + m[41]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0xc24b8b70u + m[42]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0xc76c51a3u + m[43]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0xd192e819u + m[44]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0xd6990624u + m[45]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0xf40e3585u + m[46]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x106aa070u + m[47]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x19a4c116u + m[48]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x1e376c08u + m[49]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x2748774cu + m[50]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x34b0bcb5u + m[51]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x391c0cb3u + m[52]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x4ed8aa4au + m[53]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x5b9cca4fu + m[54]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x682e6ff3u + m[55]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x748f82eeu + m[56]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x78a5636fu + m[57]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x84c87814u + m[58]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x8cc70208u + m[59]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0x90befffau + m[60]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0xa4506cebu + m[61]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0xbef9a3f7u + m[62]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    t1 = h + sigma1(e) + ch(e, f, g) + 0xc67178f2u + m[63]; t2 = sigma0(a) + maj(a, b, c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;

    (*ctx).state[0] += a;
    (*ctx).state[1] += b;
    (*ctx).state[2] += c;
    (*ctx).state[3] += d;
    (*ctx).state[4] += e;
    (*ctx).state[5] += f;
    (*ctx).state[6] += g;
    (*ctx).state[7] += h;
}

fn sha256_update(ctx: ptr<function, Sha256State>, data: ptr<function, array<u32, 33>>, len_bytes: u32) {
    for (var i = 0u; i < len_bytes; i++) {
        let byte_val = ((*data)[i / 4u] >> (24u - (i % 4u) * 8u)) & 0xFFu;
        let word_idx = (((*ctx).count_lo % 64u) / 4u);
        let byte_idx = ((*ctx).count_lo % 4u);
        
        // Clear byte position
        (*ctx).buffer[word_idx] &= ~(0xFFu << (24u - byte_idx * 8u));
        // Set new byte
        (*ctx).buffer[word_idx] |= (byte_val << (24u - byte_idx * 8u));
        
        (*ctx).count_lo += 1u;
        if ((*ctx).count_lo == 0u) { (*ctx).count_hi += 1u; }
        
        if ((*ctx).count_lo % 64u == 0u) {
            sha256_transform(ctx, &(*ctx).buffer);
        }
    }
}

fn sha256_final(ctx: ptr<function, Sha256State>) -> array<u32, 8> {
    var count_lo = (*ctx).count_lo;
    let k = count_lo % 64u;
    
    // Append 0x80
    let word_idx = k / 4u;
    let byte_idx = k % 4u;
    (*ctx).buffer[word_idx] &= ~(0xFFu << (24u - byte_idx * 8u));
    (*ctx).buffer[word_idx] |= (0x80u << (24u - byte_idx * 8u));
    
    var next_k = k + 1u;
    
    if (next_k > 56u) {
        while (next_k < 64u) {
            let wi = next_k / 4u;
            let bi = next_k % 4u;
            (*ctx).buffer[wi] &= ~(0xFFu << (24u - bi * 8u));
            next_k += 1u;
        }
        sha256_transform(ctx, &(*ctx).buffer);
        next_k = 0u;
    }
    
    while (next_k < 56u) {
        let wi = next_k / 4u;
        let bi = next_k % 4u;
        (*ctx).buffer[wi] &= ~(0xFFu << (24u - bi * 8u));
        next_k += 1u;
    }
    
    // Store bit length (big endian)
    // count_lo is bytes. Bits = count_lo * 8.
    // Low 32 bits of total bits:
    let bit_len_lo = (count_lo << 3u);
    let bit_len_hi = (count_lo >> 29u) | ((*ctx).count_hi << 3u);
    
    (*ctx).buffer[14] = bit_len_hi;
    (*ctx).buffer[15] = bit_len_lo;
    
    sha256_transform(ctx, &(*ctx).buffer);
    
    return (*ctx).state;
}

// --- RIPEMD160 Implementation ---
// Note: Optimized for processing a single 32-byte block (SHA256 output)
struct Ripemd160State {
    state: array<u32, 5>,
    buffer: array<u32, 16>, 
};

// Circle shifts
fn rol(x: u32, n: u32) -> u32 {
    return (x << n) | (x >> (32u - n));
}

fn ripemd160_transform(state: ptr<function, array<u32, 5>>, block: array<u32, 16>) {
    var a = (*state)[0]; var b = (*state)[1]; var c = (*state)[2]; var d = (*state)[3]; var e = (*state)[4];
    var ap = a; var bp = b; var cp = c; var dp = d; var ep = e;

    // Round1: F1 left, F5 right
    a += (b ^ c ^ d) + block[0] + 0x00000000u; a = rol(a, 11u) + e; c = rol(c, 10u);
    ap += (bp ^ (cp | (~dp))) + block[5] + 0x50a28be6u; ap = rol(ap, 8u) + ep; cp = rol(cp, 10u);
    e += (a ^ b ^ c) + block[1] + 0x00000000u; e = rol(e, 14u) + d; b = rol(b, 10u);
    ep += (ap ^ (bp | (~cp))) + block[14] + 0x50a28be6u; ep = rol(ep, 9u) + dp; bp = rol(bp, 10u);
    d += (e ^ a ^ b) + block[2] + 0x00000000u; d = rol(d, 15u) + c; a = rol(a, 10u);
    dp += (ep ^ (ap | (~bp))) + block[7] + 0x50a28be6u; dp = rol(dp, 9u) + cp; ap = rol(ap, 10u);
    c += (d ^ e ^ a) + block[3] + 0x00000000u; c = rol(c, 12u) + b; e = rol(e, 10u);
    cp += (dp ^ (ep | (~ap))) + block[0] + 0x50a28be6u; cp = rol(cp, 11u) + bp; ep = rol(ep, 10u);
    b += (c ^ d ^ e) + block[4] + 0x00000000u; b = rol(b, 5u) + a; d = rol(d, 10u);
    bp += (cp ^ (dp | (~ep))) + block[9] + 0x50a28be6u; bp = rol(bp, 13u) + ap; dp = rol(dp, 10u);
    a += (b ^ c ^ d) + block[5] + 0x00000000u; a = rol(a, 8u) + e; c = rol(c, 10u);
    ap += (bp ^ (cp | (~dp))) + block[2] + 0x50a28be6u; ap = rol(ap, 15u) + ep; cp = rol(cp, 10u);
    e += (a ^ b ^ c) + block[6] + 0x00000000u; e = rol(e, 7u) + d; b = rol(b, 10u);
    ep += (ap ^ (bp | (~cp))) + block[11] + 0x50a28be6u; ep = rol(ep, 15u) + dp; bp = rol(bp, 10u);
    d += (e ^ a ^ b) + block[7] + 0x00000000u; d = rol(d, 9u) + c; a = rol(a, 10u);
    dp += (ep ^ (ap | (~bp))) + block[4] + 0x50a28be6u; dp = rol(dp, 5u) + cp; ap = rol(ap, 10u);
    c += (d ^ e ^ a) + block[8] + 0x00000000u; c = rol(c, 11u) + b; e = rol(e, 10u);
    cp += (dp ^ (ep | (~ap))) + block[13] + 0x50a28be6u; cp = rol(cp, 7u) + bp; ep = rol(ep, 10u);
    b += (c ^ d ^ e) + block[9] + 0x00000000u; b = rol(b, 13u) + a; d = rol(d, 10u);
    bp += (cp ^ (dp | (~ep))) + block[6] + 0x50a28be6u; bp = rol(bp, 7u) + ap; dp = rol(dp, 10u);
    a += (b ^ c ^ d) + block[10] + 0x00000000u; a = rol(a, 14u) + e; c = rol(c, 10u);
    ap += (bp ^ (cp | (~dp))) + block[15] + 0x50a28be6u; ap = rol(ap, 8u) + ep; cp = rol(cp, 10u);
    e += (a ^ b ^ c) + block[11] + 0x00000000u; e = rol(e, 15u) + d; b = rol(b, 10u);
    ep += (ap ^ (bp | (~cp))) + block[8] + 0x50a28be6u; ep = rol(ep, 11u) + dp; bp = rol(bp, 10u);
    d += (e ^ a ^ b) + block[12] + 0x00000000u; d = rol(d, 6u) + c; a = rol(a, 10u);
    dp += (ep ^ (ap | (~bp))) + block[1] + 0x50a28be6u; dp = rol(dp, 14u) + cp; ap = rol(ap, 10u);
    c += (d ^ e ^ a) + block[13] + 0x00000000u; c = rol(c, 7u) + b; e = rol(e, 10u);
    cp += (dp ^ (ep | (~ap))) + block[10] + 0x50a28be6u; cp = rol(cp, 14u) + bp; ep = rol(ep, 10u);
    b += (c ^ d ^ e) + block[14] + 0x00000000u; b = rol(b, 9u) + a; d = rol(d, 10u);
    bp += (cp ^ (dp | (~ep))) + block[3] + 0x50a28be6u; bp = rol(bp, 12u) + ap; dp = rol(dp, 10u);
    a += (b ^ c ^ d) + block[15] + 0x00000000u; a = rol(a, 8u) + e; c = rol(c, 10u);
    ap += (bp ^ (cp | (~dp))) + block[12] + 0x50a28be6u; ap = rol(ap, 6u) + ep; cp = rol(cp, 10u);

    // Round2: F2 left, F4 right
    e += ((a & b) | ((~a) & c)) + block[7] + 0x5a827999u; e = rol(e, 7u) + d; b = rol(b, 10u);
    ep += ((ap & cp) | (bp & (~cp))) + block[6] + 0x5c4dd124u; ep = rol(ep, 9u) + dp; bp = rol(bp, 10u);
    d += ((e & a) | ((~e) & b)) + block[4] + 0x5a827999u; d = rol(d, 6u) + c; a = rol(a, 10u);
    dp += ((ep & bp) | (ap & (~bp))) + block[11] + 0x5c4dd124u; dp = rol(dp, 13u) + cp; ap = rol(ap, 10u);
    c += ((d & e) | ((~d) & a)) + block[13] + 0x5a827999u; c = rol(c, 8u) + b; e = rol(e, 10u);
    cp += ((dp & ap) | (ep & (~ap))) + block[3] + 0x5c4dd124u; cp = rol(cp, 15u) + bp; ep = rol(ep, 10u);
    b += ((c & d) | ((~c) & e)) + block[1] + 0x5a827999u; b = rol(b, 13u) + a; d = rol(d, 10u);
    bp += ((cp & ep) | (dp & (~ep))) + block[7] + 0x5c4dd124u; bp = rol(bp, 7u) + ap; dp = rol(dp, 10u);
    a += ((b & c) | ((~b) & d)) + block[10] + 0x5a827999u; a = rol(a, 11u) + e; c = rol(c, 10u);
    ap += ((bp & dp) | (cp & (~dp))) + block[0] + 0x5c4dd124u; ap = rol(ap, 12u) + ep; cp = rol(cp, 10u);
    e += ((a & b) | ((~a) & c)) + block[6] + 0x5a827999u; e = rol(e, 9u) + d; b = rol(b, 10u);
    ep += ((ap & cp) | (bp & (~cp))) + block[13] + 0x5c4dd124u; ep = rol(ep, 8u) + dp; bp = rol(bp, 10u);
    d += ((e & a) | ((~e) & b)) + block[15] + 0x5a827999u; d = rol(d, 7u) + c; a = rol(a, 10u);
    dp += ((ep & bp) | (ap & (~bp))) + block[5] + 0x5c4dd124u; dp = rol(dp, 9u) + cp; ap = rol(ap, 10u);
    c += ((d & e) | ((~d) & a)) + block[3] + 0x5a827999u; c = rol(c, 15u) + b; e = rol(e, 10u);
    cp += ((dp & ap) | (ep & (~ap))) + block[10] + 0x5c4dd124u; cp = rol(cp, 11u) + bp; ep = rol(ep, 10u);
    b += ((c & d) | ((~c) & e)) + block[12] + 0x5a827999u; b = rol(b, 7u) + a; d = rol(d, 10u);
    bp += ((cp & ep) | (dp & (~ep))) + block[14] + 0x5c4dd124u; bp = rol(bp, 7u) + ap; dp = rol(dp, 10u);
    a += ((b & c) | ((~b) & d)) + block[0] + 0x5a827999u; a = rol(a, 12u) + e; c = rol(c, 10u);
    ap += ((bp & dp) | (cp & (~dp))) + block[15] + 0x5c4dd124u; ap = rol(ap, 7u) + ep; cp = rol(cp, 10u);
    e += ((a & b) | ((~a) & c)) + block[9] + 0x5a827999u; e = rol(e, 15u) + d; b = rol(b, 10u);
    ep += ((ap & cp) | (bp & (~cp))) + block[8] + 0x5c4dd124u; ep = rol(ep, 12u) + dp; bp = rol(bp, 10u);
    d += ((e & a) | ((~e) & b)) + block[5] + 0x5a827999u; d = rol(d, 9u) + c; a = rol(a, 10u);
    dp += ((ep & bp) | (ap & (~bp))) + block[12] + 0x5c4dd124u; dp = rol(dp, 7u) + cp; ap = rol(ap, 10u);
    c += ((d & e) | ((~d) & a)) + block[2] + 0x5a827999u; c = rol(c, 11u) + b; e = rol(e, 10u);
    cp += ((dp & ap) | (ep & (~ap))) + block[4] + 0x5c4dd124u; cp = rol(cp, 6u) + bp; ep = rol(ep, 10u);
    b += ((c & d) | ((~c) & e)) + block[14] + 0x5a827999u; b = rol(b, 7u) + a; d = rol(d, 10u);
    bp += ((cp & ep) | (dp & (~ep))) + block[9] + 0x5c4dd124u; bp = rol(bp, 15u) + ap; dp = rol(dp, 10u);
    a += ((b & c) | ((~b) & d)) + block[11] + 0x5a827999u; a = rol(a, 13u) + e; c = rol(c, 10u);
    ap += ((bp & dp) | (cp & (~dp))) + block[1] + 0x5c4dd124u; ap = rol(ap, 13u) + ep; cp = rol(cp, 10u);
    e += ((a & b) | ((~a) & c)) + block[8] + 0x5a827999u; e = rol(e, 12u) + d; b = rol(b, 10u);
    ep += ((ap & cp) | (bp & (~cp))) + block[2] + 0x5c4dd124u; ep = rol(ep, 11u) + dp; bp = rol(bp, 10u);

    // Round3: F3 left, F3 right
    d += ((e | (~a)) ^ b) + block[3] + 0x6ed9eba1u; d = rol(d, 11u) + c; a = rol(a, 10u);
    dp += ((ep | (~ap)) ^ bp) + block[15] + 0x6d703ef3u; dp = rol(dp, 9u) + cp; ap = rol(ap, 10u);
    c += ((d | (~e)) ^ a) + block[10] + 0x6ed9eba1u; c = rol(c, 13u) + b; e = rol(e, 10u);
    cp += ((dp | (~ep)) ^ ap) + block[5] + 0x6d703ef3u; cp = rol(cp, 7u) + bp; ep = rol(ep, 10u);
    b += ((c | (~d)) ^ e) + block[14] + 0x6ed9eba1u; b = rol(b, 6u) + a; d = rol(d, 10u);
    bp += ((cp | (~dp)) ^ ep) + block[1] + 0x6d703ef3u; bp = rol(bp, 15u) + ap; dp = rol(dp, 10u);
    a += ((b | (~c)) ^ d) + block[4] + 0x6ed9eba1u; a = rol(a, 7u) + e; c = rol(c, 10u);
    ap += ((bp | (~cp)) ^ dp) + block[3] + 0x6d703ef3u; ap = rol(ap, 11u) + ep; cp = rol(cp, 10u);
    e += ((a | (~b)) ^ c) + block[9] + 0x6ed9eba1u; e = rol(e, 14u) + d; b = rol(b, 10u);
    ep += ((ap | (~bp)) ^ cp) + block[7] + 0x6d703ef3u; ep = rol(ep, 8u) + dp; bp = rol(bp, 10u);
    d += ((e | (~a)) ^ b) + block[15] + 0x6ed9eba1u; d = rol(d, 9u) + c; a = rol(a, 10u);
    dp += ((ep | (~ap)) ^ bp) + block[14] + 0x6d703ef3u; dp = rol(dp, 6u) + cp; ap = rol(ap, 10u);
    c += ((d | (~e)) ^ a) + block[8] + 0x6ed9eba1u; c = rol(c, 13u) + b; e = rol(e, 10u);
    cp += ((dp | (~ep)) ^ ap) + block[6] + 0x6d703ef3u; cp = rol(cp, 6u) + bp; ep = rol(ep, 10u);
    b += ((c | (~d)) ^ e) + block[1] + 0x6ed9eba1u; b = rol(b, 15u) + a; d = rol(d, 10u);
    bp += ((cp | (~dp)) ^ ep) + block[9] + 0x6d703ef3u; bp = rol(bp, 14u) + ap; dp = rol(dp, 10u);
    a += ((b | (~c)) ^ d) + block[2] + 0x6ed9eba1u; a = rol(a, 14u) + e; c = rol(c, 10u);
    ap += ((bp | (~cp)) ^ dp) + block[11] + 0x6d703ef3u; ap = rol(ap, 12u) + ep; cp = rol(cp, 10u);
    e += ((a | (~b)) ^ c) + block[7] + 0x6ed9eba1u; e = rol(e, 8u) + d; b = rol(b, 10u);
    ep += ((ap | (~bp)) ^ cp) + block[8] + 0x6d703ef3u; ep = rol(ep, 13u) + dp; bp = rol(bp, 10u);
    d += ((e | (~a)) ^ b) + block[0] + 0x6ed9eba1u; d = rol(d, 13u) + c; a = rol(a, 10u);
    dp += ((ep | (~ap)) ^ bp) + block[12] + 0x6d703ef3u; dp = rol(dp, 5u) + cp; ap = rol(ap, 10u);
    c += ((d | (~e)) ^ a) + block[6] + 0x6ed9eba1u; c = rol(c, 6u) + b; e = rol(e, 10u);
    cp += ((dp | (~ep)) ^ ap) + block[2] + 0x6d703ef3u; cp = rol(cp, 14u) + bp; ep = rol(ep, 10u);
    b += ((c | (~d)) ^ e) + block[13] + 0x6ed9eba1u; b = rol(b, 5u) + a; d = rol(d, 10u);
    bp += ((cp | (~dp)) ^ ep) + block[10] + 0x6d703ef3u; bp = rol(bp, 13u) + ap; dp = rol(dp, 10u);
    a += ((b | (~c)) ^ d) + block[11] + 0x6ed9eba1u; a = rol(a, 12u) + e; c = rol(c, 10u);
    ap += ((bp | (~cp)) ^ dp) + block[0] + 0x6d703ef3u; ap = rol(ap, 13u) + ep; cp = rol(cp, 10u);
    e += ((a | (~b)) ^ c) + block[5] + 0x6ed9eba1u; e = rol(e, 7u) + d; b = rol(b, 10u);
    ep += ((ap | (~bp)) ^ cp) + block[4] + 0x6d703ef3u; ep = rol(ep, 7u) + dp; bp = rol(bp, 10u);
    d += ((e | (~a)) ^ b) + block[12] + 0x6ed9eba1u; d = rol(d, 5u) + c; a = rol(a, 10u);
    dp += ((ep | (~ap)) ^ bp) + block[13] + 0x6d703ef3u; dp = rol(dp, 5u) + cp; ap = rol(ap, 10u);

    // Round4: F4 left, F2 right
    c += ((d & a) | (e & (~a))) + block[1] + 0x8f1bbcdcu; c = rol(c, 11u) + b; e = rol(e, 10u);
    cp += ((dp & ep) | ((~dp) & ap)) + block[8] + 0x7a6d76e9u; cp = rol(cp, 15u) + bp; ep = rol(ep, 10u);
    b += ((c & e) | (d & (~e))) + block[9] + 0x8f1bbcdcu; b = rol(b, 12u) + a; d = rol(d, 10u);
    bp += ((cp & dp) | ((~cp) & ep)) + block[6] + 0x7a6d76e9u; bp = rol(bp, 5u) + ap; dp = rol(dp, 10u);
    a += ((b & d) | (c & (~d))) + block[11] + 0x8f1bbcdcu; a = rol(a, 14u) + e; c = rol(c, 10u);
    ap += ((bp & cp) | ((~bp) & dp)) + block[4] + 0x7a6d76e9u; ap = rol(ap, 8u) + ep; cp = rol(cp, 10u);
    e += ((a & c) | (b & (~c))) + block[10] + 0x8f1bbcdcu; e = rol(e, 15u) + d; b = rol(b, 10u);
    ep += ((ap & bp) | ((~ap) & cp)) + block[1] + 0x7a6d76e9u; ep = rol(ep, 11u) + dp; bp = rol(bp, 10u);
    d += ((e & b) | (a & (~b))) + block[0] + 0x8f1bbcdcu; d = rol(d, 14u) + c; a = rol(a, 10u);
    dp += ((ep & ap) | ((~ep) & bp)) + block[3] + 0x7a6d76e9u; dp = rol(dp, 14u) + cp; ap = rol(ap, 10u);
    c += ((d & a) | (e & (~a))) + block[8] + 0x8f1bbcdcu; c = rol(c, 15u) + b; e = rol(e, 10u);
    cp += ((dp & ep) | ((~dp) & ap)) + block[11] + 0x7a6d76e9u; cp = rol(cp, 14u) + bp; ep = rol(ep, 10u);
    b += ((c & e) | (d & (~e))) + block[12] + 0x8f1bbcdcu; b = rol(b, 9u) + a; d = rol(d, 10u);
    bp += ((cp & dp) | ((~cp) & ep)) + block[15] + 0x7a6d76e9u; bp = rol(bp, 6u) + ap; dp = rol(dp, 10u);
    a += ((b & d) | (c & (~d))) + block[4] + 0x8f1bbcdcu; a = rol(a, 8u) + e; c = rol(c, 10u);
    ap += ((bp & cp) | ((~bp) & dp)) + block[0] + 0x7a6d76e9u; ap = rol(ap, 14u) + ep; cp = rol(cp, 10u);
    e += ((a & c) | (b & (~c))) + block[13] + 0x8f1bbcdcu; e = rol(e, 9u) + d; b = rol(b, 10u);
    ep += ((ap & bp) | ((~ap) & cp)) + block[5] + 0x7a6d76e9u; ep = rol(ep, 6u) + dp; bp = rol(bp, 10u);
    d += ((e & b) | (a & (~b))) + block[3] + 0x8f1bbcdcu; d = rol(d, 14u) + c; a = rol(a, 10u);
    dp += ((ep & ap) | ((~ep) & bp)) + block[12] + 0x7a6d76e9u; dp = rol(dp, 9u) + cp; ap = rol(ap, 10u);
    c += ((d & a) | (e & (~a))) + block[7] + 0x8f1bbcdcu; c = rol(c, 5u) + b; e = rol(e, 10u);
    cp += ((dp & ep) | ((~dp) & ap)) + block[2] + 0x7a6d76e9u; cp = rol(cp, 12u) + bp; ep = rol(ep, 10u);
    b += ((c & e) | (d & (~e))) + block[15] + 0x8f1bbcdcu; b = rol(b, 6u) + a; d = rol(d, 10u);
    bp += ((cp & dp) | ((~cp) & ep)) + block[13] + 0x7a6d76e9u; bp = rol(bp, 9u) + ap; dp = rol(dp, 10u);
    a += ((b & d) | (c & (~d))) + block[14] + 0x8f1bbcdcu; a = rol(a, 8u) + e; c = rol(c, 10u);
    ap += ((bp & cp) | ((~bp) & dp)) + block[9] + 0x7a6d76e9u; ap = rol(ap, 12u) + ep; cp = rol(cp, 10u);
    e += ((a & c) | (b & (~c))) + block[5] + 0x8f1bbcdcu; e = rol(e, 6u) + d; b = rol(b, 10u);
    ep += ((ap & bp) | ((~ap) & cp)) + block[7] + 0x7a6d76e9u; ep = rol(ep, 5u) + dp; bp = rol(bp, 10u);
    d += ((e & b) | (a & (~b))) + block[6] + 0x8f1bbcdcu; d = rol(d, 5u) + c; a = rol(a, 10u);
    dp += ((ep & ap) | ((~ep) & bp)) + block[10] + 0x7a6d76e9u; dp = rol(dp, 15u) + cp; ap = rol(ap, 10u);
    c += ((d & a) | (e & (~a))) + block[2] + 0x8f1bbcdcu; c = rol(c, 12u) + b; e = rol(e, 10u);
    cp += ((dp & ep) | ((~dp) & ap)) + block[14] + 0x7a6d76e9u; cp = rol(cp, 8u) + bp; ep = rol(ep, 10u);

    // Round5: F5 left, F1 right
    b += (c ^ (d | (~e))) + block[4] + 0xa953fd4eu; b = rol(b, 9u) + a; d = rol(d, 10u);
    bp += (cp ^ dp ^ ep) + block[12] + 0x00000000u; bp = rol(bp, 8u) + ap; dp = rol(dp, 10u);
    a += (b ^ (c | (~d))) + block[0] + 0xa953fd4eu; a = rol(a, 15u) + e; c = rol(c, 10u);
    ap += (bp ^ cp ^ dp) + block[15] + 0x00000000u; ap = rol(ap, 5u) + ep; cp = rol(cp, 10u);
    e += (a ^ (b | (~c))) + block[5] + 0xa953fd4eu; e = rol(e, 5u) + d; b = rol(b, 10u);
    ep += (ap ^ bp ^ cp) + block[10] + 0x00000000u; ep = rol(ep, 12u) + dp; bp = rol(bp, 10u);
    d += (e ^ (a | (~b))) + block[9] + 0xa953fd4eu; d = rol(d, 11u) + c; a = rol(a, 10u);
    dp += (ep ^ ap ^ bp) + block[4] + 0x00000000u; dp = rol(dp, 9u) + cp; ap = rol(ap, 10u);
    c += (d ^ (e | (~a))) + block[7] + 0xa953fd4eu; c = rol(c, 6u) + b; e = rol(e, 10u);
    cp += (dp ^ ep ^ ap) + block[1] + 0x00000000u; cp = rol(cp, 12u) + bp; ep = rol(ep, 10u);
    b += (c ^ (d | (~e))) + block[12] + 0xa953fd4eu; b = rol(b, 8u) + a; d = rol(d, 10u);
    bp += (cp ^ dp ^ ep) + block[5] + 0x00000000u; bp = rol(bp, 5u) + ap; dp = rol(dp, 10u);
    a += (b ^ (c | (~d))) + block[2] + 0xa953fd4eu; a = rol(a, 13u) + e; c = rol(c, 10u);
    ap += (bp ^ cp ^ dp) + block[8] + 0x00000000u; ap = rol(ap, 14u) + ep; cp = rol(cp, 10u);
    e += (a ^ (b | (~c))) + block[10] + 0xa953fd4eu; e = rol(e, 12u) + d; b = rol(b, 10u);
    ep += (ap ^ bp ^ cp) + block[7] + 0x00000000u; ep = rol(ep, 6u) + dp; bp = rol(bp, 10u);
    d += (e ^ (a | (~b))) + block[14] + 0xa953fd4eu; d = rol(d, 5u) + c; a = rol(a, 10u);
    dp += (ep ^ ap ^ bp) + block[6] + 0x00000000u; dp = rol(dp, 8u) + cp; ap = rol(ap, 10u);
    c += (d ^ (e | (~a))) + block[1] + 0xa953fd4eu; c = rol(c, 12u) + b; e = rol(e, 10u);
    cp += (dp ^ ep ^ ap) + block[2] + 0x00000000u; cp = rol(cp, 13u) + bp; ep = rol(ep, 10u);
    b += (c ^ (d | (~e))) + block[3] + 0xa953fd4eu; b = rol(b, 13u) + a; d = rol(d, 10u);
    bp += (cp ^ dp ^ ep) + block[13] + 0x00000000u; bp = rol(bp, 6u) + ap; dp = rol(dp, 10u);
    a += (b ^ (c | (~d))) + block[8] + 0xa953fd4eu; a = rol(a, 14u) + e; c = rol(c, 10u);
    ap += (bp ^ cp ^ dp) + block[14] + 0x00000000u; ap = rol(ap, 5u) + ep; cp = rol(cp, 10u);
    e += (a ^ (b | (~c))) + block[11] + 0xa953fd4eu; e = rol(e, 11u) + d; b = rol(b, 10u);
    ep += (ap ^ bp ^ cp) + block[0] + 0x00000000u; ep = rol(ep, 15u) + dp; bp = rol(bp, 10u);
    d += (e ^ (a | (~b))) + block[6] + 0xa953fd4eu; d = rol(d, 8u) + c; a = rol(a, 10u);
    dp += (ep ^ ap ^ bp) + block[3] + 0x00000000u; dp = rol(dp, 13u) + cp; ap = rol(ap, 10u);
    c += (d ^ (e | (~a))) + block[15] + 0xa953fd4eu; c = rol(c, 5u) + b; e = rol(e, 10u);
    cp += (dp ^ ep ^ ap) + block[9] + 0x00000000u; cp = rol(cp, 11u) + bp; ep = rol(ep, 10u);
    b += (c ^ (d | (~e))) + block[13] + 0xa953fd4eu; b = rol(b, 6u) + a; d = rol(d, 10u);
    bp += (cp ^ dp ^ ep) + block[11] + 0x00000000u; bp = rol(bp, 11u) + ap; dp = rol(dp, 10u);

    let h0 = (*state)[0];
    let h1 = (*state)[1];
    let h2 = (*state)[2];
    let h3 = (*state)[3];
    let h4 = (*state)[4];
    
    (*state)[0] = h1 + c + dp;
    (*state)[1] = h2 + d + ep;
    (*state)[2] = h3 + e + ap;
    (*state)[3] = h4 + a + bp;
    (*state)[4] = h0 + b + cp;
}

// Optimized for 32-byte input (SHA256 digest) -> 20-byte hash
fn ripemd160_digest_32(input: array<u32, 8>) -> array<u32, 5> {
    var state = array<u32, 5>(0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u);
    
    // Prepare block: 32 bytes input + padding
    // RIPEMD uses LITTLE ENDIAN words. 
    // SHA256 output is BIG ENDIAN words.
    // We need to swap byte order if we want to match the reference.
    
    var b64: array<u32, 16>;
    // Swap BE -> LE for 8 words
    var v0 = input[0]; b64[0] = ((v0 & 0xFFu) << 24u) | ((v0 & 0xFF00u) << 8u) | ((v0 & 0xFF0000u) >> 8u) | (v0 >> 24u);
    var v1 = input[1]; b64[1] = ((v1 & 0xFFu) << 24u) | ((v1 & 0xFF00u) << 8u) | ((v1 & 0xFF0000u) >> 8u) | (v1 >> 24u);
    var v2 = input[2]; b64[2] = ((v2 & 0xFFu) << 24u) | ((v2 & 0xFF00u) << 8u) | ((v2 & 0xFF0000u) >> 8u) | (v2 >> 24u);
    var v3 = input[3]; b64[3] = ((v3 & 0xFFu) << 24u) | ((v3 & 0xFF00u) << 8u) | ((v3 & 0xFF0000u) >> 8u) | (v3 >> 24u);
    var v4 = input[4]; b64[4] = ((v4 & 0xFFu) << 24u) | ((v4 & 0xFF00u) << 8u) | ((v4 & 0xFF0000u) >> 8u) | (v4 >> 24u);
    var v5 = input[5]; b64[5] = ((v5 & 0xFFu) << 24u) | ((v5 & 0xFF00u) << 8u) | ((v5 & 0xFF0000u) >> 8u) | (v5 >> 24u);
    var v6 = input[6]; b64[6] = ((v6 & 0xFFu) << 24u) | ((v6 & 0xFF00u) << 8u) | ((v6 & 0xFF0000u) >> 8u) | (v6 >> 24u);
    // Wait, let's just do it carefully.
    v6 = input[6]; b64[6] = ((v6 & 0xFFu) << 24u) | ((v6 & 0xFF00u) << 8u) | ((v6 & 0xFF0000u) >> 8u) | (v6 >> 24u);
    var v7 = input[7]; b64[7] = ((v7 & 0xFFu) << 24u) | ((v7 & 0xFF00u) << 8u) | ((v7 & 0xFF0000u) >> 8u) | (v7 >> 24u);
    
    // Padding for RIPEMD: 0x80 byte, then 0s, then 64-bit length in bits.
    // Length is 256 bits = 0x100.
    // In LE u32:
    // m[8] = 0x00000080
    // m[14] = 0x00000100
    // m[15] = 0
    b64[8] = 0x00000080u;
    for (var i = 9u; i < 14u; i++) { b64[i] = 0u; }
    b64[14] = 256u;
    b64[15] = 0u;
    
    ripemd160_transform(&state, b64);
    
    return state;
}


struct BigInt256 {
    limbs: array<u32, 8>,
};

// secp256k1 P = 2^256 - 2^32 - 977
// P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
const SECP256K1_P: array<u32, 8> = array<u32, 8>(
    0xFFFFFC2Fu, 0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu, 
    0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu
);

struct Point {
    x: BigInt256,
    y: BigInt256,
    z: BigInt256, // Jacobian Z
};

const G_X: array<u32, 8> = array<u32, 8>(
    0x16F81798u, 0x59F2815Bu, 0x2DCE28D9u, 0x029BFCDBu,
    0xCE870B07u, 0x55A06295u, 0xF9DCBBACu, 0x79BE667Eu
);
const G_Y: array<u32, 8> = array<u32, 8>(
    0xFB10D4B8u, 0x9C648136u, 0x86C3B336u, 0xE78D28A2u,
    0x856853Cu, 0x5284D852u, 0x38550253u, 0x483ADA77u
);

fn secp256k1_mul_g(k: array<u32, 8>) -> Point {
    // STUB: This is valid WGSL but mathematically meaningless for ECC.
    // It allows testing the downstream SHA256->RIPEMD160->Bloom pipeline.
    var p: Point;
    p.x.limbs = k; // Fake: x = k
    p.y.limbs = k; // Fake: y = k
    p.z.limbs = array<u32, 8>(1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u);
    return p;
}

fn secp256k1_to_affine_x(p: Point) -> array<u32, 8> {
    return p.x.limbs;
}

fn get_compressed_pubkey(p: Point) -> array<u32, 33> {
    var out: array<u32, 33>;
    out[0] = (0x02u << 24u) | (((p.x.limbs[7] >> 24u) & 0xFFu) << 16u) | (((p.x.limbs[7] >> 16u) & 0xFFu) << 8u) | ((p.x.limbs[7] >> 8u) & 0xFFu);
    out[1] = ((p.x.limbs[7] & 0xFFu) << 24u) | (((p.x.limbs[6] >> 24u) & 0xFFu) << 16u) | (((p.x.limbs[6] >> 16u) & 0xFFu) << 8u) | ((p.x.limbs[6] >> 8u) & 0xFFu);
    out[2] = ((p.x.limbs[6] & 0xFFu) << 24u) | (((p.x.limbs[5] >> 24u) & 0xFFu) << 16u) | (((p.x.limbs[5] >> 16u) & 0xFFu) << 8u) | ((p.x.limbs[5] >> 8u) & 0xFFu);
    out[3] = ((p.x.limbs[5] & 0xFFu) << 24u) | (((p.x.limbs[4] >> 24u) & 0xFFu) << 16u) | (((p.x.limbs[4] >> 16u) & 0xFFu) << 8u) | ((p.x.limbs[4] >> 8u) & 0xFFu);
    out[4] = ((p.x.limbs[4] & 0xFFu) << 24u) | (((p.x.limbs[3] >> 24u) & 0xFFu) << 16u) | (((p.x.limbs[3] >> 16u) & 0xFFu) << 8u) | ((p.x.limbs[3] >> 8u) & 0xFFu);
    out[5] = ((p.x.limbs[3] & 0xFFu) << 24u) | (((p.x.limbs[2] >> 24u) & 0xFFu) << 16u) | (((p.x.limbs[2] >> 16u) & 0xFFu) << 8u) | ((p.x.limbs[2] >> 8u) & 0xFFu);
    out[6] = ((p.x.limbs[2] & 0xFFu) << 24u) | (((p.x.limbs[1] >> 24u) & 0xFFu) << 16u) | (((p.x.limbs[1] >> 16u) & 0xFFu) << 8u) | ((p.x.limbs[1] >> 8u) & 0xFFu);
    out[7] = ((p.x.limbs[1] & 0xFFu) << 24u) | (((p.x.limbs[0] >> 24u) & 0xFFu) << 16u) | (((p.x.limbs[0] >> 16u) & 0xFFu) << 8u) | ((p.x.limbs[0] >> 8u) & 0xFFu);
    out[8] = (p.x.limbs[0] & 0xFFu) << 24u;
    out[9] = 0u; out[10] = 0u; out[11] = 0u; out[12] = 0u; out[13] = 0u; out[14] = 0u; out[15] = 0u;
    out[16] = 0u; out[17] = 0u; out[18] = 0u; out[19] = 0u; out[20] = 0u; out[21] = 0u; out[22] = 0u; out[23] = 0u;
    out[24] = 0u; out[25] = 0u; out[26] = 0u; out[27] = 0u; out[28] = 0u; out[29] = 0u; out[30] = 0u; out[31] = 0u; out[32] = 0u;
    return out;
}

fn murmur_hash(d0: u32, d1: u32, d2: u32, d3: u32, d4: u32, seed: u32) -> u32 {
    var h = seed;
    
    var k = d0;
    k *= 0xCC9E2D51u;
    k = (k << 15u) | (k >> 17u);
    k *= 0x1B873593u;
    h ^= k;
    h = (h << 13u) | (h >> 19u);
    h = h * 5u + 0xE6546B64u;

    k = d1;
    k *= 0xCC9E2D51u;
    k = (k << 15u) | (k >> 17u);
    k *= 0x1B873593u;
    h ^= k;
    h = (h << 13u) | (h >> 19u);
    h = h * 5u + 0xE6546B64u;

    k = d2;
    k *= 0xCC9E2D51u;
    k = (k << 15u) | (k >> 17u);
    k *= 0x1B873593u;
    h ^= k;
    h = (h << 13u) | (h >> 19u);
    h = h * 5u + 0xE6546B64u;

    k = d3;
    k *= 0xCC9E2D51u;
    k = (k << 15u) | (k >> 17u);
    k *= 0x1B873593u;
    h ^= k;
    h = (h << 13u) | (h >> 19u);
    h = h * 5u + 0xE6546B64u;

    k = d4;
    k *= 0xCC9E2D51u;
    k = (k << 15u) | (k >> 17u);
    k *= 0x1B873593u;
    h ^= k;
    h = (h << 13u) | (h >> 19u);
    h = h * 5u + 0xE6546B64u;

    h ^= 20u;
    h ^= h >> 16u;
    h *= 0x85EBCA6Bu;
    h ^= h >> 13u;
    h *= 0xC2B2AE35u;
    h ^= h >> 16u;
    return h;
}

fn get_bloom_bit(d0: u32, d1: u32, d2: u32, d3: u32, d4: u32, k: u32, filter_size_bits: u32) -> u32 {
    let h1 = murmur_hash(d0, d1, d2, d3, d4, BLOOM_HASH_SEED);
    let h2 = murmur_hash(d0, d1, d2, d3, d4, h1);
    return (h1 + k * h2) % filter_size_bits;
}

struct PrngState {
    s1: u32,
    s2: u32,
}

fn v8_mwc1616_next(state: ptr<function, PrngState>) -> u32 {
    (*state).s1 = 18000u * ((*state).s1 & 0xFFFFu) + ((*state).s1 >> 16u);
    (*state).s2 = 30903u * ((*state).s2 & 0xFFFFu) + ((*state).s2 >> 16u);
    return ((*state).s1 << 16u) + (*state).s2;
}

struct Arc4State {
    i: u32,
    j: u32,
    s: array<u32, 256>,
}

fn arc4_init(state: ptr<function, Arc4State>, key: ptr<function, array<u32, 64>>) {
    for (var i = 0u; i < 256u; i++) {
        (*state).s[i] = i;
    }
    var j = 0u;
    for (var i = 0u; i < 256u; i++) {
        let key_byte = ((*key)[i / 4u] >> (24u - (i % 4u) * 8u)) & 0xFFu;
        j = (j + (*state).s[i] + key_byte) & 0xFFu;
        let tmp = (*state).s[i];
        (*state).s[i] = (*state).s[j];
        (*state).s[j] = tmp;
    }
    (*state).i = 0u;
    (*state).j = 0u;
}

fn arc4_next(state: ptr<function, Arc4State>) -> u32 {
    (*state).i = ((*state).i + 1u) & 0xFFu;
    (*state).j = ((*state).j + (*state).s[(*state).i]) & 0xFFu;
    let tmp = (*state).s[(*state).i];
    (*state).s[(*state).i] = (*state).s[(*state).j];
    (*state).s[(*state).j] = tmp;
    return (*state).s[((*state).s[(*state).i] + (*state).s[(*state).j]) & 0xFFu];
}

@compute @workgroup_size(64)
fn randstorm_main(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let idx = global_id.x;
    if (idx >= arrayLength(&fingerprints)) { return; }

    let fp = fingerprints[idx];
    let timestamp_lo = fp.timestamp_lo;
    let timestamp_hi = fp.timestamp_hi;

    var p_state: PrngState;
    p_state.s1 = timestamp_lo;
    p_state.s2 = timestamp_hi;

    var pool_bytes: array<u32, 256>;
    for (var i = 0u; i < 128u; i++) {
        let val = v8_mwc1616_next(&p_state);
        pool_bytes[i*2u] = (val >> 24u) & 0xFFu;
        pool_bytes[i*2u+1u] = (val >> 16u) & 0xFFu;
    }

    pool_bytes[0] ^= (timestamp_lo & 0xFFu);
    pool_bytes[1] ^= ((timestamp_lo >> 8u) & 0xFFu);
    pool_bytes[2] ^= ((timestamp_lo >> 16u) & 0xFFu);
    pool_bytes[3] ^= ((timestamp_lo >> 24u) & 0xFFu);

    var key_words: array<u32, 64>;
    for (var i = 0u; i < 64u; i++) {
        key_words[i] = (pool_bytes[i*4u] << 24u) | (pool_bytes[i*4u+1u] << 16u) | (pool_bytes[i*4u+2u] << 8u) | pool_bytes[i*4u+3u];
    }

    var a_state: Arc4State;
    arc4_init(&a_state, &key_words);

    var privkey: array<u32, 8>;
    for (var i = 0u; i < 8u; i++) {
        let b0 = arc4_next(&a_state);
        let b1 = arc4_next(&a_state);
        let b2 = arc4_next(&a_state);
        let b3 = arc4_next(&a_state);
        privkey[7u - i] = (b0 << 24u) | (b1 << 16u) | (b2 << 8u) | b3;
    }

    let p_point = secp256k1_mul_g(privkey);
    var input_pk = get_compressed_pubkey(p_point);

    // Test SHA256 with known vector first
    var test_abc: array<u32, 33>;
    test_abc[0] = 0x61626300u; // 'abc\0' in big-endian
    var test_sha_ctx: Sha256State;
    sha256_init(&test_sha_ctx);
    sha256_update(&test_sha_ctx, &test_abc, 3u);
    let test_abc_digest = sha256_final(&test_sha_ctx);

    var sha_ctx: Sha256State;
    sha256_init(&sha_ctx);
    sha256_update(&sha_ctx, &input_pk, 33u);
    let sha_digest = sha256_final(&sha_ctx); 
    
    let ripe_digest = ripemd160_digest_32(sha_digest); 
    
    let d0 = ripe_digest[0];
    let d1 = ripe_digest[1];
    let d2 = ripe_digest[2];
    let d3 = ripe_digest[3];
    let d4 = ripe_digest[4];

    let filter_size_bits = arrayLength(&bloom_filter) * 32u;
    var bloom_hit = true;
    for (var k = 0u; k < BLOOM_NUM_HASHES; k++) {
        let bit_pos = get_bloom_bit(d0, d1, d2, d3, d4, k, filter_size_bits);
        let word_idx = bit_pos / 32u;
        let bit_idx = bit_pos % 32u;
        if ((bloom_filter[word_idx] & (1u << bit_idx)) == 0u) {
            bloom_hit = false;
            break;
        }
    }

    let base_out = idx * 16u;

    if (bloom_hit) {
        results[base_out + 8u] = 0xFFFFFFFFu; // Flag as hit
    }
}