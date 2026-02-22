// Mobile Sensor GPU Kernel
// Simulates low‑entropy sensor readings and hashes them (SHA‑256).
// Each work‑item corresponds to a simulated device index (i).
// Output: 32‑byte SHA‑256 hash per item.

#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable

// Simple deterministic pseudo‑random generator based on the work‑item id.
static inline int pseudo_rand(int gid, int a, int b, int c) {
    // Linear congruential style mixing
    uint x = (uint)gid * 1664525u + 1013904223u;
    x ^= (x >> 16);
    x = (x * a) + b;
    return (int)(x % c);
}

__kernel void mobile_sensor_hash(
    __global ulong * indices,          // input: list of device ids (0..N-1)
    __global uchar * out_hashes,       // output: N * 32 bytes
    uint count                         // number of items
) {
    uint gid = get_global_id(0);
    if (gid >= count) return;

    ulong idx = indices[gid];

    // Simulate sensor values (same ranges as Rust version)
    int acc_x = pseudo_rand((int)idx, 12345, 0, 20) - 10;          // -10 .. 9
    int acc_y = pseudo_rand((int)idx, 67890, 0, 20) - 10;          // -10 .. 9
    int acc_z = 970 + pseudo_rand((int)idx, 13579, 0, 20);        // 970 .. 989

    // Build string "x,y,z" (max length ~12 chars)
    char buf[16];
    int pos = 0;
    // simple itoa (positive/negative handling)
    // For brevity we use a very small routine – values are small.
    // Write acc_x
    if (acc_x < 0) { buf[pos++] = '-'; }
    int ax = acc_x < 0 ? -acc_x : acc_x;
    if (ax >= 10) { buf[pos++] = (char)('0' + ax / 10); }
    buf[pos++] = (char)('0' + ax % 10);
    buf[pos++] = ',';
    // Write acc_y
    if (acc_y < 0) { buf[pos++] = '-'; }
    int ay = acc_y < 0 ? -acc_y : acc_y;
    if (ay >= 10) { buf[pos++] = (char)('0' + ay / 10); }
    buf[pos++] = (char)('0' + ay % 10);
    buf[pos++] = ',';
    // Write acc_z (always positive)
    int az = acc_z;
    if (az >= 100) { buf[pos++] = (char)('0' + az / 100); az %= 100; }
    if (az >= 10) { buf[pos++] = (char)('0' + az / 10); az %= 10; }
    buf[pos++] = (char)('0' + az);

    // Compute SHA‑256 of the string (using the same sha256 function from other kernels)
    uchar hash[32] __attribute__((aligned(4)));
    sha256((__private const uint*)buf, pos, (__private uint*)hash);

    // Write result to output buffer (32 bytes per index)
    __global uchar * dst = out_hashes + gid * 32;
    for (int i = 0; i < 32; i++) {
        dst[i] = hash[i];
    }
}
