// Mobile Sensor Cracker - FIXED VERSION
__kernel void mobile_sensor_crack(
    __global ulong* results,
    __global uint* result_count,
    ulong target_h160_part1,
    ulong target_h160_part2,
    uint target_h160_part3,
    ulong offset)
{
    ulong gid = get_global_id(0) + offset;
    
    // Map GID to x, y, z
    int range = 201;
    int z_idx = gid % range;
    int y_idx = (gid / range) % range;
    int x_idx = (gid / (range * range));
    
    if (x_idx >= range) return;
    
    int acc_x = x_idx - 100;
    int acc_y = y_idx - 100;
    int acc_z = z_idx + 900;
    
    // Build string "x,y,z"
    uchar buf[32] __attribute__((aligned(4)));
    for(int i=0; i<32; i++) buf[i] = 0;
    int pos = 0;
    
    if (acc_x < 0) { buf[pos++] = '-'; }
    int ax = acc_x < 0 ? -acc_x : acc_x;
    if (ax >= 100) { buf[pos++] = '0' + ax / 100; ax %= 100; }
    if (ax >= 10) { buf[pos++] = '0' + ax / 10; ax %= 10; }
    buf[pos++] = '0' + ax;
    buf[pos++] = ',';
    
    if (acc_y < 0) { buf[pos++] = '-'; }
    int ay = acc_y < 0 ? -acc_y : acc_y;
    if (ay >= 100) { buf[pos++] = '0' + ay / 100; ay %= 100; }
    if (ay >= 10) { buf[pos++] = '0' + ay / 10; ay %= 10; }
    buf[pos++] = '0' + ay;
    buf[pos++] = ',';
    
    int az = acc_z;
    if (az >= 1000) { buf[pos++] = '0' + az / 1000; az %= 1000; }
    if (az >= 100) { buf[pos++] = '0' + az / 100; az %= 100; }
    if (az >= 10) { buf[pos++] = '0' + az / 10; az %= 10; }
    buf[pos++] = '0' + az;
    
    // SHA256 Private Key
    uchar private_key[32] __attribute__((aligned(4)));
    sha256((__private const uint*)buf, pos, (__private uint*)private_key);
    
    // ECC - FIXED
    public_key_t pub_key;
    // Pass address of the 'key' member, NOT the struct itself!
    secp256k1_ec_pubkey_create(&pub_key.key, (const __private unsigned char*)private_key);
    
    // Serialize - Call directly to avoid type mismatch in helper function
    uchar serialized_pubkey[33] __attribute__((aligned(4)));
    secp256k1_ec_pubkey_serialize(serialized_pubkey, 33, &pub_key.key, SECP256K1_EC_COMPRESSED);
    
    // Hash160
    uchar sha256_result[32] __attribute__((aligned(4)));
    uchar ripemd160_result[20];
    
    sha256((__private const uint*)serialized_pubkey, 33, (__private uint*)sha256_result);
    ripemd160(sha256_result, 32, ripemd160_result);
    
    // Pack hash160  
    ulong h1 = 0, h2 = 0;
    uint h3 = 0;
    
    for(int i=0; i<8; i++) h1 |= ((ulong)ripemd160_result[i]) << (i*8);
    for(int i=0; i<8; i++) h2 |= ((ulong)ripemd160_result[i+8]) << (i*8);
    for(int i=0; i<4; i++) h3 |= ((uint)ripemd160_result[i+16]) << (i*8);
    
    // Compare
    if (h1 == target_h160_part1 && h2 == target_h160_part2 && h3 == target_h160_part3) {
        uint idx = atomic_inc(result_count);
        if (idx < 1024) {
            results[idx] = gid;
        }
    }
}
