// GPU-only test: Generate address for x=-17, y=14, z=978 and output the Hash160
__kernel void mobile_sensor_test(
    __global ulong* output)
{
    // Fixed values: x=-17, y=14, z=978
    int acc_x = -17;
    int acc_y = 14;
    int acc_z = 978;
    
    // Build string
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
    
    // SHA256 -> Private Key
    uchar private_key[32] __attribute__((aligned(4)));
    sha256((__private const uint*)buf, pos, (__private uint*)private_key);
    
    // Output first 8 bytes of private key
    output[0] = ((ulong)private_key[0] << 56) | ((ulong)private_key[1] << 48) | 
                ((ulong)private_key[2] << 40) | ((ulong)private_key[3] << 32) |
                ((ulong)private_key[4] << 24) | ((ulong)private_key[5] << 16) |
                ((ulong)private_key[6] << 8) | (ulong)private_key[7];
    
    // Secp256k1 -> Public Key
    public_key_t pub_key;
    if (secp256k1_ec_pubkey_create(&pub_key, (const __private unsigned char*)private_key) != 1) {
        output[1] = 0xDEADBEEF;
        return;
    }
    
    // Serialize public key
    uchar serialized_pubkey[33] __attribute__((aligned(4)));
    serialized_public_key(&pub_key, serialized_pubkey);
    
    // Output first byte of serialized pubkey (0x02 or 0x03 for compressed)
    output[1] = serialized_pubkey[0];
    
    // Hash160
    uchar sha256_result[32] __attribute__((aligned(4)));
    uchar ripemd160_result[20];
    
    sha256((__private const uint*)serialized_pubkey, 33, (__private uint*)sha256_result);
    ripemd160(sha256_result, 32, ripemd160_result);
    
    // Output Hash160 as 3 ulongs
    ulong h1 = 0, h2 = 0;
    uint h3 = 0;
    
    for(int i=0; i<8; i++) h1 |= ((ulong)ripemd160_result[i]) << (i*8);
    for(int i=0; i<8; i++) h2 |= ((ulong)ripemd160_result[i+8]) << (i*8);
    for(int i=0; i<4; i++) h3 |= ((uint)ripemd160_result[i+16]) << (i*8);
    
    output[2] = h1;
    output[3] = h2;
    output[4] = h3;
}
