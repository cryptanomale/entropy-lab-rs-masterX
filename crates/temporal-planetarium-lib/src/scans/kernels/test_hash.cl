// Standalone test kernel - verify GPU calculates correct hash for known private key
// Private key: 7c41a12223de7ce075446af0ba9e5505b0d53388f72e945d5e43570e074839a6
// Expected Hash160: b26c53a249429403cea941bd033915b71eb117b1

__kernel void test_hash_calc(__global ulong* output) {
    // Hardcoded private key for x=9, y=6, z=987
    uchar privkey[32] = {
        0x7c, 0x41, 0xa1, 0x22, 0x23, 0xde, 0x7c, 0xe0,
        0x75, 0x44, 0x6a, 0xf0, 0xba, 0x9e, 0x55, 0x05,
        0xb0, 0xd5, 0x33, 0x88, 0xf7, 0x2e, 0x94, 0x5d,
        0x5e, 0x43, 0x57, 0x0e, 0x07, 0x48, 0x39, 0xa6
    };
    
    // ECC
    public_key_t pubkey;
    int result = secp256k1_ec_pubkey_create(&pubkey, (const __private unsigned char*)privkey);
    
    if (result != 1) {
        output[0] = 0xDEADDEAD;
        return;
    }
    
    // Serialize (compressed)
    uchar ser_pubkey[33] __attribute__((aligned(4)));
    serialized_public_key(&pubkey, ser_pubkey);
    
    // Hash160
    uchar sha_result[32] __attribute__((aligned(4)));
    uchar ripemd_result[20];
    
    sha256((__private const uint*)ser_pubkey, 33, (__private uint*)sha_result);
    ripemd160(sha_result, 32, ripemd_result);
    
    // Pack and output
    ulong h1 = 0, h2 = 0;
    for(int i=0; i<8; i++) h1 |= ((ulong)ripemd_result[i]) << (i*8);
    for(int i=0; i<8; i++) h2 |= ((ulong)ripemd_result[i+8]) << (i*8);
    
    output[0] = h1;  // Should be: 03944249a2536cb2
    output[1] = h2;  // Should be: b7153903bd41a9ce
    output[2] = ((ulong)ripemd_result[16]) | ((ulong)ripemd_result[17] << 8) | 
                ((ulong)ripemd_result[18] << 16) | ((ulong)ripemd_result[19] << 24);  // Should be: b117b11e
}
