// MT19937 Implementation for OpenCL
// Based on standard implementation
// 
// Supports multiple extraction modes:
// - MSB extraction (Milk Sad/libbitcoin): 1 byte per 32-bit word
// - LSB extraction (Trust Wallet): 1 byte per 32-bit word

#define MT_N 624
#define MT_M 397
#define MT_MATRIX_A 0x9908b0dfUL
#define MT_UPPER_MASK 0x80000000UL
#define MT_LOWER_MASK 0x7fffffffUL

void mt19937_init(uint seed, __private uint* state) {
    state[0] = seed;
    for (int i = 1; i < MT_N; i++) {
        state[i] = (1812433253UL * (state[i-1] ^ (state[i-1] >> 30)) + i);
    }
}

void mt19937_twist(__private uint* state) {
    for (int i = 0; i < MT_N; i++) {
        uint x = (state[i] & MT_UPPER_MASK) | (state[(i+1) % MT_N] & MT_LOWER_MASK);
        uint y = x >> 1;
        if (x & 1) {
            y ^= MT_MATRIX_A;
        }
        state[i] = state[(i + MT_M) % MT_N] ^ y;
    }
}

// Temper a single value
uint mt19937_temper(uint y) {
    y ^= (y >> 11);
    y ^= (y << 7) & 0x9d2c5680UL;
    y ^= (y << 15) & 0xefc60000UL;
    y ^= (y >> 18);
    return y;
}

// ============================================================================
// MSB EXTRACTION (Milk Sad / libbitcoin bx)
// Takes only the MOST SIGNIFICANT BYTE from each 32-bit MT19937 output
// ============================================================================

// Extract 16 bytes (128-bit) using MSB extraction
// Requires 16 MT19937 outputs, taking only the MSB from each
void mt19937_extract_msb_128(uint seed, __private uchar* entropy) {
    uint state[MT_N];
    
    mt19937_init(seed, state);
    mt19937_twist(state);
    
    // Generate 16 tempered values, take MSB from each
    for (int i = 0; i < 16; i++) {
        uint y = mt19937_temper(state[i]);
        entropy[i] = (y >> 24) & 0xFF;  // MSB only
    }
}

// Extract 24 bytes (192-bit) using MSB extraction
void mt19937_extract_msb_192(uint seed, __private uchar* entropy) {
    uint state[MT_N];
    
    mt19937_init(seed, state);
    mt19937_twist(state);
    
    // Generate 24 tempered values, take MSB from each
    for (int i = 0; i < 24; i++) {
        uint y = mt19937_temper(state[i]);
        entropy[i] = (y >> 24) & 0xFF;  // MSB only
    }
}

// Extract 32 bytes (256-bit) using MSB extraction
void mt19937_extract_msb_256(uint seed, __private uchar* entropy) {
    uint state[MT_N];
    
    mt19937_init(seed, state);
    mt19937_twist(state);
    
    // Generate 32 tempered values, take MSB from each
    for (int i = 0; i < 32; i++) {
        uint y = mt19937_temper(state[i]);
        entropy[i] = (y >> 24) & 0xFF;  // MSB only
    }
}

// ============================================================================
// LSB EXTRACTION (Trust Wallet CVE-2023-31290)
// Takes only the LEAST SIGNIFICANT BYTE from each 32-bit MT19937 output
// ============================================================================

// Extract 16 bytes (128-bit) using LSB extraction
void mt19937_extract_lsb_128(uint seed, __private uchar* entropy) {
    uint state[MT_N];
    
    mt19937_init(seed, state);
    mt19937_twist(state);
    
    // Generate 16 tempered values, take LSB from each
    for (int i = 0; i < 16; i++) {
        uint y = mt19937_temper(state[i]);
        entropy[i] = y & 0xFF;  // LSB only
    }
}

// Extract 32 bytes (256-bit) using LSB extraction
void mt19937_extract_lsb_256(uint seed, __private uchar* entropy) {
    uint state[MT_N];
    
    mt19937_init(seed, state);
    mt19937_twist(state);
    
    // Generate 32 tempered values, take LSB from each
    for (int i = 0; i < 32; i++) {
        uint y = mt19937_temper(state[i]);
        entropy[i] = y & 0xFF;  // LSB only
    }
}

// ============================================================================
// LEGACY FUNCTIONS (for backward compatibility)
// These use the OLD behavior where all 4 bytes were taken from each word
// WARNING: This does NOT match bx behavior! Use mt19937_extract_msb_* instead
// ============================================================================

// DEPRECATED: Extract first 4 words (128 bits) - OLD MSB extraction
// This function is INCORRECT for Milk Sad - it takes all 4 bytes per word
// Keep for backward compatibility but use mt19937_extract_msb_128 instead
void mt19937_extract_128(uint seed, __private uint* output) {
    uint state[MT_N];
    
    mt19937_init(seed, state);
    mt19937_twist(state);
    
    for (int i = 0; i < 4; i++) {
        output[i] = mt19937_temper(state[i]);
    }
}

