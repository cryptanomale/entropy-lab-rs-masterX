// Base58 Encoding for OpenCL

__constant char b58digits_map[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Encodes binary data to Base58 string.
// Returns length of string.
// out buffer must be large enough (size * 138 / 100 + 1)
int base58_encode(__private uchar *in, int in_len, __private uchar *out) {
    uchar buf[40]; // Working buffer (max 25 bytes input -> ~35 chars output)
    for(int i=0; i<in_len; i++) buf[i] = in[i];
    
    int buf_len = in_len;
    int out_pos = 0;
    
    // Count leading zeros
    int zeros = 0;
    for (int i = 0; i < in_len && in[i] == 0; i++) {
        zeros++;
    }
    
    // Convert to base58
    uchar temp_out[40];
    int temp_len = 0;
    
    while (buf_len > 0) {
        int remainder = 0;
        // Divide by 58
        for (int i = 0; i < buf_len; i++) {
            int digit = buf[i];
            int val = remainder * 256 + digit;
            buf[i] = (uchar)(val / 58);
            remainder = val % 58;
        }
        
        temp_out[temp_len++] = b58digits_map[remainder];
        
        // Reduce length if leading byte is zero
        int start = 0;
        while (start < buf_len && buf[start] == 0) {
            start++;
        }
        if (start > 0) {
            for(int i=0; i<buf_len-start; i++) buf[i] = buf[i+start];
            buf_len -= start;
        }
    }
    
    // Output leading zeros
    for (int i = 0; i < zeros; i++) {
        out[out_pos++] = '1';
    }
    
    // Output reversed digits
    for (int i = 0; i < temp_len; i++) {
        out[out_pos++] = temp_out[temp_len - 1 - i];
    }
    
    out[out_pos] = 0; // Null terminate
    return out_pos;
}
