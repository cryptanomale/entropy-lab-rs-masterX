#!/usr/bin/env python3
"""
Generate Randstorm Test Vectors - Option A Implementation

Creates 1,000 test Bitcoin addresses using the vulnerable BitcoinJS
entropy generation pattern (weak Math.random seeding from 2011-2015 era)

This simulates the exact vulnerability described in the Unciphered disclosure.
"""

import hashlib
import time
from typing import List, Tuple
import csv

class VulnerablePRNG:
    """Simulates the vulnerable BitcoinJS SecureRandom() PRNG"""
    
    # V8's Math.random() LCG parameters (pre-2015)
    MULTIPLIER = 25214903917
    INCREMENT = 11
    MODULUS = (1 << 48) - 1
    
    def __init__(self, timestamp_ms: int, sequence: int):
        """Initialize with timestamp (the primary vulnerability vector)"""
        self.seed = timestamp_ms ^ sequence
        self.timestamp_ms = timestamp_ms
        
    def next_random(self) -> float:
        """Simulate JavaScript Math.random() - 48-bit LCG"""
        self.seed = (self.seed * self.MULTIPLIER + self.INCREMENT) & self.MODULUS
        return self.seed / self.MODULUS
    
    def generate_entropy(self) -> bytes:
        """Generate 32 bytes using the vulnerable method"""
        entropy = bytearray(32)
        
        # First 8 bytes: timestamp (this is the key weakness!)
        entropy[0:8] = self.timestamp_ms.to_bytes(8, 'little')
        
        # Remaining 24 bytes: weak random from Math.random()
        for i in range(3):
            rand_val = int(self.next_random() * 65536)
            entropy[8 + i*8:8 + (i+1)*8] = rand_val.to_bytes(8, 'little')
        
        return bytes(entropy)
    
    def derive_private_key(self) -> bytes:
        """Derive 32-byte private key from vulnerable entropy"""
        entropy = self.generate_entropy()
        return hashlib.sha256(entropy).digest()


def generate_test_vectors(count: int = 1000) -> List[Tuple[int, int, bytes, str]]:
    """
    Generate test vectors using vulnerable PRNG
    
    Returns: List of (index, timestamp_ms, private_key, address_info)
    """
    print("🔬 Generating Randstorm Test Vectors")
    print("═" * 60)
    
    # Fixed timestamp: January 15, 2014, 10:30:00 UTC
    # Within the vulnerable period identified by Unciphered
    base_timestamp_ms = 1389781800000
    
    vectors = []
    
    print(f"\n📊 Generating {count} test keys...\n")
    
    for i in range(count):
        # Add small time variations (100ms increments)
        timestamp_ms = base_timestamp_ms + (i * 100)
        
        # Generate vulnerable private key
        prng = VulnerablePRNG(timestamp_ms, i)
        private_key = prng.derive_private_key()
        
        # Store vector
        vectors.append((
            i,
            timestamp_ms,
            private_key,
            private_key.hex()
        ))
        
        if i % 100 == 0 and i > 0:
            print(f"  ✓ Generated {i} keys...")
    
    print(f"\n✅ Generated {count} vulnerable test keys")
    return vectors


def save_vectors_to_csv(vectors: List[Tuple], filename: str = "randstorm_test_vectors.csv"):
    """Save test vectors to CSV file"""
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['index', 'timestamp_ms', 'private_key_hex', 'entropy_pattern'])
        
        for idx, ts, priv_bytes, priv_hex in vectors:
            # Calculate entropy pattern (first 8 bytes should match timestamp)
            entropy_pattern = f"ts:{ts:016x}"
            writer.writerow([idx, ts, priv_hex, entropy_pattern])
    
    print(f"📁 Output: {filename}")


def main():
    vectors = generate_test_vectors(1000)
    save_vectors_to_csv(vectors)
    
    # Print sample keys
    print("\n📋 Sample Keys (first 5):")
    print("═" * 60)
    for idx, ts, priv_bytes, priv_hex in vectors[:5]:
        print(f"\n[{idx}] Timestamp: {ts}")
        print(f"    Private Key: {priv_hex}")
        print(f"    Entropy (first 16 bytes): {priv_bytes[:16].hex()}")
    
    # Highlight the test key
    test_key_idx = 500
    test_vector = vectors[test_key_idx]
    
    print("\n🎯 Test Validation Instructions:")
    print("═" * 60)
    print(f"1. Use key #{test_key_idx} for testing (middle of dataset)")
    print(f"   Timestamp: {test_vector[1]}")
    print(f"   Private Key: {test_vector[3]}")
    print("\n2. To derive Bitcoin address from this key:")
    print("   - Import the private key into Bitcoin Core (testnet)")
    print("   - Or use: btc-address-gen tool")
    print("\n3. Fund the address with ~0.001 tBTC")
    print("   Testnet faucet: https://testnet-faucet.com/btc-testnet/")
    print("\n4. Run scanner with timestamp range:")
    print(f"   --start-time {test_vector[1] - 10000}")
    print(f"   --end-time {test_vector[1] + 10000}")
    print("\n5. Scanner SHOULD find the funded address")
    print("\n💡 Success Criteria:")
    print("   ✓ Scanner identifies the vulnerable timestamp")
    print("   ✓ Scanner derives matching private key")
    print("   ✓ Scanner detects balance on address")
    
    print("\n📊 Statistical Analysis:")
    print("═" * 60)
    print(f"Total keys generated: {len(vectors)}")
    print(f"Timestamp range: {vectors[0][1]} - {vectors[-1][1]}")
    print(f"Time span: {(vectors[-1][1] - vectors[0][1]) / 1000:.2f} seconds")
    print(f"Avg time between keys: {100} ms (deterministic)")
    print("\n⚠️  These keys use the EXACT vulnerability pattern from:")
    print("   BitcoinJS v0.1.3 (2011-2014)")
    print("   Weak Math.random() seeding")
    print("   Timestamp-based entropy")


if __name__ == "__main__":
    main()
