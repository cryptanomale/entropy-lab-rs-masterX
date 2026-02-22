#!/usr/bin/env python3
import json
import hashlib
import binascii

# --- PRNG Implementations ---

class V8Mwc1616:
    def __init__(self, seed):
        self.s1 = seed & 0xFFFFFFFF
        self.s2 = (seed >> 32) & 0xFFFFFFFF
        if self.s1 == 0: self.s1 = 1
        if self.s2 == 0: self.s2 = 1

    def next_u16(self):
        self.s1 = (18000 * (self.s1 & 0xFFFF) + (self.s1 >> 16)) & 0xFFFFFFFF
        self.s2 = (30903 * (self.s2 & 0xFFFF) + (self.s2 >> 16)) & 0xFFFFFFFF
        combined = ((self.s1 << 16) + self.s2) & 0xFFFFFFFF
        return (combined >> 16) & 0xFFFF

class JavaLcg:
    def __init__(self, seed):
        self.state = seed & ((1 << 48) - 1)

    def next_u16(self):
        self.state = (self.state * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
        return (self.state >> 16) & 0xFFFF

class SafariCrt:
    def __init__(self, seed):
        self.state = seed & 0xFFFFFFFF
        
    def next_u16(self):
        # First call
        self.state = (self.state * 214013 + 2531011) & 0xFFFFFFFF
        r1 = (self.state >> 16) & 0x7FFF
        # Second call
        self.state = (self.state * 214013 + 2531011) & 0xFFFFFFFF
        r2 = (self.state >> 16) & 0x7FFF
        combined = (r1 << 15) | r2
        return (combined >> 14) & 0xFFFF

# --- ARC4 Implementation ---

class ARC4:
    def __init__(self, key):
        self.s = list(range(256))
        self.i = 0
        self.j = 0
        j = 0
        for i in range(256):
            j = (j + self.s[i] + key[i % len(key)]) % 256
            self.s[i], self.s[j] = self.s[j], self.s[i]

    def next_byte(self):
        self.i = (self.i + 1) % 256
        self.j = (self.j + self.s[self.i]) % 256
        self.s[self.i], self.s[self.j] = self.s[self.j], self.s[self.i]
        return self.s[(self.s[self.i] + self.s[self.j]) % 256]

# --- Randstorm Logic ---

def derive_privkey_python(ts, engine_type):
    if engine_type == 'v8':
        prng = V8Mwc1616(ts)
        pool = []
        while len(pool) < 256:
            val = prng.next_u16()
            pool.append((val >> 8) & 0xFF)
            if len(pool) < 256:
                pool.append(val & 0xFF)
    elif engine_type in ['java', 'ie']:
        prng = JavaLcg(ts)
        pool = []
        while len(pool) < 256:
            val = prng.next_u16()
            pool.append((val >> 8) & 0xFF)
            if len(pool) < 256:
                pool.append(val & 0xFF)
    elif engine_type == 'safari-win':
        prng = SafariCrt(ts)
        pool = []
        while len(pool) < 256:
            val = prng.next_u16()
            pool.append((val >> 8) & 0xFF)
            if len(pool) < 256:
                pool.append(val & 0xFF)
    else:
        return None

    # XOR with timestamp
    ts_bytes = [
        ts & 0xFF,
        (ts >> 8) & 0xFF,
        (ts >> 16) & 0xFF,
        (ts >> 24) & 0xFF
    ]
    for i in range(4):
        pool[i] ^= ts_bytes[i]

    # ARC4
    arc4 = ARC4(pool)
    privkey = bytes([arc4.next_byte() for _ in range(32)])
    return privkey

# --- Main Script ---

def main():
    print("🧪 Starting Randstorm Parity Validation...")
    
    try:
        with open('tests/fixtures/comprehensive_test_vectors.json', 'r') as f:
            vectors = json.load(f)
    except FileNotFoundError:
        print("❌ Error: comprehensive_test_vectors.json not found. Run generate_vectors first.")
        return

    passed = 0
    failed = 0
    total = len(vectors)

    for i, v in enumerate(vectors):
        if v['vulnerability'] != 'randstorm': continue
        
        py_privkey_bytes = derive_privkey_python(v['timestamp_ms'], v['engine'])
        if py_privkey_bytes is None: 
            # Skip unsupported Safari for now
            continue
            
        py_privkey_hex = binascii.hexlify(py_privkey_bytes).decode()
        
        if py_privkey_hex == v['expected_privkey_hex']:
            passed += 1
        else:
            failed += 1
            print(f"❌ Parity failure at index {i}:")
            print(f"   Engine: {v['engine']}, TS: {v['timestamp_ms']}")
            print(f"   Expected: {v['expected_privkey_hex']}")
            print(f"   Python:   {py_privkey_hex}")
            if failed > 5:
                print("Too many failures, stopping...")
                break
        
        if i % 1000 == 0 and i > 0:
            print(f"Checked {i}/{total} vectors...")

    print(f"\n✅ Parity Validation Complete")
    print(f"   Total:  {total}")
    print(f"   Passed: {passed}")
    print(f"   Failed: {failed}")
    
    if failed == 0:
        print("🎉 PERFECT PARITY ACHIEVED!")
    else:
        import sys
        sys.exit(1)

if __name__ == "__main__":
    main()
