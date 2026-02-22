#!/usr/bin/env python3
"""
GPU Scan Validation Script
Compares GPU-generated addresses with CPU reference implementation
"""

from bip_utils import Bip39SeedGenerator, Bip39MnemonicGenerator, Bip39WordsNum, Bip44, Bip44Coins, Bip44Changes, Base58Encoder
import sys

def entropy_to_mnemonic(entropy_hex: str) -> str:
    """Convert hex entropy to BIP39 mnemonic"""
    entropy_bytes = bytes.fromhex(entropy_hex)
    mnemonic = Bip39MnemonicGenerator().FromEntropy(entropy_bytes)
    return str(mnemonic)

def mnemonic_to_address_legacy(mnemonic: str) -> str:
    """Derive Legacy P2PKH address (BIP44 m/44'/0'/0'/0/0)"""
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
    
    bip44_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
    
    # m/44'/0'/0'/0/0
    bip44_acc_ctx = bip44_ctx.Purpose().Coin().Account(0)
    bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
    bip44_addr_ctx = bip44_chg_ctx.AddressIndex(0)
    
    return bip44_addr_ctx.PublicKey().ToAddress()

def derive_address_from_entropy(entropy_hex: str) -> tuple[str, str]:
    """
    Derive mnemonic and Legacy address from entropy
    Returns: (mnemonic, address)
    """
    mnemonic = entropy_to_mnemonic(entropy_hex)
    address = mnemonic_to_address_legacy(mnemonic)
    return mnemonic, address

def mt19937_generate_entropy(seed: int) -> str:
    """
    Generate 128-bit entropy using MT19937 (matching Rust implementation)
    Python's random.Random uses MT19937
    """
    import random
    rng = random.Random(seed)
    
    entropy = bytearray(16)
    for i in range(4):
        rand_u32 = rng.getrandbits(32)
        # Convert to little-endian bytes
        entropy[i*4:(i+1)*4] = rand_u32.to_bytes(4, 'little')
    
    return entropy.hex()

def validate_test_vectors():
    """Test with known test vectors"""
    print("=" * 80)
    print("VALIDATION TEST SUITE - GPU vs CPU Address Derivation")
    print("=" * 80)
    
    # Test vector 1: Known timestamp from Trust Wallet vulnerability period
    test_vectors = [
        {
            "name": "Trust Wallet - Nov 14 2022 00:00:00 UTC",
            "seed": 1668384000,
            "expected_mnemonic": "spider history orbit robust used holiday patrol ice fruit cube alpha scan"
        },
        {
            "name": "Trust Wallet - Nov 15 2022 12:00:00 UTC",
            "seed": 1668513600,
            "expected_mnemonic": None  # Don't have reference
        },
        {
            "name": "Test seed - 12345",
            "seed": 12345,
            "expected_mnemonic": None
        },
    ]
    
    print("\n" + "─" * 80)
    print("TEST 1: Known Test Vectors")
    print("─" * 80)
    
    results = []
    for vector in test_vectors:
        print(f"\nTest: {vector['name']}")
        print(f"Seed: {vector['seed']}")
        
        entropy_hex = mt19937_generate_entropy(vector['seed'])
        mnemonic, address = derive_address_from_entropy(entropy_hex)
        
        print(f"Entropy: {entropy_hex}")
        print(f"Mnemonic: {mnemonic}")
        print(f"Address: {address}")
        
        if vector['expected_mnemonic']:
            match = mnemonic == vector['expected_mnemonic']
            print(f"✓ Mnemonic Match: {match}")
            if not match:
                print(f"  Expected: {vector['expected_mnemonic']}")
                print(f"  Got:      {mnemonic}")
        
        results.append({
            'seed': vector['seed'],
            'entropy': entropy_hex,
            'mnemonic': mnemonic,
            'address': address
        })
    
    return results

def generate_gpu_comparison_file(count=100):
    """Generate reference addresses for GPU comparison"""
    print("\n" + "─" * 80)
    print(f"TEST 2: Generating {count} Reference Addresses for GPU Comparison")
    print("─" * 80)
    
    # Start from Trust Wallet vulnerability period
    start_seed = 1668384000
    
    with open('validation_reference.txt', 'w') as f:
        f.write("# GPU Validation Reference\n")
        f.write("# Format: SEED,ENTROPY,MNEMONIC,ADDRESS\n")
        
        for i in range(count):
            seed = start_seed + i
            entropy_hex = mt19937_generate_entropy(seed)
            mnemonic, address = derive_address_from_entropy(entropy_hex)
            
            f.write(f"{seed},{entropy_hex},{mnemonic},{address}\n")
            
            if (i + 1) % 10 == 0:
                print(f"  Generated {i + 1}/{count} reference addresses...")
    
    print(f"\n✓ Reference file saved: validation_reference.txt")
    print(f"  Use this to validate GPU output")

def compare_with_gpu_output(gpu_file='gpu_output.txt', ref_file='validation_reference.txt'):
    """Compare GPU output with reference"""
    print("\n" + "─" * 80)
    print("TEST 3: Comparing GPU Output with Reference")
    print("─" * 80)
    
    try:
        # Load reference
        ref_addresses = {}
        with open(ref_file, 'r') as f:
            for line in f:
                if line.startswith('#'):
                    continue
                parts = line.strip().split(',')
                if len(parts) == 4:
                    seed, entropy, mnemonic, address = parts
                    ref_addresses[entropy] = {
                        'seed': seed,
                        'mnemonic': mnemonic,
                        'address': address
                    }
        
        print(f"Loaded {len(ref_addresses)} reference addresses")
        
        # Parse GPU output (hex-encoded addresses)
        gpu_addresses = []
        with open(gpu_file, 'r') as f:
            for line in f:
                if line.startswith('ADDRESS:'):
                    hex_addr = line.strip().split('ADDRESS:')[1].strip()
                    # Decode hex to get raw bytes, then Base58 encode
                    addr_bytes = bytes.fromhex(hex_addr)
                    address = Base58Encoder.Encode(addr_bytes)
                    gpu_addresses.append(address)
        
        print(f"Loaded {len(gpu_addresses)} GPU addresses")
        
        # Compare
        matches = 0
        mismatches = 0
        
        for i, gpu_addr in enumerate(gpu_addresses):
            if i < len(ref_addresses):
                # Get corresponding reference (assuming same order)
                ref_addr = list(ref_addresses.values())[i]['address']
                
                if gpu_addr == ref_addr:
                    matches += 1
                else:
                    mismatches += 1
                    print(f"\n✗ MISMATCH at index {i}:")
                    print(f"  GPU:       {gpu_addr}")
                    print(f"  Reference: {ref_addr}")
        
        print(f"\n{'=' * 80}")
        print(f"RESULTS: {matches} matches, {mismatches} mismatches")
        print(f"Accuracy: {100 * matches / (matches + mismatches):.2f}%")
        print(f"{'=' * 80}")
        
        return matches == len(gpu_addresses) and mismatches == 0
        
    except FileNotFoundError as e:
        print(f"\n✗ File not found: {e}")
        print("  Run validation first to generate reference file")
        print("  Then run GPU scan and save output to gpu_output.txt")
        return False

if __name__ == '__main__':
    # Run validation
    results = validate_test_vectors()
    
    # Generate reference file
    generate_gpu_comparison_file(count=100)
    
    print("\n" + "=" * 80)
    print("NEXT STEPS:")
    print("=" * 80)
    print("1. Run GPU scan on server and save first 100 addresses:")
    print("   cd ~/entropy-lab-rs && cargo run --release -- trust-wallet 2>/dev/null | head -n 100 > gpu_output.txt")
    print("\n2. Copy gpu_output.txt to local machine")
    print("\n3. Run comparison:")
    print("   python3 validate_gpu.py --compare")
    print("=" * 80)
    
    # If comparison requested
    if len(sys.argv) > 1 and sys.argv[1] == '--compare':
        success = compare_with_gpu_output()
        sys.exit(0 if success else 1)
