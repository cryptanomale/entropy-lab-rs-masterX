#!/usr/bin/env python3
"""
Randstorm Scanner Validation Script

This script validates that the Randstorm scanner correctly identifies
vulnerable wallets by comparing against known test vectors.
"""

import csv
import hashlib
from typing import List, Dict, Optional

class ScannerValidator:
    """Validates Randstorm scanner output against test vectors"""
    
    def __init__(self, test_vectors_file: str):
        self.test_vectors = self.load_test_vectors(test_vectors_file)
        self.funded_key_index = 500  # The key we'll fund for testing
        
    def load_test_vectors(self, filename: str) -> List[Dict]:
        """Load test vectors from CSV"""
        vectors = []
        with open(filename, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                vectors.append({
                    'index': int(row['index']),
                    'timestamp_ms': int(row['timestamp_ms']),
                    'private_key_hex': row['private_key_hex'],
                })
        return vectors
    
    def get_funded_test_vector(self) -> Dict:
        """Get the test vector that should be funded"""
        return self.test_vectors[self.funded_key_index]
    
    def validate_scanner_output(self, scanner_output_file: str) -> Dict:
        """
        Validate scanner found the correct key
        
        Returns: {
            'success': bool,
            'found_key': Optional[str],
            'expected_key': str,
            'match': bool,
            'scan_time_ms': int,
        }
        """
        expected = self.get_funded_test_vector()
        
        # Load scanner output (assume CSV format)
        found_keys = []
        try:
            with open(scanner_output_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    found_keys.append({
                        'timestamp': int(row.get('timestamp_ms', 0)),
                        'private_key': row.get('private_key_hex', ''),
                        'address': row.get('address', ''),
                    })
        except FileNotFoundError:
            return {
                'success': False,
                'error': 'Scanner output file not found',
                'expected_key': expected['private_key_hex'],
            }
        
        # Check if expected key was found
        match = any(
            key['private_key'] == expected['private_key_hex']
            for key in found_keys
        )
        
        return {
            'success': match,
            'found_keys_count': len(found_keys),
            'expected_key': expected['private_key_hex'],
            'expected_timestamp': expected['timestamp_ms'],
            'match': match,
            'found_keys': found_keys[:5],  # First 5 for inspection
        }
    
    def generate_validation_report(self, scanner_output: Optional[str] = None):
        """Generate comprehensive validation report"""
        print("\n" + "═" * 70)
        print("🔬 RANDSTORM SCANNER VALIDATION REPORT")
        print("═" * 70)
        
        funded_vector = self.get_funded_test_vector()
        
        print("\n📋 Test Configuration:")
        print(f"  Total test vectors: {len(self.test_vectors)}")
        print(f"  Funded key index: {self.funded_key_index}")
        print(f"  Expected timestamp: {funded_vector['timestamp_ms']}")
        print(f"  Expected private key: {funded_vector['private_key_hex'][:32]}...")
        
        if scanner_output:
            print("\n🎯 Scanner Results:")
            results = self.validate_scanner_output(scanner_output)
            
            if results.get('success'):
                print("  ✅ SUCCESS - Scanner found the vulnerable key!")
                print(f"  Found {results['found_keys_count']} total keys")
                print(f"  Match confirmed at timestamp: {results['expected_timestamp']}")
            else:
                print("  ❌ FAILURE - Scanner did not find the expected key")
                if 'error' in results:
                    print(f"  Error: {results['error']}")
                else:
                    print(f"  Found {results['found_keys_count']} keys, but none matched")
                    if results['found_keys']:
                        print("\n  Found keys (sample):")
                        for key in results['found_keys']:
                            print(f"    - {key['private_key'][:32]}... @ {key['timestamp']}")
        else:
            print("\n⏳ Awaiting scanner execution...")
            print("\n📝 To run scanner:")
            print(f"  cargo run --bin randstorm_scan \\")
            print(f"    --start-time {funded_vector['timestamp_ms'] - 10000} \\")
            print(f"    --end-time {funded_vector['timestamp_ms'] + 10000} \\")
            print(f"    --output scanner_output.csv")
        
        print("\n" + "═" * 70)


def main():
    import sys
    
    test_vectors_file = "randstorm_test_vectors.csv"
    scanner_output_file = None
    
    if len(sys.argv) > 1:
        scanner_output_file = sys.argv[1]
    
    validator = ScannerValidator(test_vectors_file)
    validator.generate_validation_report(scanner_output_file)
    
    print("\n✅ Validation script ready")
    print("📌 Next steps:")
    print("   1. Generate test vectors: python3 generate_test_vectors_option_a.py")
    print("   2. Fund the test address with testnet BTC")
    print("   3. Run the Randstorm scanner")
    print("   4. Validate results: python3 validate_scanner.py scanner_output.csv")


if __name__ == "__main__":
    main()
