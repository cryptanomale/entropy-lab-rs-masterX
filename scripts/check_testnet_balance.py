#!/usr/bin/env python3
"""
Testnet Address Balance Checker
Alternative to Bitcoin Core - uses public block explorers
"""

import requests
import json
import time
import sys
from datetime import datetime

# Configuration
TARGET_ADDRESS = "n2ViH2xX7QgbouDvK2tdLmnyK2rQPYqoA1"
EXPECTED_AMOUNT_SATS = 100000  # 0.001 BTC in satoshis
CHECK_INTERVAL = 30  # seconds
MAX_CHECKS = 60  # 30 minutes total

# Block explorer APIs (multiple for redundancy)
EXPLORERS = [
    {
        "name": "Blockstream",
        "url": f"https://blockstream.info/testnet/api/address/{TARGET_ADDRESS}",
        "balance_key": "chain_stats.funded_txo_sum"
    },
    {
        "name": "Mempool.space",
        "url": f"https://mempool.space/testnet/api/address/{TARGET_ADDRESS}",
        "balance_key": "chain_stats.funded_txo_sum"
    }
]

def get_nested_value(data, key_path):
    """Extract nested dictionary value using dot notation"""
    keys = key_path.split('.')
    value = data
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key)
        else:
            return None
    return value

def check_balance():
    """Check address balance using block explorer APIs"""
    for explorer in EXPLORERS:
        try:
            print(f"  Checking {explorer['name']}...", end=' ')
            response = requests.get(explorer['url'], timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                balance = get_nested_value(data, explorer['balance_key'])
                
                if balance is not None:
                    print(f"✓ {balance} sats")
                    return balance
                else:
                    print(f"⚠ No balance data")
            else:
                print(f"⚠ HTTP {response.status_code}")
                
        except Exception as e:
            print(f"✗ {str(e)[:50]}")
            continue
    
    return None

def main():
    print("=" * 60)
    print("🔍 Testnet Address Balance Monitor")
    print("=" * 60)
    print()
    print(f"Address: {TARGET_ADDRESS}")
    print(f"Expected: {EXPECTED_AMOUNT_SATS} sats (0.001 tBTC)")
    print()
    print("📋 Instructions:")
    print("  1. Visit: https://testnet-faucet.mempool.co/")
    print(f"  2. Paste: {TARGET_ADDRESS}")
    print("  3. Request coins")
    print("  4. Wait for this script to detect funding...")
    print()
    print("=" * 60)
    print()
    
    checks = 0
    funded = False
    
    while checks < MAX_CHECKS and not funded:
        checks += 1
        timestamp = datetime.utcnow().strftime('%H:%M:%S')
        
        print(f"[{timestamp}] Check #{checks}/{MAX_CHECKS}")
        balance = check_balance()
        
        if balance is not None and balance >= EXPECTED_AMOUNT_SATS:
            print()
            print("=" * 60)
            print("✅ FUNDING DETECTED!")
            print("=" * 60)
            print()
            print(f"  Address: {TARGET_ADDRESS}")
            print(f"  Balance: {balance} sats ({balance/100000000:.8f} tBTC)")
            print(f"  Status: Ready for scanner testing")
            print()
            print("🔗 Block Explorer:")
            print(f"  https://blockstream.info/testnet/address/{TARGET_ADDRESS}")
            print()
            print("✅ Phase 2 Complete - Ready for Phase 3")
            print()
            
            # Save status
            status = {
                "address": TARGET_ADDRESS,
                "balance_sats": balance,
                "balance_btc": balance / 100000000,
                "funded_at": datetime.utcnow().isoformat(),
                "status": "funded",
                "phase": "2_complete"
            }
            
            with open('/tmp/randstorm_funding_status.json', 'w') as f:
                json.dump(status, f, indent=2)
            
            print("💾 Status saved to: /tmp/randstorm_funding_status.json")
            print()
            
            funded = True
            return 0
            
        elif balance is not None and balance > 0:
            print(f"  ⏳ Partial funding: {balance} sats (need {EXPECTED_AMOUNT_SATS})")
        else:
            print(f"  ⏳ Not yet funded (waiting...)")
        
        print()
        
        if checks < MAX_CHECKS and not funded:
            print(f"  Next check in {CHECK_INTERVAL} seconds...")
            print()
            time.sleep(CHECK_INTERVAL)
    
    if not funded:
        print("=" * 60)
        print("⏰ Timeout Reached")
        print("=" * 60)
        print()
        print("The address has not been funded within the timeout period.")
        print()
        print("Options:")
        print("  1. Re-run this script to continue monitoring")
        print("  2. Check manually: https://blockstream.info/testnet/address/")
        print(f"     {TARGET_ADDRESS}")
        print("  3. Request coins from alternative faucets:")
        print("     • https://coinfaucet.eu/en/btc-testnet/")
        print("     • https://bitcoinfaucet.uo1.net/")
        print()
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        print()
        print("⚠️  Monitoring interrupted by user")
        print()
        print("Re-run to continue checking:")
        print("  python3 scripts/check_testnet_balance.py")
        print()
        sys.exit(130)
