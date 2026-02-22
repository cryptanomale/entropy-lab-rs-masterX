from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes, Bip84, Bip84Coins, Base58Encoder
import sqlite3
import sys
import os
import requests
import json

DB_FILE = "/home/dev/hashtopolis-agent/crackers/2/loyce_targets.db"

# Bitcoin Core RPC Configuration
RPC_USER = "bitcoinrpc"
RPC_PASS = "madmad13221"  # From bitcoin.conf on server
RPC_HOST = "127.0.0.1"
RPC_PORT = 8332

def check_balance_rpc(address):
    """Check current balance via Bitcoin Core RPC"""
    try:
        payload = {
            "jsonrpc": "1.0",
            "id": "curltest",
            "method": "scantxoutset",
            "params": ["start", [f"addr({address})"]]
        }
        
        response = requests.post(
            f"http://{RPC_HOST}:{RPC_PORT}",
            auth=(RPC_USER, RPC_PASS),
            headers={'content-type': 'application/json'},
            data=json.dumps(payload),
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            if 'result' in result and result['result']:
                total_amount = result['result'].get('total_amount', 0)
                return total_amount
        return 0
    except Exception as e:
        print(f"\nRPC Error checking {address}: {e}")
        return None  # None = RPC error, 0 = checked but no balance

def main():
    # 1. Connect to DB
    print(f"Connecting to {DB_FILE}...")
    if not os.path.exists(DB_FILE):
        print(f"Error: {DB_FILE} not found!")
        return
        
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # 2. Scan (from STDIN)
    print(f"Scanning from STDIN...")
    try:
        count = 0
        for line in sys.stdin:
            line = line.strip()
            if not line: continue
            
            if line.startswith("ADDRESS: "):
                # Handle GPU Output
                hex_addr = line.split(" ")[1]
                try:
                    addr_bytes = bytes.fromhex(hex_addr)
                    # GPU returns 25 bytes (Version + Hash + Checksum)
                    # We just need to Base58 encode it.
                    address = Base58Encoder.Encode(addr_bytes)
                    
                    cursor.execute("SELECT address FROM targets WHERE address = ?", (address,))
                    hits = cursor.fetchall()
                    
                    if hits:
                        # Found in Loyce DB - now check current balance
                        print(f"\n🔍 Loyce DB hit: {address}")
                        balance = check_balance_rpc(address)
                        
                        if balance is None:
                            # RPC error - record as potential hit
                            msg = f"POTENTIAL HIT (RPC error): {address}"
                            print(f"⚠️  {msg}")
                            with open("HITS_UNVERIFIED.txt", "a") as h:
                                h.write(f"{msg}\n")
                        elif balance > 0:
                            # Confirmed balance!
                            msg = f"💰 CONFIRMED HIT! {address} | Balance: {balance} BTC"
                            print(f"\n{'='*80}")
                            print(msg)
                            print('='*80)
                            with open("HITS_CONFIRMED.txt", "a") as h:
                                h.write(f"{msg}\n")
                            # Also beep or alert
                            print("\a" * 3)  # Terminal bell
                        else:
                            # In DB but balance = 0 (funds moved)
                            print(f"ℹ️  Address in DB but no current balance: {address}")
                            with open("HITS_EMPTY.txt", "a") as h:
                                h.write(f"{address} (empty)\n")
                        
                except Exception as e:
                    pass # Ignore parse errors
                    
                count += 1
                if count % 10000 == 0:
                    print(f"\rChecked {count} addresses...", end="")
                continue

            # Fallback for CPU mnemonics (if any)
            mnemonic = line
            if len(mnemonic.split()) != 12:
                continue

            # Generate Seed
            seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
            
            # Check BIP44 (Legacy 1...)
            bip44_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
            addr44 = bip44_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
            
            # Check BIP84 (Segwit bc1...)
            bip84_ctx = Bip84.FromSeed(seed_bytes, Bip84Coins.BITCOIN)
            addr84 = bip84_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
            
            # Check DB
            cursor.execute("SELECT address FROM targets WHERE address IN (?, ?)", (addr44, addr84))
            hits = cursor.fetchall()
            
            if hits:
                for hit in hits:
                    address = hit[0]
                    print(f"\n🔍 Loyce DB hit: {mnemonic} -> {address}")
                    balance = check_balance_rpc(address)
                    
                    if balance is None:
                        msg = f"POTENTIAL HIT (RPC error): {mnemonic} -> {address}"
                        print(f"⚠️  {msg}")
                        with open("HITS_UNVERIFIED.txt", "a") as h:
                            h.write(f"{msg}\n")
                    elif balance > 0:
                        msg = f"💰 CONFIRMED HIT! {mnemonic} -> {address} | Balance: {balance} BTC"
                        print(f"\n{'='*80}")
                        print(msg)
                        print('='*80)
                        with open("HITS_CONFIRMED.txt", "a") as h:
                            h.write(f"{msg}\n")
                        print("\a" * 3)
                    else:
                        print(f"ℹ️  Address in DB but no current balance: {address}")
                        with open("HITS_EMPTY.txt", "a") as h:
                            h.write(f"{mnemonic} -> {address} (empty)\n")

            count += 1
            if count % 1000 == 0:
                print(f"\rScanned {count} mnemonics...", end="")
                    
    except KeyboardInterrupt:
        print("\nScan interrupted.")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
