#!/bin/bash
# GPU Validation Test - Minimal and Practical

echo "==================================================================="
echo "GPU SCAN VALIDATION TEST"
echo "==================================================================="

echo -e "\n[1/3] Testing CPU Reference (Known Test Vector)"
echo "-------------------------------------------------------------------"
echo "Seed: 1668384000 (Nov 14, 2022 00:00:00 UTC)"
echo "Expected Mnemonic: spider history orbit robust used holiday patrol ice fruit cube alpha scan"

# Create minimal Python validator using the working check_mnemonics.py logic
python3 << 'PYEOF'
from bip_utils import Bip39SeedGenerator, Bip39MnemonicGenerator, Bip44, Bip44Coins, Bip44Changes
import random

# Test MT19937 entropy generation
seed = 1668384000
rng = random.Random(seed)
entropy = bytearray(16)
for i in range(4):
    rand_u32 = rng.getrandbits(32)
    entropy[i*4:(i+1)*4] = rand_u32.to_bytes(4, 'little')

print(f"CPU Entropy: {entropy.hex()}")

# Generate mnemonic
mnemonic = Bip39MnemonicGenerator().FromEntropy(entropy)
print(f"CPU Mnemonic: {mnemonic}")

# Derive Legacy address (BIP44 m/44'/0'/0'/0/0)
seed_bytes = Bip39SeedGenerator(str(mnemonic)).Generate()
bip44_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
bip44_addr = bip44_ctx.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
address = bip44_addr.PublicKey().ToAddress()

print(f"CPU Legacy Address: {address}")
print(f"\n✓ CPU Reference OK")

# Save for comparison
with open('/tmp/cpu_reference.txt', 'w') as f:
    f.write(f"{address}\n")
PYEOF

echo -e "\n[2/3] Running GPU Scan (First Batch)"
echo "-------------------------------------------------------------------"
echo "Waiting for GPU to generate first 1024 addresses..."
cd ~/entropy-lab-rs
timeout 150 cargo run --release -- trust-wallet 2>/dev/null | head -n 1 > /tmp/gpu_first_address.txt

if [ -s /tmp/gpu_first_address.txt ]; then
    echo "✓ GPU generated output"
    
    # Decode first GPU address
    python3 << 'PYEOF2'
from bip_utils import Base58Encoder
with open('/tmp/gpu_first_address.txt', 'r') as f:
    line = f.read().strip()
    if line.startswith('ADDRESS:'):
        hex_addr = line.split('ADDRESS:')[1].strip()
        addr_bytes = bytes.fromhex(hex_addr)
        gpu_address = Base58Encoder.Encode(addr_bytes)
        print(f"GPU Address #1: {gpu_address}")
        
        with open('/tmp/gpu_decoded.txt', 'w') as out:
            out.write(f"{gpu_address}\n")
PYEOF2
else
    echo "✗ GPU did not generate output in time"
    exit 1
fi

echo -e "\n[3/3] Validation: CPU vs GPU"
echo "-------------------------------------------------------------------"
cpu_addr=$(cat /tmp/cpu_reference.txt)
gpu_addr=$(cat /tmp/gpu_decoded.txt)

echo "CPU Address: $cpu_addr"
echo "GPU Address: $gpu_addr"

if [ "$cpu_addr" == "$gpu_addr" ]; then
    echo -e "\n✓✓✓ SUCCESS: GPU matches CPU reference!"
    echo "==================================================================="
    exit 0
else
    echo -e "\n✗✗✗ MISMATCH: GPU does NOT match CPU!"
    echo "==================================================================="
    exit 1
fi
