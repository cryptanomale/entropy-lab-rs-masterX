#!/bin/bash
# Quick GPU Validation - Uses batch size 1 for instant results

echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║           QUICK GPU VALIDATION TEST (Batch Size: 1)              ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"

echo ""
echo "[1/3] CPU Reference (Python)"
echo "────────────────────────────────────────────────────────────────────"

CPU_ADDR=$(python3 << 'PYEOF'
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes, Bip39MnemonicGenerator
import random

seed = 1668384000
rng = random.Random(seed)
entropy = bytearray(16)
for i in range(4):
    entropy[i*4:(i+1)*4] = rng.getrandbits(32).to_bytes(4, 'little')

mnemonic = str(Bip39MnemonicGenerator().FromEntropy(entropy))
seed_bytes = Bip39SeedGenerator(mnemonic).Generate()
addr = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN).Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
print(addr)
PYEOF
)

echo "CPU Address: $CPU_ADDR"

echo ""
echo "[2/3] GPU Output (Batch Size: 1)"
echo "────────────────────────────────────────────────────────────────────"

# Temporarily modify batch size to 1 for instant output
cd ~/entropy-lab-rs/src/scans
cp trust_wallet.rs trust_wallet.rs.backup

# Replace batch size 1024 -> 1
sed -i 's/Vec::with_capacity(1024)/Vec::with_capacity(1)/' trust_wallet.rs
sed -i 's/batch.len() >= 1024/batch.len() >= 1/' trust_wallet.rs

echo "Modified batch size to 1..."

# Run GPU scan - should output instantly
cd ~/entropy-lab-rs
GPU_HEX=$(timeout 30 cargo run --release -- trust-wallet 2>/dev/null | grep "ADDRESS:" | head -n 1 | cut -d' ' -f2)

# Restore original
cd ~/entropy-lab-rs/src/scans
mv trust_wallet.rs.backup trust_wallet.rs

if [ -z "$GPU_HEX" ]; then
    echo "✗ GPU output timeout or empty"
    exit 1
fi

echo "GPU Raw Hex: $GPU_HEX"

# Decode GPU address
GPU_ADDR=$(python3 << PYEOF2
from bip_utils import Base58Encoder
try:
    addr_bytes = bytes.fromhex("$GPU_HEX")
    print(Base58Encoder.Encode(addr_bytes))
except Exception as e:
    print(f"ERROR: {e}")
PYEOF2
)

echo "GPU Address: $GPU_ADDR"

echo ""
echo "[3/3] Comparison"
echo "────────────────────────────────────────────────────────────────────"
echo "CPU: $CPU_ADDR"
echo "GPU: $GPU_ADDR"
echo ""

if [ "$CPU_ADDR" == "$GPU_ADDR" ]; then
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║                    ✅ SUCCESS: EXACT MATCH!                       ║"
    echo "║            GPU scan is generating correct addresses!              ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    exit 0
else
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║                  ❌ MISMATCH: ADDRESSES DIFFER                    ║"
    echo "║              GPU implementation needs debugging!                  ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    exit 1
fi
