#!/usr/bin/env python3
from bip_utils import Bip39SeedGenerator, Bip39MnemonicGenerator, Bip44, Bip44Coins, Bip44Changes, Bip44Levels, Base58Encoder
import binascii

def validate_cake_index_0():
    print("Generating CPU Reference for Cake Wallet (Index 0)...")
    
    # 1. Entropy: 32 bytes, index 0 in first 4 bytes (big-endian)
    # For index 0, it's all zeros.
    entropy = bytes([0] * 32)
    
    # Mnemonic from first 16 bytes (128 bits)
    entropy_128 = entropy[:16]
    mnemonic = Bip39MnemonicGenerator().FromEntropy(entropy_128)
    print(f"Mnemonic: {mnemonic}")
    
    # 2. Seed
    seed_bytes = Bip39SeedGenerator(str(mnemonic)).Generate()
    
    # 3. Derivation m/0'/0/0
    # We can use Bip44 class but need to manually specify the path levels since it's non-standard
    # m / 0' / 0 / 0
    # Purpose=0' (Hardened)
    # Coin=0 (Normal) - wait, the kernel does:
    # hardened_private_child_from_private(master, target, 0); -> m/0'
    # normal_private_child_from_private(target, target, 0);   -> m/0'/0
    # normal_private_child_from_private(target, target, 0);   -> m/0'/0/0
    
    # Using bip_utils Bip32/44
    from bip_utils import Bip32Slip10Secp256k1
    
    bip32_ctx = Bip32Slip10Secp256k1.FromSeed(seed_bytes)
    # Derive m/0'
    bip32_ctx = bip32_ctx.ChildKey(0 + 2147483648)
    # Derive m/0'/0
    bip32_ctx = bip32_ctx.ChildKey(0)
    # Derive m/0'/0/0
    bip32_ctx = bip32_ctx.ChildKey(0)
    
    # 4. Address (P2PKH Legacy)
    # Public Key -> SHA256 -> RIPEMD160 -> [0x00] + Hash + Checksum -> Base58
    pub_key_bytes = bip32_ctx.PublicKey().RawCompressed().ToBytes()
    
    import hashlib
    sha256 = hashlib.sha256(pub_key_bytes).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    
    version_payload = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(version_payload).digest()).digest()[:4]
    
    raw_address = version_payload + checksum
    address = Base58Encoder.Encode(raw_address)
    
    print(f"Expected Address (Base58): {address}")
    print(f"Expected Hex (25 bytes): {binascii.hexlify(raw_address).decode()}")
    
    return address

if __name__ == "__main__":
    validate_cake_index_0()
