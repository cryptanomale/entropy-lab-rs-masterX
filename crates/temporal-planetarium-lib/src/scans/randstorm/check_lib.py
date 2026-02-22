import hashlib
print(f"Hashlib: {hashlib.sha256(b'abc').hexdigest()}")

import sim_sha
# Result from sim_sha should have been printed by import if I didn't change it, but I'll call transform
state = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
data = [0] * 16
data[0] = 0x61626380
data[15] = 24
sim_sha.transform(state, data)
print(f"SimSHA:  {''.join(format(x, '08x') for x in state)}")
