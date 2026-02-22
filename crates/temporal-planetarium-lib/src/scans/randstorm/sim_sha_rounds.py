def rotr(x, n):
    return ((x & 0xffffffff) >> n) | ((x << (32 - n)) & 0xffffffff)
def sigma0(x): return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
def sigma1(x): return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
def ch(x, y, z): return (x & y) ^ ((~x) & z)
def maj(x, y, z): return (x & y) ^ (x & z) ^ (y & z)

K0 = 0x428a2f98
W0 = 0x61626380
state = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
a, b, c, d, e, f, g, h = state
t1 = (h + sigma1(e) + ch(e, f, g) + K0 + W0) & 0xffffffff
t2 = (sigma0(a) + maj(a, b, c)) & 0xffffffff
h = g; g = f; f = e; e = (d + t1) & 0xffffffff; d = c; c = b; b = a; a = (t1 + t2) & 0xffffffff
print(f"Round 0 State: {a:08x} {b:08x} {c:08x} {d:08x} {e:08x} {f:08x} {g:08x} {h:08x}")
