# Randstorm Vulnerable Code - Exact Extraction from BitcoinJS v0.1.3

## Source: Real Disclosure Data
**From:** BitcoinJS-lib v0.1.3 (https://cdnjs.cloudflare.com/ajax/libs/bitcoinjs-lib/0.1.3/bitcoinjs-min.js)  
**Vulnerability Period:** 2011-2015  
**Disclosure:** Unciphered "Randstorm" (November 2023)  
**Original Alert:** "Ketamine" bitcoin-dev mailing list (April 6, 2018)

---

## The Vulnerable Function: `SecureRandom()`

### Location in Source
The critical flaw is in the entropy collection section of the JSBN library's `SecureRandom()` implementation.

### Exact Vulnerable Code (Deobfuscated)

```javascript
function SecureRandom() {}

var rng_state, rng_pool, rng_pptr;

if (rng_pool == null) {
    rng_pool = new Array;
    rng_pptr = 0;
    var t;
    
    // VULNERABILITY #1: Type comparison error
    if (navigator.appName == "Netscape" && navigator.appVersion < "5" && window.crypto) {
        var z = window.crypto.random(32);
        for (t = 0; t < z.length; ++t)
            rng_pool[rng_pptr++] = z.charCodeAt(t) & 255;
    }
    
    // VULNERABILITY #2: Fallback to Math.random() (weak PRNG)
    while (rng_pptr < rng_psize) {
        t = Math.floor(65536 * Math.random());
        rng_pool[rng_pptr++] = t >>> 8;
        rng_pool[rng_pptr++] = t & 255;
    }
    
    rng_pptr = 0;
    rng_seed_time();
}

SecureRandom.prototype.nextBytes = rng_get_bytes;
```

---

## The Two Critical Flaws

### Flaw #1: String Comparison Type Error

```javascript
if (navigator.appName == "Netscape" && navigator.appVersion < "5" && window.crypto) {
```

**The Problem:**
- `navigator.appVersion` returns a **string** (e.g., "5.0")
- JavaScript's `<` operator on strings does **lexicographic comparison**, not numeric
- `"5.0" < "5"` evaluates to **false** (should be true)
- **Result:** Modern browsers (appVersion "5.0") **skip the secure entropy source**

**As Mustafa Al-Bassam ("tflow") noted:**
> "The real issue is that modern browsers don't have `window.crypto.Randomly` defined, so Bitcoin wallets using a pre-2013 version of jsbn may not be using a CSPRNG when run on a modern browser."

### Flaw #2: Math.random() Fallback (Weak Entropy)

```javascript
while (rng_pptr < rng_psize) {
    t = Math.floor(65536 * Math.random());
    rng_pool[rng_pptr++] = t >>> 8;
    rng_pool[rng_pptr++] = t & 255;
}
```

**The Problem:**
- `Math.random()` in browsers (2011-2015) was a **48-bit Linear Congruential Generator (LCG)**
- Seeded with **current time** in milliseconds
- Effective entropy: **~48 bits** (not 256 bits required for secure keys)
- Predictable state can be brute-forced

**From "Ketamine's" disclosure:**
> "Entropy is subsequently gathered from Math.random (a 48-bit linear congruential generator, seeded by the time in some browsers), and a single execution of a medium resolution timer. In some known configurations this system has substantially less than 48 bits of entropy."

---

## Attack Vector: Private Key Generation

### How Bitcoin Private Keys Were Generated

```javascript
// ECKey generation (simplified)
Bitcoin.ECKey = function(priv) {
    if (!priv) {
        var n = secp256k1.getN(); // Curve order
        this.priv = ECDSA.getBigRandom(n); // Uses SecureRandom!
    }
    // ...
}

// getBigRandom uses the vulnerable RNG
getBigRandom: function(max) {
    return (new BigInteger(max.bitLength(), securerandom_instance))
        .mod(max.subtract(BigInteger.ONE))
        .add(BigInteger.ONE);
}
```

**Attack Flow:**
1. User generates wallet in browser (2011-2015)
2. `SecureRandom()` initializes with weak Math.random()
3. Private key generated from ~48 bits of entropy (not 256)
4. Attacker brute-forces timestamp + Math.random() state
5. Derives same private key → steals funds

---

## Real-World Test Vector Requirements

### What You Need to Recreate the Vulnerability

To test your Randstorm scanner, you need:

1. **Browser Fingerprint** (timestamp, user agent, screen resolution)
2. **Timestamp Range** (when wallet was created, ±1 hour)
3. **Math.random() Implementation** (browser-specific LCG)
4. **Target Address** (known vulnerable wallet address)

### Generating Test Vectors

```javascript
// Pseudocode for recreating vulnerable keys
function generateVulnerableKey(timestamp, browserSeed) {
    // Seed Math.random() with timestamp
    let prngState = initMathRandom(timestamp, browserSeed);
    
    // Fill entropy pool (256 bytes)
    let rngPool = new Array(256);
    for (let i = 0; i < 256; i += 2) {
        let t = Math.floor(65536 * mathRandom(prngState));
        rngPool[i] = t >>> 8;
        rngPool[i+1] = t & 255;
    }
    
    // Initialize ARC4 cipher with weak pool
    let arc4 = new Arcfour();
    arc4.init(rngPool);
    
    // Generate "random" bytes for private key
    let privKeyBytes = new Array(32);
    for (let i = 0; i < 32; i++) {
        privKeyBytes[i] = arc4.next();
    }
    
    // Convert to BigInteger and derive address
    let privKey = BigInteger.fromByteArrayUnsigned(privKeyBytes);
    let pubKey = secp256k1.G.multiply(privKey);
    let address = pubKeyToAddress(pubKey);
    
    return { privKey, address };
}
```

---

## Known Vulnerable Platforms

### Confirmed Affected Projects
1. **Blockchain.info** (now Blockchain.com) - legacy wallets
2. **Dogechain.info** - Dogecoin web wallets
3. **Litecoin web wallets** - various
4. **Custom BitcoinJS implementations** - unknown count

### Wallet Generation Timeline
- **2011-March 2014:** BitcoinJS used vulnerable JSBN library
- **April 2018:** "Ketamine" publicly disclosed the flaw
- **November 2023:** Unciphered weaponized the exploit ("Randstorm")

---

## Test Vector Recommendations for Your Scanner

### Option A: Generate Synthetic Test Vectors
1. Pick known timestamp (e.g., `1420070400000` - Jan 1, 2015 00:00:00 UTC)
2. Use Chrome V8's Math.random() implementation from 2015
3. Generate 1,000 addresses with timestamp ±1 hour
4. Fund one test address with minimal BTC
5. Verify your scanner finds it

### Option B: Use Unciphered's Lookup Tool
- Visit **keybleed.com** (Unciphered's official checker)
- They maintain the database of vulnerable addresses
- No public API, but you can manually test addresses

### Option C: Request Test Vectors from Disclosure
- Contact Unciphered directly
- Explain you're building a security scanner
- Request sanitized test vectors (addresses only, no private keys)

---

## Critical Code Comparison: Before vs. After Fix

### Vulnerable Version (0.1.3 - March 2014)
```javascript
if (navigator.appName == "Netscape" && navigator.appVersion < "5" && window.crypto) {
    // Secure entropy (never executed in modern browsers)
}
while (rng_pptr < rng_psize) {
    t = Math.floor(65536 * Math.random()); // WEAK!
}
```

### Fixed Version (Post-March 2014)
```javascript
// Proper use of window.crypto.getRandomValues()
if (window.crypto && window.crypto.getRandomValues) {
    var cryptoArray = new Uint8Array(256);
    window.crypto.getRandomValues(cryptoArray);
    for (var i = 0; i < cryptoArray.length; i++) {
        rng_pool[rng_pptr++] = cryptoArray[i];
    }
}
```

---

## Next Steps for Your Implementation

### For Story 1.8 (CPU Fallback Scanner)

You now have the **exact vulnerable code**. Your scanner needs to:

1. **Replicate Math.random() LCG** for each browser (Chrome V8, Firefox SpiderMonkey, Safari JavaScriptCore)
2. **Enumerate timestamps** in the vulnerability window (2011-2015)
3. **Derive keys using the vulnerable SecureRandom() logic**
4. **Check against target address list**

### Critical Implementation Detail

The ARC4 cipher is seeded with the weak entropy pool:
```javascript
function ARC4init(key) {
    for (t = 0; t < 256; ++t) this.S[t] = t;
    n = 0;
    for (t = 0; t < 256; ++t) {
        n = (n + this.S[t] + key[t % key.length]) & 255;
        r = this.S[t];
        this.S[t] = this.S[n];
        this.S[n] = r;
    }
}
```

**Your scanner must:**
- Replicate this exact ARC4 initialization
- Use the weak rng_pool from Math.random()
- Generate private keys from the ARC4 stream

---

## Verification Checklist

- [ ] Extracted exact vulnerable SecureRandom() code
- [ ] Understood type comparison bug (appVersion < "5")
- [ ] Identified Math.random() LCG as entropy source
- [ ] Reviewed ARC4 seeding mechanism
- [ ] Know timeline: 2011-2015 vulnerability window
- [ ] Have list of affected platforms (Blockchain.info, etc.)
- [ ] Ready to implement browser-specific Math.random() replicas
- [ ] Can generate test vectors for validation

---

## References

1. **Original Disclosure:** "Ketamine" - bitcoin-dev mailing list (April 6, 2018)
2. **Weaponized Exploit:** Unciphered "Randstorm" disclosure (November 2023)
3. **Verification Tool:** https://keybleed.com
4. **Vulnerable Source:** BitcoinJS v0.1.3 (JSBN library SecureRandom)
5. **Mustafa Al-Bassam Comment:** bitcoin-dev mailing list thread

---

**Status:** Real vulnerability code extracted and documented.  
**Ready for:** CPU fallback scanner implementation (Story 1.8).  
**Next Action:** Implement browser-specific Math.random() LCG replication.
