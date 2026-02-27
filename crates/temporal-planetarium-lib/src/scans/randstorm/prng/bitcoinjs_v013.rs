/// BitcoinJS v0.1.3 PRNG Implementation (ARC4 + Weak Math.random)
///
/// Replicates the exact vulnerability in BitcoinJS v0.1.3 (2011-2014).
/// Bug: `navigator.appVersion < "5"` always fails in modern browsers
/// (string compare "5.0" < "5" is false), causing fallback to weak Math.random().
use super::{BrowserVersion, MathRandomEngine, PrngEngine, PrngState, SeedComponents};

// ─── ARC4 ─────────────────────────────────────────────────────────────────────

/// ARC4 cipher state (as used in BitcoinJS v0.1.3 SecureRandom pool)
#[derive(Debug, Clone)]
pub struct Arc4 {
    i: u8,
    j: u8,
    s: [u8; 256],
}

impl Arc4 {
    /// Initialise ARC4 with an entropy pool (KSA phase)
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for i in 0..256 {
            s[i] = i as u8;
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Arc4 { i: 0, j: 0, s }
    }

    /// PRGA: generate next pseudo-random byte
    pub fn next(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s[self.i as usize]);
        self.s.swap(self.i as usize, self.j as usize);
        let k = self.s[self.i as usize].wrapping_add(self.s[self.j as usize]);
        self.s[k as usize]
    }

    /// Fill buffer with pseudo-random bytes
    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            *byte = self.next();
        }
    }
}

// ─── WeakMathRandom ───────────────────────────────────────────────────────────

/// Simulation of `Math.random()` across historical browser JS engines
#[derive(Debug, Clone)]
pub struct WeakMathRandom {
    engine: MathRandomEngine,
    seed: u64,
    s1: u32,
    s2: u32,
    xorshift_s0: u64,
    xorshift_s1: u64,
}

impl WeakMathRandom {
    /// Create PRNG seeded with a Unix timestamp in milliseconds
    pub fn from_timestamp(
        engine: MathRandomEngine,
        timestamp_ms: u64,
        seed_override: Option<u64>,
    ) -> Self {
        let seed = seed_override.unwrap_or(timestamp_ms);
        let s1 = (seed & 0xFFFF_FFFF) as u32; // low 32 bits
        let s2 = (seed >> 32) as u32;          // high 32 bits
        // FIX 1: SpiderMonkeyLcg also uses XorShift128+ algorithm in next(),
        // so it needs the same splitmix64 initialisation that XorShift128Plus uses.
        // Previously xorshift_s0/s1 were left as 0 for SpiderMonkeyLcg, producing
        // a degenerate (all-zero) PRNG output.
        let (xorshift_s0, xorshift_s1) = if engine == MathRandomEngine::XorShift128Plus
            || engine == MathRandomEngine::SpiderMonkeyLcg
        {
            fn splitmix64(mut x: u64) -> u64 {
                x = x.wrapping_add(0x9E3779B97F4A7C15);
                let mut z = x;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
                z ^ (z >> 31)
            }
            (
                splitmix64(seed),
                splitmix64(seed.wrapping_add(0x9E3779B97F4A7C15)),
            )
        } else {
            (0, 0)
        };
        Self { engine, seed, s1, s2, xorshift_s0, xorshift_s1 }
    }

    /// Advance PRNG and return next `Math.random()` value in [0, 1)
    pub fn next(&mut self) -> f64 {
        match self.engine {
            MathRandomEngine::V8Mwc1616 => {
                self.s1 = 18_000_u32.wrapping_mul(self.s1 & 0xFFFF).wrapping_add(self.s1 >> 16);
                self.s2 = 30_903_u32.wrapping_mul(self.s2 & 0xFFFF).wrapping_add(self.s2 >> 16);
                // combined must be computed in u32 to match JS 32-bit integer semantics:
                //   return ((s1 << 16) + s2) / 4294967296.0
                let combined = self.s1.wrapping_shl(16).wrapping_add(self.s2);
                (combined as f64) / 4_294_967_296.0
            }
            MathRandomEngine::Drand48 | MathRandomEngine::JavaUtil => {
                const MULT: u64 = 25_214_903_917;
                const INC: u64 = 11;
                const MASK: u64 = (1u64 << 48) - 1;
                self.seed = self.seed.wrapping_mul(MULT).wrapping_add(INC) & MASK;
                (self.seed as f64) / 281_474_976_710_656.0
            }
            MathRandomEngine::XorShift128Plus => {
                let mut s1 = self.xorshift_s0;
                let s0 = self.xorshift_s1;
                self.xorshift_s0 = s0;
                s1 ^= s1 << 23;
                self.xorshift_s1 = s1 ^ s0 ^ (s1 >> 17) ^ (s0 >> 26);
                let result = self.xorshift_s1.wrapping_add(s0);
                ((result >> 11) as f64) / (1u64 << 53) as f64
            }
            // SpiderMonkey 2011-2015 used XorShift128+.
            // Previously this arm was missing the seed initialisation (xorshift_s0/s1 were 0).
            // Fixed in from_timestamp() above — now both engines run splitmix64 init.
            MathRandomEngine::SpiderMonkeyLcg => {
                let mut s1 = self.xorshift_s0;
                let s0 = self.xorshift_s1;
                self.xorshift_s0 = s0;
                s1 ^= s1 << 23;
                self.xorshift_s1 = s1 ^ s0 ^ (s1 >> 17) ^ (s0 >> 26);
                let result = self.xorshift_s1.wrapping_add(s0);
                ((result >> 11) as f64) / (1u64 << 53) as f64
            }
            MathRandomEngine::Jsc => {
                const MULT: u64 = 0x5DEECE66D;
                const INC: u64 = 0xB;
                const MASK: u64 = (1u64 << 48) - 1;
                self.seed = self.seed.wrapping_mul(MULT).wrapping_add(INC) & MASK;
                let high = self.seed >> 22;
                self.seed = self.seed.wrapping_mul(MULT).wrapping_add(INC) & MASK;
                let low = self.seed >> 21;
                let val = ((high << 27) | low) as f64;
                val / ((1u64 << 53) as f64)
            }
            MathRandomEngine::IeChakraLcg => {
                const MULT: u64 = 0x5DEECE66D;
                const INC: u64 = 11;
                const MASK: u64 = (1u64 << 48) - 1;
                self.seed = self.seed.wrapping_mul(MULT).wrapping_add(INC) & MASK;
                (self.seed as f64) / 281_474_976_710_656.0
            }
            MathRandomEngine::SafariWindowsCrt => {
                const MULT: u32 = 214_013;
                const ADD: u32 = 2_531_011;
                self.s1 = self.s1.wrapping_mul(MULT).wrapping_add(ADD);
                let r1 = (self.s1 >> 16) & 0x7FFF;
                self.s1 = self.s1.wrapping_mul(MULT).wrapping_add(ADD);
                let r2 = (self.s1 >> 16) & 0x7FFF;
                let combined = (r1 << 15) | r2;
                combined as f64 / 1_073_741_824.0
            }
        }
    }

    /// Equivalent to `Math.floor(65536 * Math.random())` — the value BitcoinJS
    /// uses to fill each 2-byte chunk of the entropy pool.
    ///
    /// # Critical fix (V8Mwc1616)
    ///
    /// The combined value MUST be truncated to u32 before the right-shift.
    /// JS `<<` converts operands to Int32 (32-bit), so upper bits of s1 are
    /// discarded during the shift — u64 arithmetic does NOT do this
    /// automatically and preserves those bits, producing wrong pool bytes.
    ///
    /// Wrong:   `((s1 as u64) << 16 + s2 as u64) >> 16` — upper bits of s1 leak
    /// Correct: `s1.wrapping_shl(16).wrapping_add(s2) >> 16` — matches JS
    ///
    /// # FIX 2 (IeChakraLcg)
    ///
    /// next() returns seed/2^48, so:
    ///   floor(next() * 65536) = floor(seed / 2^32) = seed >> 32
    /// Old code returned (seed >> 16) — wrong by 16 bits.
    ///
    /// # FIX 3 (Jsc)
    ///
    /// next() uses TWO LCG advances to build a 53-bit value.
    /// next_u16() must mirror that: two advances, then val53 >> 37.
    /// Old code did ONE advance and seed >> 16 — diverged from next().
    pub fn next_u16(&mut self) -> u16 {
        match self.engine {
            MathRandomEngine::V8Mwc1616 => {
                self.s1 = 18_000_u32.wrapping_mul(self.s1 & 0xFFFF).wrapping_add(self.s1 >> 16);
                self.s2 = 30_903_u32.wrapping_mul(self.s2 & 0xFFFF).wrapping_add(self.s2 >> 16);
                // ✅ Truncate to u32 FIRST, then shift — mirrors JS 32-bit integer arithmetic.
                let combined: u32 = self.s1.wrapping_shl(16).wrapping_add(self.s2);
                (combined >> 16) as u16
            }
            MathRandomEngine::Drand48 => {
                const MULT: u64 = 25_214_903_917;
                const INC: u64 = 11;
                const MASK: u64 = (1u64 << 48) - 1;
                self.seed = self.seed.wrapping_mul(MULT).wrapping_add(INC) & MASK;
                (self.seed >> 32) as u16
            }
            MathRandomEngine::JavaUtil => {
                const MULT: u64 = 0x5DEECE66D;
                const INC: u64 = 0xB;
                const MASK: u64 = (1u64 << 48) - 1;
                self.seed = self.seed.wrapping_mul(MULT).wrapping_add(INC) & MASK;
                let high = self.seed >> 16;
                self.seed = self.seed.wrapping_mul(MULT).wrapping_add(INC) & MASK;
                let low = self.seed >> 16;
                let bits26 = (high >> 6) & 0x3FF_FFFF;
                let bits27 = low >> 5;
                let val = ((bits26 << 27) | bits27) as f64;
                (val / ((1u64 << 53) as f64) * 65536.0).floor() as u16
            }
            MathRandomEngine::XorShift128Plus => {
                let mut s1 = self.xorshift_s0;
                let s0 = self.xorshift_s1;
                self.xorshift_s0 = s0;
                s1 ^= s1 << 23;
                self.xorshift_s1 = s1 ^ s0 ^ (s1 >> 17) ^ (s0 >> 26);
                let result = self.xorshift_s1.wrapping_add(s0);
                (result >> 48) as u16
            }
            // SpiderMonkeyLcg next_u16 mirrors next() — XorShift128+.
            // floor(((result>>11)/2^42) * 65536) = result >> 48
            MathRandomEngine::SpiderMonkeyLcg => {
                let mut s1 = self.xorshift_s0;
                let s0 = self.xorshift_s1;
                self.xorshift_s0 = s0;
                s1 ^= s1 << 23;
                self.xorshift_s1 = s1 ^ s0 ^ (s1 >> 17) ^ (s0 >> 26);
                let result = self.xorshift_s1.wrapping_add(s0);
                // floor(next()*65536): (result>>11)/2^42 * 2^16 = result >> 48
                (result >> 48) as u16
            }
            // FIX 3: TWO LCG advances, matching next() for Jsc.
            // floor(val53 / 2^53 * 65536) = val53 >> 37
            MathRandomEngine::Jsc => {
                const MULT: u64 = 0x5DEECE66D;
                const INC: u64 = 0xB;
                const MASK: u64 = (1u64 << 48) - 1;
                self.seed = self.seed.wrapping_mul(MULT).wrapping_add(INC) & MASK;
                let high = self.seed >> 22; // 26 bits
                self.seed = self.seed.wrapping_mul(MULT).wrapping_add(INC) & MASK;
                let low = self.seed >> 21;  // 27 bits
                let val53 = (high << 27) | low; // 53-bit integer
                // floor(val53 / 2^53 * 65536) = floor(val53 / 2^37) = val53 >> 37
                (val53 >> 37) as u16
            }
            // FIX 2: seed>>32 instead of seed>>16.
            // next() = seed/2^48; floor(next()*65536) = floor(seed/2^32) = seed>>32.
            MathRandomEngine::IeChakraLcg => {
                const MULT: u64 = 0x5DEECE66D;
                const INC: u64 = 11;
                const MASK: u64 = (1u64 << 48) - 1;
                self.seed = self.seed.wrapping_mul(MULT).wrapping_add(INC) & MASK;
                (self.seed >> 32) as u16
            }
            MathRandomEngine::SafariWindowsCrt => {
                const MULT: u32 = 214_013;
                const ADD: u32 = 2_531_011;
                self.s1 = self.s1.wrapping_mul(MULT).wrapping_add(ADD);
                let r1 = (self.s1 >> 16) & 0x7FFF;
                self.s1 = self.s1.wrapping_mul(MULT).wrapping_add(ADD);
                let r2 = (self.s1 >> 16) & 0x7FFF;
                let combined = (r1 << 15) | r2;
                (combined >> 14) as u16
            }
        }
    }

    /// Generate random bytes as `Math.floor(256 * Math.random())` per byte
    pub fn random_bytes(&mut self, count: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(count);
        for _ in 0..count {
            let rand_val = (self.next() * 256.0).floor() as u8;
            bytes.push(rand_val);
        }
        bytes
    }
}

// ─── BitcoinJsV013Prng ────────────────────────────────────────────────────────

/// BitcoinJS v0.1.3 PRNG (vulnerable implementation)
pub struct BitcoinJsV013Prng {
    versions: Vec<BrowserVersion>,
}

impl BitcoinJsV013Prng {
    pub fn new() -> Self {
        Self {
            versions: vec![
                BrowserVersion::new("Chrome", 5..=45),
                BrowserVersion::new("Firefox", 4..=35),
                BrowserVersion::new("Safari", 5..=8),
                BrowserVersion::new("Opera", 11..=30),
                BrowserVersion::new("IE", 9..=11),
            ],
        }
    }

    /// Reconstruct the 256-byte entropy pool exactly as BitcoinJS v0.1.3 does:
    ///   1. Fill pool[0..256] with pairs of bytes from `Math.floor(65536 * Math.random())`
    ///   2. XOR the low 32 bits of `timestamp_ms` into pool[0..4] (`rng_seed_time`)
    pub fn generate_entropy_pool_with_engine(
        timestamp_ms: u64,
        engine: MathRandomEngine,
        seed_override: Option<u64>,
    ) -> Vec<u8> {
        let mut pool = vec![0u8; 256];
        let mut prng = WeakMathRandom::from_timestamp(engine, timestamp_ms, seed_override);
        let mut ptr = 0usize;

        // Step 1: fill pool with weak Math.random() output (the vulnerability)
        while ptr < 256 {
            let rand16 = prng.next_u16();
            pool[ptr] = (rand16 >> 8) as u8;
            ptr += 1;
            if ptr < 256 {
                pool[ptr] = (rand16 & 0xFF) as u8;
                ptr += 1;
            }
        }

        // Step 2: XOR timestamp low 32 bits into pool[0..4]
        let ts32 = timestamp_ms as u32;
        pool[0] ^= (ts32 & 0xFF) as u8;
        pool[1] ^= ((ts32 >> 8) & 0xFF) as u8;
        pool[2] ^= ((ts32 >> 16) & 0xFF) as u8;
        pool[3] ^= ((ts32 >> 24) & 0xFF) as u8;

        pool
    }

    /// Convenience wrapper using the default V8 MWC1616 engine
    pub fn generate_entropy_pool(timestamp_ms: u64) -> Vec<u8> {
        Self::generate_entropy_pool_with_engine(timestamp_ms, MathRandomEngine::V8Mwc1616, None)
    }

    /// Generate 32 private-key bytes for a given timestamp + engine
    pub fn generate_privkey_bytes(
        timestamp_ms: u64,
        engine: MathRandomEngine,
        seed_override: Option<u64>,
    ) -> [u8; 32] {
        let pool = Self::generate_entropy_pool_with_engine(timestamp_ms, engine, seed_override);
        let mut arc4 = Arc4::new(&pool);
        let mut priv_bytes = [0u8; 32];
        arc4.fill_bytes(&mut priv_bytes);
        priv_bytes
    }
}

impl Default for BitcoinJsV013Prng {
    fn default() -> Self {
        Self::new()
    }
}

impl PrngEngine for BitcoinJsV013Prng {
    fn generate_state(&self, seed: &SeedComponents) -> PrngState {
        let timestamp_ms = seed.timestamp_ms;
        let _pool = Self::generate_entropy_pool(timestamp_ms);
        PrngState {
            s1: (timestamp_ms & 0xFFFF_FFFF) as u32,
            s2: (timestamp_ms >> 32) as u32,
        }
    }

    fn generate_bytes(&self, state: &PrngState, count: usize) -> Vec<u8> {
        let timestamp_ms = ((state.s2 as u64) << 32) | (state.s1 as u64);
        let entropy_pool = Self::generate_entropy_pool(timestamp_ms);
        let mut arc4 = Arc4::new(&entropy_pool);
        let mut bytes = vec![0u8; count];
        arc4.fill_bytes(&mut bytes);
        bytes
    }

    fn applicable_to(&self) -> &[BrowserVersion] {
        &self.versions
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weak_prng_deterministic() {
        let mut prng1 =
            WeakMathRandom::from_timestamp(MathRandomEngine::V8Mwc1616, 1_389_781_850_000, None);
        let mut prng2 =
            WeakMathRandom::from_timestamp(MathRandomEngine::V8Mwc1616, 1_389_781_850_000, None);
        assert_eq!(prng1.next(), prng2.next());
        assert_eq!(prng1.next(), prng2.next());
        assert_eq!(prng1.next(), prng2.next());
    }

    #[test]
    fn test_arc4_deterministic() {
        let key = b"test_key";
        let mut arc1 = Arc4::new(key);
        let mut arc2 = Arc4::new(key);
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        arc1.fill_bytes(&mut buf1);
        arc2.fill_bytes(&mut buf2);
        assert_eq!(buf1, buf2);
    }

    #[test]
    fn test_entropy_pool_deterministic() {
        let pool1 = BitcoinJsV013Prng::generate_entropy_pool(1_389_781_850_000);
        let pool2 = BitcoinJsV013Prng::generate_entropy_pool(1_389_781_850_000);
        assert_eq!(pool1, pool2);
        assert_eq!(pool1.len(), 256);
    }

    /// next_u16() must equal Math.floor(65536 * Math.random()) for V8Mwc1616.
    #[test]
    fn test_next_u16_consistent_with_next_v8() {
        let seed = 1_389_781_850_000u64;
        let mut prng_f =
            WeakMathRandom::from_timestamp(MathRandomEngine::V8Mwc1616, seed, None);
        let mut prng_u =
            WeakMathRandom::from_timestamp(MathRandomEngine::V8Mwc1616, seed, None);
        for _ in 0..128 {
            let f_val = prng_f.next();
            let u_val = prng_u.next_u16();
            let expected = (f_val * 65536.0).floor() as u16;
            assert_eq!(
                u_val, expected,
                "next_u16() must match Math.floor(65536 * Math.random()) for V8Mwc1616"
            );
        }
    }

    /// FIX 2 regression: IeChakraLcg next_u16 must match floor(next()*65536).
    #[test]
    fn test_next_u16_consistent_with_next_ie_chakra() {
        let seed = 1_389_781_850_000u64;
        let mut prng_f =
            WeakMathRandom::from_timestamp(MathRandomEngine::IeChakraLcg, seed, None);
        let mut prng_u =
            WeakMathRandom::from_timestamp(MathRandomEngine::IeChakraLcg, seed, None);
        for _ in 0..128 {
            let f_val = prng_f.next();
            let u_val = prng_u.next_u16();
            let expected = (f_val * 65536.0).floor() as u16;
            assert_eq!(
                u_val, expected,
                "next_u16() must match Math.floor(65536 * Math.random()) for IeChakraLcg"
            );
        }
    }

    /// FIX 3 regression: Jsc next_u16 must match floor(next()*65536).
    #[test]
    fn test_next_u16_consistent_with_next_jsc() {
        let seed = 1_389_781_850_000u64;
        let mut prng_f =
            WeakMathRandom::from_timestamp(MathRandomEngine::Jsc, seed, None);
        let mut prng_u =
            WeakMathRandom::from_timestamp(MathRandomEngine::Jsc, seed, None);
        for _ in 0..128 {
            let f_val = prng_f.next();
            let u_val = prng_u.next_u16();
            let expected = (f_val * 65536.0).floor() as u16;
            assert_eq!(
                u_val, expected,
                "next_u16() must match Math.floor(65536 * Math.random()) for Jsc"
            );
        }
    }

    /// FIX 1 regression: SpiderMonkeyLcg next_u16 must match floor(next()*65536).
    #[test]
    fn test_next_u16_consistent_with_next_spidermonkey() {
        let seed = 1_389_781_850_000u64;
        let mut prng_f =
            WeakMathRandom::from_timestamp(MathRandomEngine::SpiderMonkeyLcg, seed, None);
        let mut prng_u =
            WeakMathRandom::from_timestamp(MathRandomEngine::SpiderMonkeyLcg, seed, None);
        for _ in 0..128 {
            let f_val = prng_f.next();
            let u_val = prng_u.next_u16();
            let expected = (f_val * 65536.0).floor() as u16;
            assert_eq!(
                u_val, expected,
                "next_u16() must match Math.floor(65536 * Math.random()) for SpiderMonkeyLcg"
            );
        }
    }

    /// Regression: s1 with high bits set was the original bug trigger.
    #[test]
    fn test_next_u16_high_s1_bits() {
        let seed = 0x6F0E_6E10u64; // low 32 bits → s1, high → s2 = 0
        let mut prng = WeakMathRandom::from_timestamp(MathRandomEngine::V8Mwc1616, seed, None);
        let s1_init = 0x6F0E_6E10u32;
        let s2_init = 0u32;
        let s1n = 18_000u32.wrapping_mul(s1_init & 0xFFFF).wrapping_add(s1_init >> 16);
        let s2n = 30_903u32.wrapping_mul(s2_init & 0xFFFF).wrapping_add(s2_init >> 16);
        let combined: u32 = s1n.wrapping_shl(16).wrapping_add(s2n);
        let expected = (combined >> 16) as u16;
        assert_eq!(prng.next_u16(), expected);
    }

    #[test]
    fn test_bitcoinjs_prng_engine() {
        let prng = BitcoinJsV013Prng::new();
        let seed = SeedComponents {
            timestamp_ms: 1_389_781_850_000,
            user_agent: "Mozilla/5.0".to_string(),
            screen_width: 1920,
            screen_height: 1080,
            color_depth: 24,
            timezone_offset: 0,
            language: "en-US".to_string(),
            platform: "Win32".to_string(),
        };
        let state = prng.generate_state(&seed);
        let bytes1 = prng.generate_bytes(&state, 32);
        let bytes2 = prng.generate_bytes(&state, 32);
        assert_eq!(bytes1, bytes2);
        assert_eq!(bytes1.len(), 32);
    }

    #[test]
    fn test_known_test_vector() {
        let timestamp_ms = 1_389_781_850_000;
        let expected_pool32 = "c31bd379e0304e75edd7eb3075cc421024b66e2259f36e99c27262bba0cf8007";
        let expected_priv32 = "8459259a725f3e05f777dd419c65d816ab58ea1978132a09779f9cad70cf44b7";
        let pool = BitcoinJsV013Prng::generate_entropy_pool(timestamp_ms);
        assert_eq!(hex::encode(&pool[..32]), expected_pool32);
        let mut arc4 = Arc4::new(&pool);
        let mut privkey_bytes = [0u8; 32];
        arc4.fill_bytes(&mut privkey_bytes);
        assert_eq!(hex::encode(privkey_bytes), expected_priv32);
    }
}
