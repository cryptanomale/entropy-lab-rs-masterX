/// BitcoinJS v0.1.3 PRNG Implementation (ARC4 + Weak Math.random)
///
/// This module replicates the exact vulnerability in BitcoinJS v0.1.3 from 2011-2014.
/// The bug: `navigator.appVersion < "5"` fails in modern browsers because "5.0" is NOT
/// less than "5" in string comparison, causing fallback to weak Math.random().
use super::{BrowserVersion, MathRandomEngine, PrngEngine, PrngState, SeedComponents};

/// ARC4 cipher state (as used in BitcoinJS v0.1.3)
#[derive(Debug, Clone)]
pub struct Arc4 {
    i: u8,
    j: u8,
    s: [u8; 256],
}

impl Arc4 {
    /// Initialize ARC4 with key (entropy pool)
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

    /// Generate next pseudo-random byte
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

/// Weak Math.random() simulation for multiple historical engines
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
    /// Create PRNG seeded with timestamp (milliseconds)
    pub fn from_timestamp(
        engine: MathRandomEngine,
        timestamp_ms: u64,
        seed_override: Option<u64>,
    ) -> Self {
        let seed = seed_override.unwrap_or(timestamp_ms);
        // For engines that split into 32-bit parts, derive s1/s2 from seed.
        let s1 = (seed & 0xFFFF_FFFF) as u32; // low
        let s2 = (seed >> 32) as u32; // high
        let (xorshift_s0, xorshift_s1) = if engine == MathRandomEngine::XorShift128Plus {
            // Use splitmix64 to expand seed into 128 bits
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
        Self {
            engine,
            seed,
            s1,
            s2,
            xorshift_s0,
            xorshift_s1,
        }
    }

    /// Advance MWC1616 state and return next f64 in [0,1)
    pub fn next(&mut self) -> f64 {
        match self.engine {
            MathRandomEngine::V8Mwc1616 => {
                self.s1 = 18_000_u32.wrapping_mul(self.s1 & 0xFFFF) + (self.s1 >> 16);
                self.s2 = 30_903_u32.wrapping_mul(self.s2 & 0xFFFF) + (self.s2 >> 16);
                let combined: u32 = (((self.s1 as u64) << 16) + (self.s2 as u64)) as u32;
                (combined as f64) / 4_294_967_296.0 // 2^32
            }
            MathRandomEngine::Drand48 | MathRandomEngine::JavaUtil => {
                // 48-bit LCG
                const MULT: u64 = 25_214_903_917;
                const INC: u64 = 11;
                const MASK: u64 = (1u64 << 48) - 1;
                self.seed = (self.seed.wrapping_mul(MULT).wrapping_add(INC)) & MASK;
                (self.seed as f64) / 281_474_976_710_656.0 // 2^48
            }
            MathRandomEngine::XorShift128Plus => {
                // Standard xorshift128+; output 64-bit then scale
                let mut s1 = self.xorshift_s0;
                let s0 = self.xorshift_s1;
                self.xorshift_s0 = s0;
                s1 ^= s1 << 23;
                self.xorshift_s1 = s1 ^ s0 ^ (s1 >> 17) ^ (s0 >> 26);
                let result = self.xorshift_s1.wrapping_add(s0);
                ((result >> 11) as f64) / (1u64 << 53) as f64
            }
            MathRandomEngine::SpiderMonkeyLcg => {
                // SpiderMonkey Math.random historically used xorshift128+ (similar to SM 31/32 era)
                let mut s1 = self.xorshift_s0;
                let s0 = self.xorshift_s1;
                self.xorshift_s0 = s0;
                s1 ^= s1 << 23;
                self.xorshift_s1 = s1 ^ s0 ^ (s1 >> 17) ^ (s0 >> 26);
                let result = self.xorshift_s1.wrapping_add(s0);
                ((result >> 11) as f64) / (1u64 << 53) as f64
            }
            MathRandomEngine::Jsc => {
                // WebKit JSC historically used a 48-bit LCG with 53-bit output
                const MULT: u64 = 0x5DEECE66D;
                const INC: u64 = 0xB;
                const MASK: u64 = (1u64 << 48) - 1;
                self.seed = (self.seed.wrapping_mul(MULT).wrapping_add(INC)) & MASK;
                let high = self.seed >> 22; // 26 bits
                self.seed = (self.seed.wrapping_mul(MULT).wrapping_add(INC)) & MASK;
                let low = self.seed >> 21; // 27 bits
                let val = ((high << 27) | low) as f64;
                val / ((1u64 << 53) as f64)
            }
            MathRandomEngine::IeChakraLcg => {
                // IE Chakra uses identical algorithm to Firefox (Java-derived LCG)
                const MULT: u64 = 0x5DEECE66D;
                const INC: u64 = 11;
                const MASK: u64 = (1u64 << 48) - 1;
                self.seed = (self.seed.wrapping_mul(MULT).wrapping_add(INC)) & MASK;
                (self.seed as f64) / 281_474_976_710_656.0
            }
            MathRandomEngine::SafariWindowsCrt => {
                // Safari Windows uses MSVC CRT rand() - two 15-bit values combined
                const MULT: u32 = 214013;
                const ADD: u32 = 2531011;
                let s = self.s1.wrapping_mul(MULT).wrapping_add(ADD);
                let r1 = (s >> 16) & 0x7FFF;
                self.s1 = s;
                let s = self.s1.wrapping_mul(MULT).wrapping_add(ADD);
                let r2 = (s >> 16) & 0x7FFF;
                self.s1 = s;
                let combined = (r1 << 15) | r2;
                combined as f64 / 1073741824.0
            }
        }
    }

    /// Return the upper 16 bits as integer (Math.floor(65536 * Math.random()))
    pub fn next_u16(&mut self) -> u16 {
        match self.engine {
            MathRandomEngine::V8Mwc1616 => {
                self.s1 = 18_000_u32.wrapping_mul(self.s1 & 0xFFFF) + (self.s1 >> 16);
                self.s2 = 30_903_u32.wrapping_mul(self.s2 & 0xFFFF) + (self.s2 >> 16);
                ((((self.s1 as u64) << 16) + (self.s2 as u64)) >> 16) as u16
            }
            MathRandomEngine::Drand48 => {
                const MULT: u64 = 25_214_903_917;
                const INC: u64 = 11;
                const MASK: u64 = (1u64 << 48) - 1;
                self.seed = (self.seed.wrapping_mul(MULT).wrapping_add(INC)) & MASK;
                (self.seed >> 32) as u16
            }
            MathRandomEngine::JavaUtil => {
                // java.util.Random: next(32) twice to build 53-bit double
                const MULT: u64 = 0x5DEECE66D;
                const INC: u64 = 0xB;
                const MASK: u64 = (1u64 << 48) - 1;
                // next(32)
                self.seed = (self.seed.wrapping_mul(MULT).wrapping_add(INC)) & MASK;
                let high = self.seed >> 16;
                self.seed = (self.seed.wrapping_mul(MULT).wrapping_add(INC)) & MASK;
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
            MathRandomEngine::SpiderMonkeyLcg => {
                // Firefox SpiderMonkey used Java LCG (48-bit)
                const MULT: u64 = 0x5DEECE66D;
                const INC: u64 = 0xB;
                const MASK: u64 = (1u64 << 48) - 1;
                self.seed = (self.seed.wrapping_mul(MULT).wrapping_add(INC)) & MASK;
                (self.seed >> 16) as u16
            }
            MathRandomEngine::Jsc => {
                const MULT: u64 = 0x5DEECE66D;
                const INC: u64 = 0xB;
                const MASK: u64 = (1u64 << 48) - 1;
                self.seed = (self.seed.wrapping_mul(MULT).wrapping_add(INC)) & MASK;
                (self.seed >> 16) as u16
            }
            MathRandomEngine::IeChakraLcg => {
                // IE Chakra uses identical algorithm to Firefox (Java-derived LCG)
                const MULT: u64 = 0x5DEECE66D;
                const INC: u64 = 11;
                const MASK: u64 = (1u64 << 48) - 1;
                self.seed = (self.seed.wrapping_mul(MULT).wrapping_add(INC)) & MASK;
                (self.seed >> 16) as u16
            }
            MathRandomEngine::SafariWindowsCrt => {
                // Safari Windows uses MSVC CRT rand() - two 15-bit values combined
                const MULT: u32 = 214013;
                const ADD: u32 = 2531011;
                let s = self.s1.wrapping_mul(MULT).wrapping_add(ADD);
                let r1 = (s >> 16) & 0x7FFF;
                self.s1 = s;
                let s = self.s1.wrapping_mul(MULT).wrapping_add(ADD);
                let r2 = (s >> 16) & 0x7FFF;
                self.s1 = s;
                let combined = (r1 << 15) | r2;
                (combined >> 14) as u16
            }
        }
    }

    /// Generate random bytes (as BitcoinJS randomBytes does)
    pub fn random_bytes(&mut self, count: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(count);
        for _ in 0..count {
            let rand_val = (self.next() * 256.0).floor() as u8;
            bytes.push(rand_val);
        }
        bytes
    }
}

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

    /// Generate entropy pool exactly as BitcoinJS v0.1.3 does
    pub fn generate_entropy_pool_with_engine(
        timestamp_ms: u64,
        engine: MathRandomEngine,
        seed_override: Option<u64>,
    ) -> Vec<u8> {
        let mut pool = vec![0u8; 256];
        let mut prng = WeakMathRandom::from_timestamp(engine, timestamp_ms, seed_override);
        let mut ptr = 0usize;

        // STEP 1: Fill pool with weak Math.random() (the bug - no crypto.random)
        while ptr < 256 {
            let rand16 = prng.next_u16();
            pool[ptr] = (rand16 >> 8) as u8; // high byte
            ptr += 1;
            if ptr < 256 {
                pool[ptr] = (rand16 & 0xFF) as u8; // low byte
                ptr += 1;
            }
        }
        
        if timestamp_ms == 1365000000000 {
            println!("RUST PRE-XOR POOL (0-7): {:02x?}", &pool[0..8]);
        }

        // STEP 2: XOR timestamp (low 32 bits) into first 4 bytes (rng_seed_time)
        let ts32 = timestamp_ms as u32;
        if timestamp_ms == 0x12345678 {
            println!("RUST XOR MASK: {:08x} bytes: [{:02x}, {:02x}, {:02x}, {:02x}]", 
                ts32, (ts32 & 0xFF), (ts32 >> 8 & 0xFF), (ts32 >> 16 & 0xFF), (ts32 >> 24 & 0xFF));
        }
        pool[0] ^= (ts32 & 0xFF) as u8;
        pool[1] ^= ((ts32 >> 8) & 0xFF) as u8;
        pool[2] ^= ((ts32 >> 16) & 0xFF) as u8;
        pool[3] ^= ((ts32 >> 24) & 0xFF) as u8;
        
        if timestamp_ms == 0x12345678 {
            println!("RUST POST-XOR POOL (0-7): {:02x?}", &pool[0..8]);
        }

        pool
    }

    /// Backward-compatible helper using the default V8 MWC engine
    pub fn generate_entropy_pool(timestamp_ms: u64) -> Vec<u8> {
        Self::generate_entropy_pool_with_engine(timestamp_ms, MathRandomEngine::V8Mwc1616, None)
    }

    /// Generate private key bytes with configurable engine/seed
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
        // For BitcoinJS, the state is derived from timestamp only
        // (This is the vulnerability - insufficient entropy sources)
        let timestamp_ms = seed.timestamp_ms;

        // Generate entropy pool
        let _pool = Self::generate_entropy_pool(timestamp_ms);

        // Return minimal state (just timestamp for reproduction)
        PrngState {
            s1: (timestamp_ms & 0xFFFF_FFFF) as u32, // low
            s2: (timestamp_ms >> 32) as u32,         // high
        }
    }

    fn generate_bytes(&self, state: &PrngState, count: usize) -> Vec<u8> {
        // Reconstruct timestamp from state
        let timestamp_ms = ((state.s2 as u64) << 32) | (state.s1 as u64);

        // Generate entropy pool
        let entropy_pool = Self::generate_entropy_pool(timestamp_ms);

        // Initialize ARC4 with entropy pool
        let mut arc4 = Arc4::new(&entropy_pool);

        // Generate bytes
        let mut bytes = vec![0u8; count];
        arc4.fill_bytes(&mut bytes);

        bytes
    }

    fn applicable_to(&self) -> &[BrowserVersion] {
        &self.versions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weak_prng_deterministic() {
        let mut prng1 =
            WeakMathRandom::from_timestamp(MathRandomEngine::V8Mwc1616, 1389781850000, None);
        let mut prng2 =
            WeakMathRandom::from_timestamp(MathRandomEngine::V8Mwc1616, 1389781850000, None);

        // Same seed should produce same sequence
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
        let pool1 = BitcoinJsV013Prng::generate_entropy_pool(1389781850000);
        let pool2 = BitcoinJsV013Prng::generate_entropy_pool(1389781850000);

        assert_eq!(pool1, pool2);
        assert_eq!(pool1.len(), 256);
    }

    #[test]
    fn test_bitcoinjs_prng_engine() {
        let prng = BitcoinJsV013Prng::new();

        let seed = SeedComponents {
            timestamp_ms: 1389781850000,
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

        // Same state should produce same output
        assert_eq!(bytes1, bytes2);
        assert_eq!(bytes1.len(), 32);
    }

    #[test]
    fn test_known_test_vector() {
        let timestamp_ms = 1389781850000;
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
