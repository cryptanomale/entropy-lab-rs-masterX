/// Internet Explorer (Chakra) Historical PRNG (pre-2015)
/// Designated as a secondary Golden Reference for Randstorm.
/// Logic: 48-bit LCG identical to Java/SpiderMonkey.
pub struct ChakraLcg;

impl ChakraLcg {
    /// Generates the next state using the 48-bit LCG.
    pub fn next_state(state: &mut u64) -> u64 {
        const MASK: u64 = (1 << 48) - 1;
        *state = state.wrapping_mul(0x5DEECE66D).wrapping_add(0xB) & MASK;
        *state
    }

    /// Extracted value (comparable to Math.random() result)
    pub fn next_f64(state: &mut u64) -> f64 {
        let val = Self::next_state(state) >> 22; // Java nextInt(2^26) style
        let next_val = Self::next_state(state) >> 21; // Java nextInt(2^27) style
        ((val << 27) + next_val) as f64 / (1u64 << 53) as f64
    }
}

pub struct ChakraEngine {
    pub state: u64,
}

impl ChakraEngine {
    pub fn new(seed: u64) -> Self {
        // Seeding in Chakra/Java: (seed ^ 0x5DEECE66D) & ((1 << 48) - 1)
        Self { state: (seed ^ 0x5DEECE66D) & ((1 << 48) - 1) }
    }

    pub fn next_u32(&mut self) -> u32 {
        (ChakraLcg::next_state(&mut self.state) >> 16) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chakra_determinism() {
        // Matches standard Java LCG output for seed 12345
        let mut engine = ChakraEngine::new(12345);
        let val1 = engine.next_u32();
        assert_eq!(val1, 1553932502); // Standard Java nextInt() for this seed
    }
}
