#![cfg(feature = "z3-solver")]
//! Z3-based PRNG State Recovery for MWC1616
//!
//! Uses the Z3 theorem prover to recover the initial (s1, s2) state 
//! of the MWC1616 PRNG given 2 or more observed outputs.

use z3::ast::{Ast, BV};
use z3::{Config, Context, Solver};
use anyhow::{Result, Context as AnyhowContext};

/// Z3 Solver for MWC1616 state recovery
pub struct Z3MwcSolver {
    ctx: Context,
}

impl Z3MwcSolver {
    /// Create new Z3 solver instance
    pub fn new() -> Self {
        let mut cfg = Config::new();
        cfg.set_model_generation(true);
        let ctx = Context::new(&cfg);
        Self { ctx }
    }

    /// Recover state from two 32-bit PRNG outputs
    /// 
    /// MWC1616:
    /// s1 = 18000 * (s1 & 0xFFFF) + (s1 >> 16)
    /// s2 = 30903 * (s2 & 0xFFFF) + (s2 >> 16)
    /// result = (s1 << 16) + s2
    pub fn solve_from_outputs(&self, outputs: &[u32]) -> Result<(u32, u32)> {
        if outputs.len() < 2 {
            anyhow::bail!("At least 2 outputs are required to recover MWC1616 state");
        }

        let solver = Solver::new(&self.ctx);
        
        // Initial state variables (32rd order BV)
        let s1_0 = BV::new_const(&self.ctx, "s1_0", 32);
        let s2_0 = BV::new_const(&self.ctx, "s2_0", 32);
        
        // Non-zero constraint
        solver.assert(&s1_0.bveq(&BV::from_u64(&self.ctx, 0, 32)).not());
        solver.assert(&s2_0.bveq(&BV::from_u64(&self.ctx, 0, 32)).not());

        let mut curr_s1 = s1_0.clone();
        let mut curr_s2 = s2_0.clone();

        for &target_output in outputs {
            // Apply MWC1616 transformation
            // s1 = 18000 * (s1 & 0xFFFF) + (s1 >> 16)
            let s1_low = curr_s1.bvand(&BV::from_u64(&self.ctx, 0xFFFF, 32));
            let s1_high = curr_s1.bvlshr(&BV::from_u64(&self.ctx, 16, 32));
            let s1_next = s1_low.bvmul(&BV::from_u64(&self.ctx, 18000, 32)).bvadd(&s1_high);
            
            // s2 = 30903 * (s2 & 0xFFFF) + (s2 >> 16)
            let s2_low = curr_s2.bvand(&BV::from_u64(&self.ctx, 0xFFFF, 32));
            let s2_high = curr_s2.bvlshr(&BV::from_u64(&self.ctx, 16, 32));
            let s2_next = s2_low.bvmul(&BV::from_u64(&self.ctx, 30903, 32)).bvadd(&s2_high);
            
            // output = (s1 << 16) + s2
            let output = s1_next.bvshl(&BV::from_u64(&self.ctx, 16, 32)).bvadd(&s2_next);
            
            // Assert output matches target
            solver.assert(&output.bveq(&BV::from_u64(&self.ctx, target_output as u64, 32)));
            
            curr_s1 = s1_next;
            curr_s2 = s2_next;
        }

        if solver.check() == z3::SatResult::Sat {
            let model = solver.get_model().context("Failed to get model from Z3")?;
            let s1_val = model.eval(&s1_0, true).context("Failed to eval s1")?.as_u64().unwrap();
            let s2_val = model.eval(&s2_0, true).context("Failed to eval s2")?.as_u64().unwrap();
            
            Ok((s1_val as u32, s2_val as u32))
        } else {
            anyhow::bail!("No state found for given outputs (Unsat or Unknown)")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires Z3 library installed
    fn test_mwc_solver() -> Result<()> {
        let solver = Z3MwcSolver::new();
        
        // Generate test data
        let mut s1 = 0x12345678u32;
        let mut s2 = 0x87654321u32;
        
        let mut outputs = Vec::new();
        for _ in 0..2 {
            s1 = 18000 * (s1 & 0xFFFF) + (s1 >> 16);
            s2 = 30903 * (s2 & 0xFFFF) + (s2 >> 16);
            outputs.push((s1 << 16).wrapping_add(s2));
        }
        
        let (recovered_s1, recovered_s2) = solver.solve_from_outputs(&outputs)?;
        
        assert_eq!(recovered_s1, 0x12345678);
        assert_eq!(recovered_s2, 0x87654321);
        
        Ok(())
    }
}
