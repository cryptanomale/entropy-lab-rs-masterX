//! Z3-based MWC1616 PRNG state recovery
//!
//! Recovers the initial `(s1_0, s2_0)` seed from observed PRNG outputs.
//!
//! Two observation modes:
//!
//! * [`Z3MwcSolver::solve_from_combined`] — inputs are full 32-bit values
//!   `s1.wrapping_shl(16).wrapping_add(s2)`. Use when raw combined integers
//!   are available.
//!
//! * [`Z3MwcSolver::solve_from_u16`] — inputs are the 16-bit values from
//!   `Math.floor(65536 * Math.random())`, i.e. `combined_u32 >> 16`.
//!   This matches exactly what fills the BitcoinJS entropy pool via `next_u16()`.
//!   Requires ≥ 4 observations (4 × 16 bits ≥ 2 × 32-bit unknowns).
//!
//! # Feature gate
//!
//! Compile with `--features z3-solver`. Without the feature a stub struct is
//! always exported that returns `Err` on every call, preventing the silent
//! compile-out that was the original missing-solution bug.

#[cfg(feature = "z3-solver")]
use z3::ast::{Ast, BV};
#[cfg(feature = "z3-solver")]
use z3::{Config, Context, Solver};
use anyhow::{Context as AnyhowContext, Result};

// ─── Public struct ────────────────────────────────────────────────────────────

/// Z3 theorem-prover solver for MWC1616 state recovery.
///
/// When the `z3-solver` feature is **disabled**, all methods return `Err`
/// with a message explaining what to do — no silent no-op.
pub struct Z3MwcSolver {
    #[cfg(feature = "z3-solver")]
    ctx: Context,
}

impl Z3MwcSolver {
    pub fn new() -> Self {
        #[cfg(feature = "z3-solver")]
        {
            let mut cfg = Config::new();
            cfg.set_model_generation(true);
            return Self { ctx: Context::new(&cfg) };
        }
        #[cfg(not(feature = "z3-solver"))]
        Self {}
    }

    /// Recover `(s1_0, s2_0)` from ≥ 2 full 32-bit MWC1616 outputs.
    ///
    /// Each element of `outputs` is:
    /// ```text
    /// s1 = 18000 * (s1 & 0xFFFF) + (s1 >> 16)   // wrapping u32
    /// s2 = 30903 * (s2 & 0xFFFF) + (s2 >> 16)   // wrapping u32
    /// output = s1.wrapping_shl(16).wrapping_add(s2)
    /// ```
    pub fn solve_from_combined(&self, outputs: &[u32]) -> Result<(u32, u32)> {
        #[cfg(not(feature = "z3-solver"))]
        anyhow::bail!(
            "Z3 solver is not compiled in. \
             Recompile with `--features z3-solver`."
        );
        #[cfg(feature = "z3-solver")]
        {
            if outputs.len() < 2 {
                anyhow::bail!("Need at least 2 combined outputs to recover MWC1616 state");
            }
            self.solve_impl(outputs, ObsKind::Combined)
        }
    }

    /// Recover `(s1_0, s2_0)` from ≥ 4 sixteen-bit MWC1616 observations.
    ///
    /// Each element is `combined_u32 >> 16`, matching
    /// `Math.floor(65536 * Math.random())` — the values written into the
    /// BitcoinJS v0.1.3 entropy pool by `next_u16()`.
    pub fn solve_from_u16(&self, outputs: &[u16]) -> Result<(u32, u32)> {
        #[cfg(not(feature = "z3-solver"))]
        anyhow::bail!(
            "Z3 solver is not compiled in. \
             Recompile with `--features z3-solver`."
        );
        #[cfg(feature = "z3-solver")]
        {
            if outputs.len() < 4 {
                anyhow::bail!(
                    "Need at least 4 sixteen-bit outputs for sufficient constraint \
                     (16 bits/obs × 4 = 64 bits ≥ 2×32 unknowns)"
                );
            }
            let wide: Vec<u32> = outputs.iter().map(|&v| v as u32).collect();
            self.solve_impl(&wide, ObsKind::Upper16)
        }
    }
}

impl Default for Z3MwcSolver {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Internal implementation ──────────────────────────────────────────────────

#[cfg(feature = "z3-solver")]
#[derive(Clone, Copy)]
enum ObsKind {
    /// Full 32-bit combined value is observed
    Combined,
    /// Only the upper 16 bits of combined are observed (next_u16 mode)
    Upper16,
}

#[cfg(feature = "z3-solver")]
impl Z3MwcSolver {
    /// One MWC1616 step for a symbolic BV32:
    ///   s_next = mult * (s & 0xFFFF) + (s >> 16)   [BV32 wrapping]
    fn mwc_step<'c>(ctx: &'c Context, s: &BV<'c>, mult: u64) -> BV<'c> {
        let s_low = s.bvand(&BV::from_u64(ctx, 0xFFFF, 32));
        let s_high = s.bvlshr(&BV::from_u64(ctx, 16, 32));
        s_low.bvmul(&BV::from_u64(ctx, mult, 32)).bvadd(&s_high)
    }

    fn solve_impl(&self, outputs: &[u32], kind: ObsKind) -> Result<(u32, u32)> {
        let solver = Solver::new(&self.ctx);

        let s1_0 = BV::new_const(&self.ctx, "s1_0", 32);
        let s2_0 = BV::new_const(&self.ctx, "s2_0", 32);

        // Degenerate all-zero state produces only zeros — exclude it.
        solver.assert(&s1_0.bveq(&BV::from_u64(&self.ctx, 0, 32)).not());
        solver.assert(&s2_0.bveq(&BV::from_u64(&self.ctx, 0, 32)).not());

        let mut s1 = s1_0.clone();
        let mut s2 = s2_0.clone();

        for &target in outputs {
            let s1n = Self::mwc_step(&self.ctx, &s1, 18_000);
            let s2n = Self::mwc_step(&self.ctx, &s2, 30_903);

            // combined = s1.wrapping_shl(16).wrapping_add(s2) in BV32.
            // bvshl on a 32-bit BV naturally discards upper bits of s1,
            // matching JS `<<` Int32 semantics. bvadd is also wrapping BV32.
            let combined = s1n
                .bvshl(&BV::from_u64(&self.ctx, 16, 32))
                .bvadd(&s2n);

            let observed = match kind {
                ObsKind::Combined => combined.clone(),
                // Upper 16 bits: shift right and mask to 16 bits.
                ObsKind::Upper16 => combined
                    .bvlshr(&BV::from_u64(&self.ctx, 16, 32))
                    .bvand(&BV::from_u64(&self.ctx, 0xFFFF, 32)),
            };

            solver.assert(&observed.bveq(&BV::from_u64(&self.ctx, target as u64, 32)));

            s1 = s1n;
            s2 = s2n;
        }

        match solver.check() {
            z3::SatResult::Sat => {
                let model = solver.get_model().context("Z3 failed to produce model")?;
                let s1_val = model
                    .eval(&s1_0, true)
                    .context("eval s1_0")?
                    .as_u64()
                    .context("s1_0 is not a concrete value")?;
                let s2_val = model
                    .eval(&s2_0, true)
                    .context("eval s2_0")?
                    .as_u64()
                    .context("s2_0 is not a concrete value")?;
                Ok((s1_val as u32, s2_val as u32))
            }
            z3::SatResult::Unsat => {
                anyhow::bail!("Z3: UNSAT — no MWC1616 state satisfies the given outputs")
            }
            z3::SatResult::Unknown => {
                anyhow::bail!("Z3: UNKNOWN — solver timed out or gave up")
            }
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// CPU reference: one MWC1616 step (all wrapping u32)
    fn mwc_step_cpu(s1: u32, s2: u32) -> (u32, u32, u32) {
        let s1n = 18_000u32.wrapping_mul(s1 & 0xFFFF).wrapping_add(s1 >> 16);
        let s2n = 30_903u32.wrapping_mul(s2 & 0xFFFF).wrapping_add(s2 >> 16);
        let combined = s1n.wrapping_shl(16).wrapping_add(s2n);
        (s1n, s2n, combined)
    }

    #[test]
    #[cfg(not(feature = "z3-solver"))]
    fn test_stub_returns_err_without_feature() {
        let solver = Z3MwcSolver::new();
        assert!(solver.solve_from_combined(&[0u32; 2]).is_err());
        assert!(solver.solve_from_u16(&[0u16; 4]).is_err());
    }

    #[test]
    #[ignore = "Requires Z3 native library and --features z3-solver"]
    #[cfg(feature = "z3-solver")]
    fn test_solve_from_combined_recovers_state() -> Result<()> {
        let s1_init = 0x12345678u32;
        let s2_init = 0x87654321u32;
        let mut s1 = s1_init;
        let mut s2 = s2_init;
        let mut outputs = Vec::new();
        for _ in 0..2 {
            let (s1n, s2n, comb) = mwc_step_cpu(s1, s2);
            s1 = s1n;
            s2 = s2n;
            outputs.push(comb);
        }
        let solver = Z3MwcSolver::new();
        let (rs1, rs2) = solver.solve_from_combined(&outputs)?;
        assert_eq!(rs1, s1_init, "s1 recovery mismatch");
        assert_eq!(rs2, s2_init, "s2 recovery mismatch");
        Ok(())
    }

    /// For 16-bit observations, Z3 may return any consistent state.
    /// Validate by forward-simulating the recovered state.
    #[test]
    #[ignore = "Requires Z3 native library and --features z3-solver"]
    #[cfg(feature = "z3-solver")]
    fn test_solve_from_u16_forward_validates() -> Result<()> {
        let s1_init = 0xABCD1234u32;
        let s2_init = 0x5678EF01u32;
        let mut s1 = s1_init;
        let mut s2 = s2_init;
        let mut outputs = Vec::new();
        for _ in 0..6 {
            let (s1n, s2n, comb) = mwc_step_cpu(s1, s2);
            s1 = s1n;
            s2 = s2n;
            outputs.push((comb >> 16) as u16);
        }
        let solver = Z3MwcSolver::new();
        let (rs1, rs2) = solver.solve_from_u16(&outputs)?;
        let mut vs1 = rs1;
        let mut vs2 = rs2;
        for (i, &expected) in outputs.iter().enumerate() {
            let (s1n, s2n, comb) = mwc_step_cpu(vs1, vs2);
            vs1 = s1n;
            vs2 = s2n;
            assert_eq!(
                (comb >> 16) as u16, expected,
                "Forward validation failed at step {i}"
            );
        }
        Ok(())
    }
}
