//! Round orchestration for the `WilisPerm-384` cryptographic permutation.
//!
//! Each round combines five strictly bijective sub-layers:
//! 1. Asymmetric round-constant injection (XOR on word 0, modular addition on word 3).
//! 2. Primary pairwise ARX mixing across `(0,1)`, `(2,3)`, `(4,5)`.
//! 3. Constant-time bitsliced nonlinear layer (`Chi-5` + `Feistel-6`).
//! 4. Staggered cross-word ARX mixing across `(1,2)`, `(3,4)`, `(5,0)`.
//! 5. Per-word 3-tap linear diffusion + cyclic word-lane rotation.

use crate::core::arx::{
    apply_primary_arx, apply_staggered_arx, inverse_primary_arx, inverse_staggered_arx,
};
use crate::core::constants::{MAX_ROUNDS, ROUND_CONSTANTS};
use crate::core::diffusion::{apply_diffusion, inverse_diffusion};
use crate::core::sbox::{apply_sbox, inverse_sbox};
use crate::core::state::State;

/// Executes `rounds` rounds of `WilisPerm-384` in place (`1 <= rounds <= 16`).
///
/// Rounds are indexed from the tail of the constant schedule (`MAX_ROUNDS - rounds..MAX_ROUNDS`)
/// so reduced-round calls (e.g., 12 rounds) use distinct constants from early rounds.
pub fn permute(state: &mut State, rounds: usize) {
    assert!(
        rounds > 0 && rounds <= MAX_ROUNDS,
        "rounds must be within 1..={MAX_ROUNDS}"
    );
    let start_round = MAX_ROUNDS - rounds;
    let w = &mut state.words;

    for r in start_round..MAX_ROUNDS {
        // 1. Asymmetric round constant injection
        w[0] ^= ROUND_CONSTANTS[r * 2];
        w[3] = w[3].wrapping_add(ROUND_CONSTANTS[r * 2 + 1]);

        // 2. Primary ARX mixing
        apply_primary_arx(w);

        // 3. Bitsliced nonlinear substitution
        apply_sbox(w);

        // 4. Staggered cross-word ARX mixing
        apply_staggered_arx(w);

        // 5. Intra-word linear diffusion + lane rotation
        apply_diffusion(w);
    }
}

/// Exact mathematical inverse of [`permute`].
///
/// Used to verify bijectivity of `WilisPerm-384` (`permute_inverse(permute(s)) == s`),
/// proving zero state-space shrinkage across all rounds.
pub fn permute_inverse(state: &mut State, rounds: usize) {
    assert!(
        rounds > 0 && rounds <= MAX_ROUNDS,
        "rounds must be within 1..={MAX_ROUNDS}"
    );
    let start_round = MAX_ROUNDS - rounds;
    let w = &mut state.words;

    for r in (start_round..MAX_ROUNDS).rev() {
        inverse_diffusion(w);
        inverse_staggered_arx(w);
        inverse_sbox(w);
        inverse_primary_arx(w);
        w[3] = w[3].wrapping_sub(ROUND_CONSTANTS[r * 2 + 1]);
        w[0] ^= ROUND_CONSTANTS[r * 2];
    }
}
