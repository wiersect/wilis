//! Exact Differential Distribution Table (DDT) and Linear Approximation Table (LAT)
//! cryptanalysis of the 5-bit Chi S-Box core used in `WilisPerm-384`.

/// Exact algebraic & cryptanalytic metrics of the 5-bit Chi S-Box.
#[derive(Debug, Clone)]
pub struct SboxMetrics {
    pub is_bijective: bool,
    pub fixed_points: usize,
    /// Maximum non-trivial entry in the Differential Distribution Table (lower is stronger).
    pub differential_uniformity: u32,
    /// Maximum absolute linear bias `|count - 16|` in the Linear Approximation Table.
    pub max_linear_bias: u32,
    /// Nonlinearity `16 - max_linear_bias` (for 5-bit S-Box, theoretical max for degree-2 is 8).
    pub nonlinearity: u32,
    pub passed: bool,
}

/// Evaluates the 5-bit Chi map directly on a 5-bit value `x in 0..32`.
fn chi5_eval(x: u8) -> u8 {
    let mut y = 0u8;
    for i in 0..5 {
        let b0 = (x >> i) & 1;
        let b1 = (x >> ((i + 1) % 5)) & 1;
        let b2 = (x >> ((i + 2) % 5)) & 1;
        let out_bit = b0 ^ ((!b1 & 1) & b2);
        y |= out_bit << i;
    }
    y
}

/// Computes exact bijectivity, fixed points, DDT differential uniformity, and LAT nonlinearity.
pub fn analyze_chi5_sbox() -> SboxMetrics {
    let mut table = [0u8; 32];
    let mut seen = [false; 32];
    let mut fixed_points = 0usize;

    for x in 0..32u8 {
        let y = chi5_eval(x);
        table[x as usize] = y;
        seen[y as usize] = true;
        if x == y {
            fixed_points += 1;
        }
    }
    let is_bijective = seen.iter().all(|&v| v);

    // Compute exact 32x32 Differential Distribution Table (DDT)
    let mut max_ddt: u32 = 0;
    for dx in 1..32u8 {
        let mut counts = [0u32; 32];
        for x in 0..32u8 {
            let dy = table[x as usize] ^ table[(x ^ dx) as usize];
            counts[dy as usize] += 1;
        }
        for &c in &counts {
            max_ddt = max_ddt.max(c);
        }
    }

    // Compute exact 32x32 Linear Approximation Table (LAT)
    let mut max_bias: u32 = 0;
    for mask_in in 1..32u8 {
        for mask_out in 1..32u8 {
            let mut matches: i32 = 0;
            for x in 0..32u8 {
                let in_par = (x & mask_in).count_ones() & 1;
                let out_par = (table[x as usize] & mask_out).count_ones() & 1;
                if in_par == out_par {
                    matches += 1;
                }
            }
            let bias = (matches - 16).unsigned_abs();
            max_bias = max_bias.max(bias);
        }
    }

    let nonlinearity = 16u32.saturating_sub(max_bias);
    // Known exact properties of 5-bit Chi: bijective, diff uniformity = 8, max bias = 8, NL = 8
    // (ARX modular additions across every round further lift algebraic degree to 63!)
    let passed = is_bijective && max_ddt <= 8 && nonlinearity >= 8;

    SboxMetrics {
        is_bijective,
        fixed_points,
        differential_uniformity: max_ddt,
        max_linear_bias: max_bias,
        nonlinearity,
        passed,
    }
}
