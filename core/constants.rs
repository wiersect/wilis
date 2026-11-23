//! Mathematical constants, sizes, and domain separators for `WilisPerm-384`.
//!
//! All 32 round constants are "nothing-up-my-sleeve" values computed as the
//! first 64 fractional bits of the fifth roots of the first 32 prime numbers:
//! `floor(2^64 * (p^(1/5) - floor(p^(1/5))))`.

/// Number of 64-bit words in the internal state (6 * 64 = 384 bits).
pub const STATE_WORDS: usize = 6;

/// Total internal state size in bytes (48 bytes = 384 bits).
pub const STATE_BYTES: usize = STATE_WORDS * 8;

/// Sponge rate in bytes (16 bytes = 128 bits).
pub const RATE_BYTES: usize = 16;

/// Sponge capacity in bytes (32 bytes = 256 bits).
pub const CAPACITY_BYTES: usize = STATE_BYTES - RATE_BYTES;

/// Secret key size in bytes (32 bytes = 256 bits).
pub const KEY_BYTES: usize = 32;

/// Nonce size in bytes (24 bytes = 192 bits).
pub const NONCE_BYTES: usize = 24;

/// Salt size in bytes for passphrase key derivation (24 bytes = 192 bits).
pub const SALT_BYTES: usize = 24;

/// Authentication tag size in bytes (32 bytes = 256 bits).
pub const TAG_BYTES: usize = 32;

/// Hash digest size in bytes (32 bytes = 256 bits).
pub const HASH_BYTES: usize = 32;

/// Maximum supported rounds (must match `ROUND_CONSTANTS.len() / 2`).
pub const MAX_ROUNDS: usize = 16;

/// Full-strength round count used during initialization, finalization, KDF, and hashing.
pub const ROUNDS_FULL: usize = 16;

/// Data-phase round count used when absorbing AAD or processing message blocks.
pub const ROUNDS_DATA: usize = 12;

/// Domain separator for AEAD state initialization ("WILS_INI").
pub const DOMAIN_INIT: u64 = 0x5749_4C53_5F49_4E49;

/// Domain separator for Associated Data absorption ("WILS_AAD").
pub const DOMAIN_AAD: u64 = 0x5749_4C53_5F41_4144;

/// Domain separator for plaintext/ciphertext processing ("WILS_MSG").
pub const DOMAIN_MSG: u64 = 0x5749_4C53_5F4D_5347;

/// Domain separator for AEAD tag finalization ("WILS_FIN").
pub const DOMAIN_FINAL: u64 = 0x5749_4C53_5F46_494E;

/// Domain separator for memory-mixed key derivation ("WILS_KDF").
pub const DOMAIN_KDF: u64 = 0x5749_4C53_5F4B_4446;

/// Domain separator for WilisHash-256 ("WILS_HSH").
pub const DOMAIN_HASH: u64 = 0x5749_4C53_5F48_5348;

/// Domain separator for WilisXOF extendable-output sponge ("WILS_XOF").
pub const DOMAIN_XOF: u64 = 0x5749_4C53_5F58_4F46;

/// Domain separator for WilisMAC keyed 256-bit MAC ("WILS_MAC").
pub const DOMAIN_MAC: u64 = 0x5749_4C53_5F4D_4143;

/// Domain separator for WilisRatchet forward-secret chain ("WILS_RAT").
pub const DOMAIN_RATCHET: u64 = 0x5749_4C53_5F52_4154;

/// 32 original 64-bit round constants derived from `frac(p^(1/5))` for the first 32 primes.
/// Each round consumes two constants: one via XOR on word 0, one via modular addition on word 3.
pub const ROUND_CONSTANTS: [u64; MAX_ROUNDS * 2] = [
    0x2611_186B_AE67_496A, // frac(2^(1/5))
    0x3EE8_390D_4395_5AEC, // frac(3^(1/5))
    0x6135_F68D_4C0C_BB6F, // frac(5^(1/5))
    0x79CC_4519_5CF5_B7A4, // frac(7^(1/5))
    0x9D8A_7A87_7BF9_4AB1, // frac(11^(1/5))
    0xAB97_50F4_0485_EF65, // frac(13^(1/5))
    0xC328_BCAE_5C6E_D363, // frac(17^(1/5))
    0xCD4E_C427_C55B_B231, // frac(19^(1/5))
    0xDF46_9D1F_BEC4_AD12, // frac(23^(1/5))
    0xF604_B088_ED54_6037, // frac(29^(1/5))
    0xFCC2_5D1B_4AB3_D2C2, // frac(31^(1/5))
    0x0F15_A6F7_1ECA_28C6, // frac(37^(1/5))
    0x1A04_960A_67EA_C257, // frac(41^(1/5))
    0x1F2A_D772_AFDE_B38E, // frac(43^(1/5))
    0x28EA_9EA1_729A_FC53, // frac(47^(1/5))
    0x365D_0446_C226_DFEA, // frac(53^(1/5))
    0x42A4_7E4D_760C_6775, // frac(59^(1/5))
    0x4683_6F3E_D7CD_E648, // frac(61^(1/5))
    0x518B_F751_64F5_62A9, // frac(67^(1/5))
    0x5878_6EF6_213F_A0F5, // frac(71^(1/5))
    0x5BD0_DE21_DD34_54F6, // frac(73^(1/5))
    0x656E_36EC_5E9B_8673, // frac(79^(1/5))
    0x6B85_3653_315B_0681, // frac(83^(1/5))
    0x743A_9E75_0949_3FB4, // frac(89^(1/5))
    0x7F23_3469_F8A8_96B5, // frac(97^(1/5))
    0x8452_EB05_3CC3_BD7E, // frac(101^(1/5))
    0x86DB_0F3B_FA5C_695D, // frac(103^(1/5))
    0x8BCD_B563_D00B_36C8, // frac(107^(1/5))
    0x8E38_E0E4_180C_CEE1, // frac(109^(1/5))
    0x92F4_7092_B35C_0163, // frac(113^(1/5))
    0xA287_750A_C0E0_F50B, // frac(127^(1/5))
    0xA6B9_C057_5AF3_D994, // frac(131^(1/5))
];

/// Rotation pairs `(r1, r2)` used in the primary ARX mixing layer.
/// All values are distinct primes coprime to 64 and spread across byte boundaries.
pub const ARX_PRIMARY_ROTS: [(u32, u32); 3] = [(13, 37), (19, 43), (29, 53)];

/// Rotation pairs `(r1, r2)` used in the staggered cross-word ARX mixing layer.
pub const ARX_STAGGERED_ROTS: [(u32, u32); 3] = [(17, 41), (23, 47), (31, 59)];

/// Intra-word 3-tap rotation pairs `(a, b)` for linear diffusion.
/// Because `1 + x^a + x^b` has odd Hamming weight over GF(2)[x]/(x^64 + 1),
/// every single tap pair is mathematically guaranteed to be invertible.
pub const DIFFUSION_TAPS: [(u32, u32); STATE_WORDS] = [
    (7, 29),
    (11, 41),
    (17, 53),
    (23, 37),
    (13, 47),
    (19, 59),
];
