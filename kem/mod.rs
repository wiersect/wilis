//! `WilisKEM` — Post-Quantum Lattice-Based Key Encapsulation Mechanism (Module-LWE)
//! & Hybrid Public-Key Encryption (`WilisKEM` + `WilisAEAD`).
//!
//! Parameters:
//! - Polynomial ring: `Z_q[X] / (X^256 + 1)` with prime modulus `q = 7681`
//! - Module rank: `k = 3` (total lattice dimension `768`)
//! - Noise distribution: Centered Binomial `CBD_2` (coefficients in `[-2, 2]`)
//! - Noise margin: `49 sigma` below `q/4 = 1920` (practically zero decryption failures)
//! - IND-CCA2 security: Fujisaki-Okamoto transform with constant-time implicit rejection,
//!   using `WilisXOF` and `WilisHash-256` exclusively (zero external crypto).

pub mod hybrid;
pub mod mlwe;
pub mod poly;

pub use hybrid::{pub_decrypt, pub_encrypt};
pub use mlwe::{
    decapsulate, encapsulate, keygen, KemCiphertext, KemPublicKey, KemSecretKey,
    KEM_CT_BYTES, KEM_PK_BYTES, KEM_SK_BYTES, KEM_SS_BYTES,
};
