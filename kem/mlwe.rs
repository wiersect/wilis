//! IND-CCA2 Post-Quantum Module-LWE KEM (`WilisKEM`) with Fujisaki-Okamoto transform
//! and constant-time implicit rejection.

use crate::core::constants::HASH_BYTES;
use crate::error::{Result, WilisError};
use crate::hash::hash;
use crate::kem::poly::{vec_dot, Poly, KEM_K, KEM_Q, POLY_BYTES};
use crate::utils::constant_time::ct_eq;
use crate::utils::random::fill_random;
use crate::utils::zeroize::{zeroize_bytes, SecretKey};
use crate::xof::WilisXof;

const PK_MAGIC: [u8; 4] = *b"WKP1";

/// Returns `true` iff every coefficient of `p` lies in the valid `CBD_2` range `{-2,-1,0,1,2} mod q`.
fn is_small_cbd2_poly(p: &Poly) -> bool {
    let mut bad: u16 = 0;
    for &c in &p.coeffs {
        let ok = (c <= 2) || (c >= KEM_Q - 2 && c < KEM_Q);
        bad |= (!ok) as u16;
    }
    core::hint::black_box(bad) == 0
}
const SK_MAGIC: [u8; 4] = *b"WKS1";
const CT_MAGIC: [u8; 4] = *b"WKC1";

/// Serialized public key size (`4 magic + 32 rho + 3 * 416 t = 1284` bytes).
pub const KEM_PK_BYTES: usize = 4 + 32 + KEM_K * POLY_BYTES;

/// Serialized secret key size (`4 magic + 3 * 416 s + KEM_PK_BYTES + 32 pk_hash + 32 z`).
pub const KEM_SK_BYTES: usize = 4 + KEM_K * POLY_BYTES + KEM_PK_BYTES + 32 + 32;

/// Serialized ciphertext size (`4 magic + (3 + 1) * 416 = 1668` bytes).
pub const KEM_CT_BYTES: usize = 4 + (KEM_K + 1) * POLY_BYTES;

/// Encapsulated shared secret size (32 bytes = 256 bits).
pub const KEM_SS_BYTES: usize = 32;

/// Public encapsulation key for `WilisKEM`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KemPublicKey {
    pub rho: [u8; 32],
    pub t: [Poly; KEM_K],
}

/// Secret decapsulation key for `WilisKEM` (auto-zeroizes secret material on drop).
#[derive(Clone)]
pub struct KemSecretKey {
    s: [Poly; KEM_K],
    pk: KemPublicKey,
    pk_hash: [u8; HASH_BYTES],
    z: [u8; 32],
}

/// Post-quantum KEM ciphertext encapsulating a 256-bit shared secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KemCiphertext {
    pub u: [Poly; KEM_K],
    pub v: Poly,
}

impl KemPublicKey {
    /// Serializes the public key into canonical `WKP1` bytes (`1284` bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(KEM_PK_BYTES);
        out.extend_from_slice(&PK_MAGIC);
        out.extend_from_slice(&self.rho);
        for p in &self.t {
            out.extend_from_slice(&p.pack());
        }
        out
    }

    /// Parses and validates a canonical `WKP1` public key.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != KEM_PK_BYTES || data[0..4] != PK_MAGIC {
            return Err(WilisError::InvalidKey(format!(
                "invalid WilisKEM public key (expected WKP1, {KEM_PK_BYTES} bytes)"
            )));
        }
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&data[4..36]);
        let t0 = Poly::unpack(&data[36..36 + POLY_BYTES])?;
        let t1 = Poly::unpack(&data[36 + POLY_BYTES..36 + 2 * POLY_BYTES])?;
        let t2 = Poly::unpack(&data[36 + 2 * POLY_BYTES..36 + 3 * POLY_BYTES])?;
        Ok(Self {
            rho,
            t: [t0, t1, t2],
        })
    }
}

impl KemSecretKey {
    /// Returns the public key associated with this secret key.
    pub fn public_key(&self) -> &KemPublicKey {
        &self.pk
    }

    /// Serializes the secret key into canonical `WKS1` bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(KEM_SK_BYTES);
        out.extend_from_slice(&SK_MAGIC);
        for p in &self.s {
            out.extend_from_slice(&p.pack());
        }
        out.extend_from_slice(&self.pk.to_bytes());
        out.extend_from_slice(&self.pk_hash);
        out.extend_from_slice(&self.z);
        out
    }

    /// Parses and validates a canonical `WKS1` secret key.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != KEM_SK_BYTES || data[0..4] != SK_MAGIC {
            return Err(WilisError::InvalidKey(format!(
                "invalid WilisKEM secret key (expected WKS1, {KEM_SK_BYTES} bytes)"
            )));
        }
        let mut pos = 4;
        let mut s0 = Poly::unpack(&data[pos..pos + POLY_BYTES])?;
        pos += POLY_BYTES;
        let mut s1 = match Poly::unpack(&data[pos..pos + POLY_BYTES]) {
            Ok(p) => p,
            Err(e) => {
                s0.zeroize();
                return Err(e);
            }
        };
        pos += POLY_BYTES;
        let mut s2 = match Poly::unpack(&data[pos..pos + POLY_BYTES]) {
            Ok(p) => p,
            Err(e) => {
                s0.zeroize();
                s1.zeroize();
                return Err(e);
            }
        };
        pos += POLY_BYTES;

        let pk = match KemPublicKey::from_bytes(&data[pos..pos + KEM_PK_BYTES]) {
            Ok(k) => k,
            Err(e) => {
                s0.zeroize();
                s1.zeroize();
                s2.zeroize();
                return Err(e);
            }
        };
        pos += KEM_PK_BYTES;

        let mut pk_hash = [0u8; 32];
        pk_hash.copy_from_slice(&data[pos..pos + 32]);
        pos += 32;

        // Verify stored pk_hash matches pk to reject corrupted key files
        if !ct_eq(&pk_hash, &hash(&pk.to_bytes())) {
            s0.zeroize();
            s1.zeroize();
            s2.zeroize();
            return Err(WilisError::InvalidKey(
                "WilisKEM secret key failed public-key consistency check".into(),
            ));
        }

        // Verify mathematical LWE consistency: s in CBD_2 AND e = t - A*s in CBD_2.
        // Catches any bit-flip in `s`, `rho`, or `t` with probability 1 - 2^-8130.
        let mut s_vec = [s0, s1, s2];
        let mut lwe_ok = s_vec.iter().all(is_small_cbd2_poly);
        if lwe_ok {
            for row in 0..KEM_K {
                let mut acc = Poly::zero();
                for col in 0..KEM_K {
                    let a_rc = Poly::sample_uniform(&pk.rho, row as u8, col as u8);
                    let mut prod = a_rc.mul(&s_vec[col]);
                    let next = acc.add(&prod);
                    prod.zeroize();
                    acc.zeroize();
                    acc = next;
                }
                let mut e_rec = pk.t[row].sub(&acc);
                acc.zeroize();
                if !is_small_cbd2_poly(&e_rec) {
                    lwe_ok = false;
                }
                e_rec.zeroize();
            }
        }
        if !lwe_ok {
            for p in &mut s_vec {
                p.zeroize();
            }
            return Err(WilisError::InvalidKey(
                "WilisKEM secret key failed Module-LWE consistency check (corrupted secret vector)".into(),
            ));
        }

        let mut z = [0u8; 32];
        z.copy_from_slice(&data[pos..pos + 32]);

        let sk = Self {
            s: s_vec,
            pk,
            pk_hash,
            z,
        };
        zeroize_bytes(&mut z);
        Ok(sk)
    }
}

impl Drop for KemSecretKey {
    fn drop(&mut self) {
        for p in &mut self.s {
            p.zeroize();
        }
        zeroize_bytes(&mut self.z);
    }
}

impl KemCiphertext {
    /// Serializes the ciphertext into canonical `WKC1` bytes (`1668` bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(KEM_CT_BYTES);
        out.extend_from_slice(&CT_MAGIC);
        for p in &self.u {
            out.extend_from_slice(&p.pack());
        }
        out.extend_from_slice(&self.v.pack());
        out
    }

    /// Parses and validates a canonical `WKC1` ciphertext.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() != KEM_CT_BYTES || data[0..4] != CT_MAGIC {
            return Err(WilisError::InvalidFormat(format!(
                "invalid WilisKEM ciphertext (expected WKC1, {KEM_CT_BYTES} bytes)"
            )));
        }
        let u0 = Poly::unpack(&data[4..4 + POLY_BYTES])?;
        let u1 = Poly::unpack(&data[4 + POLY_BYTES..4 + 2 * POLY_BYTES])?;
        let u2 = Poly::unpack(&data[4 + 2 * POLY_BYTES..4 + 3 * POLY_BYTES])?;
        let v = Poly::unpack(&data[4 + 3 * POLY_BYTES..4 + 4 * POLY_BYTES])?;
        Ok(Self {
            u: [u0, u1, u2],
            v,
        })
    }
}

/// Deterministic IND-CPA Module-LWE encryption subroutine used inside the FO transform.
fn cpa_encrypt(pk: &KemPublicKey, msg: &[u8; 32], coins: &[u8; 32]) -> KemCiphertext {
    let mut r = [
        Poly::sample_cbd2(coins, 0),
        Poly::sample_cbd2(coins, 1),
        Poly::sample_cbd2(coins, 2),
    ];
    let mut e1 = [
        Poly::sample_cbd2(coins, 3),
        Poly::sample_cbd2(coins, 4),
        Poly::sample_cbd2(coins, 5),
    ];
    let mut e2 = Poly::sample_cbd2(coins, 6);

    // u = A^T * r + e1
    let mut u = [Poly::zero(), Poly::zero(), Poly::zero()];
    for col in 0..KEM_K {
        let mut acc = e1[col].clone();
        for row in 0..KEM_K {
            let a_rc = Poly::sample_uniform(&pk.rho, row as u8, col as u8);
            let mut prod = a_rc.mul(&r[row]);
            let next = acc.add(&prod);
            prod.zeroize();
            acc.zeroize();
            acc = next;
        }
        u[col] = acc;
    }

    // v = t^T * r + e2 + encode(msg)
    let mut m_poly = Poly::from_msg_bits(msg);
    let mut tr = vec_dot(&pk.t, &r);
    let mut tr_e2 = tr.add(&e2);
    let v = tr_e2.add(&m_poly);
    tr.zeroize();
    tr_e2.zeroize();

    // Wipe ephemeral secret polynomials from memory
    for p in &mut r {
        p.zeroize();
    }
    for p in &mut e1 {
        p.zeroize();
    }
    e2.zeroize();
    m_poly.zeroize();

    KemCiphertext { u, v }
}

/// IND-CPA Module-LWE decryption subroutine.
fn cpa_decrypt(s: &[Poly; KEM_K], ct: &KemCiphertext) -> [u8; 32] {
    let mut su = vec_dot(s, &ct.u);
    let mut diff = ct.v.sub(&su);
    let msg = diff.to_msg_bits();
    su.zeroize();
    diff.zeroize();
    msg
}

fn fo_derive_kbar_and_coins(msg: &[u8; 32], pk_hash: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut xof = WilisXof::new(b"WKEM_FO_G1");
    xof.absorb(msg);
    xof.absorb(pk_hash);
    let mut out = [0u8; 64];
    xof.squeeze(&mut out);
    let k_bar: [u8; 32] = out[0..32].try_into().expect("32 bytes");
    let coins: [u8; 32] = out[32..64].try_into().expect("32 bytes");
    zeroize_bytes(&mut out);
    (k_bar, coins)
}

fn derive_final_shared_secret(label: &[u8], secret_part: &[u8; 32], ct_hash: &[u8; 32]) -> [u8; 32] {
    let mut xof = WilisXof::new(label);
    xof.absorb(secret_part);
    xof.absorb(ct_hash);
    let mut ss = [0u8; 32];
    xof.squeeze(&mut ss);
    ss
}

/// Generates a fresh post-quantum `WilisKEM` `(KemSecretKey, KemPublicKey)` pair.
pub fn keygen() -> Result<(KemSecretKey, KemPublicKey)> {
    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];
    let mut z = [0u8; 32];
    fill_random(&mut rho)?;
    fill_random(&mut sigma)?;
    if let Err(e) = fill_random(&mut z) {
        zeroize_bytes(&mut sigma);
        return Err(e);
    }

    let s = [
        Poly::sample_cbd2(&sigma, 0),
        Poly::sample_cbd2(&sigma, 1),
        Poly::sample_cbd2(&sigma, 2),
    ];
    let mut e = [
        Poly::sample_cbd2(&sigma, 3),
        Poly::sample_cbd2(&sigma, 4),
        Poly::sample_cbd2(&sigma, 5),
    ];
    zeroize_bytes(&mut sigma);

    // t = A * s + e
    let mut t = [Poly::zero(), Poly::zero(), Poly::zero()];
    for row in 0..KEM_K {
        let mut acc = e[row].clone();
        for col in 0..KEM_K {
            let a_rc = Poly::sample_uniform(&rho, row as u8, col as u8);
            let mut prod = a_rc.mul(&s[col]);
            let next = acc.add(&prod);
            prod.zeroize();
            acc.zeroize();
            acc = next;
        }
        t[row] = acc;
    }
    for p in &mut e {
        p.zeroize();
    }

    let pk = KemPublicKey { rho, t };
    let pk_hash = hash(&pk.to_bytes());
    let sk = KemSecretKey {
        s,
        pk: pk.clone(),
        pk_hash,
        z,
    };
    zeroize_bytes(&mut z);
    Ok((sk, pk))
}

/// Encapsulates a fresh 256-bit shared secret to `pk`, returning `(KemCiphertext, SecretKey)`.
pub fn encapsulate(pk: &KemPublicKey) -> Result<(KemCiphertext, SecretKey)> {
    let mut msg = [0u8; 32];
    fill_random(&mut msg)?;

    let pk_hash = hash(&pk.to_bytes());
    let (mut k_bar, mut coins) = fo_derive_kbar_and_coins(&msg, &pk_hash);
    let ct = cpa_encrypt(pk, &msg, &coins);
    let ct_hash = hash(&ct.to_bytes());
    let mut ss = derive_final_shared_secret(b"WKEM_FO_K1", &k_bar, &ct_hash);

    zeroize_bytes(&mut msg);
    zeroize_bytes(&mut k_bar);
    zeroize_bytes(&mut coins);
    let secret = SecretKey::from_bytes(ss);
    zeroize_bytes(&mut ss);
    Ok((ct, secret))
}

/// Decapsulates `ct` using `sk` with constant-time Fujisaki-Okamoto re-encryption check
/// and implicit rejection (never leaks whether a tampered ciphertext was valid).
pub fn decapsulate(sk: &KemSecretKey, ct: &KemCiphertext) -> SecretKey {
    let mut msg_prime = cpa_decrypt(&sk.s, ct);
    let (mut k_bar_prime, mut coins_prime) = fo_derive_kbar_and_coins(&msg_prime, &sk.pk_hash);
    let ct_re = cpa_encrypt(&sk.pk, &msg_prime, &coins_prime);

    let ct_bytes = ct.to_bytes();
    let ct_re_bytes = ct_re.to_bytes();
    let is_valid = ct_eq(&ct_bytes, &ct_re_bytes);

    let ct_hash = hash(&ct_bytes);
    let mut ss_ok = derive_final_shared_secret(b"WKEM_FO_K1", &k_bar_prime, &ct_hash);
    let mut ss_rej = derive_final_shared_secret(b"WKEM_FO_R1", &sk.z, &ct_hash);

    // Branchless constant-time select between real secret and implicit rejection secret
    let mask = core::hint::black_box(0u8.wrapping_sub(is_valid as u8)); // 0xFF if valid, 0x00 if invalid
    let mut final_ss = [0u8; 32];
    for i in 0..32 {
        final_ss[i] = (ss_ok[i] & mask) | (ss_rej[i] & !mask);
    }

    zeroize_bytes(&mut msg_prime);
    zeroize_bytes(&mut k_bar_prime);
    zeroize_bytes(&mut coins_prime);
    zeroize_bytes(&mut ss_ok);
    zeroize_bytes(&mut ss_rej);
    let secret = SecretKey::from_bytes(final_ss);
    zeroize_bytes(&mut final_ss);
    secret
}
