//! Post-Quantum Balanced Password-Authenticated Key Exchange (`WilisPAKE`).
//!
//! Allows two peers sharing only a human password to derive a high-entropy 256-bit
//! post-quantum session key without sending the password over the wire:
//! 1. Initiator generates an ephemeral `WilisKEM` keypair `(sk, pk)`, derives a password mask
//!    using `WilisKDF(password, salt)` + `WilisXOF`, and sends `(salt, masked_pk)` (`WPKM` Msg 1).
//! 2. Responder unmasks `pk`, validates `KemPublicKey::from_bytes`, encapsulates a fresh
//!    Module-LWE shared secret `(kem_ct, pq_ss)`, derives `(session_key, confirm_r, confirm_i)`
//!    bound to the full transcript + `pw_key`, and sends `(kem_ct, confirm_r)` (Msg 2).
//! 3. Initiator decapsulates `kem_ct`, verifies `confirm_r` in constant time, and emits
//!    `confirm_i` (Msg 3) — limiting an active MITM to 1 online guess per handshake!

use crate::core::constants::{KEY_BYTES, SALT_BYTES, TAG_BYTES};
use crate::error::{Result, WilisError};
use crate::kdf::{derive_key, KdfParams};
use crate::kem::{
    decapsulate, encapsulate, keygen, KemCiphertext, KemPublicKey, KemSecretKey, KEM_CT_BYTES,
    KEM_PK_BYTES,
};
use crate::mac::mac;
use crate::utils::random::generate_salt;
use crate::utils::zeroize::{zeroize_bytes, SecretKey};
use crate::xof::WilisXof;

/// PAKE Message 1 sent by initiator (contains random salt + password-masked `WKP1` public key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PakeClientHello {
    pub salt: [u8; SALT_BYTES],
    pub kdf_params: KdfParams,
    pub masked_pk: Vec<u8>,
}

/// PAKE Message 2 sent by responder (encapsulated KEM ciphertext + responder key-confirmation MAC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PakeServerHello {
    pub kem_ct: KemCiphertext,
    pub server_confirm: [u8; TAG_BYTES],
}

/// PAKE Message 3 sent by initiator (initiator key-confirmation MAC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PakeClientFinish {
    pub client_confirm: [u8; TAG_BYTES],
}

/// Initiator state held between Message 1 and Message 2 (auto-zeroizes on drop).
pub struct PakeClientState {
    sk: KemSecretKey,
    pw_key: SecretKey,
    salt: [u8; SALT_BYTES],
    masked_pk: Vec<u8>,
    context: Vec<u8>,
}

/// Responder state held between Message 2 and Message 3 (auto-zeroizes on drop).
pub struct PakeServerState {
    expected_client_confirm: [u8; TAG_BYTES],
    session_key: SecretKey,
}

impl Drop for PakeServerState {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.expected_client_confirm);
    }
}

fn derive_pk_mask(pw_key: &[u8; KEY_BYTES], salt: &[u8; SALT_BYTES], context: &[u8]) -> Vec<u8> {
    let mut xof = WilisXof::new(b"WPAKE_MASK_V1");
    xof.absorb(pw_key);
    xof.absorb(salt);
    xof.absorb(&(context.len() as u64).to_le_bytes());
    xof.absorb(context);
    xof.squeeze_vec(KEM_PK_BYTES)
}

fn derive_pake_keys(
    pw_key: &[u8; KEY_BYTES],
    pq_ss: &[u8; KEY_BYTES],
    salt: &[u8; SALT_BYTES],
    masked_pk: &[u8],
    kem_ct_bytes: &[u8],
    context: &[u8],
) -> (SecretKey, [u8; TAG_BYTES], [u8; TAG_BYTES]) {
    let mut xof = WilisXof::new(b"WPAKE_KEY_V1");
    xof.absorb(pw_key);
    xof.absorb(pq_ss);
    xof.absorb(salt);
    xof.absorb(masked_pk);
    xof.absorb(kem_ct_bytes);
    xof.absorb(&(context.len() as u64).to_le_bytes());
    xof.absorb(context);

    let mut mat = [0u8; KEY_BYTES * 3];
    xof.squeeze(&mut mat);
    let mut sess = [0u8; KEY_BYTES];
    let mut k_srv = [0u8; KEY_BYTES];
    let mut k_cli = [0u8; KEY_BYTES];
    sess.copy_from_slice(&mat[0..32]);
    k_srv.copy_from_slice(&mat[32..64]);
    k_cli.copy_from_slice(&mat[64..96]);
    zeroize_bytes(&mut mat);

    let srv_confirm = mac(&k_srv, b"WPAKE_SRV_OK_V1");
    let cli_confirm = mac(&k_cli, b"WPAKE_CLI_OK_V1");
    zeroize_bytes(&mut k_srv);
    zeroize_bytes(&mut k_cli);

    let session_key = SecretKey::from_bytes(sess);
    zeroize_bytes(&mut sess);
    (session_key, srv_confirm, cli_confirm)
}

/// Step 1 (Client): Generates masked ephemeral `WilisKEM` public key from `password`.
pub fn pake_client_start(
    password: &[u8],
    context: &[u8],
    kdf_params: KdfParams,
) -> Result<(PakeClientState, PakeClientHello)> {
    let salt = generate_salt()?;
    let pw_key = derive_key(password, &salt, kdf_params)?;
    let (sk, pk) = keygen()?;
    let pk_bytes = pk.to_bytes();
    let mut mask = derive_pk_mask(pw_key.as_bytes(), &salt, context);
    let mut masked_pk = vec![0u8; KEM_PK_BYTES];
    for i in 0..KEM_PK_BYTES {
        masked_pk[i] = pk_bytes[i] ^ mask[i];
    }
    zeroize_bytes(&mut mask);

    let hello = PakeClientHello {
        salt,
        kdf_params,
        masked_pk: masked_pk.clone(),
    };
    let state = PakeClientState {
        sk,
        pw_key,
        salt,
        masked_pk,
        context: context.to_vec(),
    };
    Ok((state, hello))
}

/// Step 2 (Server): Unmasks client PK using `password`, encapsulates PQ secret, and computes confirmation tag.
pub fn pake_server_respond(
    password: &[u8],
    context: &[u8],
    hello: &PakeClientHello,
) -> Result<(PakeServerState, PakeServerHello)> {
    if hello.masked_pk.len() != KEM_PK_BYTES {
        return Err(WilisError::InvalidFormat("invalid PAKE masked_pk length".into()));
    }
    let pw_key = derive_key(password, &hello.salt, hello.kdf_params)?;
    let mut mask = derive_pk_mask(pw_key.as_bytes(), &hello.salt, context);
    let mut unmasked = vec![0u8; KEM_PK_BYTES];
    for i in 0..KEM_PK_BYTES {
        unmasked[i] = hello.masked_pk[i] ^ mask[i];
    }
    zeroize_bytes(&mut mask);

    let pk = match KemPublicKey::from_bytes(&unmasked) {
        Ok(k) => k,
        Err(_) => {
            zeroize_bytes(&mut unmasked);
            return Err(WilisError::AuthenticationFailed);
        }
    };
    zeroize_bytes(&mut unmasked);

    let (kem_ct, pq_ss) = encapsulate(&pk)?;
    let kem_ct_bytes = kem_ct.to_bytes();
    let (session_key, server_confirm, expected_client_confirm) = derive_pake_keys(
        pw_key.as_bytes(),
        pq_ss.as_bytes(),
        &hello.salt,
        &hello.masked_pk,
        &kem_ct_bytes,
        context,
    );

    let state = PakeServerState {
        expected_client_confirm,
        session_key,
    };
    let resp = PakeServerHello {
        kem_ct,
        server_confirm,
    };
    Ok((state, resp))
}

/// Step 3 (Client): Decapsulates server ciphertext, verifies `server_confirm`, and returns `(session_key, finish)`.
pub fn pake_client_finish(
    state: PakeClientState,
    resp: &PakeServerHello,
) -> Result<(SecretKey, PakeClientFinish)> {
    let pq_ss = decapsulate(&state.sk, &resp.kem_ct);
    let kem_ct_bytes = resp.kem_ct.to_bytes();
    if kem_ct_bytes.len() != KEM_CT_BYTES {
        return Err(WilisError::InvalidFormat("invalid KEM ciphertext".into()));
    }
    let (session_key, expected_srv, client_confirm) = derive_pake_keys(
        state.pw_key.as_bytes(),
        pq_ss.as_bytes(),
        &state.salt,
        &state.masked_pk,
        &kem_ct_bytes,
        &state.context,
    );

    // Constant-time verification of server key confirmation
    if !crate::utils::constant_time::ct_eq(&expected_srv, &resp.server_confirm) {
        return Err(WilisError::AuthenticationFailed);
    }

    Ok((session_key, PakeClientFinish { client_confirm }))
}

/// Step 4 (Server): Verifies `client_confirm` in constant time and releases the mutual 256-bit `SecretKey`.
pub fn pake_server_finish(
    state: PakeServerState,
    finish: &PakeClientFinish,
) -> Result<SecretKey> {
    if !crate::utils::constant_time::ct_eq(&state.expected_client_confirm, &finish.client_confirm) {
        return Err(WilisError::AuthenticationFailed);
    }
    Ok(state.session_key.clone())
}
