/*
 * Wilis v0.7.0 — C99 Foreign Function Interface Header (33 exported functions)
 * Standalone zero-dependency post-quantum & symmetric cryptography built on WilisPerm-384.
 */

#ifndef WILIS_H
#define WILIS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WILIS_KEY_BYTES            32
#define WILIS_NONCE_BYTES          24
#define WILIS_SALT_BYTES           24
#define WILIS_TAG_BYTES            32
#define WILIS_SIV_TAG_BYTES        64
#define WILIS_HASH_BYTES           32

#define WILIS_KEM_PK_BYTES         1284
#define WILIS_KEM_SK_BYTES         2600
#define WILIS_KEM_CT_BYTES         1668
#define WILIS_KEM_SS_BYTES         32

#define WILIS_SIGN_PK_BYTES        101
#define WILIS_SIGN_SK_BYTES        137
#define WILIS_SIGN_MAX_SIG_BYTES   2506

#define WILIS_SLH_PK_BYTES         100
#define WILIS_SLH_SK_BYTES         164
#define WILIS_SLH_SIG_BYTES        8165

/* WPSC v1 overhead: 4 magic + 1 ver + 1668 kem_ct + 24 nonce + 8165 slh_sig + 32 tag */
#define WILIS_SIGNCRYPT_OVERHEAD   9894

#define WILIS_OK                   0
#define WILIS_ERR_INVALID_ARG      (-1)
#define WILIS_ERR_AUTH_FAILED      (-2)
#define WILIS_ERR_INTERNAL         (-3)
#define WILIS_ERR_BUF_TOO_SMALL    (-4)

/* --- Metadata & Constant-Time / Memory Safety Utilities --- */

const char *wilis_version(void);

int32_t wilis_ct_eq(
    const uint8_t *a,
    const uint8_t *b,
    size_t len
);

int32_t wilis_zeroize(
    uint8_t *buf,
    size_t len
);

int32_t wilis_random_bytes(
    uint8_t *out,
    size_t len
);

/* --- Hash, Parallel Merkle TreeHash, MAC, Subkey & XOF --- */

int32_t wilis_hash_256(
    const uint8_t *data,
    size_t data_len,
    uint8_t out_32[WILIS_HASH_BYTES]
);

int32_t wilis_tree_hash_256(
    const uint8_t *data,
    size_t data_len,
    uint8_t out_32[WILIS_HASH_BYTES]
);

int32_t wilis_mac_256(
    const uint8_t key_32[WILIS_KEY_BYTES],
    const uint8_t *msg,
    size_t msg_len,
    uint8_t tag_32_out[WILIS_TAG_BYTES]
);

int32_t wilis_subkey_derive(
    const uint8_t master_key_32[WILIS_KEY_BYTES],
    const uint8_t *context,
    size_t context_len,
    uint8_t subkey_32_out[WILIS_KEY_BYTES]
);

int32_t wilis_xof_derive(
    const uint8_t *label,
    size_t label_len,
    const uint8_t *seed,
    size_t seed_len,
    uint8_t *out,
    size_t out_len
);

/* --- Authenticated Encryption (WilisAEAD & Nonce-Misuse-Resistant WilisAEAD-SIV) --- */

int32_t wilis_aead_seal(
    const uint8_t key_32[WILIS_KEY_BYTES],
    const uint8_t nonce_24[WILIS_NONCE_BYTES],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *pt,
    size_t pt_len,
    uint8_t *ct_out,
    uint8_t tag_32_out[WILIS_TAG_BYTES]
);

int32_t wilis_aead_open(
    const uint8_t key_32[WILIS_KEY_BYTES],
    const uint8_t nonce_24[WILIS_NONCE_BYTES],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ct,
    size_t ct_len,
    const uint8_t tag_32[WILIS_TAG_BYTES],
    uint8_t *pt_out
);

int32_t wilis_siv_seal(
    const uint8_t key_32[WILIS_KEY_BYTES],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *pt,
    size_t pt_len,
    uint8_t *ct_out,
    uint8_t siv_tag_64_out[WILIS_SIV_TAG_BYTES]
);

int32_t wilis_siv_open(
    const uint8_t key_32[WILIS_KEY_BYTES],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ct,
    size_t ct_len,
    const uint8_t siv_tag_64[WILIS_SIV_TAG_BYTES],
    uint8_t *pt_out
);

/* --- Memory-Hard KDF (v2 Sequential & v3 Multi-Lane Parallel) --- */

int32_t wilis_kdf_derive(
    const uint8_t *pass,
    size_t pass_len,
    const uint8_t salt_24[WILIS_SALT_BYTES],
    uint32_t memory_blocks,
    uint32_t passes,
    uint8_t key_32_out[WILIS_KEY_BYTES]
);

int32_t wilis_kdf_parallel_derive(
    const uint8_t *pass,
    size_t pass_len,
    const uint8_t salt_24[WILIS_SALT_BYTES],
    uint32_t memory_blocks,
    uint32_t passes,
    uint32_t lanes,
    uint8_t key_32_out[WILIS_KEY_BYTES]
);

/* --- Post-Quantum Module-LWE KEM (NTT-Accelerated IND-CCA2) --- */

int32_t wilis_kem_keygen(
    uint8_t pk_out[WILIS_KEM_PK_BYTES],
    uint8_t sk_out[WILIS_KEM_SK_BYTES]
);

int32_t wilis_kem_encapsulate(
    const uint8_t pk[WILIS_KEM_PK_BYTES],
    uint8_t ct_out[WILIS_KEM_CT_BYTES],
    uint8_t ss_32_out[WILIS_KEM_SS_BYTES]
);

int32_t wilis_kem_decapsulate(
    const uint8_t sk[WILIS_KEM_SK_BYTES],
    const uint8_t ct[WILIS_KEM_CT_BYTES],
    uint8_t ss_32_out[WILIS_KEM_SS_BYTES]
);

/* --- Post-Quantum Digital Signatures (Stateful WOTS+ Merkle & Stateless WilisSLH) --- */

int32_t wilis_sign_keygen(
    uint8_t height,
    uint8_t pk_out[WILIS_SIGN_PK_BYTES],
    uint8_t sk_out[WILIS_SIGN_SK_BYTES]
);

int32_t wilis_sign_message(
    uint8_t sk_inout[WILIS_SIGN_SK_BYTES],
    const uint8_t *msg,
    size_t msg_len,
    uint8_t *sig_out,
    size_t sig_cap,
    size_t *sig_len_out
);

int32_t wilis_verify_message(
    const uint8_t pk[WILIS_SIGN_PK_BYTES],
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t *sig,
    size_t sig_len
);

int32_t wilis_slh_keygen(
    uint8_t pk_out[WILIS_SLH_PK_BYTES],
    uint8_t sk_out[WILIS_SLH_SK_BYTES]
);

int32_t wilis_slh_sign(
    const uint8_t sk[WILIS_SLH_SK_BYTES],
    const uint8_t *msg,
    size_t msg_len,
    uint8_t sig_out[WILIS_SLH_SIG_BYTES]
);

int32_t wilis_slh_verify(
    const uint8_t pk[WILIS_SLH_PK_BYTES],
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t sig[WILIS_SLH_SIG_BYTES]
);

/* --- Post-Quantum Signcryption (WPSC v1 = WilisKEM + WilisSLH + WilisAEAD) --- */

int32_t wilis_signcrypt(
    const uint8_t sender_slh_sk[WILIS_SLH_SK_BYTES],
    const uint8_t recipient_kem_pk[WILIS_KEM_PK_BYTES],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *pt,
    size_t pt_len,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len_out
);

int32_t wilis_unsigncrypt(
    const uint8_t sender_slh_pk[WILIS_SLH_PK_BYTES],
    const uint8_t recipient_kem_sk[WILIS_KEM_SK_BYTES],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *packet,
    size_t packet_len,
    uint8_t *pt_out,
    size_t pt_cap,
    size_t *pt_len_out
);

/* --- Protocols & Utilities (TOTP 2FA, Format-Preserving Encryption, Mnemonic, WilisLZ) --- */

int32_t wilis_totp_at(
    const uint8_t *secret,
    size_t secret_len,
    uint64_t unix_secs,
    uint64_t period,
    uint32_t digits,
    uint8_t *code_out,
    size_t code_cap,
    uint64_t *remaining_out
);

int32_t wilis_fpe_encrypt(
    const uint8_t key_32[WILIS_KEY_BYTES],
    const uint8_t *tweak,
    size_t tweak_len,
    const uint8_t *alphabet,
    size_t alpha_len,
    const uint8_t *pt,
    size_t pt_len,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len_out
);

int32_t wilis_fpe_decrypt(
    const uint8_t key_32[WILIS_KEY_BYTES],
    const uint8_t *tweak,
    size_t tweak_len,
    const uint8_t *alphabet,
    size_t alpha_len,
    const uint8_t *ct,
    size_t ct_len,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len_out
);

int32_t wilis_mnemonic_encode(
    const uint8_t *secret,
    size_t secret_len,
    uint8_t *out_utf8,
    size_t out_cap,
    size_t *out_len_out
);

int32_t wilis_mnemonic_decode(
    const uint8_t *phrase,
    size_t phrase_len,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len_out
);

int32_t wilis_lz_compress(
    const uint8_t *data,
    size_t data_len,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len_out
);

int32_t wilis_lz_decompress(
    const uint8_t *data,
    size_t data_len,
    size_t max_out,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len_out
);

#ifdef __cplusplus
}
#endif

#endif /* WILIS_H */
