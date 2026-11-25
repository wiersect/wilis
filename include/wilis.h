/*
 * Wilis v0.6.0 — C Foreign Function Interface Header
 * Standalone zero-dependency cryptography built on WilisPerm-384.
 */

#ifndef WILIS_H
#define WILIS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WILIS_KEY_BYTES     32
#define WILIS_NONCE_BYTES   24
#define WILIS_SALT_BYTES    24
#define WILIS_TAG_BYTES     32
#define WILIS_SIV_TAG_BYTES 64
#define WILIS_HASH_BYTES    32

#define WILIS_KEM_PK_BYTES       1284
#define WILIS_KEM_SK_BYTES       2600
#define WILIS_KEM_CT_BYTES       1668
#define WILIS_KEM_SS_BYTES       32

#define WILIS_SIGN_PK_BYTES      101
#define WILIS_SIGN_SK_BYTES      137
#define WILIS_SIGN_MAX_SIG_BYTES 2506

#define WILIS_SLH_PK_BYTES       100
#define WILIS_SLH_SK_BYTES       164
#define WILIS_SLH_SIG_BYTES      8165

#define WILIS_OK              0
#define WILIS_ERR_INVALID_ARG (-1)
#define WILIS_ERR_AUTH_FAILED (-2)
#define WILIS_ERR_INTERNAL    (-3)

int32_t wilis_hash_256(
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

int32_t wilis_xof_derive(
    const uint8_t *label,
    size_t label_len,
    const uint8_t *seed,
    size_t seed_len,
    uint8_t *out,
    size_t out_len
);

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

int32_t wilis_kdf_derive(
    const uint8_t *pass,
    size_t pass_len,
    const uint8_t salt_24[WILIS_SALT_BYTES],
    uint32_t memory_blocks,
    uint32_t passes,
    uint8_t key_32_out[WILIS_KEY_BYTES]
);

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

int32_t wilis_random_bytes(
    uint8_t *out,
    size_t len
);

const char *wilis_version(void);

int32_t wilis_subkey_derive(
    const uint8_t master_key_32[WILIS_KEY_BYTES],
    const uint8_t *context,
    size_t context_len,
    uint8_t subkey_32_out[WILIS_KEY_BYTES]
);

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

int32_t wilis_tree_hash_256(
    const uint8_t *data,
    size_t data_len,
    uint8_t out_32[WILIS_HASH_BYTES]
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

#ifdef __cplusplus
}
#endif

#endif /* WILIS_H */
