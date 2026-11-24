/*
 * Wilis v0.4.4 — C Foreign Function Interface Header
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
#define WILIS_HASH_BYTES    32

#define WILIS_KEM_PK_BYTES  1284
#define WILIS_KEM_SK_BYTES  2600
#define WILIS_KEM_CT_BYTES  1668
#define WILIS_KEM_SS_BYTES  32

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

#ifdef __cplusplus
}
#endif

#endif /* WILIS_H */
