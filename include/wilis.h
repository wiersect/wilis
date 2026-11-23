/*
 * Wilis v0.3.0 — C Foreign Function Interface Header
 * Standalone zero-dependency cryptography built on WilisPerm-384.
 */

#ifndef WILIS_H
#define WILIS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WILIS_KEY_BYTES   32
#define WILIS_NONCE_BYTES 24
#define WILIS_SALT_BYTES  24
#define WILIS_TAG_BYTES   32
#define WILIS_HASH_BYTES  32

#define WILIS_OK              0
#define WILIS_ERR_INVALID_ARG (-1)
#define WILIS_ERR_AUTH_FAILED (-2)
#define WILIS_ERR_INTERNAL    (-3)

int32_t wilis_hash_256(
    const uint8_t *data,
    size_t data_len,
    uint8_t out_32[WILIS_HASH_BYTES]
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

int32_t wilis_random_bytes(
    uint8_t *out,
    size_t len
);

#ifdef __cplusplus
}
#endif

#endif /* WILIS_H */
