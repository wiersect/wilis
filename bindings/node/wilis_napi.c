/*
 * Zero-NPM-Dependency Native Node-API (N-API) C Addon for Wilis v0.7.0 (`libwilis`).
 *
 * Compiles directly against Node's built-in `node_api.h` + `include/wilis.h` with zero npm deps:
 *   node-gyp rebuild   (or cc -shared -fPIC -I<node_include> -I../../include wilis_napi.c -L../../target/release -lwilis -o wilis_napi.node)
 */

#define NAPI_VERSION 8
#include <node_api.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "wilis.h"

static napi_value throw_err(napi_env env, const char *msg) {
    napi_throw_error(env, NULL, msg);
    return NULL;
}

static napi_value fn_version(napi_env env, napi_callback_info info) {
    (void)info;
    napi_value out;
    napi_create_string_utf8(env, wilis_version(), NAPI_AUTO_LENGTH, &out);
    return out;
}

static napi_value fn_hash256(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    if (argc < 1) return throw_err(env, "hash256 requires a Buffer argument");
    void *data = NULL;
    size_t len = 0;
    if (napi_get_buffer_info(env, argv[0], &data, &len) != napi_ok)
        return throw_err(env, "expected Buffer");
    void *out_ptr = NULL;
    napi_value out_buf;
    napi_create_buffer(env, WILIS_HASH_BYTES, &out_ptr, &out_buf);
    if (wilis_hash_256((const uint8_t *)data, len, (uint8_t *)out_ptr) != WILIS_OK)
        return throw_err(env, "wilis_hash_256 failed");
    return out_buf;
}

static napi_value fn_tree_hash256(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value argv[1];
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    if (argc < 1) return throw_err(env, "treeHash256 requires a Buffer argument");
    void *data = NULL;
    size_t len = 0;
    if (napi_get_buffer_info(env, argv[0], &data, &len) != napi_ok)
        return throw_err(env, "expected Buffer");
    void *out_ptr = NULL;
    napi_value out_buf;
    napi_create_buffer(env, WILIS_HASH_BYTES, &out_ptr, &out_buf);
    if (wilis_tree_hash_256((const uint8_t *)data, len, (uint8_t *)out_ptr) != WILIS_OK)
        return throw_err(env, "wilis_tree_hash_256 failed");
    return out_buf;
}

static napi_value fn_aead_seal(napi_env env, napi_callback_info info) {
    size_t argc = 4;
    napi_value argv[4];
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    if (argc < 4) return throw_err(env, "aeadSeal(key, nonce, aad, pt) requires 4 Buffers");
    void *key, *nonce, *aad, *pt;
    size_t klen, nlen, alen, plen;
    if (napi_get_buffer_info(env, argv[0], &key, &klen) != napi_ok || klen != WILIS_KEY_BYTES ||
        napi_get_buffer_info(env, argv[1], &nonce, &nlen) != napi_ok || nlen != WILIS_NONCE_BYTES ||
        napi_get_buffer_info(env, argv[2], &aad, &alen) != napi_ok ||
        napi_get_buffer_info(env, argv[3], &pt, &plen) != napi_ok)
        return throw_err(env, "invalid Buffer lengths");

    void *ct_ptr = NULL, *tag_ptr = NULL;
    napi_value ct_buf, tag_buf, res;
    napi_create_buffer(env, plen, &ct_ptr, &ct_buf);
    napi_create_buffer(env, WILIS_TAG_BYTES, &tag_ptr, &tag_buf);
    if (wilis_aead_seal((const uint8_t *)key, (const uint8_t *)nonce,
                        (const uint8_t *)aad, alen, (const uint8_t *)pt, plen,
                        (uint8_t *)ct_ptr, (uint8_t *)tag_ptr) != WILIS_OK)
        return throw_err(env, "wilis_aead_seal failed");
    napi_create_object(env, &res);
    napi_set_named_property(env, res, "ciphertext", ct_buf);
    napi_set_named_property(env, res, "tag", tag_buf);
    return res;
}

static napi_value fn_aead_open(napi_env env, napi_callback_info info) {
    size_t argc = 5;
    napi_value argv[5];
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    if (argc < 5) return throw_err(env, "aeadOpen(key, nonce, aad, ct, tag) requires 5 Buffers");
    void *key, *nonce, *aad, *ct, *tag;
    size_t klen, nlen, alen, clen, tlen;
    if (napi_get_buffer_info(env, argv[0], &key, &klen) != napi_ok || klen != WILIS_KEY_BYTES ||
        napi_get_buffer_info(env, argv[1], &nonce, &nlen) != napi_ok || nlen != WILIS_NONCE_BYTES ||
        napi_get_buffer_info(env, argv[2], &aad, &alen) != napi_ok ||
        napi_get_buffer_info(env, argv[3], &ct, &clen) != napi_ok ||
        napi_get_buffer_info(env, argv[4], &tag, &tlen) != napi_ok || tlen != WILIS_TAG_BYTES)
        return throw_err(env, "invalid Buffer lengths");

    void *pt_ptr = NULL;
    napi_value pt_buf;
    napi_create_buffer(env, clen, &pt_ptr, &pt_buf);
    int32_t rc = wilis_aead_open((const uint8_t *)key, (const uint8_t *)nonce,
                                 (const uint8_t *)aad, alen, (const uint8_t *)ct, clen,
                                 (const uint8_t *)tag, (uint8_t *)pt_ptr);
    if (rc == WILIS_ERR_AUTH_FAILED) return throw_err(env, "authentication failed");
    if (rc != WILIS_OK) return throw_err(env, "wilis_aead_open failed");
    return pt_buf;
}

static napi_value fn_kem_keygen(napi_env env, napi_callback_info info) {
    (void)info;
    void *pk_ptr = NULL, *sk_ptr = NULL;
    napi_value pk_buf, sk_buf, res;
    napi_create_buffer(env, WILIS_KEM_PK_BYTES, &pk_ptr, &pk_buf);
    napi_create_buffer(env, WILIS_KEM_SK_BYTES, &sk_ptr, &sk_buf);
    if (wilis_kem_keygen((uint8_t *)pk_ptr, (uint8_t *)sk_ptr) != WILIS_OK)
        return throw_err(env, "wilis_kem_keygen failed");
    napi_create_object(env, &res);
    napi_set_named_property(env, res, "publicKey", pk_buf);
    napi_set_named_property(env, res, "secretKey", sk_buf);
    return res;
}

static napi_value init(napi_env env, napi_value exports) {
    napi_property_descriptor props[] = {
        {"version", NULL, fn_version, NULL, NULL, NULL, napi_default, NULL},
        {"hash256", NULL, fn_hash256, NULL, NULL, NULL, napi_default, NULL},
        {"treeHash256", NULL, fn_tree_hash256, NULL, NULL, NULL, napi_default, NULL},
        {"aeadSeal", NULL, fn_aead_seal, NULL, NULL, NULL, napi_default, NULL},
        {"aeadOpen", NULL, fn_aead_open, NULL, NULL, NULL, napi_default, NULL},
        {"kemKeygen", NULL, fn_kem_keygen, NULL, NULL, NULL, napi_default, NULL},
    };
    napi_define_properties(env, exports, sizeof(props) / sizeof(props[0]), props);
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
