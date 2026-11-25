/*
 * Wilis v0.7.0 — Zero-Dependency C++17 Header-Only RAII Wrapper over libwilis (33 functions)
 *
 * Compile example:
 *   c++ -std=c++17 -Wall -Wextra -Werror -Iinclude app.cpp -Ltarget/release -lwilis -Wl,-rpath,target/release -o app
 */

#ifndef WILIS_HPP
#define WILIS_HPP

#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "wilis.h"

namespace wilis {

class Error : public std::runtime_error {
public:
    explicit Error(const std::string &msg) : std::runtime_error(msg) {}
};

class AuthError : public Error {
public:
    explicit AuthError(const std::string &msg = "Wilis authentication/verification failed")
        : Error(msg) {}
};

using Bytes = std::vector<uint8_t>;
using Key = std::array<uint8_t, WILIS_KEY_BYTES>;
using Nonce = std::array<uint8_t, WILIS_NONCE_BYTES>;
using Salt = std::array<uint8_t, WILIS_SALT_BYTES>;
using Tag = std::array<uint8_t, WILIS_TAG_BYTES>;
using SivTag = std::array<uint8_t, WILIS_SIV_TAG_BYTES>;
using Hash = std::array<uint8_t, WILIS_HASH_BYTES>;

using KemPk = std::array<uint8_t, WILIS_KEM_PK_BYTES>;
using KemSk = std::array<uint8_t, WILIS_KEM_SK_BYTES>;
using KemCt = std::array<uint8_t, WILIS_KEM_CT_BYTES>;
using KemSs = std::array<uint8_t, WILIS_KEM_SS_BYTES>;

using SignPk = std::array<uint8_t, WILIS_SIGN_PK_BYTES>;
using SignSk = std::array<uint8_t, WILIS_SIGN_SK_BYTES>;

using SlhPk = std::array<uint8_t, WILIS_SLH_PK_BYTES>;
using SlhSk = std::array<uint8_t, WILIS_SLH_SK_BYTES>;
using SlhSig = std::array<uint8_t, WILIS_SLH_SIG_BYTES>;

/// RAII wrapper that automatically volatile-wipes fixed-size secret buffers via `wilis_zeroize`.
template <size_t N>
class SecretArray {
public:
    std::array<uint8_t, N> bytes{};

    SecretArray() = default;
    explicit SecretArray(const std::array<uint8_t, N> &src) : bytes(src) {}
    SecretArray(const SecretArray &other) : bytes(other.bytes) {}
    SecretArray(SecretArray &&other) noexcept : bytes(other.bytes) {
        wilis_zeroize(other.bytes.data(), other.bytes.size());
    }
    SecretArray &operator=(const SecretArray &other) {
        if (this != &other) {
            wilis_zeroize(bytes.data(), bytes.size());
            bytes = other.bytes;
        }
        return *this;
    }
    SecretArray &operator=(SecretArray &&other) noexcept {
        if (this != &other) {
            wilis_zeroize(bytes.data(), bytes.size());
            bytes = other.bytes;
            wilis_zeroize(other.bytes.data(), other.bytes.size());
        }
        return *this;
    }
    ~SecretArray() { wilis_zeroize(bytes.data(), bytes.size()); }

    const uint8_t *data() const noexcept { return bytes.data(); }
    uint8_t *data() noexcept { return bytes.data(); }
    constexpr size_t size() const noexcept { return N; }
};

namespace detail {
inline void check_rc(int32_t rc, const char *fn) {
    if (rc == WILIS_OK) return;
    if (rc == WILIS_ERR_AUTH_FAILED) throw AuthError(std::string(fn) + ": authentication failed");
    throw Error(std::string(fn) + " failed with code " + std::to_string(rc));
}
inline const uint8_t *ptr_or_null(const Bytes &v) noexcept {
    return v.empty() ? nullptr : v.data();
}
inline uint8_t *mut_or_null(Bytes &v) noexcept {
    return v.empty() ? nullptr : v.data();
}
} // namespace detail

inline std::string version() {
    const char *v = wilis_version();
    return v ? std::string(v) : std::string();
}

inline bool ct_eq(const Bytes &a, const Bytes &b) {
    if (a.size() != b.size()) return false;
    int32_t rc = wilis_ct_eq(detail::ptr_or_null(a), detail::ptr_or_null(b), a.size());
    if (rc < 0) detail::check_rc(rc, "wilis_ct_eq");
    return rc == 1;
}

inline void zeroize(Bytes &buf) {
    if (!buf.empty()) detail::check_rc(wilis_zeroize(buf.data(), buf.size()), "wilis_zeroize");
}

inline Bytes random_bytes(size_t len) {
    Bytes out(len);
    if (len > 0) detail::check_rc(wilis_random_bytes(out.data(), len), "wilis_random_bytes");
    return out;
}

inline Hash hash_256(const Bytes &data) {
    Hash out{};
    detail::check_rc(wilis_hash_256(detail::ptr_or_null(data), data.size(), out.data()), "wilis_hash_256");
    return out;
}

inline Hash tree_hash_256(const Bytes &data) {
    Hash out{};
    detail::check_rc(wilis_tree_hash_256(detail::ptr_or_null(data), data.size(), out.data()), "wilis_tree_hash_256");
    return out;
}

inline Tag mac_256(const Key &key, const Bytes &msg) {
    Tag out{};
    detail::check_rc(wilis_mac_256(key.data(), detail::ptr_or_null(msg), msg.size(), out.data()), "wilis_mac_256");
    return out;
}

inline Key derive_subkey(const Key &master_key, const Bytes &context) {
    Key out{};
    detail::check_rc(
        wilis_subkey_derive(master_key.data(), detail::ptr_or_null(context), context.size(), out.data()),
        "wilis_subkey_derive");
    return out;
}

inline Bytes xof_derive(const Bytes &label, const Bytes &seed, size_t out_len) {
    Bytes out(out_len);
    if (out_len > 0) {
        detail::check_rc(
            wilis_xof_derive(detail::ptr_or_null(label), label.size(), detail::ptr_or_null(seed), seed.size(),
                             out.data(), out_len),
            "wilis_xof_derive");
    }
    return out;
}

inline std::pair<Bytes, Tag> aead_seal(const Key &key, const Nonce &nonce, const Bytes &aad, const Bytes &pt) {
    Bytes ct(pt.size());
    Tag tag{};
    detail::check_rc(
        wilis_aead_seal(key.data(), nonce.data(), detail::ptr_or_null(aad), aad.size(),
                        detail::ptr_or_null(pt), pt.size(), detail::mut_or_null(ct), tag.data()),
        "wilis_aead_seal");
    return {std::move(ct), tag};
}

inline Bytes aead_open(const Key &key, const Nonce &nonce, const Bytes &aad, const Bytes &ct, const Tag &tag) {
    Bytes pt(ct.size());
    detail::check_rc(
        wilis_aead_open(key.data(), nonce.data(), detail::ptr_or_null(aad), aad.size(),
                        detail::ptr_or_null(ct), ct.size(), tag.data(), detail::mut_or_null(pt)),
        "wilis_aead_open");
    return pt;
}

inline std::pair<Bytes, SivTag> siv_seal(const Key &key, const Bytes &aad, const Bytes &pt) {
    Bytes ct(pt.size());
    SivTag tag{};
    detail::check_rc(
        wilis_siv_seal(key.data(), detail::ptr_or_null(aad), aad.size(),
                       detail::ptr_or_null(pt), pt.size(), detail::mut_or_null(ct), tag.data()),
        "wilis_siv_seal");
    return {std::move(ct), tag};
}

inline Bytes siv_open(const Key &key, const Bytes &aad, const Bytes &ct, const SivTag &tag) {
    Bytes pt(ct.size());
    detail::check_rc(
        wilis_siv_open(key.data(), detail::ptr_or_null(aad), aad.size(),
                       detail::ptr_or_null(ct), ct.size(), tag.data(), detail::mut_or_null(pt)),
        "wilis_siv_open");
    return pt;
}

inline Key kdf_derive(const Bytes &pass, const Salt &salt, uint32_t memory_blocks, uint32_t passes) {
    Key out{};
    detail::check_rc(
        wilis_kdf_derive(detail::ptr_or_null(pass), pass.size(), salt.data(), memory_blocks, passes, out.data()),
        "wilis_kdf_derive");
    return out;
}

inline Key kdf_parallel_derive(const Bytes &pass, const Salt &salt, uint32_t memory_blocks, uint32_t passes,
                               uint32_t lanes) {
    Key out{};
    detail::check_rc(
        wilis_kdf_parallel_derive(detail::ptr_or_null(pass), pass.size(), salt.data(), memory_blocks, passes,
                                  lanes, out.data()),
        "wilis_kdf_parallel_derive");
    return out;
}

inline std::pair<KemPk, SecretArray<WILIS_KEM_SK_BYTES>> kem_keygen() {
    KemPk pk{};
    SecretArray<WILIS_KEM_SK_BYTES> sk;
    detail::check_rc(wilis_kem_keygen(pk.data(), sk.data()), "wilis_kem_keygen");
    return {pk, std::move(sk)};
}

inline std::pair<KemCt, SecretArray<WILIS_KEM_SS_BYTES>> kem_encapsulate(const KemPk &pk) {
    KemCt ct{};
    SecretArray<WILIS_KEM_SS_BYTES> ss;
    detail::check_rc(wilis_kem_encapsulate(pk.data(), ct.data(), ss.data()), "wilis_kem_encapsulate");
    return {ct, std::move(ss)};
}

inline SecretArray<WILIS_KEM_SS_BYTES> kem_decapsulate(const SecretArray<WILIS_KEM_SK_BYTES> &sk, const KemCt &ct) {
    SecretArray<WILIS_KEM_SS_BYTES> ss;
    detail::check_rc(wilis_kem_decapsulate(sk.data(), ct.data(), ss.data()), "wilis_kem_decapsulate");
    return ss;
}

inline std::pair<SignPk, SecretArray<WILIS_SIGN_SK_BYTES>> sign_keygen(uint8_t height = 6) {
    SignPk pk{};
    SecretArray<WILIS_SIGN_SK_BYTES> sk;
    detail::check_rc(wilis_sign_keygen(height, pk.data(), sk.data()), "wilis_sign_keygen");
    return {pk, std::move(sk)};
}

inline Bytes sign_message(SecretArray<WILIS_SIGN_SK_BYTES> &sk_inout, const Bytes &msg) {
    Bytes sig(WILIS_SIGN_MAX_SIG_BYTES);
    size_t sig_len = 0;
    detail::check_rc(
        wilis_sign_message(sk_inout.data(), detail::ptr_or_null(msg), msg.size(), sig.data(), sig.size(), &sig_len),
        "wilis_sign_message");
    sig.resize(sig_len);
    return sig;
}

inline bool verify_message(const SignPk &pk, const Bytes &msg, const Bytes &sig) {
    int32_t rc = wilis_verify_message(pk.data(), detail::ptr_or_null(msg), msg.size(),
                                      detail::ptr_or_null(sig), sig.size());
    if (rc == WILIS_OK) return true;
    if (rc == WILIS_ERR_AUTH_FAILED) return false;
    detail::check_rc(rc, "wilis_verify_message");
    return false;
}

inline std::pair<SlhPk, SecretArray<WILIS_SLH_SK_BYTES>> slh_keygen() {
    SlhPk pk{};
    SecretArray<WILIS_SLH_SK_BYTES> sk;
    detail::check_rc(wilis_slh_keygen(pk.data(), sk.data()), "wilis_slh_keygen");
    return {pk, std::move(sk)};
}

inline SlhSig slh_sign(const SecretArray<WILIS_SLH_SK_BYTES> &sk, const Bytes &msg) {
    SlhSig sig{};
    detail::check_rc(wilis_slh_sign(sk.data(), detail::ptr_or_null(msg), msg.size(), sig.data()), "wilis_slh_sign");
    return sig;
}

inline bool slh_verify(const SlhPk &pk, const Bytes &msg, const SlhSig &sig) {
    int32_t rc = wilis_slh_verify(pk.data(), detail::ptr_or_null(msg), msg.size(), sig.data());
    if (rc == WILIS_OK) return true;
    if (rc == WILIS_ERR_AUTH_FAILED) return false;
    detail::check_rc(rc, "wilis_slh_verify");
    return false;
}

inline Bytes signcrypt(const SecretArray<WILIS_SLH_SK_BYTES> &sender_sk, const KemPk &recipient_pk,
                       const Bytes &aad, const Bytes &pt) {
    Bytes out(WILIS_SIGNCRYPT_OVERHEAD + pt.size());
    size_t out_len = 0;
    detail::check_rc(
        wilis_signcrypt(sender_sk.data(), recipient_pk.data(), detail::ptr_or_null(aad), aad.size(),
                        detail::ptr_or_null(pt), pt.size(), out.data(), out.size(), &out_len),
        "wilis_signcrypt");
    out.resize(out_len);
    return out;
}

inline Bytes unsigncrypt(const SlhPk &sender_pk, const SecretArray<WILIS_KEM_SK_BYTES> &recipient_sk,
                         const Bytes &aad, const Bytes &packet) {
    size_t cap = packet.size() >= WILIS_SIGNCRYPT_OVERHEAD ? (packet.size() - WILIS_SIGNCRYPT_OVERHEAD) : 0;
    Bytes pt(cap);
    size_t out_len = 0;
    detail::check_rc(
        wilis_unsigncrypt(sender_pk.data(), recipient_sk.data(), detail::ptr_or_null(aad), aad.size(),
                          detail::ptr_or_null(packet), packet.size(), detail::mut_or_null(pt), pt.size(), &out_len),
        "wilis_unsigncrypt");
    pt.resize(out_len);
    return pt;
}

inline std::pair<std::string, uint64_t> totp_at(const Bytes &secret, uint64_t unix_secs,
                                                uint64_t period = 30, uint32_t digits = 6) {
    std::array<uint8_t, 16> buf{};
    uint64_t rem = 0;
    detail::check_rc(
        wilis_totp_at(detail::ptr_or_null(secret), secret.size(), unix_secs, period, digits,
                      buf.data(), buf.size(), &rem),
        "wilis_totp_at");
    return {std::string(reinterpret_cast<const char *>(buf.data())), rem};
}

inline std::string fpe_encrypt(const Key &key, const Bytes &tweak, const std::string &alphabet,
                               const std::string &pt) {
    std::string out(pt.size() + 16, '\0');
    size_t out_len = 0;
    int32_t rc = wilis_fpe_encrypt(
        key.data(), detail::ptr_or_null(tweak), tweak.size(),
        reinterpret_cast<const uint8_t *>(alphabet.data()), alphabet.size(),
        reinterpret_cast<const uint8_t *>(pt.data()), pt.size(),
        reinterpret_cast<uint8_t *>(&out[0]), out.size(), &out_len);
    if (rc == WILIS_ERR_BUF_TOO_SMALL) {
        out.resize(out_len);
        rc = wilis_fpe_encrypt(
            key.data(), detail::ptr_or_null(tweak), tweak.size(),
            reinterpret_cast<const uint8_t *>(alphabet.data()), alphabet.size(),
            reinterpret_cast<const uint8_t *>(pt.data()), pt.size(),
            reinterpret_cast<uint8_t *>(&out[0]), out.size(), &out_len);
    }
    detail::check_rc(rc, "wilis_fpe_encrypt");
    out.resize(out_len);
    return out;
}

inline std::string fpe_decrypt(const Key &key, const Bytes &tweak, const std::string &alphabet,
                               const std::string &ct) {
    std::string out(ct.size() + 16, '\0');
    size_t out_len = 0;
    int32_t rc = wilis_fpe_decrypt(
        key.data(), detail::ptr_or_null(tweak), tweak.size(),
        reinterpret_cast<const uint8_t *>(alphabet.data()), alphabet.size(),
        reinterpret_cast<const uint8_t *>(ct.data()), ct.size(),
        reinterpret_cast<uint8_t *>(&out[0]), out.size(), &out_len);
    if (rc == WILIS_ERR_BUF_TOO_SMALL) {
        out.resize(out_len);
        rc = wilis_fpe_decrypt(
            key.data(), detail::ptr_or_null(tweak), tweak.size(),
            reinterpret_cast<const uint8_t *>(alphabet.data()), alphabet.size(),
            reinterpret_cast<const uint8_t *>(ct.data()), ct.size(),
            reinterpret_cast<uint8_t *>(&out[0]), out.size(), &out_len);
    }
    detail::check_rc(rc, "wilis_fpe_decrypt");
    out.resize(out_len);
    return out;
}

inline std::string mnemonic_encode(const Bytes &secret) {
    size_t needed = 0;
    int32_t rc = wilis_mnemonic_encode(detail::ptr_or_null(secret), secret.size(), nullptr, 0, &needed);
    if (rc != WILIS_ERR_BUF_TOO_SMALL && rc != WILIS_OK) detail::check_rc(rc, "wilis_mnemonic_encode");
    std::string out(needed, '\0');
    detail::check_rc(
        wilis_mnemonic_encode(detail::ptr_or_null(secret), secret.size(),
                              reinterpret_cast<uint8_t *>(&out[0]), out.size(), &needed),
        "wilis_mnemonic_encode");
    out.resize(needed);
    return out;
}

inline Bytes mnemonic_decode(const std::string &phrase) {
    size_t needed = 0;
    int32_t rc = wilis_mnemonic_decode(reinterpret_cast<const uint8_t *>(phrase.data()), phrase.size(),
                                       nullptr, 0, &needed);
    if (rc != WILIS_ERR_BUF_TOO_SMALL && rc != WILIS_OK) detail::check_rc(rc, "wilis_mnemonic_decode");
    Bytes out(needed);
    detail::check_rc(
        wilis_mnemonic_decode(reinterpret_cast<const uint8_t *>(phrase.data()), phrase.size(),
                              detail::mut_or_null(out), out.size(), &needed),
        "wilis_mnemonic_decode");
    out.resize(needed);
    return out;
}

inline Bytes lz_compress(const Bytes &data) {
    size_t needed = 0;
    int32_t rc = wilis_lz_compress(detail::ptr_or_null(data), data.size(), nullptr, 0, &needed);
    if (rc != WILIS_ERR_BUF_TOO_SMALL && rc != WILIS_OK) detail::check_rc(rc, "wilis_lz_compress");
    Bytes out(needed);
    detail::check_rc(
        wilis_lz_compress(detail::ptr_or_null(data), data.size(), detail::mut_or_null(out), out.size(), &needed),
        "wilis_lz_compress");
    out.resize(needed);
    return out;
}

inline Bytes lz_decompress(const Bytes &data, size_t max_out) {
    size_t needed = 0;
    int32_t rc = wilis_lz_decompress(detail::ptr_or_null(data), data.size(), max_out, nullptr, 0, &needed);
    if (rc != WILIS_ERR_BUF_TOO_SMALL && rc != WILIS_OK) detail::check_rc(rc, "wilis_lz_decompress");
    Bytes out(needed);
    detail::check_rc(
        wilis_lz_decompress(detail::ptr_or_null(data), data.size(), max_out, detail::mut_or_null(out), out.size(),
                            &needed),
        "wilis_lz_decompress");
    out.resize(needed);
    return out;
}

} // namespace wilis

#endif /* WILIS_HPP */
