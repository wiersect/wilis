// Package wilis provides complete, zero-dependency Go (cgo) bindings for ALL 33 functions
// exported by the native Wilis v0.7.0 C-ABI (`libwilis` + `include/wilis.h`).
//
// Build the shared library first:
//
//	cargo build --release
//
// Then run tests with:
//
//	cd bindings/go && LD_LIBRARY_PATH=../../target/release go test -v ./...
package wilis

/*
#cgo CFLAGS: -I../../include
#cgo linux LDFLAGS: -L../../target/release -lwilis -Wl,-rpath,${SRCDIR}/../../target/release
#cgo darwin LDFLAGS: -L../../target/release -lwilis -Wl,-rpath,${SRCDIR}/../../target/release
#cgo windows LDFLAGS: -L../../target/release -lwilis
#include <stdint.h>
#include <stdlib.h>
#include "wilis.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

const (
	KeyBytes          = C.WILIS_KEY_BYTES
	NonceBytes        = C.WILIS_NONCE_BYTES
	SaltBytes         = C.WILIS_SALT_BYTES
	TagBytes          = C.WILIS_TAG_BYTES
	SivTagBytes       = C.WILIS_SIV_TAG_BYTES
	HashBytes         = C.WILIS_HASH_BYTES
	KemPkBytes        = C.WILIS_KEM_PK_BYTES
	KemSkBytes        = C.WILIS_KEM_SK_BYTES
	KemCtBytes        = C.WILIS_KEM_CT_BYTES
	KemSsBytes        = C.WILIS_KEM_SS_BYTES
	SignPkBytes       = C.WILIS_SIGN_PK_BYTES
	SignSkBytes       = C.WILIS_SIGN_SK_BYTES
	SignMaxSigBytes   = C.WILIS_SIGN_MAX_SIG_BYTES
	SlhPkBytes        = C.WILIS_SLH_PK_BYTES
	SlhSkBytes        = C.WILIS_SLH_SK_BYTES
	SlhSigBytes       = C.WILIS_SLH_SIG_BYTES
	SigncryptOverhead = C.WILIS_SIGNCRYPT_OVERHEAD
)

var (
	ErrInvalidArg  = errors.New("wilis: invalid argument")
	ErrAuthFailed  = errors.New("wilis: authentication or verification failed")
	ErrInternal    = errors.New("wilis: internal or OS CSPRNG error")
	ErrBufTooSmall = errors.New("wilis: output buffer too small")
)

func mapErr(rc C.int32_t) error {
	switch rc {
	case C.WILIS_OK:
		return nil
	case C.WILIS_ERR_AUTH_FAILED:
		return ErrAuthFailed
	case C.WILIS_ERR_INVALID_ARG:
		return ErrInvalidArg
	case C.WILIS_ERR_BUF_TOO_SMALL:
		return ErrBufTooSmall
	default:
		return ErrInternal
	}
}

func bytePtr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

func Version() string { return C.GoString(C.wilis_version()) }

func ConstantTimeEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return C.wilis_ct_eq(bytePtr(a), bytePtr(b), C.size_t(len(a))) == 1
}

func Zeroize(buf []byte) {
	if len(buf) > 0 {
		C.wilis_zeroize(bytePtr(buf), C.size_t(len(buf)))
	}
}

func RandomBytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, ErrInvalidArg
	}
	out := make([]byte, n)
	if n == 0 {
		return out, nil
	}
	return out, mapErr(C.wilis_random_bytes(bytePtr(out), C.size_t(n)))
}

func Hash256(data []byte) ([HashBytes]byte, error) {
	var out [HashBytes]byte
	rc := C.wilis_hash_256(bytePtr(data), C.size_t(len(data)), (*C.uint8_t)(unsafe.Pointer(&out[0])))
	return out, mapErr(rc)
}

func TreeHash256(data []byte) ([HashBytes]byte, error) {
	var out [HashBytes]byte
	rc := C.wilis_tree_hash_256(bytePtr(data), C.size_t(len(data)), (*C.uint8_t)(unsafe.Pointer(&out[0])))
	return out, mapErr(rc)
}

func Mac256(key [KeyBytes]byte, msg []byte) ([TagBytes]byte, error) {
	var out [TagBytes]byte
	rc := C.wilis_mac_256((*C.uint8_t)(unsafe.Pointer(&key[0])), bytePtr(msg), C.size_t(len(msg)), (*C.uint8_t)(unsafe.Pointer(&out[0])))
	return out, mapErr(rc)
}

func DeriveSubkey(masterKey [KeyBytes]byte, context []byte) ([KeyBytes]byte, error) {
	var out [KeyBytes]byte
	rc := C.wilis_subkey_derive((*C.uint8_t)(unsafe.Pointer(&masterKey[0])), bytePtr(context), C.size_t(len(context)), (*C.uint8_t)(unsafe.Pointer(&out[0])))
	return out, mapErr(rc)
}

func XofDerive(label, seed []byte, outLen int) ([]byte, error) {
	if outLen < 0 {
		return nil, ErrInvalidArg
	}
	out := make([]byte, outLen)
	if outLen == 0 {
		return out, nil
	}
	rc := C.wilis_xof_derive(bytePtr(label), C.size_t(len(label)), bytePtr(seed), C.size_t(len(seed)), bytePtr(out), C.size_t(outLen))
	return out, mapErr(rc)
}

func AeadSeal(key [KeyBytes]byte, nonce [NonceBytes]byte, aad, pt []byte) ([]byte, [TagBytes]byte, error) {
	ct := make([]byte, len(pt))
	var tag [TagBytes]byte
	rc := C.wilis_aead_seal(
		(*C.uint8_t)(unsafe.Pointer(&key[0])), (*C.uint8_t)(unsafe.Pointer(&nonce[0])),
		bytePtr(aad), C.size_t(len(aad)), bytePtr(pt), C.size_t(len(pt)),
		bytePtr(ct), (*C.uint8_t)(unsafe.Pointer(&tag[0])),
	)
	return ct, tag, mapErr(rc)
}

func AeadOpen(key [KeyBytes]byte, nonce [NonceBytes]byte, aad, ct []byte, tag [TagBytes]byte) ([]byte, error) {
	pt := make([]byte, len(ct))
	rc := C.wilis_aead_open(
		(*C.uint8_t)(unsafe.Pointer(&key[0])), (*C.uint8_t)(unsafe.Pointer(&nonce[0])),
		bytePtr(aad), C.size_t(len(aad)), bytePtr(ct), C.size_t(len(ct)),
		(*C.uint8_t)(unsafe.Pointer(&tag[0])), bytePtr(pt),
	)
	if err := mapErr(rc); err != nil {
		return nil, err
	}
	return pt, nil
}

func SivSeal(key [KeyBytes]byte, aad, pt []byte) ([]byte, [SivTagBytes]byte, error) {
	ct := make([]byte, len(pt))
	var tag [SivTagBytes]byte
	rc := C.wilis_siv_seal(
		(*C.uint8_t)(unsafe.Pointer(&key[0])), bytePtr(aad), C.size_t(len(aad)),
		bytePtr(pt), C.size_t(len(pt)), bytePtr(ct), (*C.uint8_t)(unsafe.Pointer(&tag[0])),
	)
	return ct, tag, mapErr(rc)
}

func SivOpen(key [KeyBytes]byte, aad, ct []byte, tag [SivTagBytes]byte) ([]byte, error) {
	pt := make([]byte, len(ct))
	rc := C.wilis_siv_open(
		(*C.uint8_t)(unsafe.Pointer(&key[0])), bytePtr(aad), C.size_t(len(aad)),
		bytePtr(ct), C.size_t(len(ct)), (*C.uint8_t)(unsafe.Pointer(&tag[0])), bytePtr(pt),
	)
	if err := mapErr(rc); err != nil {
		return nil, err
	}
	return pt, nil
}

func KdfDerive(pass []byte, salt [SaltBytes]byte, memoryBlocks, passes uint32) ([KeyBytes]byte, error) {
	var out [KeyBytes]byte
	rc := C.wilis_kdf_derive(bytePtr(pass), C.size_t(len(pass)), (*C.uint8_t)(unsafe.Pointer(&salt[0])),
		C.uint32_t(memoryBlocks), C.uint32_t(passes), (*C.uint8_t)(unsafe.Pointer(&out[0])))
	return out, mapErr(rc)
}

func KdfParallelDerive(pass []byte, salt [SaltBytes]byte, memoryBlocks, passes, lanes uint32) ([KeyBytes]byte, error) {
	var out [KeyBytes]byte
	rc := C.wilis_kdf_parallel_derive(bytePtr(pass), C.size_t(len(pass)), (*C.uint8_t)(unsafe.Pointer(&salt[0])),
		C.uint32_t(memoryBlocks), C.uint32_t(passes), C.uint32_t(lanes), (*C.uint8_t)(unsafe.Pointer(&out[0])))
	return out, mapErr(rc)
}

func KemKeygen() ([KemPkBytes]byte, [KemSkBytes]byte, error) {
	var pk [KemPkBytes]byte
	var sk [KemSkBytes]byte
	rc := C.wilis_kem_keygen((*C.uint8_t)(unsafe.Pointer(&pk[0])), (*C.uint8_t)(unsafe.Pointer(&sk[0])))
	return pk, sk, mapErr(rc)
}

func KemEncapsulate(pk [KemPkBytes]byte) ([KemCtBytes]byte, [KemSsBytes]byte, error) {
	var ct [KemCtBytes]byte
	var ss [KemSsBytes]byte
	rc := C.wilis_kem_encapsulate((*C.uint8_t)(unsafe.Pointer(&pk[0])), (*C.uint8_t)(unsafe.Pointer(&ct[0])), (*C.uint8_t)(unsafe.Pointer(&ss[0])))
	return ct, ss, mapErr(rc)
}

func KemDecapsulate(sk [KemSkBytes]byte, ct [KemCtBytes]byte) ([KemSsBytes]byte, error) {
	var ss [KemSsBytes]byte
	rc := C.wilis_kem_decapsulate((*C.uint8_t)(unsafe.Pointer(&sk[0])), (*C.uint8_t)(unsafe.Pointer(&ct[0])), (*C.uint8_t)(unsafe.Pointer(&ss[0])))
	return ss, mapErr(rc)
}

func SignKeygen(height uint8) ([SignPkBytes]byte, [SignSkBytes]byte, error) {
	var pk [SignPkBytes]byte
	var sk [SignSkBytes]byte
	rc := C.wilis_sign_keygen(C.uint8_t(height), (*C.uint8_t)(unsafe.Pointer(&pk[0])), (*C.uint8_t)(unsafe.Pointer(&sk[0])))
	return pk, sk, mapErr(rc)
}

func SignMessage(sk *[SignSkBytes]byte, msg []byte) ([]byte, error) {
	sig := make([]byte, SignMaxSigBytes)
	var sigLen C.size_t
	rc := C.wilis_sign_message((*C.uint8_t)(unsafe.Pointer(&sk[0])), bytePtr(msg), C.size_t(len(msg)),
		bytePtr(sig), C.size_t(len(sig)), &sigLen)
	if err := mapErr(rc); err != nil {
		return nil, err
	}
	return sig[:int(sigLen)], nil
}

func VerifyMessage(pk [SignPkBytes]byte, msg, sig []byte) bool {
	return C.wilis_verify_message((*C.uint8_t)(unsafe.Pointer(&pk[0])), bytePtr(msg), C.size_t(len(msg)),
		bytePtr(sig), C.size_t(len(sig))) == C.WILIS_OK
}

func SlhKeygen() ([SlhPkBytes]byte, [SlhSkBytes]byte, error) {
	var pk [SlhPkBytes]byte
	var sk [SlhSkBytes]byte
	rc := C.wilis_slh_keygen((*C.uint8_t)(unsafe.Pointer(&pk[0])), (*C.uint8_t)(unsafe.Pointer(&sk[0])))
	return pk, sk, mapErr(rc)
}

func SlhSign(sk [SlhSkBytes]byte, msg []byte) ([SlhSigBytes]byte, error) {
	var sig [SlhSigBytes]byte
	rc := C.wilis_slh_sign((*C.uint8_t)(unsafe.Pointer(&sk[0])), bytePtr(msg), C.size_t(len(msg)), (*C.uint8_t)(unsafe.Pointer(&sig[0])))
	return sig, mapErr(rc)
}

func SlhVerify(pk [SlhPkBytes]byte, msg []byte, sig [SlhSigBytes]byte) bool {
	return C.wilis_slh_verify((*C.uint8_t)(unsafe.Pointer(&pk[0])), bytePtr(msg), C.size_t(len(msg)), (*C.uint8_t)(unsafe.Pointer(&sig[0]))) == C.WILIS_OK
}

func Signcrypt(senderSk [SlhSkBytes]byte, recipientPk [KemPkBytes]byte, aad, pt []byte) ([]byte, error) {
	out := make([]byte, SigncryptOverhead+len(pt))
	var outLen C.size_t
	rc := C.wilis_signcrypt(
		(*C.uint8_t)(unsafe.Pointer(&senderSk[0])), (*C.uint8_t)(unsafe.Pointer(&recipientPk[0])),
		bytePtr(aad), C.size_t(len(aad)), bytePtr(pt), C.size_t(len(pt)),
		bytePtr(out), C.size_t(len(out)), &outLen,
	)
	if err := mapErr(rc); err != nil {
		return nil, err
	}
	return out[:int(outLen)], nil
}

func Unsigncrypt(senderPk [SlhPkBytes]byte, recipientSk [KemSkBytes]byte, aad, packet []byte) ([]byte, error) {
	capLen := len(packet) - SigncryptOverhead
	if capLen < 0 {
		capLen = 0
	}
	out := make([]byte, capLen)
	var outLen C.size_t
	rc := C.wilis_unsigncrypt(
		(*C.uint8_t)(unsafe.Pointer(&senderPk[0])), (*C.uint8_t)(unsafe.Pointer(&recipientSk[0])),
		bytePtr(aad), C.size_t(len(aad)), bytePtr(packet), C.size_t(len(packet)),
		bytePtr(out), C.size_t(len(out)), &outLen,
	)
	if err := mapErr(rc); err != nil {
		return nil, err
	}
	return out[:int(outLen)], nil
}

func TotpAt(secret []byte, unixSecs, period uint64, digits uint32) (string, uint64, error) {
	var buf [16]byte
	var rem C.uint64_t
	rc := C.wilis_totp_at(bytePtr(secret), C.size_t(len(secret)), C.uint64_t(unixSecs), C.uint64_t(period),
		C.uint32_t(digits), (*C.uint8_t)(unsafe.Pointer(&buf[0])), 16, &rem)
	if err := mapErr(rc); err != nil {
		return "", 0, err
	}
	return C.GoString((*C.char)(unsafe.Pointer(&buf[0]))), uint64(rem), nil
}

func FpeEncrypt(key [KeyBytes]byte, tweak []byte, alphabet, pt string) (string, error) {
	ab, pb := []byte(alphabet), []byte(pt)
	out := make([]byte, len(pb)*4+16)
	var outLen C.size_t
	rc := C.wilis_fpe_encrypt((*C.uint8_t)(unsafe.Pointer(&key[0])), bytePtr(tweak), C.size_t(len(tweak)),
		bytePtr(ab), C.size_t(len(ab)), bytePtr(pb), C.size_t(len(pb)), bytePtr(out), C.size_t(len(out)), &outLen)
	if err := mapErr(rc); err != nil {
		return "", err
	}
	return string(out[:int(outLen)]), nil
}

func FpeDecrypt(key [KeyBytes]byte, tweak []byte, alphabet, ct string) (string, error) {
	ab, cb := []byte(alphabet), []byte(ct)
	out := make([]byte, len(cb)*4+16)
	var outLen C.size_t
	rc := C.wilis_fpe_decrypt((*C.uint8_t)(unsafe.Pointer(&key[0])), bytePtr(tweak), C.size_t(len(tweak)),
		bytePtr(ab), C.size_t(len(ab)), bytePtr(cb), C.size_t(len(cb)), bytePtr(out), C.size_t(len(out)), &outLen)
	if err := mapErr(rc); err != nil {
		return "", err
	}
	return string(out[:int(outLen)]), nil
}

func MnemonicEncode(secret []byte) (string, error) {
	var needed C.size_t
	rc := C.wilis_mnemonic_encode(bytePtr(secret), C.size_t(len(secret)), nil, 0, &needed)
	if rc != C.WILIS_ERR_BUF_TOO_SMALL && rc != C.WILIS_OK {
		return "", mapErr(rc)
	}
	out := make([]byte, int(needed))
	rc = C.wilis_mnemonic_encode(bytePtr(secret), C.size_t(len(secret)), bytePtr(out), needed, &needed)
	if err := mapErr(rc); err != nil {
		return "", err
	}
	return string(out[:int(needed)]), nil
}

func MnemonicDecode(phrase string) ([]byte, error) {
	pb := []byte(phrase)
	var needed C.size_t
	rc := C.wilis_mnemonic_decode(bytePtr(pb), C.size_t(len(pb)), nil, 0, &needed)
	if rc != C.WILIS_ERR_BUF_TOO_SMALL && rc != C.WILIS_OK {
		return nil, mapErr(rc)
	}
	out := make([]byte, int(needed))
	rc = C.wilis_mnemonic_decode(bytePtr(pb), C.size_t(len(pb)), bytePtr(out), needed, &needed)
	if err := mapErr(rc); err != nil {
		return nil, err
	}
	return out[:int(needed)], nil
}

func LzCompress(data []byte) ([]byte, error) {
	var needed C.size_t
	rc := C.wilis_lz_compress(bytePtr(data), C.size_t(len(data)), nil, 0, &needed)
	if rc != C.WILIS_ERR_BUF_TOO_SMALL && rc != C.WILIS_OK {
		return nil, mapErr(rc)
	}
	out := make([]byte, int(needed))
	rc = C.wilis_lz_compress(bytePtr(data), C.size_t(len(data)), bytePtr(out), needed, &needed)
	if err := mapErr(rc); err != nil {
		return nil, err
	}
	return out[:int(needed)], nil
}

func LzDecompress(data []byte, maxOut int) ([]byte, error) {
	var needed C.size_t
	rc := C.wilis_lz_decompress(bytePtr(data), C.size_t(len(data)), C.size_t(maxOut), nil, 0, &needed)
	if rc != C.WILIS_ERR_BUF_TOO_SMALL && rc != C.WILIS_OK {
		return nil, mapErr(rc)
	}
	out := make([]byte, int(needed))
	rc = C.wilis_lz_decompress(bytePtr(data), C.size_t(len(data)), C.size_t(maxOut), bytePtr(out), needed, &needed)
	if err := mapErr(rc); err != nil {
		return nil, err
	}
	return out[:int(needed)], nil
}
