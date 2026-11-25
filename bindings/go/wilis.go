// Package wilis provides zero-dependency Go (cgo) bindings over the native Wilis v0.6.0
// C-ABI (`libwilis` + `include/wilis.h`).
//
// Build the native shared library first:
//
//	cargo build --release
//
// Then link with:
//
//	CGO_LDFLAGS="-L../../target/release -lwilis -Wl,-rpath,../../target/release" go test ./...
package wilis

/*
#cgo CFLAGS: -I../../include
#cgo LDFLAGS: -L../../target/release -lwilis
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
	KeyBytes    = C.WILIS_KEY_BYTES
	NonceBytes  = C.WILIS_NONCE_BYTES
	SaltBytes   = C.WILIS_SALT_BYTES
	TagBytes    = C.WILIS_TAG_BYTES
	SivTagBytes = C.WILIS_SIV_TAG_BYTES
	HashBytes   = C.WILIS_HASH_BYTES

	KemPkBytes  = C.WILIS_KEM_PK_BYTES
	KemSkBytes  = C.WILIS_KEM_SK_BYTES
	KemCtBytes  = C.WILIS_KEM_CT_BYTES
	KemSsBytes  = C.WILIS_KEM_SS_BYTES
	SlhPkBytes  = C.WILIS_SLH_PK_BYTES
	SlhSkBytes  = C.WILIS_SLH_SK_BYTES
	SlhSigBytes = C.WILIS_SLH_SIG_BYTES
)

var (
	ErrInvalidArg = errors.New("wilis: invalid argument")
	ErrAuthFailed = errors.New("wilis: authentication or verification failed")
	ErrInternal   = errors.New("wilis: internal or OS CSPRNG error")
)

func mapErr(rc C.int32_t) error {
	switch rc {
	case C.WILIS_OK:
		return nil
	case C.WILIS_ERR_AUTH_FAILED:
		return ErrAuthFailed
	case C.WILIS_ERR_INVALID_ARG:
		return ErrInvalidArg
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

// Version returns the native libwilis semantic version string.
func Version() string {
	return C.GoString(C.wilis_version())
}

// Hash256 computes the 256-bit WilisHash-256 digest of data.
func Hash256(data []byte) ([HashBytes]byte, error) {
	var out [HashBytes]byte
	rc := C.wilis_hash_256(bytePtr(data), C.size_t(len(data)), (*C.uint8_t)(unsafe.Pointer(&out[0])))
	return out, mapErr(rc)
}

// TreeHash256 computes the parallel multi-core WilisTreeHash root digest of data.
func TreeHash256(data []byte) ([HashBytes]byte, error) {
	var out [HashBytes]byte
	rc := C.wilis_tree_hash_256(bytePtr(data), C.size_t(len(data)), (*C.uint8_t)(unsafe.Pointer(&out[0])))
	return out, mapErr(rc)
}

// AeadSeal encrypts plaintext with WilisAEAD (256-bit key, 192-bit nonce, 256-bit tag).
func AeadSeal(key [KeyBytes]byte, nonce [NonceBytes]byte, aad, pt []byte) ([]byte, [TagBytes]byte, error) {
	ct := make([]byte, len(pt))
	var tag [TagBytes]byte
	rc := C.wilis_aead_seal(
		(*C.uint8_t)(unsafe.Pointer(&key[0])),
		(*C.uint8_t)(unsafe.Pointer(&nonce[0])),
		bytePtr(aad), C.size_t(len(aad)),
		bytePtr(pt), C.size_t(len(pt)),
		bytePtr(ct),
		(*C.uint8_t)(unsafe.Pointer(&tag[0])),
	)
	return ct, tag, mapErr(rc)
}

// AeadOpen authenticates and decrypts ciphertext with WilisAEAD.
func AeadOpen(key [KeyBytes]byte, nonce [NonceBytes]byte, aad, ct []byte, tag [TagBytes]byte) ([]byte, error) {
	pt := make([]byte, len(ct))
	rc := C.wilis_aead_open(
		(*C.uint8_t)(unsafe.Pointer(&key[0])),
		(*C.uint8_t)(unsafe.Pointer(&nonce[0])),
		bytePtr(aad), C.size_t(len(aad)),
		bytePtr(ct), C.size_t(len(ct)),
		(*C.uint8_t)(unsafe.Pointer(&tag[0])),
		bytePtr(pt),
	)
	if err := mapErr(rc); err != nil {
		return nil, err
	}
	return pt, nil
}

// SivSeal performs nonce-misuse-resistant WilisAEAD-SIV encryption.
func SivSeal(key [KeyBytes]byte, aad, pt []byte) ([]byte, [SivTagBytes]byte, error) {
	ct := make([]byte, len(pt))
	var tag [SivTagBytes]byte
	rc := C.wilis_siv_seal(
		(*C.uint8_t)(unsafe.Pointer(&key[0])),
		bytePtr(aad), C.size_t(len(aad)),
		bytePtr(pt), C.size_t(len(pt)),
		bytePtr(ct),
		(*C.uint8_t)(unsafe.Pointer(&tag[0])),
	)
	return ct, tag, mapErr(rc)
}

// SivOpen authenticates and decrypts WilisAEAD-SIV ciphertext.
func SivOpen(key [KeyBytes]byte, aad, ct []byte, tag [SivTagBytes]byte) ([]byte, error) {
	pt := make([]byte, len(ct))
	rc := C.wilis_siv_open(
		(*C.uint8_t)(unsafe.Pointer(&key[0])),
		bytePtr(aad), C.size_t(len(aad)),
		bytePtr(ct), C.size_t(len(ct)),
		(*C.uint8_t)(unsafe.Pointer(&tag[0])),
		bytePtr(pt),
	)
	if err := mapErr(rc); err != nil {
		return nil, err
	}
	return pt, nil
}

// KemKeygen generates a post-quantum WilisKEM Module-LWE keypair (pk, sk).
func KemKeygen() ([KemPkBytes]byte, [KemSkBytes]byte, error) {
	var pk [KemPkBytes]byte
	var sk [KemSkBytes]byte
	rc := C.wilis_kem_keygen((*C.uint8_t)(unsafe.Pointer(&pk[0])), (*C.uint8_t)(unsafe.Pointer(&sk[0])))
	return pk, sk, mapErr(rc)
}

// KemEncapsulate encapsulates a fresh 256-bit post-quantum shared secret to pk.
func KemEncapsulate(pk [KemPkBytes]byte) ([KemCtBytes]byte, [KemSsBytes]byte, error) {
	var ct [KemCtBytes]byte
	var ss [KemSsBytes]byte
	rc := C.wilis_kem_encapsulate(
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&ct[0])),
		(*C.uint8_t)(unsafe.Pointer(&ss[0])),
	)
	return ct, ss, mapErr(rc)
}

// KemDecapsulate decapsulates a 256-bit shared secret using sk and ct.
func KemDecapsulate(sk [KemSkBytes]byte, ct [KemCtBytes]byte) ([KemSsBytes]byte, error) {
	var ss [KemSsBytes]byte
	rc := C.wilis_kem_decapsulate(
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		(*C.uint8_t)(unsafe.Pointer(&ct[0])),
		(*C.uint8_t)(unsafe.Pointer(&ss[0])),
	)
	return ss, mapErr(rc)
}

// SlhKeygen generates a stateless post-quantum WilisSLH keypair (unlimited signatures).
func SlhKeygen() ([SlhPkBytes]byte, [SlhSkBytes]byte, error) {
	var pk [SlhPkBytes]byte
	var sk [SlhSkBytes]byte
	rc := C.wilis_slh_keygen((*C.uint8_t)(unsafe.Pointer(&pk[0])), (*C.uint8_t)(unsafe.Pointer(&sk[0])))
	return pk, sk, mapErr(rc)
}

// SlhSign statelessly signs msg with a WLS1 secret key.
func SlhSign(sk [SlhSkBytes]byte, msg []byte) ([SlhSigBytes]byte, error) {
	var sig [SlhSigBytes]byte
	rc := C.wilis_slh_sign(
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		bytePtr(msg), C.size_t(len(msg)),
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
	)
	return sig, mapErr(rc)
}

// SlhVerify verifies a stateless WLSG signature over msg using pk.
func SlhVerify(pk [SlhPkBytes]byte, msg []byte, sig [SlhSigBytes]byte) bool {
	rc := C.wilis_slh_verify(
		(*C.uint8_t)(unsafe.Pointer(&pk[0])),
		bytePtr(msg), C.size_t(len(msg)),
		(*C.uint8_t)(unsafe.Pointer(&sig[0])),
	)
	return rc == C.WILIS_OK
}
