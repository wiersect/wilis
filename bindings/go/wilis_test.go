package wilis

import (
	"bytes"
	"strings"
	"testing"
)

func TestAll33Functions(t *testing.T) {
	if got := Version(); got != "0.7.0" {
		t.Fatalf("unexpected version: %q", got)
	}

	rnd, err := RandomBytes(32)
	if err != nil || len(rnd) != 32 {
		t.Fatalf("RandomBytes failed: %v", err)
	}
	var key [KeyBytes]byte
	copy(key[:], rnd)
	Zeroize(rnd)
	if !bytes.Equal(rnd, make([]byte, 32)) {
		t.Fatalf("Zeroize did not wipe slice")
	}

	var nonce [NonceBytes]byte
	rn, _ := RandomBytes(NonceBytes)
	copy(nonce[:], rn)

	msg := []byte("Hello from Wilis v0.7.0 Go cgo 33-function binding!")

	if !ConstantTimeEq(msg, msg) || ConstantTimeEq(msg, []byte("different")) {
		t.Fatalf("ConstantTimeEq failed")
	}

	if _, err := Hash256(msg); err != nil {
		t.Fatalf("Hash256: %v", err)
	}
	if _, err := TreeHash256(bytes.Repeat(msg, 200)); err != nil {
		t.Fatalf("TreeHash256: %v", err)
	}
	if _, err := Mac256(key, msg); err != nil {
		t.Fatalf("Mac256: %v", err)
	}
	sub1, err := DeriveSubkey(key, []byte("a"))
	sub2, err2 := DeriveSubkey(key, []byte("b"))
	if err != nil || err2 != nil || sub1 == sub2 {
		t.Fatalf("DeriveSubkey failed")
	}
	if xof, err := XofDerive([]byte("lbl"), key[:], 64); err != nil || len(xof) != 64 {
		t.Fatalf("XofDerive failed: %v", err)
	}

	// AEAD & SIV
	ct, tag, err := AeadSeal(key, nonce, []byte("aad"), msg)
	if err != nil {
		t.Fatalf("AeadSeal: %v", err)
	}
	pt, err := AeadOpen(key, nonce, []byte("aad"), ct, tag)
	if err != nil || !bytes.Equal(pt, msg) {
		t.Fatalf("AeadOpen mismatch: %v", err)
	}

	sivCt, sivTag, err := SivSeal(key, []byte("siv"), msg)
	if err != nil {
		t.Fatalf("SivSeal: %v", err)
	}
	sivPt, err := SivOpen(key, []byte("siv"), sivCt, sivTag)
	if err != nil || !bytes.Equal(sivPt, msg) {
		t.Fatalf("SivOpen mismatch: %v", err)
	}

	// KDF v2 & v3 Parallel
	if _, err := KdfDerive([]byte("pw"), nonce, 64, 2); err != nil {
		t.Fatalf("KdfDerive: %v", err)
	}
	pkdf1, err := KdfParallelDerive([]byte("pw"), nonce, 128, 2, 4)
	pkdf2, err2 := KdfParallelDerive([]byte("pw"), nonce, 128, 2, 4)
	if err != nil || err2 != nil || pkdf1 != pkdf2 {
		t.Fatalf("KdfParallelDerive failed")
	}

	// Post-Quantum KEM + Stateful Sign + Stateless SLH + Signcrypt
	kpk, ksk, err := KemKeygen()
	if err != nil {
		t.Fatalf("KemKeygen: %v", err)
	}
	kct, ss1, err := KemEncapsulate(kpk)
	if err != nil {
		t.Fatalf("KemEncapsulate: %v", err)
	}
	ss2, err := KemDecapsulate(ksk, kct)
	if err != nil || ss1 != ss2 {
		t.Fatalf("KemDecapsulate mismatch: %v", err)
	}

	spk, ssk, err := SignKeygen(2)
	if err != nil {
		t.Fatalf("SignKeygen: %v", err)
	}
	sig, err := SignMessage(&ssk, msg)
	if err != nil || !VerifyMessage(spk, msg, sig) {
		t.Fatalf("WilisSign verify failed: %v", err)
	}

	lpk, lsk, err := SlhKeygen()
	if err != nil {
		t.Fatalf("SlhKeygen: %v", err)
	}
	lsig, err := SlhSign(lsk, msg)
	if err != nil || !SlhVerify(lpk, msg, lsig) {
		t.Fatalf("WilisSLH verify failed: %v", err)
	}

	wpsc, err := Signcrypt(lsk, kpk, []byte("hdr"), msg)
	if err != nil {
		t.Fatalf("Signcrypt: %v", err)
	}
	unsc, err := Unsigncrypt(lpk, ksk, []byte("hdr"), wpsc)
	if err != nil || !bytes.Equal(unsc, msg) {
		t.Fatalf("Unsigncrypt mismatch: %v", err)
	}

	// TOTP, FPE, Mnemonic, WilisLZ
	code, rem, err := TotpAt([]byte("12345678901234567890"), 1_700_000_020, 30, 6)
	if err != nil || len(code) != 6 || rem != 20 {
		t.Fatalf("TotpAt failed: %q %d %v", code, rem, err)
	}
	fpeCt, err := FpeEncrypt(key, []byte("acct"), "0123456789", "4532015112830366")
	if err != nil || len(fpeCt) != 16 {
		t.Fatalf("FpeEncrypt failed: %v", err)
	}
	fpePt, err := FpeDecrypt(key, []byte("acct"), "0123456789", fpeCt)
	if err != nil || fpePt != "4532015112830366" {
		t.Fatalf("FpeDecrypt mismatch: %q %v", fpePt, err)
	}
	phrase, err := MnemonicEncode(key[:])
	if err != nil || len(strings.Fields(phrase)) != 34 {
		t.Fatalf("MnemonicEncode failed: %v", err)
	}
	decKey, err := MnemonicDecode(phrase)
	if err != nil || !bytes.Equal(decKey, key[:]) {
		t.Fatalf("MnemonicDecode mismatch: %v", err)
	}
	big := bytes.Repeat([]byte("WilisLZ Go test payload! "), 50)
	comp, err := LzCompress(big)
	if err != nil || len(comp) >= len(big) {
		t.Fatalf("LzCompress failed: %v", err)
	}
	decomp, err := LzDecompress(comp, len(big))
	if err != nil || !bytes.Equal(decomp, big) {
		t.Fatalf("LzDecompress mismatch: %v", err)
	}
}
