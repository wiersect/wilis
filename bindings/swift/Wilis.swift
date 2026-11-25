// Wilis v0.7.0 — Zero-Dependency Swift Native C-Interop Bindings (All 33 C-ABI exports)
//
// Compile with swiftc after `cargo build --release`:
//   swiftc -I bindings/swift -L target/release -lwilis -Xlinker -rpath -Xlinker target/release \
//     bindings/swift/Wilis.swift main.swift -o wilis_swift_app

import Foundation
import CWilis

public enum WilisError: Error, Equatable {
    case invalidArg(String)
    case authFailed(String)
    case bufTooSmall(String)
    case internalError(String, Int32)
}

public enum Wilis {
    public static let keyBytes = Int(WILIS_KEY_BYTES)
    public static let nonceBytes = Int(WILIS_NONCE_BYTES)
    public static let saltBytes = Int(WILIS_SALT_BYTES)
    public static let tagBytes = Int(WILIS_TAG_BYTES)
    public static let sivTagBytes = Int(WILIS_SIV_TAG_BYTES)
    public static let hashBytes = Int(WILIS_HASH_BYTES)
    public static let kemPkBytes = Int(WILIS_KEM_PK_BYTES)
    public static let kemSkBytes = Int(WILIS_KEM_SK_BYTES)
    public static let kemCtBytes = Int(WILIS_KEM_CT_BYTES)
    public static let kemSsBytes = Int(WILIS_KEM_SS_BYTES)
    public static let signPkBytes = Int(WILIS_SIGN_PK_BYTES)
    public static let signSkBytes = Int(WILIS_SIGN_SK_BYTES)
    public static let signMaxSigBytes = Int(WILIS_SIGN_MAX_SIG_BYTES)
    public static let slhPkBytes = Int(WILIS_SLH_PK_BYTES)
    public static let slhSkBytes = Int(WILIS_SLH_SK_BYTES)
    public static let slhSigBytes = Int(WILIS_SLH_SIG_BYTES)
    public static let signcryptOverhead = Int(WILIS_SIGNCRYPT_OVERHEAD)

    private static func check(_ op: String, _ rc: Int32) throws {
        switch rc {
        case WILIS_OK: return
        case WILIS_ERR_INVALID_ARG: throw WilisError.invalidArg(op)
        case WILIS_ERR_AUTH_FAILED: throw WilisError.authFailed(op)
        case WILIS_ERR_BUF_TOO_SMALL: throw WilisError.bufTooSmall(op)
        default: throw WilisError.internalError(op, rc)
        }
    }

    private static func checkLen(_ name: String, _ data: Data, _ expected: Int) throws {
        if data.count != expected { throw WilisError.invalidArg("\(name) must be \(expected) bytes") }
    }

    private static func callVarOut(_ op: String, _ fn: (UnsafeMutablePointer<UInt8>?, Int, UnsafeMutablePointer<Int>) -> Int32) throws -> Data {
        var needed = 0
        let rc0 = fn(nil, 0, &needed)
        if rc0 == WILIS_OK && needed == 0 { return Data() }
        if rc0 != WILIS_ERR_BUF_TOO_SMALL { try check(op, rc0) }
        var out = Data(count: needed)
        var actual = 0
        let rc1 = out.withUnsafeMutableBytes { ptr in
            fn(ptr.bindMemory(to: UInt8.self).baseAddress, needed, &actual)
        }
        try check(op, rc1)
        return out.prefix(actual)
    }

    public static func version() -> String {
        String(cString: wilis_version())
    }

    public static func ctEq(_ a: Data, _ b: Data) throws -> Bool {
        if a.count != b.count { return false }
        let rc: Int32 = a.withUnsafeBytes { ap in
            b.withUnsafeBytes { bp in
                wilis_ct_eq(
                    ap.bindMemory(to: UInt8.self).baseAddress,
                    bp.bindMemory(to: UInt8.self).baseAddress,
                    a.count
                )
            }
        }
        if rc < 0 { try check("ct_eq", rc) }
        return rc == 1
    }

    public static func zeroize(_ data: inout Data) throws {
        let count = data.count
        let rc: Int32 = data.withUnsafeMutableBytes { p in
            wilis_zeroize(p.bindMemory(to: UInt8.self).baseAddress, count)
        }
        try check("zeroize", rc)
    }

    public static func randomBytes(_ count: Int) throws -> Data {
        var out = Data(count: count)
        let rc: Int32 = out.withUnsafeMutableBytes { p in
            wilis_random_bytes(p.bindMemory(to: UInt8.self).baseAddress, count)
        }
        try check("random_bytes", rc)
        return out
    }

    public static func hash256(_ data: Data) throws -> Data {
        var out = Data(count: hashBytes)
        let rc: Int32 = data.withUnsafeBytes { dp in
            out.withUnsafeMutableBytes { op in
                wilis_hash_256(dp.bindMemory(to: UInt8.self).baseAddress, data.count, op.bindMemory(to: UInt8.self).baseAddress)
            }
        }
        try check("hash_256", rc)
        return out
    }

    public static func treeHash256(_ data: Data) throws -> Data {
        var out = Data(count: hashBytes)
        let rc: Int32 = data.withUnsafeBytes { dp in
            out.withUnsafeMutableBytes { op in
                wilis_tree_hash_256(dp.bindMemory(to: UInt8.self).baseAddress, data.count, op.bindMemory(to: UInt8.self).baseAddress)
            }
        }
        try check("tree_hash_256", rc)
        return out
    }

    public static func mac256(key: Data, msg: Data) throws -> Data {
        try checkLen("key", key, keyBytes)
        var tag = Data(count: tagBytes)
        let rc: Int32 = key.withUnsafeBytes { kp in
            msg.withUnsafeBytes { mp in
                tag.withUnsafeMutableBytes { tp in
                    wilis_mac_256(kp.bindMemory(to: UInt8.self).baseAddress, mp.bindMemory(to: UInt8.self).baseAddress, msg.count, tp.bindMemory(to: UInt8.self).baseAddress)
                }
            }
        }
        try check("mac_256", rc)
        return tag
    }

    public static func subkeyDerive(masterKey: Data, context: Data) throws -> Data {
        try checkLen("masterKey", masterKey, keyBytes)
        var out = Data(count: keyBytes)
        let rc: Int32 = masterKey.withUnsafeBytes { kp in
            context.withUnsafeBytes { cp in
                out.withUnsafeMutableBytes { op in
                    wilis_subkey_derive(kp.bindMemory(to: UInt8.self).baseAddress, cp.bindMemory(to: UInt8.self).baseAddress, context.count, op.bindMemory(to: UInt8.self).baseAddress)
                }
            }
        }
        try check("subkey_derive", rc)
        return out
    }

    public static func xofDerive(label: Data, seed: Data, outLen: Int) throws -> Data {
        var out = Data(count: outLen)
        let rc: Int32 = label.withUnsafeBytes { lp in
            seed.withUnsafeBytes { sp in
                out.withUnsafeMutableBytes { op in
                    wilis_xof_derive(lp.bindMemory(to: UInt8.self).baseAddress, label.count, sp.bindMemory(to: UInt8.self).baseAddress, seed.count, op.bindMemory(to: UInt8.self).baseAddress, outLen)
                }
            }
        }
        try check("xof_derive", rc)
        return out
    }

    public static func aeadSeal(key: Data, nonce: Data, aad: Data, plaintext: Data) throws -> (ciphertext: Data, tag: Data) {
        try checkLen("key", key, keyBytes)
        try checkLen("nonce", nonce, nonceBytes)
        var ct = Data(count: plaintext.count)
        var tag = Data(count: tagBytes)
        let rc: Int32 = key.withUnsafeBytes { kp in
            nonce.withUnsafeBytes { np in
                aad.withUnsafeBytes { ap in
                    plaintext.withUnsafeBytes { pp in
                        ct.withUnsafeMutableBytes { cp in
                            tag.withUnsafeMutableBytes { tp in
                                wilis_aead_seal(
                                    kp.bindMemory(to: UInt8.self).baseAddress,
                                    np.bindMemory(to: UInt8.self).baseAddress,
                                    ap.bindMemory(to: UInt8.self).baseAddress, aad.count,
                                    pp.bindMemory(to: UInt8.self).baseAddress, plaintext.count,
                                    cp.bindMemory(to: UInt8.self).baseAddress,
                                    tp.bindMemory(to: UInt8.self).baseAddress
                                )
                            }
                        }
                    }
                }
            }
        }
        try check("aead_seal", rc)
        return (ct, tag)
    }

    public static func aeadOpen(key: Data, nonce: Data, aad: Data, ciphertext: Data, tag: Data) throws -> Data {
        try checkLen("key", key, keyBytes)
        try checkLen("nonce", nonce, nonceBytes)
        try checkLen("tag", tag, tagBytes)
        var pt = Data(count: ciphertext.count)
        let rc: Int32 = key.withUnsafeBytes { kp in
            nonce.withUnsafeBytes { np in
                aad.withUnsafeBytes { ap in
                    ciphertext.withUnsafeBytes { cp in
                        tag.withUnsafeBytes { tp in
                            pt.withUnsafeMutableBytes { pp in
                                wilis_aead_open(
                                    kp.bindMemory(to: UInt8.self).baseAddress,
                                    np.bindMemory(to: UInt8.self).baseAddress,
                                    ap.bindMemory(to: UInt8.self).baseAddress, aad.count,
                                    cp.bindMemory(to: UInt8.self).baseAddress, ciphertext.count,
                                    tp.bindMemory(to: UInt8.self).baseAddress,
                                    pp.bindMemory(to: UInt8.self).baseAddress
                                )
                            }
                        }
                    }
                }
            }
        }
        try check("aead_open", rc)
        return pt
    }

    public static func sivSeal(key: Data, aad: Data, plaintext: Data) throws -> (ciphertext: Data, sivTag: Data) {
        try checkLen("key", key, keyBytes)
        var ct = Data(count: plaintext.count)
        var tag = Data(count: sivTagBytes)
        let rc: Int32 = key.withUnsafeBytes { kp in
            aad.withUnsafeBytes { ap in
                plaintext.withUnsafeBytes { pp in
                    ct.withUnsafeMutableBytes { cp in
                        tag.withUnsafeMutableBytes { tp in
                            wilis_siv_seal(
                                kp.bindMemory(to: UInt8.self).baseAddress,
                                ap.bindMemory(to: UInt8.self).baseAddress, aad.count,
                                pp.bindMemory(to: UInt8.self).baseAddress, plaintext.count,
                                cp.bindMemory(to: UInt8.self).baseAddress,
                                tp.bindMemory(to: UInt8.self).baseAddress
                            )
                        }
                    }
                }
            }
        }
        try check("siv_seal", rc)
        return (ct, tag)
    }

    public static func sivOpen(key: Data, aad: Data, ciphertext: Data, sivTag: Data) throws -> Data {
        try checkLen("key", key, keyBytes)
        try checkLen("sivTag", sivTag, sivTagBytes)
        var pt = Data(count: ciphertext.count)
        let rc: Int32 = key.withUnsafeBytes { kp in
            aad.withUnsafeBytes { ap in
                ciphertext.withUnsafeBytes { cp in
                    sivTag.withUnsafeBytes { tp in
                        pt.withUnsafeMutableBytes { pp in
                            wilis_siv_open(
                                kp.bindMemory(to: UInt8.self).baseAddress,
                                ap.bindMemory(to: UInt8.self).baseAddress, aad.count,
                                cp.bindMemory(to: UInt8.self).baseAddress, ciphertext.count,
                                tp.bindMemory(to: UInt8.self).baseAddress,
                                pp.bindMemory(to: UInt8.self).baseAddress
                            )
                        }
                    }
                }
            }
        }
        try check("siv_open", rc)
        return pt
    }

    public static func kdfDerive(password: Data, salt: Data, memoryBlocks: UInt32 = 16384, passes: UInt32 = 3) throws -> Data {
        try checkLen("salt", salt, saltBytes)
        var key = Data(count: keyBytes)
        let rc: Int32 = password.withUnsafeBytes { pp in
            salt.withUnsafeBytes { sp in
                key.withUnsafeMutableBytes { kp in
                    wilis_kdf_derive(pp.bindMemory(to: UInt8.self).baseAddress, password.count, sp.bindMemory(to: UInt8.self).baseAddress, memoryBlocks, passes, kp.bindMemory(to: UInt8.self).baseAddress)
                }
            }
        }
        try check("kdf_derive", rc)
        return key
    }

    public static func kdfParallelDerive(password: Data, salt: Data, memoryBlocks: UInt32 = 16384, passes: UInt32 = 3, lanes: UInt32 = 4) throws -> Data {
        try checkLen("salt", salt, saltBytes)
        var key = Data(count: keyBytes)
        let rc: Int32 = password.withUnsafeBytes { pp in
            salt.withUnsafeBytes { sp in
                key.withUnsafeMutableBytes { kp in
                    wilis_kdf_parallel_derive(pp.bindMemory(to: UInt8.self).baseAddress, password.count, sp.bindMemory(to: UInt8.self).baseAddress, memoryBlocks, passes, lanes, kp.bindMemory(to: UInt8.self).baseAddress)
                }
            }
        }
        try check("kdf_parallel_derive", rc)
        return key
    }

    public static func kemKeygen() throws -> (pk: Data, sk: Data) {
        var pk = Data(count: kemPkBytes)
        var sk = Data(count: kemSkBytes)
        let rc: Int32 = pk.withUnsafeMutableBytes { pkp in
            sk.withUnsafeMutableBytes { skp in
                wilis_kem_keygen(pkp.bindMemory(to: UInt8.self).baseAddress, skp.bindMemory(to: UInt8.self).baseAddress)
            }
        }
        try check("kem_keygen", rc)
        return (pk, sk)
    }

    public static func kemEncapsulate(pk: Data) throws -> (ct: Data, ss: Data) {
        try checkLen("pk", pk, kemPkBytes)
        var ct = Data(count: kemCtBytes)
        var ss = Data(count: kemSsBytes)
        let rc: Int32 = pk.withUnsafeBytes { pkp in
            ct.withUnsafeMutableBytes { ctp in
                ss.withUnsafeMutableBytes { ssp in
                    wilis_kem_encapsulate(pkp.bindMemory(to: UInt8.self).baseAddress, ctp.bindMemory(to: UInt8.self).baseAddress, ssp.bindMemory(to: UInt8.self).baseAddress)
                }
            }
        }
        try check("kem_encapsulate", rc)
        return (ct, ss)
    }

    public static func kemDecapsulate(sk: Data, ct: Data) throws -> Data {
        try checkLen("sk", sk, kemSkBytes)
        try checkLen("ct", ct, kemCtBytes)
        var ss = Data(count: kemSsBytes)
        let rc: Int32 = sk.withUnsafeBytes { skp in
            ct.withUnsafeBytes { ctp in
                ss.withUnsafeMutableBytes { ssp in
                    wilis_kem_decapsulate(skp.bindMemory(to: UInt8.self).baseAddress, ctp.bindMemory(to: UInt8.self).baseAddress, ssp.bindMemory(to: UInt8.self).baseAddress)
                }
            }
        }
        try check("kem_decapsulate", rc)
        return ss
    }

    public static func signKeygen(height: UInt8 = 4) throws -> (pk: Data, sk: Data) {
        var pk = Data(count: signPkBytes)
        var sk = Data(count: signSkBytes)
        let rc: Int32 = pk.withUnsafeMutableBytes { pkp in
            sk.withUnsafeMutableBytes { skp in
                wilis_sign_keygen(height, pkp.bindMemory(to: UInt8.self).baseAddress, skp.bindMemory(to: UInt8.self).baseAddress)
            }
        }
        try check("sign_keygen", rc)
        return (pk, sk)
    }

    public static func signMessage(sk: Data, msg: Data) throws -> (sig: Data, nextSk: Data) {
        try checkLen("sk", sk, signSkBytes)
        var nextSk = sk
        var sig = Data(count: signMaxSigBytes)
        var sigLen = 0
        let rc: Int32 = nextSk.withUnsafeMutableBytes { skp in
            msg.withUnsafeBytes { mp in
                sig.withUnsafeMutableBytes { sp in
                    wilis_sign_message(skp.bindMemory(to: UInt8.self).baseAddress, mp.bindMemory(to: UInt8.self).baseAddress, msg.count, sp.bindMemory(to: UInt8.self).baseAddress, signMaxSigBytes, &sigLen)
                }
            }
        }
        try check("sign_message", rc)
        return (sig.prefix(sigLen), nextSk)
    }

    public static func verifyMessage(pk: Data, msg: Data, sig: Data) throws -> Bool {
        try checkLen("pk", pk, signPkBytes)
        let rc: Int32 = pk.withUnsafeBytes { pkp in
            msg.withUnsafeBytes { mp in
                sig.withUnsafeBytes { sp in
                    wilis_verify_message(pkp.bindMemory(to: UInt8.self).baseAddress, mp.bindMemory(to: UInt8.self).baseAddress, msg.count, sp.bindMemory(to: UInt8.self).baseAddress, sig.count)
                }
            }
        }
        if rc == WILIS_OK { return true }
        if rc == WILIS_ERR_AUTH_FAILED { return false }
        try check("verify_message", rc)
        return false
    }

    public static func slhKeygen() throws -> (pk: Data, sk: Data) {
        var pk = Data(count: slhPkBytes)
        var sk = Data(count: slhSkBytes)
        let rc: Int32 = pk.withUnsafeMutableBytes { pkp in
            sk.withUnsafeMutableBytes { skp in
                wilis_slh_keygen(pkp.bindMemory(to: UInt8.self).baseAddress, skp.bindMemory(to: UInt8.self).baseAddress)
            }
        }
        try check("slh_keygen", rc)
        return (pk, sk)
    }

    public static func slhSign(sk: Data, msg: Data) throws -> Data {
        try checkLen("sk", sk, slhSkBytes)
        var sig = Data(count: slhSigBytes)
        let rc: Int32 = sk.withUnsafeBytes { skp in
            msg.withUnsafeBytes { mp in
                sig.withUnsafeMutableBytes { sp in
                    wilis_slh_sign(skp.bindMemory(to: UInt8.self).baseAddress, mp.bindMemory(to: UInt8.self).baseAddress, msg.count, sp.bindMemory(to: UInt8.self).baseAddress)
                }
            }
        }
        try check("slh_sign", rc)
        return sig
    }

    public static func slhVerify(pk: Data, msg: Data, sig: Data) throws -> Bool {
        try checkLen("pk", pk, slhPkBytes)
        try checkLen("sig", sig, slhSigBytes)
        let rc: Int32 = pk.withUnsafeBytes { pkp in
            msg.withUnsafeBytes { mp in
                sig.withUnsafeBytes { sp in
                    wilis_slh_verify(pkp.bindMemory(to: UInt8.self).baseAddress, mp.bindMemory(to: UInt8.self).baseAddress, msg.count, sp.bindMemory(to: UInt8.self).baseAddress)
                }
            }
        }
        if rc == WILIS_OK { return true }
        if rc == WILIS_ERR_AUTH_FAILED { return false }
        try check("slh_verify", rc)
        return false
    }

    public static func signcrypt(senderSlhSk: Data, recipientKemPk: Data, aad: Data, plaintext: Data) throws -> Data {
        try checkLen("senderSlhSk", senderSlhSk, slhSkBytes)
        try checkLen("recipientKemPk", recipientKemPk, kemPkBytes)
        return try senderSlhSk.withUnsafeBytes { skp in
            try recipientKemPk.withUnsafeBytes { pkp in
                try aad.withUnsafeBytes { ap in
                    try plaintext.withUnsafeBytes { pp in
                        try callVarOut("signcrypt") { out, cap, len in
                            wilis_signcrypt(skp.bindMemory(to: UInt8.self).baseAddress, pkp.bindMemory(to: UInt8.self).baseAddress, ap.bindMemory(to: UInt8.self).baseAddress, aad.count, pp.bindMemory(to: UInt8.self).baseAddress, plaintext.count, out, cap, len)
                        }
                    }
                }
            }
        }
    }

    public static func unsigncrypt(senderSlhPk: Data, recipientKemSk: Data, aad: Data, packet: Data) throws -> Data {
        try checkLen("senderSlhPk", senderSlhPk, slhPkBytes)
        try checkLen("recipientKemSk", recipientKemSk, kemSkBytes)
        return try senderSlhPk.withUnsafeBytes { pkp in
            try recipientKemSk.withUnsafeBytes { skp in
                try aad.withUnsafeBytes { ap in
                    try packet.withUnsafeBytes { pktp in
                        try callVarOut("unsigncrypt") { out, cap, len in
                            wilis_unsigncrypt(pkp.bindMemory(to: UInt8.self).baseAddress, skp.bindMemory(to: UInt8.self).baseAddress, ap.bindMemory(to: UInt8.self).baseAddress, aad.count, pktp.bindMemory(to: UInt8.self).baseAddress, packet.count, out, cap, len)
                        }
                    }
                }
            }
        }
    }

    public static func totpAt(secret: Data, unixSecs: UInt64, period: UInt64 = 30, digits: UInt32 = 6) throws -> (code: String, remaining: UInt64) {
        var buf = [UInt8](repeating: 0, count: Int(digits) + 1)
        var rem: UInt64 = 0
        let rc: Int32 = secret.withUnsafeBytes { sp in
            wilis_totp_at(sp.bindMemory(to: UInt8.self).baseAddress, secret.count, unixSecs, period, digits, &buf, buf.count, &rem)
        }
        try check("totp_at", rc)
        return (String(cString: buf), rem)
    }

    public static func fpeEncrypt(key: Data, tweak: Data, alphabet: String, plaintext: String) throws -> String {
        try checkLen("key", key, keyBytes)
        let alpha = Data(alphabet.utf8), pt = Data(plaintext.utf8)
        let out = try key.withUnsafeBytes { kp in
            try tweak.withUnsafeBytes { tp in
                try alpha.withUnsafeBytes { ap in
                    try pt.withUnsafeBytes { pp in
                        try callVarOut("fpe_encrypt") { o, cap, len in
                            wilis_fpe_encrypt(kp.bindMemory(to: UInt8.self).baseAddress, tp.bindMemory(to: UInt8.self).baseAddress, tweak.count, ap.bindMemory(to: UInt8.self).baseAddress, alpha.count, pp.bindMemory(to: UInt8.self).baseAddress, pt.count, o, cap, len)
                        }
                    }
                }
            }
        }
        return String(decoding: out, as: UTF8.self)
    }

    public static func fpeDecrypt(key: Data, tweak: Data, alphabet: String, ciphertext: String) throws -> String {
        try checkLen("key", key, keyBytes)
        let alpha = Data(alphabet.utf8), ct = Data(ciphertext.utf8)
        let out = try key.withUnsafeBytes { kp in
            try tweak.withUnsafeBytes { tp in
                try alpha.withUnsafeBytes { ap in
                    try ct.withUnsafeBytes { cp in
                        try callVarOut("fpe_decrypt") { o, cap, len in
                            wilis_fpe_decrypt(kp.bindMemory(to: UInt8.self).baseAddress, tp.bindMemory(to: UInt8.self).baseAddress, tweak.count, ap.bindMemory(to: UInt8.self).baseAddress, alpha.count, cp.bindMemory(to: UInt8.self).baseAddress, ct.count, o, cap, len)
                        }
                    }
                }
            }
        }
        return String(decoding: out, as: UTF8.self)
    }

    public static func mnemonicEncode(_ secret: Data) throws -> String {
        let out = try secret.withUnsafeBytes { sp in
            try callVarOut("mnemonic_encode") { o, cap, len in
                wilis_mnemonic_encode(sp.bindMemory(to: UInt8.self).baseAddress, secret.count, o, cap, len)
            }
        }
        return String(decoding: out, as: UTF8.self)
    }

    public static func mnemonicDecode(_ phrase: String) throws -> Data {
        let utf8 = Data(phrase.utf8)
        return try utf8.withUnsafeBytes { pp in
            try callVarOut("mnemonic_decode") { o, cap, len in
                wilis_mnemonic_decode(pp.bindMemory(to: UInt8.self).baseAddress, utf8.count, o, cap, len)
            }
        }
    }

    public static func lzCompress(_ data: Data) throws -> Data {
        try data.withUnsafeBytes { dp in
            try callVarOut("lz_compress") { o, cap, len in
                wilis_lz_compress(dp.bindMemory(to: UInt8.self).baseAddress, data.count, o, cap, len)
            }
        }
    }

    public static func lzDecompress(_ compressed: Data, maxOut: Int = 64 * 1024 * 1024) throws -> Data {
        try compressed.withUnsafeBytes { cp in
            try callVarOut("lz_decompress") { o, cap, len in
                wilis_lz_decompress(cp.bindMemory(to: UInt8.self).baseAddress, compressed.count, maxOut, o, cap, len)
            }
        }
    }
}
