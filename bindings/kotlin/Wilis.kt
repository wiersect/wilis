// Wilis v0.7.0 — Idiomatic Kotlin JVM Bindings (All 33 C-ABI exports via Java 22+ Panama FFM)
//
// Compile alongside bindings/java/Wilis.java:
//   javac --release 22 bindings/java/Wilis.java
//   kotlinc -cp bindings/java bindings/kotlin/Wilis.kt -d build/
//   kotlin -J--enable-native-access=ALL-UNNAMED -cp bindings/java:build/ WilisKt

package wilis

data class TotpCode(val code: String, val remainingSeconds: Long)

object WilisCrypto {
    const val KEY_BYTES = Wilis.KEY_BYTES
    const val NONCE_BYTES = Wilis.NONCE_BYTES
    const val SALT_BYTES = Wilis.SALT_BYTES
    const val TAG_BYTES = Wilis.TAG_BYTES
    const val SIV_TAG_BYTES = Wilis.SIV_TAG_BYTES
    const val HASH_BYTES = Wilis.HASH_BYTES
    const val KEM_PK_BYTES = Wilis.KEM_PK_BYTES
    const val KEM_SK_BYTES = Wilis.KEM_SK_BYTES
    const val KEM_CT_BYTES = Wilis.KEM_CT_BYTES
    const val KEM_SS_BYTES = Wilis.KEM_SS_BYTES
    const val SIGN_PK_BYTES = Wilis.SIGN_PK_BYTES
    const val SIGN_SK_BYTES = Wilis.SIGN_SK_BYTES
    const val SIGN_MAX_SIG_BYTES = Wilis.SIGN_MAX_SIG_BYTES
    const val SLH_PK_BYTES = Wilis.SLH_PK_BYTES
    const val SLH_SK_BYTES = Wilis.SLH_SK_BYTES
    const val SLH_SIG_BYTES = Wilis.SLH_SIG_BYTES
    const val SIGNCRYPT_OVERHEAD = Wilis.SIGNCRYPT_OVERHEAD

    fun version(): String = Wilis.version()
    fun ctEq(a: ByteArray, b: ByteArray): Boolean = Wilis.ctEq(a, b)
    fun zeroize(buf: ByteArray) = Wilis.zeroize(buf)
    fun randomBytes(len: Int): ByteArray = Wilis.randomBytes(len)

    fun hash256(data: ByteArray): ByteArray = Wilis.hash256(data)
    fun treeHash256(data: ByteArray): ByteArray = Wilis.treeHash256(data)
    fun mac256(key: ByteArray, msg: ByteArray): ByteArray = Wilis.mac256(key, msg)
    fun subkeyDerive(masterKey: ByteArray, context: ByteArray): ByteArray =
        Wilis.subkeyDerive(masterKey, context)
    fun xofDerive(label: ByteArray, seed: ByteArray, outLen: Int): ByteArray =
        Wilis.xofDerive(label, seed, outLen)

    fun aeadSeal(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): Pair<ByteArray, ByteArray> {
        val r = Wilis.aeadSeal(key, nonce, aad, plaintext)
        return r.first() to r.second()
    }

    fun aeadOpen(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray, tag: ByteArray): ByteArray =
        Wilis.aeadOpen(key, nonce, aad, ciphertext, tag)

    fun sivSeal(key: ByteArray, aad: ByteArray, plaintext: ByteArray): Pair<ByteArray, ByteArray> {
        val r = Wilis.sivSeal(key, aad, plaintext)
        return r.first() to r.second()
    }

    fun sivOpen(key: ByteArray, aad: ByteArray, ciphertext: ByteArray, sivTag: ByteArray): ByteArray =
        Wilis.sivOpen(key, aad, ciphertext, sivTag)

    fun kdfDerive(password: ByteArray, salt: ByteArray, memoryBlocks: Int = 16384, passes: Int = 3): ByteArray =
        Wilis.kdfDerive(password, salt, memoryBlocks, passes)

    fun kdfParallelDerive(
        password: ByteArray,
        salt: ByteArray,
        memoryBlocks: Int = 16384,
        passes: Int = 3,
        lanes: Int = 4,
    ): ByteArray = Wilis.kdfParallelDerive(password, salt, memoryBlocks, passes, lanes)

    fun kemKeygen(): Pair<ByteArray, ByteArray> = Wilis.kemKeygen().let { it.first() to it.second() }
    fun kemEncapsulate(pk: ByteArray): Pair<ByteArray, ByteArray> = Wilis.kemEncapsulate(pk).let { it.first() to it.second() }
    fun kemDecapsulate(sk: ByteArray, ct: ByteArray): ByteArray = Wilis.kemDecapsulate(sk, ct)

    fun signKeygen(height: Int = 4): Pair<ByteArray, ByteArray> = Wilis.signKeygen(height).let { it.first() to it.second() }
    fun signMessage(sk: ByteArray, msg: ByteArray): Pair<ByteArray, ByteArray> =
        Wilis.signMessage(sk, msg).let { it.first() to it.second() }
    fun verifyMessage(pk: ByteArray, msg: ByteArray, sig: ByteArray): Boolean = Wilis.verifyMessage(pk, msg, sig)

    fun slhKeygen(): Pair<ByteArray, ByteArray> = Wilis.slhKeygen().let { it.first() to it.second() }
    fun slhSign(sk: ByteArray, msg: ByteArray): ByteArray = Wilis.slhSign(sk, msg)
    fun slhVerify(pk: ByteArray, msg: ByteArray, sig: ByteArray): Boolean = Wilis.slhVerify(pk, msg, sig)

    fun signcrypt(senderSlhSk: ByteArray, recipientKemPk: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray =
        Wilis.signcrypt(senderSlhSk, recipientKemPk, aad, plaintext)
    fun unsigncrypt(senderSlhPk: ByteArray, recipientKemSk: ByteArray, aad: ByteArray, packet: ByteArray): ByteArray =
        Wilis.unsigncrypt(senderSlhPk, recipientKemSk, aad, packet)

    fun totpAt(secret: ByteArray, unixSecs: Long, period: Long = 30L, digits: Int = 6): TotpCode =
        Wilis.totpAt(secret, unixSecs, period, digits).let { TotpCode(it.code(), it.remainingSeconds()) }

    fun fpeEncrypt(key: ByteArray, tweak: ByteArray, alphabet: String, plaintext: String): String =
        Wilis.fpeEncrypt(key, tweak, alphabet, plaintext)
    fun fpeDecrypt(key: ByteArray, tweak: ByteArray, alphabet: String, ciphertext: String): String =
        Wilis.fpeDecrypt(key, tweak, alphabet, ciphertext)

    fun mnemonicEncode(secret: ByteArray): String = Wilis.mnemonicEncode(secret)
    fun mnemonicDecode(phrase: String): ByteArray = Wilis.mnemonicDecode(phrase)

    fun lzCompress(data: ByteArray): ByteArray = Wilis.lzCompress(data)
    fun lzDecompress(compressed: ByteArray, maxOut: Long = 64L * 1024L * 1024L): ByteArray =
        Wilis.lzDecompress(compressed, maxOut)
}
