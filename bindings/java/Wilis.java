// Wilis v0.7.0 — Zero-Dependency Java 22+ Project Panama FFM Bindings (All 33 C-ABI exports)
//
// Compile & run self-test (Java 22+):
//   javac --release 22 bindings/java/Wilis.java
//   java --enable-native-access=ALL-UNNAMED -cp bindings/java Wilis

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public final class Wilis {

    public static final int KEY_BYTES = 32;
    public static final int NONCE_BYTES = 24;
    public static final int SALT_BYTES = 24;
    public static final int TAG_BYTES = 32;
    public static final int SIV_TAG_BYTES = 64;
    public static final int HASH_BYTES = 32;

    public static final int KEM_PK_BYTES = 1284;
    public static final int KEM_SK_BYTES = 2600;
    public static final int KEM_CT_BYTES = 1668;
    public static final int KEM_SS_BYTES = 32;

    public static final int SIGN_PK_BYTES = 101;
    public static final int SIGN_SK_BYTES = 137;
    public static final int SIGN_MAX_SIG_BYTES = 2506;

    public static final int SLH_PK_BYTES = 100;
    public static final int SLH_SK_BYTES = 164;
    public static final int SLH_SIG_BYTES = 8165;
    public static final int SIGNCRYPT_OVERHEAD = 9894;

    public static final int OK = 0;
    public static final int ERR_INVALID_ARG = -1;
    public static final int ERR_AUTH_FAILED = -2;
    public static final int ERR_INTERNAL = -3;
    public static final int ERR_BUF_TOO_SMALL = -4;

    public static class WilisException extends RuntimeException {
        public final int code;
        public WilisException(String op, int code) {
            super("Wilis " + op + " failed with code " + code);
            this.code = code;
        }
    }

    public static final class WilisAuthException extends WilisException {
        public WilisAuthException(String op) {
            super(op, ERR_AUTH_FAILED);
        }
    }

    public record BytesPair(byte[] first, byte[] second) {}
    public record TotpResult(String code, long remainingSeconds) {}

    private static final Linker LINKER = Linker.nativeLinker();
    private static final ValueLayout.OfAddress PTR = ValueLayout.ADDRESS;
    private static final ValueLayout.OfInt I32 = ValueLayout.JAVA_INT;
    private static final ValueLayout.OfLong U64 = ValueLayout.JAVA_LONG;
    private static final ValueLayout.OfByte U8 = ValueLayout.JAVA_BYTE;
    private static final ValueLayout.OfLong SIZE_T = ValueLayout.JAVA_LONG;

    private static final SymbolLookup LIB = loadLibrary();

    private static SymbolLookup loadLibrary() {
        String env = System.getenv("WILIS_LIB");
        if (env != null && !env.isEmpty()) {
            return SymbolLookup.libraryLookup(Path.of(env), Arena.global());
        }
        String os = System.getProperty("os.name", "").toLowerCase();
        String libName = os.contains("win") ? "wilis.dll"
            : os.contains("mac") ? "libwilis.dylib" : "libwilis.so";
        Path[] candidates = {
            Path.of("target/release", libName),
            Path.of("target/debug", libName),
            Path.of("../../target/release", libName),
            Path.of("../../target/debug", libName),
        };
        for (Path p : candidates) {
            if (Files.isRegularFile(p)) {
                return SymbolLookup.libraryLookup(p.toAbsolutePath(), Arena.global());
            }
        }
        return SymbolLookup.libraryLookup(libName, Arena.global());
    }

    private static MethodHandle fn(String name, FunctionDescriptor desc) {
        MemorySegment sym = LIB.find(name)
            .orElseThrow(() -> new UnsatisfiedLinkError("Missing symbol: " + name));
        return LINKER.downcallHandle(sym, desc);
    }

    // All 33 C-ABI method handles
    private static final MethodHandle H_VERSION = fn("wilis_version", FunctionDescriptor.of(PTR));
    private static final MethodHandle H_CT_EQ = fn("wilis_ct_eq", FunctionDescriptor.of(I32, PTR, PTR, SIZE_T));
    private static final MethodHandle H_ZEROIZE = fn("wilis_zeroize", FunctionDescriptor.of(I32, PTR, SIZE_T));
    private static final MethodHandle H_RANDOM_BYTES = fn("wilis_random_bytes", FunctionDescriptor.of(I32, PTR, SIZE_T));

    private static final MethodHandle H_HASH_256 = fn("wilis_hash_256", FunctionDescriptor.of(I32, PTR, SIZE_T, PTR));
    private static final MethodHandle H_TREE_HASH_256 = fn("wilis_tree_hash_256", FunctionDescriptor.of(I32, PTR, SIZE_T, PTR));
    private static final MethodHandle H_MAC_256 = fn("wilis_mac_256", FunctionDescriptor.of(I32, PTR, PTR, SIZE_T, PTR));
    private static final MethodHandle H_SUBKEY_DERIVE = fn("wilis_subkey_derive", FunctionDescriptor.of(I32, PTR, PTR, SIZE_T, PTR));
    private static final MethodHandle H_XOF_DERIVE = fn("wilis_xof_derive", FunctionDescriptor.of(I32, PTR, SIZE_T, PTR, SIZE_T, PTR, SIZE_T));

    private static final MethodHandle H_AEAD_SEAL = fn("wilis_aead_seal", FunctionDescriptor.of(I32, PTR, PTR, PTR, SIZE_T, PTR, SIZE_T, PTR, PTR));
    private static final MethodHandle H_AEAD_OPEN = fn("wilis_aead_open", FunctionDescriptor.of(I32, PTR, PTR, PTR, SIZE_T, PTR, SIZE_T, PTR, PTR));
    private static final MethodHandle H_SIV_SEAL = fn("wilis_siv_seal", FunctionDescriptor.of(I32, PTR, PTR, SIZE_T, PTR, SIZE_T, PTR, PTR));
    private static final MethodHandle H_SIV_OPEN = fn("wilis_siv_open", FunctionDescriptor.of(I32, PTR, PTR, SIZE_T, PTR, SIZE_T, PTR, PTR));

    private static final MethodHandle H_KDF_DERIVE = fn("wilis_kdf_derive", FunctionDescriptor.of(I32, PTR, SIZE_T, PTR, I32, I32, PTR));
    private static final MethodHandle H_KDF_PARALLEL = fn("wilis_kdf_parallel_derive", FunctionDescriptor.of(I32, PTR, SIZE_T, PTR, I32, I32, I32, PTR));

    private static final MethodHandle H_KEM_KEYGEN = fn("wilis_kem_keygen", FunctionDescriptor.of(I32, PTR, PTR));
    private static final MethodHandle H_KEM_ENCAP = fn("wilis_kem_encapsulate", FunctionDescriptor.of(I32, PTR, PTR, PTR));
    private static final MethodHandle H_KEM_DECAP = fn("wilis_kem_decapsulate", FunctionDescriptor.of(I32, PTR, PTR, PTR));

    private static final MethodHandle H_SIGN_KEYGEN = fn("wilis_sign_keygen", FunctionDescriptor.of(I32, U8, PTR, PTR));
    private static final MethodHandle H_SIGN_MESSAGE = fn("wilis_sign_message", FunctionDescriptor.of(I32, PTR, PTR, SIZE_T, PTR, SIZE_T, PTR));
    private static final MethodHandle H_VERIFY_MESSAGE = fn("wilis_verify_message", FunctionDescriptor.of(I32, PTR, PTR, SIZE_T, PTR, SIZE_T));

    private static final MethodHandle H_SLH_KEYGEN = fn("wilis_slh_keygen", FunctionDescriptor.of(I32, PTR, PTR));
    private static final MethodHandle H_SLH_SIGN = fn("wilis_slh_sign", FunctionDescriptor.of(I32, PTR, PTR, SIZE_T, PTR));
    private static final MethodHandle H_SLH_VERIFY = fn("wilis_slh_verify", FunctionDescriptor.of(I32, PTR, PTR, SIZE_T, PTR));

    private static final MethodHandle H_SIGNCRYPT = fn("wilis_signcrypt", FunctionDescriptor.of(I32, PTR, PTR, PTR, SIZE_T, PTR, SIZE_T, PTR, SIZE_T, PTR));
    private static final MethodHandle H_UNSIGNCRYPT = fn("wilis_unsigncrypt", FunctionDescriptor.of(I32, PTR, PTR, PTR, SIZE_T, PTR, SIZE_T, PTR, SIZE_T, PTR));

    private static final MethodHandle H_TOTP_AT = fn("wilis_totp_at", FunctionDescriptor.of(I32, PTR, SIZE_T, U64, U64, I32, PTR, SIZE_T, PTR));
    private static final MethodHandle H_FPE_ENCRYPT = fn("wilis_fpe_encrypt", FunctionDescriptor.of(I32, PTR, PTR, SIZE_T, PTR, SIZE_T, PTR, SIZE_T, PTR, SIZE_T, PTR));
    private static final MethodHandle H_FPE_DECRYPT = fn("wilis_fpe_decrypt", FunctionDescriptor.of(I32, PTR, PTR, SIZE_T, PTR, SIZE_T, PTR, SIZE_T, PTR, SIZE_T, PTR));
    private static final MethodHandle H_MNEMONIC_ENCODE = fn("wilis_mnemonic_encode", FunctionDescriptor.of(I32, PTR, SIZE_T, PTR, SIZE_T, PTR));
    private static final MethodHandle H_MNEMONIC_DECODE = fn("wilis_mnemonic_decode", FunctionDescriptor.of(I32, PTR, SIZE_T, PTR, SIZE_T, PTR));
    private static final MethodHandle H_LZ_COMPRESS = fn("wilis_lz_compress", FunctionDescriptor.of(I32, PTR, SIZE_T, PTR, SIZE_T, PTR));
    private static final MethodHandle H_LZ_DECOMPRESS = fn("wilis_lz_decompress", FunctionDescriptor.of(I32, PTR, SIZE_T, SIZE_T, PTR, SIZE_T, PTR));

    private Wilis() {}

    private static void check(String op, int rc) {
        if (rc == OK) return;
        if (rc == ERR_AUTH_FAILED) throw new WilisAuthException(op);
        throw new WilisException(op, rc);
    }

    private static void checkLen(String name, byte[] b, int expected) {
        if (b == null || b.length != expected) {
            throw new IllegalArgumentException(name + " must be exactly " + expected + " bytes");
        }
    }

    private static MemorySegment seg(Arena arena, byte[] data) {
        if (data == null || data.length == 0) return MemorySegment.NULL;
        return arena.allocateFrom(U8, data);
    }

    @FunctionalInterface
    private interface VarOutFn {
        int call(MemorySegment outSeg, long cap, MemorySegment lenSeg) throws Throwable;
    }

    private static byte[] callVarOut(Arena arena, String op, VarOutFn fn) {
        try {
            MemorySegment lenSeg = arena.allocate(SIZE_T);
            int rc = fn.call(MemorySegment.NULL, 0L, lenSeg);
            long needed = lenSeg.get(SIZE_T, 0);
            if (rc == OK && needed == 0L) return new byte[0];
            if (rc != ERR_BUF_TOO_SMALL) check(op, rc);
            MemorySegment outSeg = arena.allocate(needed);
            rc = fn.call(outSeg, needed, lenSeg);
            check(op, rc);
            long actual = lenSeg.get(SIZE_T, 0);
            return outSeg.asSlice(0, actual).toArray(U8);
        } catch (WilisException e) {
            throw e;
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    // --- 1..4: Metadata & Constant-Time / Memory Safety ---

    public static String version() {
        try {
            MemorySegment ptr = (MemorySegment) H_VERSION.invokeExact();
            return ptr.reinterpret(128).getString(0, StandardCharsets.UTF_8);
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    public static boolean ctEq(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        try (Arena arena = Arena.ofConfined()) {
            int rc = (int) H_CT_EQ.invokeExact(seg(arena, a), seg(arena, b), (long) a.length);
            if (rc < 0) check("ct_eq", rc);
            return rc == 1;
        } catch (WilisException e) {
            throw e;
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    public static void zeroize(byte[] buf) {
        if (buf == null || buf.length == 0) return;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment s = seg(arena, buf);
            int rc = (int) H_ZEROIZE.invokeExact(s, (long) buf.length);
            check("zeroize", rc);
            Arrays.fill(buf, (byte) 0);
        } catch (WilisException e) {
            throw e;
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    public static byte[] randomBytes(int length) {
        if (length < 0) throw new IllegalArgumentException("length < 0");
        if (length == 0) return new byte[0];
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(length);
            check("random_bytes", (int) H_RANDOM_BYTES.invokeExact(out, (long) length));
            return out.toArray(U8);
        } catch (WilisException e) {
            throw e;
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }

    // --- 5..9: Hash, TreeHash, MAC, Subkey, XOF ---

    public static byte[] hash256(byte[] data) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(HASH_BYTES);
            check("hash_256", (int) H_HASH_256.invokeExact(seg(arena, data), (long) data.length, out));
            return out.toArray(U8);
        } catch (WilisException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    public static byte[] treeHash256(byte[] data) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = arena.allocate(HASH_BYTES);
            check("tree_hash_256", (int) H_TREE_HASH_256.invokeExact(seg(arena, data), (long) data.length, out));
            return out.toArray(U8);
        } catch (WilisException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    public static byte[] mac256(byte[] key, byte[] msg) {
        checkLen("key", key, KEY_BYTES);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment tag = arena.allocate(TAG_BYTES);
            check("mac_256", (int) H_MAC_256.invokeExact(seg(arena, key), seg(arena, msg), (long) msg.length, tag));
            return tag.toArray(U8);
        } catch (WilisException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    public static byte[] subkeyDerive(byte[] masterKey, byte[] context) {
        checkLen("masterKey", masterKey, KEY_BYTES);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment sub = arena.allocate(KEY_BYTES);
            check("subkey_derive", (int) H_SUBKEY_DERIVE.invokeExact(seg(arena, masterKey), seg(arena, context), (long) context.length, sub));
            return sub.toArray(U8);
        } catch (WilisException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    public static byte[] xofDerive(byte[] label, byte[] seed, int outLen) {
        if (outLen < 0) throw new IllegalArgumentException("outLen < 0");
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment out = outLen == 0 ? MemorySegment.NULL : arena.allocate(outLen);
            check("xof_derive", (int) H_XOF_DERIVE.invokeExact(seg(arena, label), (long) label.length, seg(arena, seed), (long) seed.length, out, (long) outLen));
            return outLen == 0 ? new byte[0] : out.toArray(U8);
        } catch (WilisException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    // --- 10..13: AEAD & SIV ---

    public static BytesPair aeadSeal(byte[] key, byte[] nonce, byte[] aad, byte[] pt) {
        checkLen("key", key, KEY_BYTES);
        checkLen("nonce", nonce, NONCE_BYTES);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment ct = pt.length == 0 ? MemorySegment.NULL : arena.allocate(pt.length);
            MemorySegment tag = arena.allocate(TAG_BYTES);
            check("aead_seal", (int) H_AEAD_SEAL.invokeExact(seg(arena, key), seg(arena, nonce), seg(arena, aad), (long) aad.length, seg(arena, pt), (long) pt.length, ct, tag));
            return new BytesPair(pt.length == 0 ? new byte[0] : ct.toArray(U8), tag.toArray(U8));
        } catch (WilisException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    public static byte[] aeadOpen(byte[] key, byte[] nonce, byte[] aad, byte[] ct, byte[] tag) {
        checkLen("key", key, KEY_BYTES);
        checkLen("nonce", nonce, NONCE_BYTES);
        checkLen("tag", tag, TAG_BYTES);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment pt = ct.length == 0 ? MemorySegment.NULL : arena.allocate(ct.length);
            check("aead_open", (int) H_AEAD_OPEN.invokeExact(seg(arena, key), seg(arena, nonce), seg(arena, aad), (long) aad.length, seg(arena, ct), (long) ct.length, seg(arena, tag), pt));
            return ct.length == 0 ? new byte[0] : pt.toArray(U8);
        } catch (WilisException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    public static BytesPair sivSeal(byte[] key, byte[] aad, byte[] pt) {
        checkLen("key", key, KEY_BYTES);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment ct = pt.length == 0 ? MemorySegment.NULL : arena.allocate(pt.length);
            MemorySegment tag = arena.allocate(SIV_TAG_BYTES);
            check("siv_seal", (int) H_SIV_SEAL.invokeExact(seg(arena, key), seg(arena, aad), (long) aad.length, seg(arena, pt), (long) pt.length, ct, tag));
            return new BytesPair(pt.length == 0 ? new byte[0] : ct.toArray(U8), tag.toArray(U8));
        } catch (WilisException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    public static byte[] sivOpen(byte[] key, byte[] aad, byte[] ct, byte[] sivTag) {
        checkLen("key", key, KEY_BYTES);
        checkLen("sivTag", sivTag, SIV_TAG_BYTES);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment pt = ct.length == 0 ? MemorySegment.NULL : arena.allocate(ct.length);
            check("siv_open", (int) H_SIV_OPEN.invokeExact(seg(arena, key), seg(arena, aad), (long) aad.length, seg(arena, ct), (long) ct.length, seg(arena, sivTag), pt));
            return ct.length == 0 ? new byte[0] : pt.toArray(U8);
        } catch (WilisException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    // --- 14..15: KDF ---

    public static byte[] kdfDerive(byte[] pass, byte[] salt, int memoryBlocks, int passes) {
        checkLen("salt", salt, SALT_BYTES);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = arena.allocate(KEY_BYTES);
            check("kdf_derive", (int) H_KDF_DERIVE.invokeExact(seg(arena, pass), (long) pass.length, seg(arena, salt), memoryBlocks, passes, key));
            return key.toArray(U8);
        } catch (WilisException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    public static byte[] kdfParallelDerive(byte[] pass, byte[] salt, int memoryBlocks, int passes, int lanes) {
        checkLen("salt", salt, SALT_BYTES);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment key = arena.allocate(KEY_BYTES);
            check("kdf_parallel_derive", (int) H_KDF_PARALLEL.invokeExact(seg(arena, pass), (long) pass.length, seg(arena, salt), memoryBlocks, passes, lanes, key));
            return key.toArray(U8);
        } catch (WilisException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    // --- 16..18: KEM ---

    public static BytesPair kemKeygen() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment pk = arena.allocate(KEM_PK_BYTES);
            MemorySegment sk = arena.allocate(KEM_SK_BYTES);
            check("kem_keygen", (int) H_KEM_KEYGEN.invokeExact(pk, sk));
            return new BytesPair(pk.toArray(U8), sk.toArray(U8));
        } catch (WilisException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    public static BytesPair kemEncapsulate(byte[] pk) {
        checkLen("pk", pk, KEM_PK_BYTES);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment ct = arena.allocate(KEM_CT_BYTES);
            MemorySegment ss = arena.allocate(KEM_SS_BYTES);
            check("kem_encapsulate", (int) H_KEM_ENCAP.invokeExact(seg(arena, pk), ct, ss));
            return new BytesPair(ct.toArray(U8), ss.toArray(U8));
        } catch (WilisException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    public static byte[] kemDecapsulate(byte[] sk, byte[] ct) {
        checkLen("sk", sk, KEM_SK_BYTES);
        checkLen("ct", ct, KEM_CT_BYTES);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment ss = arena.allocate(KEM_SS_BYTES);
            check("kem_decapsulate", (int) H_KEM_DECAP.invokeExact(seg(arena, sk), seg(arena, ct), ss));
            return ss.toArray(U8);
        } catch (WilisException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    // --- 19..24: Signatures ---

    public static BytesPair signKeygen(int height) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment pk = arena.allocate(SIGN_PK_BYTES);
            MemorySegment sk = arena.allocate(SIGN_SK_BYTES);
            check("sign_keygen", (int) H_SIGN_KEYGEN.invokeExact((byte) height, pk, sk));
            return new BytesPair(pk.toArray(U8), sk.toArray(U8));
        } catch (WilisException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    public static BytesPair signMessage(byte[] sk, byte[] msg) {
        checkLen("sk", sk, SIGN_SK_BYTES);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment skSeg = seg(arena, sk);
            MemorySegment sig = arena.allocate(SIGN_MAX_SIG_BYTES);
            MemorySegment sigLen = arena.allocate(SIZE_T);
            check("sign_message", (int) H_SIGN_MESSAGE.invokeExact(skSeg, seg(arena, msg), (long) msg.length, sig, (long) SIGN_MAX_SIG_BYTES, sigLen));
            long actual = sigLen.get(SIZE_T, 0);
            return new BytesPair(sig.asSlice(0, actual).toArray(U8), skSeg.toArray(U8));
        } catch (WilisException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    public static boolean verifyMessage(byte[] pk, byte[] msg, byte[] sig) {
        checkLen("pk", pk, SIGN_PK_BYTES);
        try (Arena arena = Arena.ofConfined()) {
            int rc = (int) H_VERIFY_MESSAGE.invokeExact(seg(arena, pk), seg(arena, msg), (long) msg.length, seg(arena, sig), (long) sig.length);
            if (rc == OK) return true;
            if (rc == ERR_AUTH_FAILED) return false;
            check("verify_message", rc);
            return false;
        } catch (WilisException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    public static BytesPair slhKeygen() {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment pk = arena.allocate(SLH_PK_BYTES);
            MemorySegment sk = arena.allocate(SLH_SK_BYTES);
            check("slh_keygen", (int) H_SLH_KEYGEN.invokeExact(pk, sk));
            return new BytesPair(pk.toArray(U8), sk.toArray(U8));
        } catch (WilisException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    public static byte[] slhSign(byte[] sk, byte[] msg) {
        checkLen("sk", sk, SLH_SK_BYTES);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment sig = arena.allocate(SLH_SIG_BYTES);
            check("slh_sign", (int) H_SLH_SIGN.invokeExact(seg(arena, sk), seg(arena, msg), (long) msg.length, sig));
            return sig.toArray(U8);
        } catch (WilisException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    public static boolean slhVerify(byte[] pk, byte[] msg, byte[] sig) {
        checkLen("pk", pk, SLH_PK_BYTES);
        checkLen("sig", sig, SLH_SIG_BYTES);
        try (Arena arena = Arena.ofConfined()) {
            int rc = (int) H_SLH_VERIFY.invokeExact(seg(arena, pk), seg(arena, msg), (long) msg.length, seg(arena, sig));
            if (rc == OK) return true;
            if (rc == ERR_AUTH_FAILED) return false;
            check("slh_verify", rc);
            return false;
        } catch (WilisException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    // --- 25..26: Signcryption ---

    public static byte[] signcrypt(byte[] senderSlhSk, byte[] recipientKemPk, byte[] aad, byte[] pt) {
        checkLen("senderSlhSk", senderSlhSk, SLH_SK_BYTES);
        checkLen("recipientKemPk", recipientKemPk, KEM_PK_BYTES);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment sk = seg(arena, senderSlhSk);
            MemorySegment pk = seg(arena, recipientKemPk);
            MemorySegment aadSeg = seg(arena, aad);
            MemorySegment ptSeg = seg(arena, pt);
            return callVarOut(arena, "signcrypt", (out, cap, len) ->
                (int) H_SIGNCRYPT.invokeExact(sk, pk, aadSeg, (long) aad.length, ptSeg, (long) pt.length, out, cap, len));
        }
    }

    public static byte[] unsigncrypt(byte[] senderSlhPk, byte[] recipientKemSk, byte[] aad, byte[] packet) {
        checkLen("senderSlhPk", senderSlhPk, SLH_PK_BYTES);
        checkLen("recipientKemSk", recipientKemSk, KEM_SK_BYTES);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment pk = seg(arena, senderSlhPk);
            MemorySegment sk = seg(arena, recipientKemSk);
            MemorySegment aadSeg = seg(arena, aad);
            MemorySegment pktSeg = seg(arena, packet);
            return callVarOut(arena, "unsigncrypt", (out, cap, len) ->
                (int) H_UNSIGNCRYPT.invokeExact(pk, sk, aadSeg, (long) aad.length, pktSeg, (long) packet.length, out, cap, len));
        }
    }

    // --- 27..33: TOTP, FPE, Mnemonic, WilisLZ ---

    public static TotpResult totpAt(byte[] secret, long unixSecs, long period, int digits) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment codeBuf = arena.allocate(digits + 1L);
            MemorySegment remBuf = arena.allocate(U64);
            check("totp_at", (int) H_TOTP_AT.invokeExact(seg(arena, secret), (long) secret.length, unixSecs, period, digits, codeBuf, (long) (digits + 1), remBuf));
            return new TotpResult(codeBuf.getString(0, StandardCharsets.US_ASCII), remBuf.get(U64, 0));
        } catch (WilisException e) { throw e; } catch (Throwable t) { throw new RuntimeException(t); }
    }

    public static String fpeEncrypt(byte[] key, byte[] tweak, String alphabet, String plaintext) {
        checkLen("key", key, KEY_BYTES);
        byte[] alpha = alphabet.getBytes(StandardCharsets.UTF_8);
        byte[] pt = plaintext.getBytes(StandardCharsets.UTF_8);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment kSeg = seg(arena, key), twSeg = seg(arena, tweak), alSeg = seg(arena, alpha), ptSeg = seg(arena, pt);
            byte[] out = callVarOut(arena, "fpe_encrypt", (o, cap, len) ->
                (int) H_FPE_ENCRYPT.invokeExact(kSeg, twSeg, (long) tweak.length, alSeg, (long) alpha.length, ptSeg, (long) pt.length, o, cap, len));
            return new String(out, StandardCharsets.UTF_8);
        }
    }

    public static String fpeDecrypt(byte[] key, byte[] tweak, String alphabet, String ciphertext) {
        checkLen("key", key, KEY_BYTES);
        byte[] alpha = alphabet.getBytes(StandardCharsets.UTF_8);
        byte[] ct = ciphertext.getBytes(StandardCharsets.UTF_8);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment kSeg = seg(arena, key), twSeg = seg(arena, tweak), alSeg = seg(arena, alpha), ctSeg = seg(arena, ct);
            byte[] out = callVarOut(arena, "fpe_decrypt", (o, cap, len) ->
                (int) H_FPE_DECRYPT.invokeExact(kSeg, twSeg, (long) tweak.length, alSeg, (long) alpha.length, ctSeg, (long) ct.length, o, cap, len));
            return new String(out, StandardCharsets.UTF_8);
        }
    }

    public static String mnemonicEncode(byte[] secret) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment sSeg = seg(arena, secret);
            byte[] utf8 = callVarOut(arena, "mnemonic_encode", (o, cap, len) ->
                (int) H_MNEMONIC_ENCODE.invokeExact(sSeg, (long) secret.length, o, cap, len));
            return new String(utf8, StandardCharsets.UTF_8);
        }
    }

    public static byte[] mnemonicDecode(String phrase) {
        byte[] utf8 = phrase.getBytes(StandardCharsets.UTF_8);
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment pSeg = seg(arena, utf8);
            return callVarOut(arena, "mnemonic_decode", (o, cap, len) ->
                (int) H_MNEMONIC_DECODE.invokeExact(pSeg, (long) utf8.length, o, cap, len));
        }
    }

    public static byte[] lzCompress(byte[] data) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment dSeg = seg(arena, data);
            return callVarOut(arena, "lz_compress", (o, cap, len) ->
                (int) H_LZ_COMPRESS.invokeExact(dSeg, (long) data.length, o, cap, len));
        }
    }

    public static byte[] lzDecompress(byte[] compressed, long maxOut) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment dSeg = seg(arena, compressed);
            return callVarOut(arena, "lz_decompress", (o, cap, len) ->
                (int) H_LZ_DECOMPRESS.invokeExact(dSeg, (long) compressed.length, maxOut, o, cap, len));
        }
    }

    public static void main(String[] args) {
        String ver = version();
        if (!ver.equals("0.7.0")) throw new AssertionError("bad version: " + ver);
        byte[] key = randomBytes(KEY_BYTES);
        byte[] nonce = randomBytes(NONCE_BYTES);
        byte[] pt = "hello java panama ffm".getBytes(StandardCharsets.UTF_8);
        BytesPair sealed = aeadSeal(key, nonce, "aad".getBytes(StandardCharsets.UTF_8), pt);
        byte[] opened = aeadOpen(key, nonce, "aad".getBytes(StandardCharsets.UTF_8), sealed.first(), sealed.second());
        if (!ctEq(pt, opened)) throw new AssertionError("AEAD mismatch");
        BytesPair kem = kemKeygen();
        BytesPair enc = kemEncapsulate(kem.first());
        if (!ctEq(enc.second(), kemDecapsulate(kem.second(), enc.first()))) throw new AssertionError("KEM mismatch");
        BytesPair slh = slhKeygen();
        byte[] pkt = signcrypt(slh.second(), kem.first(), "ctx".getBytes(StandardCharsets.UTF_8), pt);
        if (!ctEq(pt, unsigncrypt(slh.first(), kem.second(), "ctx".getBytes(StandardCharsets.UTF_8), pkt))) throw new AssertionError("signcrypt mismatch");
        TotpResult totp = totpAt(key, 1700000000L, 30L, 6);
        if (totp.code().length() != 6) throw new AssertionError("TOTP len");
        String fpeCt = fpeEncrypt(key, "cc".getBytes(StandardCharsets.UTF_8), "0123456789", "4111111111111111");
        if (!"4111111111111111".equals(fpeDecrypt(key, "cc".getBytes(StandardCharsets.UTF_8), "0123456789", fpeCt))) throw new AssertionError("FPE mismatch");
        if (!ctEq(key, mnemonicDecode(mnemonicEncode(key)))) throw new AssertionError("Mnemonic mismatch");
        byte[] rep = "WilisJavaPanama!".repeat(20).getBytes(StandardCharsets.UTF_8);
        if (!ctEq(rep, lzDecompress(lzCompress(rep), 1024 * 1024))) throw new AssertionError("LZ mismatch");
        zeroize(key);
        System.out.println("Wilis Java Panama FFM OK (v" + ver + ", 33 C-ABI exports)");
    }
}
