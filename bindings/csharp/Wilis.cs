// Wilis v0.7.0 — Zero-Dependency C# / .NET P/Invoke Bindings (All 33 C-ABI exports)
//
// Build libwilis first:
//   cargo build --release
//
// Ensure libwilis.so / libwilis.dylib / wilis.dll is on the dynamic library search path
// (e.g. LD_LIBRARY_PATH, DYLD_LIBRARY_PATH, PATH, or next to the .NET assembly).

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace WilisCrypto;

public class WilisException : Exception
{
    public int Code { get; }

    public WilisException(string op, int code)
        : base($"Wilis {op} failed with code {code}")
    {
        Code = code;
    }
}

public sealed class WilisAuthException : WilisException
{
    public WilisAuthException(string op)
        : base(op, Wilis.ErrAuthFailed) { }
}

/// <summary>
/// Auto-zeroizing wrapper around sensitive key bytes using libwilis volatile zeroize.
/// </summary>
public sealed class WilisSecret : IDisposable
{
    private byte[] _bytes;
    private bool _disposed;

    public WilisSecret(byte[] bytes)
    {
        _bytes = bytes ?? throw new ArgumentNullException(nameof(bytes));
    }

    public byte[] Bytes => _disposed
        ? throw new ObjectDisposedException(nameof(WilisSecret))
        : _bytes;

    public void Dispose()
    {
        if (!_disposed)
        {
            Wilis.Zeroize(_bytes);
            _disposed = true;
        }
    }
}

public readonly record struct TotpResult(string Code, ulong RemainingSeconds);

public static class Wilis
{
    private const string LibName = "wilis";

    public const int KeyBytes = 32;
    public const int NonceBytes = 24;
    public const int SaltBytes = 24;
    public const int TagBytes = 32;
    public const int SivTagBytes = 64;
    public const int HashBytes = 32;

    public const int KemPkBytes = 1284;
    public const int KemSkBytes = 2600;
    public const int KemCtBytes = 1668;
    public const int KemSsBytes = 32;

    public const int SignPkBytes = 101;
    public const int SignSkBytes = 137;
    public const int SignMaxSigBytes = 2506;

    public const int SlhPkBytes = 100;
    public const int SlhSkBytes = 164;
    public const int SlhSigBytes = 8165;
    public const int SigncryptOverhead = 9894;

    public const int Ok = 0;
    public const int ErrInvalidArg = -1;
    public const int ErrAuthFailed = -2;
    public const int ErrInternal = -3;
    public const int ErrBufTooSmall = -4;

    private static class Native
    {
        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr wilis_version();

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_ct_eq(byte[]? a, byte[]? b, nuint len);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_zeroize([In, Out] byte[]? buf, nuint len);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_random_bytes([Out] byte[]? outBuf, nuint len);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_hash_256(byte[]? data, nuint dataLen, [Out] byte[] out32);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_tree_hash_256(byte[]? data, nuint dataLen, [Out] byte[] out32);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_mac_256(byte[] key32, byte[]? msg, nuint msgLen, [Out] byte[] tag32Out);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_subkey_derive(byte[] masterKey32, byte[]? context, nuint contextLen, [Out] byte[] subkey32Out);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_xof_derive(byte[]? label, nuint labelLen, byte[]? seed, nuint seedLen, [Out] byte[]? outBuf, nuint outLen);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_aead_seal(
            byte[] key32, byte[] nonce24,
            byte[]? aad, nuint aadLen,
            byte[]? pt, nuint ptLen,
            [Out] byte[]? ctOut, [Out] byte[] tag32Out);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_aead_open(
            byte[] key32, byte[] nonce24,
            byte[]? aad, nuint aadLen,
            byte[]? ct, nuint ctLen,
            byte[] tag32, [Out] byte[]? ptOut);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_siv_seal(
            byte[] key32,
            byte[]? aad, nuint aadLen,
            byte[]? pt, nuint ptLen,
            [Out] byte[]? ctOut, [Out] byte[] sivTag64Out);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_siv_open(
            byte[] key32,
            byte[]? aad, nuint aadLen,
            byte[]? ct, nuint ctLen,
            byte[] sivTag64, [Out] byte[]? ptOut);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_kdf_derive(
            byte[]? pass, nuint passLen,
            byte[] salt24, uint memoryBlocks, uint passes,
            [Out] byte[] key32Out);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_kdf_parallel_derive(
            byte[]? pass, nuint passLen,
            byte[] salt24, uint memoryBlocks, uint passes, uint lanes,
            [Out] byte[] key32Out);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_kem_keygen([Out] byte[] pkOut, [Out] byte[] skOut);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_kem_encapsulate(byte[] pk, [Out] byte[] ctOut, [Out] byte[] ss32Out);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_kem_decapsulate(byte[] sk, byte[] ct, [Out] byte[] ss32Out);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_sign_keygen(byte height, [Out] byte[] pkOut, [Out] byte[] skOut);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_sign_message(
            [In, Out] byte[] skInOut,
            byte[]? msg, nuint msgLen,
            [Out] byte[] sigOut, nuint sigCap, out nuint sigLenOut);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_verify_message(
            byte[] pk,
            byte[]? msg, nuint msgLen,
            byte[] sig, nuint sigLen);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_slh_keygen([Out] byte[] pkOut, [Out] byte[] skOut);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_slh_sign(byte[] sk, byte[]? msg, nuint msgLen, [Out] byte[] sigOut);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_slh_verify(byte[] pk, byte[]? msg, nuint msgLen, byte[] sig);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_signcrypt(
            byte[] senderSlhSk, byte[] recipientKemPk,
            byte[]? aad, nuint aadLen,
            byte[]? pt, nuint ptLen,
            [Out] byte[]? outBuf, nuint outCap, out nuint outLenOut);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_unsigncrypt(
            byte[] senderSlhPk, byte[] recipientKemSk,
            byte[]? aad, nuint aadLen,
            byte[]? packet, nuint packetLen,
            [Out] byte[]? ptOut, nuint ptCap, out nuint ptLenOut);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_totp_at(
            byte[]? secret, nuint secretLen,
            ulong unixSecs, ulong period, uint digits,
            [Out] byte[] codeOut, nuint codeCap, out ulong remainingOut);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_fpe_encrypt(
            byte[] key32,
            byte[]? tweak, nuint tweakLen,
            byte[] alphabet, nuint alphaLen,
            byte[]? pt, nuint ptLen,
            [Out] byte[]? outBuf, nuint outCap, out nuint outLenOut);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_fpe_decrypt(
            byte[] key32,
            byte[]? tweak, nuint tweakLen,
            byte[] alphabet, nuint alphaLen,
            byte[]? ct, nuint ctLen,
            [Out] byte[]? outBuf, nuint outCap, out nuint outLenOut);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_mnemonic_encode(
            byte[]? secret, nuint secretLen,
            [Out] byte[]? outUtf8, nuint outCap, out nuint outLenOut);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_mnemonic_decode(
            byte[]? phrase, nuint phraseLen,
            [Out] byte[]? outBuf, nuint outCap, out nuint outLenOut);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_lz_compress(
            byte[]? data, nuint dataLen,
            [Out] byte[]? outBuf, nuint outCap, out nuint outLenOut);

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int wilis_lz_decompress(
            byte[]? data, nuint dataLen, nuint maxOut,
            [Out] byte[]? outBuf, nuint outCap, out nuint outLenOut);
    }

    private static void Check(string op, int rc)
    {
        if (rc == Ok) return;
        if (rc == ErrAuthFailed) throw new WilisAuthException(op);
        throw new WilisException(op, rc);
    }

    private static void CheckLen(string name, byte[] buf, int expected)
    {
        if (buf is null || buf.Length != expected)
            throw new ArgumentException($"{name} must be exactly {expected} bytes", name);
    }

    private delegate int VarOutCall(byte[]? outBuf, nuint outCap, out nuint outLen);

    private static byte[] CallVarOut(string op, VarOutCall fn)
    {
        int rc = fn(null, 0, out nuint needed);
        if (rc == Ok && needed == 0) return Array.Empty<byte>();
        if (rc != ErrBufTooSmall) Check(op, rc);
        byte[] buf = new byte[(int)needed];
        rc = fn(buf, needed, out nuint actual);
        Check(op, rc);
        if ((int)actual == buf.Length) return buf;
        byte[] trimmed = new byte[(int)actual];
        Buffer.BlockCopy(buf, 0, trimmed, 0, (int)actual);
        return trimmed;
    }

    // --- 1..4: Metadata & Memory / Constant-Time Utilities ---

    public static string Version() =>
        Marshal.PtrToStringUTF8(Native.wilis_version()) ?? string.Empty;

    public static bool CtEq(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        int rc = Native.wilis_ct_eq(a, b, (nuint)a.Length);
        if (rc < 0) Check("ct_eq", rc);
        return rc == 1;
    }

    public static void Zeroize(byte[] buf)
    {
        if (buf is null || buf.Length == 0) return;
        Check("zeroize", Native.wilis_zeroize(buf, (nuint)buf.Length));
    }

    public static byte[] RandomBytes(int length)
    {
        if (length < 0) throw new ArgumentOutOfRangeException(nameof(length));
        byte[] outBuf = new byte[length];
        if (length > 0) Check("random_bytes", Native.wilis_random_bytes(outBuf, (nuint)length));
        return outBuf;
    }

    // --- 5..9: Hash, TreeHash, MAC, Subkey, XOF ---

    public static byte[] Hash256(byte[] data)
    {
        byte[] outBuf = new byte[HashBytes];
        Check("hash_256", Native.wilis_hash_256(data, (nuint)data.Length, outBuf));
        return outBuf;
    }

    public static byte[] TreeHash256(byte[] data)
    {
        byte[] outBuf = new byte[HashBytes];
        Check("tree_hash_256", Native.wilis_tree_hash_256(data, (nuint)data.Length, outBuf));
        return outBuf;
    }

    public static byte[] Mac256(byte[] key, byte[] msg)
    {
        CheckLen(nameof(key), key, KeyBytes);
        byte[] tag = new byte[TagBytes];
        Check("mac_256", Native.wilis_mac_256(key, msg, (nuint)msg.Length, tag));
        return tag;
    }

    public static byte[] SubkeyDerive(byte[] masterKey, byte[] context)
    {
        CheckLen(nameof(masterKey), masterKey, KeyBytes);
        byte[] sub = new byte[KeyBytes];
        Check("subkey_derive", Native.wilis_subkey_derive(masterKey, context, (nuint)context.Length, sub));
        return sub;
    }

    public static byte[] XofDerive(byte[] label, byte[] seed, int outLen)
    {
        if (outLen < 0) throw new ArgumentOutOfRangeException(nameof(outLen));
        byte[] outBuf = new byte[outLen];
        Check("xof_derive", Native.wilis_xof_derive(label, (nuint)label.Length, seed, (nuint)seed.Length, outBuf, (nuint)outLen));
        return outBuf;
    }

    // --- 10..13: AEAD & SIV ---

    public static (byte[] Ciphertext, byte[] Tag) AeadSeal(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext)
    {
        CheckLen(nameof(key), key, KeyBytes);
        CheckLen(nameof(nonce), nonce, NonceBytes);
        byte[] ct = new byte[plaintext.Length];
        byte[] tag = new byte[TagBytes];
        Check("aead_seal", Native.wilis_aead_seal(key, nonce, aad, (nuint)aad.Length, plaintext, (nuint)plaintext.Length, ct, tag));
        return (ct, tag);
    }

    public static byte[] AeadOpen(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext, byte[] tag)
    {
        CheckLen(nameof(key), key, KeyBytes);
        CheckLen(nameof(nonce), nonce, NonceBytes);
        CheckLen(nameof(tag), tag, TagBytes);
        byte[] pt = new byte[ciphertext.Length];
        Check("aead_open", Native.wilis_aead_open(key, nonce, aad, (nuint)aad.Length, ciphertext, (nuint)ciphertext.Length, tag, pt));
        return pt;
    }

    public static (byte[] Ciphertext, byte[] SivTag) SivSeal(byte[] key, byte[] aad, byte[] plaintext)
    {
        CheckLen(nameof(key), key, KeyBytes);
        byte[] ct = new byte[plaintext.Length];
        byte[] tag = new byte[SivTagBytes];
        Check("siv_seal", Native.wilis_siv_seal(key, aad, (nuint)aad.Length, plaintext, (nuint)plaintext.Length, ct, tag));
        return (ct, tag);
    }

    public static byte[] SivOpen(byte[] key, byte[] aad, byte[] ciphertext, byte[] sivTag)
    {
        CheckLen(nameof(key), key, KeyBytes);
        CheckLen(nameof(sivTag), sivTag, SivTagBytes);
        byte[] pt = new byte[ciphertext.Length];
        Check("siv_open", Native.wilis_siv_open(key, aad, (nuint)aad.Length, ciphertext, (nuint)ciphertext.Length, sivTag, pt));
        return pt;
    }

    // --- 14..15: Memory-Hard KDF ---

    public static byte[] KdfDerive(byte[] password, byte[] salt, uint memoryBlocks = 16384, uint passes = 3)
    {
        CheckLen(nameof(salt), salt, SaltBytes);
        byte[] key = new byte[KeyBytes];
        Check("kdf_derive", Native.wilis_kdf_derive(password, (nuint)password.Length, salt, memoryBlocks, passes, key));
        return key;
    }

    public static byte[] KdfParallelDerive(byte[] password, byte[] salt, uint memoryBlocks = 16384, uint passes = 3, uint lanes = 4)
    {
        CheckLen(nameof(salt), salt, SaltBytes);
        byte[] key = new byte[KeyBytes];
        Check("kdf_parallel_derive", Native.wilis_kdf_parallel_derive(password, (nuint)password.Length, salt, memoryBlocks, passes, lanes, key));
        return key;
    }

    // --- 16..18: Post-Quantum Module-LWE KEM ---

    public static (byte[] PublicKey, byte[] SecretKey) KemKeygen()
    {
        byte[] pk = new byte[KemPkBytes];
        byte[] sk = new byte[KemSkBytes];
        Check("kem_keygen", Native.wilis_kem_keygen(pk, sk));
        return (pk, sk);
    }

    public static (byte[] Ciphertext, byte[] SharedSecret) KemEncapsulate(byte[] pk)
    {
        CheckLen(nameof(pk), pk, KemPkBytes);
        byte[] ct = new byte[KemCtBytes];
        byte[] ss = new byte[KemSsBytes];
        Check("kem_encapsulate", Native.wilis_kem_encapsulate(pk, ct, ss));
        return (ct, ss);
    }

    public static byte[] KemDecapsulate(byte[] sk, byte[] ct)
    {
        CheckLen(nameof(sk), sk, KemSkBytes);
        CheckLen(nameof(ct), ct, KemCtBytes);
        byte[] ss = new byte[KemSsBytes];
        Check("kem_decapsulate", Native.wilis_kem_decapsulate(sk, ct, ss));
        return ss;
    }

    // --- 19..24: Signatures (Stateful WOTS+ Merkle & Stateless SLH) ---

    public static (byte[] PublicKey, byte[] SecretKey) SignKeygen(byte height = 4)
    {
        byte[] pk = new byte[SignPkBytes];
        byte[] sk = new byte[SignSkBytes];
        Check("sign_keygen", Native.wilis_sign_keygen(height, pk, sk));
        return (pk, sk);
    }

    public static (byte[] Signature, byte[] UpdatedSecretKey) SignMessage(byte[] sk, byte[] msg)
    {
        CheckLen(nameof(sk), sk, SignSkBytes);
        byte[] nextSk = (byte[])sk.Clone();
        byte[] sig = new byte[SignMaxSigBytes];
        Check("sign_message", Native.wilis_sign_message(nextSk, msg, (nuint)msg.Length, sig, (nuint)sig.Length, out nuint sigLen));
        byte[] trimmed = new byte[(int)sigLen];
        Buffer.BlockCopy(sig, 0, trimmed, 0, (int)sigLen);
        return (trimmed, nextSk);
    }

    public static bool VerifyMessage(byte[] pk, byte[] msg, byte[] sig)
    {
        CheckLen(nameof(pk), pk, SignPkBytes);
        int rc = Native.wilis_verify_message(pk, msg, (nuint)msg.Length, sig, (nuint)sig.Length);
        if (rc == Ok) return true;
        if (rc == ErrAuthFailed) return false;
        Check("verify_message", rc);
        return false;
    }

    public static (byte[] PublicKey, byte[] SecretKey) SlhKeygen()
    {
        byte[] pk = new byte[SlhPkBytes];
        byte[] sk = new byte[SlhSkBytes];
        Check("slh_keygen", Native.wilis_slh_keygen(pk, sk));
        return (pk, sk);
    }

    public static byte[] SlhSign(byte[] sk, byte[] msg)
    {
        CheckLen(nameof(sk), sk, SlhSkBytes);
        byte[] sig = new byte[SlhSigBytes];
        Check("slh_sign", Native.wilis_slh_sign(sk, msg, (nuint)msg.Length, sig));
        return sig;
    }

    public static bool SlhVerify(byte[] pk, byte[] msg, byte[] sig)
    {
        CheckLen(nameof(pk), pk, SlhPkBytes);
        CheckLen(nameof(sig), sig, SlhSigBytes);
        int rc = Native.wilis_slh_verify(pk, msg, (nuint)msg.Length, sig);
        if (rc == Ok) return true;
        if (rc == ErrAuthFailed) return false;
        Check("slh_verify", rc);
        return false;
    }

    // --- 25..26: Post-Quantum Signcryption (WPSC v1) ---

    public static byte[] Signcrypt(byte[] senderSlhSk, byte[] recipientKemPk, byte[] aad, byte[] plaintext)
    {
        CheckLen(nameof(senderSlhSk), senderSlhSk, SlhSkBytes);
        CheckLen(nameof(recipientKemPk), recipientKemPk, KemPkBytes);
        return CallVarOut("signcrypt", (byte[]? outBuf, nuint cap, out nuint len) =>
            Native.wilis_signcrypt(senderSlhSk, recipientKemPk, aad, (nuint)aad.Length, plaintext, (nuint)plaintext.Length, outBuf, cap, out len));
    }

    public static byte[] Unsigncrypt(byte[] senderSlhPk, byte[] recipientKemSk, byte[] aad, byte[] packet)
    {
        CheckLen(nameof(senderSlhPk), senderSlhPk, SlhPkBytes);
        CheckLen(nameof(recipientKemSk), recipientKemSk, KemSkBytes);
        return CallVarOut("unsigncrypt", (byte[]? outBuf, nuint cap, out nuint len) =>
            Native.wilis_unsigncrypt(senderSlhPk, recipientKemSk, aad, (nuint)aad.Length, packet, (nuint)packet.Length, outBuf, cap, out len));
    }

    // --- 27..33: TOTP, FPE, Mnemonic, WilisLZ ---

    public static TotpResult TotpAt(byte[] secret, ulong unixSecs, ulong period = 30, uint digits = 6)
    {
        byte[] codeBuf = new byte[digits + 1];
        Check("totp_at", Native.wilis_totp_at(secret, (nuint)secret.Length, unixSecs, period, digits, codeBuf, (nuint)codeBuf.Length, out ulong rem));
        return new TotpResult(Encoding.ASCII.GetString(codeBuf, 0, (int)digits), rem);
    }

    public static string FpeEncrypt(byte[] key, byte[] tweak, string alphabet, string plaintext)
    {
        CheckLen(nameof(key), key, KeyBytes);
        byte[] alpha = Encoding.UTF8.GetBytes(alphabet);
        byte[] pt = Encoding.UTF8.GetBytes(plaintext);
        byte[] ct = CallVarOut("fpe_encrypt", (byte[]? outBuf, nuint cap, out nuint len) =>
            Native.wilis_fpe_encrypt(key, tweak, (nuint)tweak.Length, alpha, (nuint)alpha.Length, pt, (nuint)pt.Length, outBuf, cap, out len));
        return Encoding.UTF8.GetString(ct);
    }

    public static string FpeDecrypt(byte[] key, byte[] tweak, string alphabet, string ciphertext)
    {
        CheckLen(nameof(key), key, KeyBytes);
        byte[] alpha = Encoding.UTF8.GetBytes(alphabet);
        byte[] ct = Encoding.UTF8.GetBytes(ciphertext);
        byte[] pt = CallVarOut("fpe_decrypt", (byte[]? outBuf, nuint cap, out nuint len) =>
            Native.wilis_fpe_decrypt(key, tweak, (nuint)tweak.Length, alpha, (nuint)alpha.Length, ct, (nuint)ct.Length, outBuf, cap, out len));
        return Encoding.UTF8.GetString(pt);
    }

    public static string MnemonicEncode(byte[] secret)
    {
        byte[] utf8 = CallVarOut("mnemonic_encode", (byte[]? outBuf, nuint cap, out nuint len) =>
            Native.wilis_mnemonic_encode(secret, (nuint)secret.Length, outBuf, cap, out len));
        return Encoding.UTF8.GetString(utf8);
    }

    public static byte[] MnemonicDecode(string phrase)
    {
        byte[] utf8 = Encoding.UTF8.GetBytes(phrase);
        return CallVarOut("mnemonic_decode", (byte[]? outBuf, nuint cap, out nuint len) =>
            Native.wilis_mnemonic_decode(utf8, (nuint)utf8.Length, outBuf, cap, out len));
    }

    public static byte[] LzCompress(byte[] data) =>
        CallVarOut("lz_compress", (byte[]? outBuf, nuint cap, out nuint len) =>
            Native.wilis_lz_compress(data, (nuint)data.Length, outBuf, cap, out len));

    public static byte[] LzDecompress(byte[] compressed, ulong maxOut = 64UL * 1024UL * 1024UL) =>
        CallVarOut("lz_decompress", (byte[]? outBuf, nuint cap, out nuint len) =>
            Native.wilis_lz_decompress(compressed, (nuint)compressed.Length, (nuint)maxOut, outBuf, cap, out len));
}
