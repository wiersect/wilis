// Wilis v0.7.0 — Zero-Dependency Dart FFI Bindings (All 33 C-ABI exports)
// Uses ONLY dart:ffi, dart:io, dart:typed_data, dart:convert (zero pub.dev packages).
//
// Run self-test after `cargo build --release`:
//   dart run bindings/dart/wilis.dart

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

const int wilisKeyBytes = 32;
const int wilisNonceBytes = 24;
const int wilisSaltBytes = 24;
const int wilisTagBytes = 32;
const int wilisSivTagBytes = 64;
const int wilisHashBytes = 32;

const int wilisKemPkBytes = 1284;
const int wilisKemSkBytes = 2600;
const int wilisKemCtBytes = 1668;
const int wilisKemSsBytes = 32;

const int wilisSignPkBytes = 101;
const int wilisSignSkBytes = 137;
const int wilisSignMaxSigBytes = 2506;

const int wilisSlhPkBytes = 100;
const int wilisSlhSkBytes = 164;
const int wilisSlhSigBytes = 8165;
const int wilisSigncryptOverhead = 9894;

const int wilisOk = 0;
const int wilisErrInvalidArg = -1;
const int wilisErrAuthFailed = -2;
const int wilisErrInternal = -3;
const int wilisErrBufTooSmall = -4;

class WilisException implements Exception {
  final String op;
  final int code;
  WilisException(this.op, this.code);
  @override
  String toString() => 'WilisException($op, code=$code)';
}

class WilisAuthException extends WilisException {
  WilisAuthException(String op) : super(op, wilisErrAuthFailed);
}

// Zero-dependency libc calloc/free allocator
typedef _CallocNative = Pointer<Void> Function(Size num, Size size);
typedef _CallocDart = Pointer<Void> Function(int num, int size);
typedef _FreeNative = Void Function(Pointer<Void> ptr);
typedef _FreeDart = void Function(Pointer<Void> ptr);

class _NativeMem {
  static final DynamicLibrary _crt = Platform.isWindows
      ? DynamicLibrary.open('ucrtbase.dll')
      : DynamicLibrary.process();
  static final _CallocDart _calloc =
      _crt.lookupFunction<_CallocNative, _CallocDart>('calloc');
  static final _FreeDart _free =
      _crt.lookupFunction<_FreeNative, _FreeDart>('free');

  final List<Pointer<Void>> _allocs = [];

  Pointer<Uint8> allocBytes(int count) {
    if (count == 0) return nullptr;
    final p = _calloc(count, 1);
    if (p == nullptr) throw StateError('Native allocation failed');
    _allocs.add(p);
    return p.cast<Uint8>();
  }

  Pointer<Uint8> fromBytes(Uint8List data) {
    if (data.isEmpty) return nullptr;
    final p = allocBytes(data.length);
    p.asTypedList(data.length).setAll(0, data);
    return p;
  }

  Pointer<Size> allocSize() {
    final p = _calloc(1, sizeOf<Size>());
    _allocs.add(p);
    return p.cast<Size>();
  }

  Pointer<Uint64> allocU64() {
    final p = _calloc(1, 8);
    _allocs.add(p);
    return p.cast<Uint64>();
  }

  void release() {
    for (final p in _allocs) {
      _free(p);
    }
    _allocs.clear();
  }
}

// Native C function typedefs (all 33 symbols)
typedef _VersionN = Pointer<Uint8> Function();
typedef _VersionD = Pointer<Uint8> Function();
typedef _CtEqN = Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Size);
typedef _CtEqD = int Function(Pointer<Uint8>, Pointer<Uint8>, int);
typedef _BufLenN = Int32 Function(Pointer<Uint8>, Size);
typedef _BufLenD = int Function(Pointer<Uint8>, int);
typedef _HashN = Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>);
typedef _HashD = int Function(Pointer<Uint8>, int, Pointer<Uint8>);
typedef _KeyMsgOutN = Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Size, Pointer<Uint8>);
typedef _KeyMsgOutD = int Function(Pointer<Uint8>, Pointer<Uint8>, int, Pointer<Uint8>);
typedef _XofN = Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _XofD = int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _AeadN = Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Pointer<Uint8>);
typedef _AeadD = int Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, Pointer<Uint8>);
typedef _SivN = Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Pointer<Uint8>);
typedef _SivD = int Function(Pointer<Uint8>, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, Pointer<Uint8>);
typedef _KdfN = Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Uint32, Uint32, Pointer<Uint8>);
typedef _KdfD = int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, int, Pointer<Uint8>);
typedef _KdfParN = Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Uint32, Uint32, Uint32, Pointer<Uint8>);
typedef _KdfParD = int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, int, int, Pointer<Uint8>);
typedef _TwoPtrN = Int32 Function(Pointer<Uint8>, Pointer<Uint8>);
typedef _TwoPtrD = int Function(Pointer<Uint8>, Pointer<Uint8>);
typedef _ThreePtrN = Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);
typedef _ThreePtrD = int Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>);
typedef _SignKeygenN = Int32 Function(Uint8, Pointer<Uint8>, Pointer<Uint8>);
typedef _SignKeygenD = int Function(int, Pointer<Uint8>, Pointer<Uint8>);
typedef _SignMsgN = Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Size>);
typedef _SignMsgD = int Function(Pointer<Uint8>, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Size>);
typedef _VerifyMsgN = Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _VerifyMsgD = int Function(Pointer<Uint8>, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef _SigncryptN = Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Size>);
typedef _SigncryptD = int Function(Pointer<Uint8>, Pointer<Uint8>, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Size>);
typedef _TotpN = Int32 Function(Pointer<Uint8>, Size, Uint64, Uint64, Uint32, Pointer<Uint8>, Size, Pointer<Uint64>);
typedef _TotpD = int Function(Pointer<Uint8>, int, int, int, int, Pointer<Uint8>, int, Pointer<Uint64>);
typedef _FpeN = Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Size>);
typedef _FpeD = int Function(Pointer<Uint8>, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Size>);
typedef _VarInOutN = Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Size>);
typedef _VarInOutD = int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Size>);
typedef _LzDecN = Int32 Function(Pointer<Uint8>, Size, Size, Pointer<Uint8>, Size, Pointer<Size>);
typedef _LzDecD = int Function(Pointer<Uint8>, int, int, Pointer<Uint8>, int, Pointer<Size>);

class Wilis {
  final DynamicLibrary _lib;

  late final _VersionD _version = _lib.lookupFunction<_VersionN, _VersionD>('wilis_version');
  late final _CtEqD _ctEq = _lib.lookupFunction<_CtEqN, _CtEqD>('wilis_ct_eq');
  late final _BufLenD _zeroize = _lib.lookupFunction<_BufLenN, _BufLenD>('wilis_zeroize');
  late final _BufLenD _randomBytes = _lib.lookupFunction<_BufLenN, _BufLenD>('wilis_random_bytes');
  late final _HashD _hash256 = _lib.lookupFunction<_HashN, _HashD>('wilis_hash_256');
  late final _HashD _treeHash256 = _lib.lookupFunction<_HashN, _HashD>('wilis_tree_hash_256');
  late final _KeyMsgOutD _mac256 = _lib.lookupFunction<_KeyMsgOutN, _KeyMsgOutD>('wilis_mac_256');
  late final _KeyMsgOutD _subkeyDerive = _lib.lookupFunction<_KeyMsgOutN, _KeyMsgOutD>('wilis_subkey_derive');
  late final _XofD _xofDerive = _lib.lookupFunction<_XofN, _XofD>('wilis_xof_derive');
  late final _AeadD _aeadSeal = _lib.lookupFunction<_AeadN, _AeadD>('wilis_aead_seal');
  late final _AeadD _aeadOpen = _lib.lookupFunction<_AeadN, _AeadD>('wilis_aead_open');
  late final _SivD _sivSeal = _lib.lookupFunction<_SivN, _SivD>('wilis_siv_seal');
  late final _SivD _sivOpen = _lib.lookupFunction<_SivN, _SivD>('wilis_siv_open');
  late final _KdfD _kdfDerive = _lib.lookupFunction<_KdfN, _KdfD>('wilis_kdf_derive');
  late final _KdfParD _kdfParallelDerive = _lib.lookupFunction<_KdfParN, _KdfParD>('wilis_kdf_parallel_derive');
  late final _TwoPtrD _kemKeygen = _lib.lookupFunction<_TwoPtrN, _TwoPtrD>('wilis_kem_keygen');
  late final _ThreePtrD _kemEncap = _lib.lookupFunction<_ThreePtrN, _ThreePtrD>('wilis_kem_encapsulate');
  late final _ThreePtrD _kemDecap = _lib.lookupFunction<_ThreePtrN, _ThreePtrD>('wilis_kem_decapsulate');
  late final _SignKeygenD _signKeygen = _lib.lookupFunction<_SignKeygenN, _SignKeygenD>('wilis_sign_keygen');
  late final _SignMsgD _signMessage = _lib.lookupFunction<_SignMsgN, _SignMsgD>('wilis_sign_message');
  late final _VerifyMsgD _verifyMessage = _lib.lookupFunction<_VerifyMsgN, _VerifyMsgD>('wilis_verify_message');
  late final _TwoPtrD _slhKeygen = _lib.lookupFunction<_TwoPtrN, _TwoPtrD>('wilis_slh_keygen');
  late final _KeyMsgOutD _slhSign = _lib.lookupFunction<_KeyMsgOutN, _KeyMsgOutD>('wilis_slh_sign');
  late final _KeyMsgOutD _slhVerify = _lib.lookupFunction<_KeyMsgOutN, _KeyMsgOutD>('wilis_slh_verify');
  late final _SigncryptD _signcrypt = _lib.lookupFunction<_SigncryptN, _SigncryptD>('wilis_signcrypt');
  late final _SigncryptD _unsigncrypt = _lib.lookupFunction<_SigncryptN, _SigncryptD>('wilis_unsigncrypt');
  late final _TotpD _totpAt = _lib.lookupFunction<_TotpN, _TotpD>('wilis_totp_at');
  late final _FpeD _fpeEncrypt = _lib.lookupFunction<_FpeN, _FpeD>('wilis_fpe_encrypt');
  late final _FpeD _fpeDecrypt = _lib.lookupFunction<_FpeN, _FpeD>('wilis_fpe_decrypt');
  late final _VarInOutD _mnemonicEncode = _lib.lookupFunction<_VarInOutN, _VarInOutD>('wilis_mnemonic_encode');
  late final _VarInOutD _mnemonicDecode = _lib.lookupFunction<_VarInOutN, _VarInOutD>('wilis_mnemonic_decode');
  late final _VarInOutD _lzCompress = _lib.lookupFunction<_VarInOutN, _VarInOutD>('wilis_lz_compress');
  late final _LzDecD _lzDecompress = _lib.lookupFunction<_LzDecN, _LzDecD>('wilis_lz_decompress');

  Wilis([String? libPath]) : _lib = DynamicLibrary.open(libPath ?? _findLib());

  static String _findLib() {
    final env = Platform.environment['WILIS_LIB'];
    if (env != null && env.isNotEmpty) return env;
    final name = Platform.isMacOS
        ? 'libwilis.dylib'
        : Platform.isWindows
            ? 'wilis.dll'
            : 'libwilis.so';
    for (final p in ['target/release/$name', 'target/debug/$name', '../../target/release/$name']) {
      if (File(p).existsSync()) return p;
    }
    return name;
  }

  T _withMem<T>(T Function(_NativeMem m) fn) {
    final m = _NativeMem();
    try {
      return fn(m);
    } finally {
      m.release();
    }
  }

  void _check(String op, int rc) {
    if (rc == wilisOk) return;
    if (rc == wilisErrAuthFailed) throw WilisAuthException(op);
    throw WilisException(op, rc);
  }

  void _checkLen(String name, Uint8List b, int expected) {
    if (b.length != expected) throw ArgumentError('$name must be $expected bytes');
  }

  Uint8List _callVarOut(_NativeMem m, String op, int Function(Pointer<Uint8> o, int cap, Pointer<Size> len) fn) {
    final lenPtr = m.allocSize();
    var rc = fn(nullptr, 0, lenPtr);
    final needed = lenPtr.value;
    if (rc == wilisOk && needed == 0) return Uint8List(0);
    if (rc != wilisErrBufTooSmall) _check(op, rc);
    final out = m.allocBytes(needed);
    rc = fn(out, needed, lenPtr);
    _check(op, rc);
    return Uint8List.fromList(out.asTypedList(lenPtr.value));
  }

  String version() {
    final p = _version();
    var len = 0;
    while (p[len] != 0) len++;
    return utf8.decode(p.asTypedList(len));
  }

  bool ctEq(Uint8List a, Uint8List b) => _withMem((m) {
        if (a.length != b.length) return false;
        final rc = _ctEq(m.fromBytes(a), m.fromBytes(b), a.length);
        if (rc < 0) _check('ct_eq', rc);
        return rc == 1;
      });

  void zeroize(Uint8List buf) => _withMem((m) {
        if (buf.isEmpty) return;
        final p = m.fromBytes(buf);
        _check('zeroize', _zeroize(p, buf.length));
        buf.fillRange(0, buf.length, 0);
      });

  Uint8List randomBytes(int len) => _withMem((m) {
        if (len == 0) return Uint8List(0);
        final out = m.allocBytes(len);
        _check('random_bytes', _randomBytes(out, len));
        return Uint8List.fromList(out.asTypedList(len));
      });

  Uint8List hash256(Uint8List data) => _withMem((m) {
        final out = m.allocBytes(wilisHashBytes);
        _check('hash_256', _hash256(m.fromBytes(data), data.length, out));
        return Uint8List.fromList(out.asTypedList(wilisHashBytes));
      });

  Uint8List treeHash256(Uint8List data) => _withMem((m) {
        final out = m.allocBytes(wilisHashBytes);
        _check('tree_hash_256', _treeHash256(m.fromBytes(data), data.length, out));
        return Uint8List.fromList(out.asTypedList(wilisHashBytes));
      });

  Uint8List mac256(Uint8List key, Uint8List msg) => _withMem((m) {
        _checkLen('key', key, wilisKeyBytes);
        final tag = m.allocBytes(wilisTagBytes);
        _check('mac_256', _mac256(m.fromBytes(key), m.fromBytes(msg), msg.length, tag));
        return Uint8List.fromList(tag.asTypedList(wilisTagBytes));
      });

  Uint8List subkeyDerive(Uint8List masterKey, Uint8List context) => _withMem((m) {
        _checkLen('masterKey', masterKey, wilisKeyBytes);
        final out = m.allocBytes(wilisKeyBytes);
        _check('subkey_derive', _subkeyDerive(m.fromBytes(masterKey), m.fromBytes(context), context.length, out));
        return Uint8List.fromList(out.asTypedList(wilisKeyBytes));
      });

  Uint8List xofDerive(Uint8List label, Uint8List seed, int outLen) => _withMem((m) {
        final out = m.allocBytes(outLen);
        _check('xof_derive', _xofDerive(m.fromBytes(label), label.length, m.fromBytes(seed), seed.length, out, outLen));
        return outLen == 0 ? Uint8List(0) : Uint8List.fromList(out.asTypedList(outLen));
      });

  (Uint8List, Uint8List) aeadSeal(Uint8List key, Uint8List nonce, Uint8List aad, Uint8List pt) => _withMem((m) {
        _checkLen('key', key, wilisKeyBytes);
        _checkLen('nonce', nonce, wilisNonceBytes);
        final ct = m.allocBytes(pt.length);
        final tag = m.allocBytes(wilisTagBytes);
        _check('aead_seal', _aeadSeal(m.fromBytes(key), m.fromBytes(nonce), m.fromBytes(aad), aad.length, m.fromBytes(pt), pt.length, ct, tag));
        return (pt.isEmpty ? Uint8List(0) : Uint8List.fromList(ct.asTypedList(pt.length)), Uint8List.fromList(tag.asTypedList(wilisTagBytes)));
      });

  Uint8List aeadOpen(Uint8List key, Uint8List nonce, Uint8List aad, Uint8List ct, Uint8List tag) => _withMem((m) {
        _checkLen('key', key, wilisKeyBytes);
        _checkLen('nonce', nonce, wilisNonceBytes);
        _checkLen('tag', tag, wilisTagBytes);
        final pt = m.allocBytes(ct.length);
        _check('aead_open', _aeadOpen(m.fromBytes(key), m.fromBytes(nonce), m.fromBytes(aad), aad.length, m.fromBytes(ct), ct.length, m.fromBytes(tag), pt));
        return ct.isEmpty ? Uint8List(0) : Uint8List.fromList(pt.asTypedList(ct.length));
      });

  (Uint8List, Uint8List) sivSeal(Uint8List key, Uint8List aad, Uint8List pt) => _withMem((m) {
        _checkLen('key', key, wilisKeyBytes);
        final ct = m.allocBytes(pt.length);
        final tag = m.allocBytes(wilisSivTagBytes);
        _check('siv_seal', _sivSeal(m.fromBytes(key), m.fromBytes(aad), aad.length, m.fromBytes(pt), pt.length, ct, tag));
        return (pt.isEmpty ? Uint8List(0) : Uint8List.fromList(ct.asTypedList(pt.length)), Uint8List.fromList(tag.asTypedList(wilisSivTagBytes)));
      });

  Uint8List sivOpen(Uint8List key, Uint8List aad, Uint8List ct, Uint8List sivTag) => _withMem((m) {
        _checkLen('key', key, wilisKeyBytes);
        _checkLen('sivTag', sivTag, wilisSivTagBytes);
        final pt = m.allocBytes(ct.length);
        _check('siv_open', _sivOpen(m.fromBytes(key), m.fromBytes(aad), aad.length, m.fromBytes(ct), ct.length, m.fromBytes(sivTag), pt));
        return ct.isEmpty ? Uint8List(0) : Uint8List.fromList(pt.asTypedList(ct.length));
      });

  Uint8List kdfDerive(Uint8List pass, Uint8List salt, {int memoryBlocks = 16384, int passes = 3}) => _withMem((m) {
        _checkLen('salt', salt, wilisSaltBytes);
        final key = m.allocBytes(wilisKeyBytes);
        _check('kdf_derive', _kdfDerive(m.fromBytes(pass), pass.length, m.fromBytes(salt), memoryBlocks, passes, key));
        return Uint8List.fromList(key.asTypedList(wilisKeyBytes));
      });

  Uint8List kdfParallelDerive(Uint8List pass, Uint8List salt, {int memoryBlocks = 16384, int passes = 3, int lanes = 4}) => _withMem((m) {
        _checkLen('salt', salt, wilisSaltBytes);
        final key = m.allocBytes(wilisKeyBytes);
        _check('kdf_parallel_derive', _kdfParallelDerive(m.fromBytes(pass), pass.length, m.fromBytes(salt), memoryBlocks, passes, lanes, key));
        return Uint8List.fromList(key.asTypedList(wilisKeyBytes));
      });

  (Uint8List, Uint8List) kemKeygen() => _withMem((m) {
        final pk = m.allocBytes(wilisKemPkBytes), sk = m.allocBytes(wilisKemSkBytes);
        _check('kem_keygen', _kemKeygen(pk, sk));
        return (Uint8List.fromList(pk.asTypedList(wilisKemPkBytes)), Uint8List.fromList(sk.asTypedList(wilisKemSkBytes)));
      });

  (Uint8List, Uint8List) kemEncapsulate(Uint8List pk) => _withMem((m) {
        _checkLen('pk', pk, wilisKemPkBytes);
        final ct = m.allocBytes(wilisKemCtBytes), ss = m.allocBytes(wilisKemSsBytes);
        _check('kem_encapsulate', _kemEncap(m.fromBytes(pk), ct, ss));
        return (Uint8List.fromList(ct.asTypedList(wilisKemCtBytes)), Uint8List.fromList(ss.asTypedList(wilisKemSsBytes)));
      });

  Uint8List kemDecapsulate(Uint8List sk, Uint8List ct) => _withMem((m) {
        _checkLen('sk', sk, wilisKemSkBytes);
        _checkLen('ct', ct, wilisKemCtBytes);
        final ss = m.allocBytes(wilisKemSsBytes);
        _check('kem_decapsulate', _kemDecap(m.fromBytes(sk), m.fromBytes(ct), ss));
        return Uint8List.fromList(ss.asTypedList(wilisKemSsBytes));
      });

  (Uint8List, Uint8List) signKeygen({int height = 4}) => _withMem((m) {
        final pk = m.allocBytes(wilisSignPkBytes), sk = m.allocBytes(wilisSignSkBytes);
        _check('sign_keygen', _signKeygen(height, pk, sk));
        return (Uint8List.fromList(pk.asTypedList(wilisSignPkBytes)), Uint8List.fromList(sk.asTypedList(wilisSignSkBytes)));
      });

  (Uint8List, Uint8List) signMessage(Uint8List sk, Uint8List msg) => _withMem((m) {
        _checkLen('sk', sk, wilisSignSkBytes);
        final skPtr = m.fromBytes(sk), sig = m.allocBytes(wilisSignMaxSigBytes), len = m.allocSize();
        _check('sign_message', _signMessage(skPtr, m.fromBytes(msg), msg.length, sig, wilisSignMaxSigBytes, len));
        return (Uint8List.fromList(sig.asTypedList(len.value)), Uint8List.fromList(skPtr.asTypedList(wilisSignSkBytes)));
      });

  bool verifyMessage(Uint8List pk, Uint8List msg, Uint8List sig) => _withMem((m) {
        _checkLen('pk', pk, wilisSignPkBytes);
        final rc = _verifyMessage(m.fromBytes(pk), m.fromBytes(msg), msg.length, m.fromBytes(sig), sig.length);
        if (rc == wilisOk) return true;
        if (rc == wilisErrAuthFailed) return false;
        _check('verify_message', rc);
        return false;
      });

  (Uint8List, Uint8List) slhKeygen() => _withMem((m) {
        final pk = m.allocBytes(wilisSlhPkBytes), sk = m.allocBytes(wilisSlhSkBytes);
        _check('slh_keygen', _slhKeygen(pk, sk));
        return (Uint8List.fromList(pk.asTypedList(wilisSlhPkBytes)), Uint8List.fromList(sk.asTypedList(wilisSlhSkBytes)));
      });

  Uint8List slhSign(Uint8List sk, Uint8List msg) => _withMem((m) {
        _checkLen('sk', sk, wilisSlhSkBytes);
        final sig = m.allocBytes(wilisSlhSigBytes);
        _check('slh_sign', _slhSign(m.fromBytes(sk), m.fromBytes(msg), msg.length, sig));
        return Uint8List.fromList(sig.asTypedList(wilisSlhSigBytes));
      });

  bool slhVerify(Uint8List pk, Uint8List msg, Uint8List sig) => _withMem((m) {
        _checkLen('pk', pk, wilisSlhPkBytes);
        _checkLen('sig', sig, wilisSlhSigBytes);
        final rc = _slhVerify(m.fromBytes(pk), m.fromBytes(msg), msg.length, m.fromBytes(sig));
        if (rc == wilisOk) return true;
        if (rc == wilisErrAuthFailed) return false;
        _check('slh_verify', rc);
        return false;
      });

  Uint8List signcrypt(Uint8List senderSlhSk, Uint8List recipientKemPk, Uint8List aad, Uint8List pt) => _withMem((m) {
        _checkLen('senderSlhSk', senderSlhSk, wilisSlhSkBytes);
        _checkLen('recipientKemPk', recipientKemPk, wilisKemPkBytes);
        final sk = m.fromBytes(senderSlhSk), pk = m.fromBytes(recipientKemPk), a = m.fromBytes(aad), p = m.fromBytes(pt);
        return _callVarOut(m, 'signcrypt', (o, c, l) => _signcrypt(sk, pk, a, aad.length, p, pt.length, o, c, l));
      });

  Uint8List unsigncrypt(Uint8List senderSlhPk, Uint8List recipientKemSk, Uint8List aad, Uint8List packet) => _withMem((m) {
        _checkLen('senderSlhPk', senderSlhPk, wilisSlhPkBytes);
        _checkLen('recipientKemSk', recipientKemSk, wilisKemSkBytes);
        final pk = m.fromBytes(senderSlhPk), sk = m.fromBytes(recipientKemSk), a = m.fromBytes(aad), pkt = m.fromBytes(packet);
        return _callVarOut(m, 'unsigncrypt', (o, c, l) => _unsigncrypt(pk, sk, a, aad.length, pkt, packet.length, o, c, l));
      });

  (String, int) totpAt(Uint8List secret, int unixSecs, {int period = 30, int digits = 6}) => _withMem((m) {
        final code = m.allocBytes(digits + 1), rem = m.allocU64();
        _check('totp_at', _totpAt(m.fromBytes(secret), secret.length, unixSecs, period, digits, code, digits + 1, rem));
        return (ascii.decode(code.asTypedList(digits)), rem.value);
      });

  String fpeEncrypt(Uint8List key, Uint8List tweak, String alphabet, String pt) => _withMem((m) {
        _checkLen('key', key, wilisKeyBytes);
        final al = Uint8List.fromList(utf8.encode(alphabet)), pb = Uint8List.fromList(utf8.encode(pt));
        final kp = m.fromBytes(key), tp = m.fromBytes(tweak), ap = m.fromBytes(al), pp = m.fromBytes(pb);
        return utf8.decode(_callVarOut(m, 'fpe_encrypt', (o, c, l) => _fpeEncrypt(kp, tp, tweak.length, ap, al.length, pp, pb.length, o, c, l)));
      });

  String fpeDecrypt(Uint8List key, Uint8List tweak, String alphabet, String ct) => _withMem((m) {
        _checkLen('key', key, wilisKeyBytes);
        final al = Uint8List.fromList(utf8.encode(alphabet)), cb = Uint8List.fromList(utf8.encode(ct));
        final kp = m.fromBytes(key), tp = m.fromBytes(tweak), ap = m.fromBytes(al), cp = m.fromBytes(cb);
        return utf8.decode(_callVarOut(m, 'fpe_decrypt', (o, c, l) => _fpeDecrypt(kp, tp, tweak.length, ap, al.length, cp, cb.length, o, c, l)));
      });

  String mnemonicEncode(Uint8List secret) => _withMem((m) {
        final sp = m.fromBytes(secret);
        return utf8.decode(_callVarOut(m, 'mnemonic_encode', (o, c, l) => _mnemonicEncode(sp, secret.length, o, c, l)));
      });

  Uint8List mnemonicDecode(String phrase) => _withMem((m) {
        final pb = Uint8List.fromList(utf8.encode(phrase));
        final pp = m.fromBytes(pb);
        return _callVarOut(m, 'mnemonic_decode', (o, c, l) => _mnemonicDecode(pp, pb.length, o, c, l));
      });

  Uint8List lzCompress(Uint8List data) => _withMem((m) {
        final dp = m.fromBytes(data);
        return _callVarOut(m, 'lz_compress', (o, c, l) => _lzCompress(dp, data.length, o, c, l));
      });

  Uint8List lzDecompress(Uint8List compressed, {int maxOut = 64 * 1024 * 1024}) => _withMem((m) {
        final cp = m.fromBytes(compressed);
        return _callVarOut(m, 'lz_decompress', (o, c, l) => _lzDecompress(cp, compressed.length, maxOut, o, c, l));
      });
}

void main() {
  final w = Wilis();
  assert(w.version() == '0.7.0');
  final k = w.randomBytes(wilisKeyBytes);
  final n = w.randomBytes(wilisNonceBytes);
  final pt = Uint8List.fromList(utf8.encode('hello dart ffi'));
  final (ct, tag) = w.aeadSeal(k, n, Uint8List(0), pt);
  assert(w.ctEq(w.aeadOpen(k, n, Uint8List(0), ct, tag), pt));
  assert(w.ctEq(w.mnemonicDecode(w.mnemonicEncode(k)), k));
  stdout.writeln('Wilis Dart FFI OK (v${w.version()}, 33 C-ABI exports)');
}
