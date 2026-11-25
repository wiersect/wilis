/**
 * Zero-dependency Bun native FFI binding for Wilis v0.7.0 (`libwilis` — ALL 33 C-ABI functions).
 *
 * Run with:
 *   bun run bindings/bun/wilis.ts
 */

import { dlopen, FFIType, CString, ptr, suffix } from "bun:ffi";
import path from "node:path";

export const WILIS_KEY_BYTES = 32;
export const WILIS_NONCE_BYTES = 24;
export const WILIS_SALT_BYTES = 24;
export const WILIS_TAG_BYTES = 32;
export const WILIS_SIV_TAG_BYTES = 64;
export const WILIS_HASH_BYTES = 32;
export const WILIS_KEM_PK_BYTES = 1284;
export const WILIS_KEM_SK_BYTES = 2600;
export const WILIS_KEM_CT_BYTES = 1668;
export const WILIS_KEM_SS_BYTES = 32;
export const WILIS_SIGN_PK_BYTES = 101;
export const WILIS_SIGN_SK_BYTES = 137;
export const WILIS_SIGN_MAX_SIG_BYTES = 2506;
export const WILIS_SLH_PK_BYTES = 100;
export const WILIS_SLH_SK_BYTES = 164;
export const WILIS_SLH_SIG_BYTES = 8165;
export const WILIS_SIGNCRYPT_OVERHEAD = 9894;

const ERR_AUTH = -2;
const ERR_BUF_TOO_SMALL = -4;

export class WilisError extends Error {}
export class WilisAuthError extends WilisError {}

const { ptr: P, u64: U64, u32: U32, u8: U8, i32: I32 } = FFIType;

const SYMBOLS = {
  wilis_version: { args: [], returns: P },
  wilis_ct_eq: { args: [P, P, U64], returns: I32 },
  wilis_zeroize: { args: [P, U64], returns: I32 },
  wilis_random_bytes: { args: [P, U64], returns: I32 },
  wilis_hash_256: { args: [P, U64, P], returns: I32 },
  wilis_tree_hash_256: { args: [P, U64, P], returns: I32 },
  wilis_mac_256: { args: [P, P, U64, P], returns: I32 },
  wilis_subkey_derive: { args: [P, P, U64, P], returns: I32 },
  wilis_xof_derive: { args: [P, U64, P, U64, P, U64], returns: I32 },
  wilis_aead_seal: { args: [P, P, P, U64, P, U64, P, P], returns: I32 },
  wilis_aead_open: { args: [P, P, P, U64, P, U64, P, P], returns: I32 },
  wilis_siv_seal: { args: [P, P, U64, P, U64, P, P], returns: I32 },
  wilis_siv_open: { args: [P, P, U64, P, U64, P, P], returns: I32 },
  wilis_kdf_derive: { args: [P, U64, P, U32, U32, P], returns: I32 },
  wilis_kdf_parallel_derive: { args: [P, U64, P, U32, U32, U32, P], returns: I32 },
  wilis_kem_keygen: { args: [P, P], returns: I32 },
  wilis_kem_encapsulate: { args: [P, P, P], returns: I32 },
  wilis_kem_decapsulate: { args: [P, P, P], returns: I32 },
  wilis_sign_keygen: { args: [U8, P, P], returns: I32 },
  wilis_sign_message: { args: [P, P, U64, P, U64, P], returns: I32 },
  wilis_verify_message: { args: [P, P, U64, P, U64], returns: I32 },
  wilis_slh_keygen: { args: [P, P], returns: I32 },
  wilis_slh_sign: { args: [P, P, U64, P], returns: I32 },
  wilis_slh_verify: { args: [P, P, U64, P], returns: I32 },
  wilis_signcrypt: { args: [P, P, P, U64, P, U64, P, U64, P], returns: I32 },
  wilis_unsigncrypt: { args: [P, P, P, U64, P, U64, P, U64, P], returns: I32 },
  wilis_totp_at: { args: [P, U64, U64, U64, U32, P, U64, P], returns: I32 },
  wilis_fpe_encrypt: { args: [P, P, U64, P, U64, P, U64, P, U64, P], returns: I32 },
  wilis_fpe_decrypt: { args: [P, P, U64, P, U64, P, U64, P, U64, P], returns: I32 },
  wilis_mnemonic_encode: { args: [P, U64, P, U64, P], returns: I32 },
  wilis_mnemonic_decode: { args: [P, U64, P, U64, P], returns: I32 },
  wilis_lz_compress: { args: [P, U64, P, U64, P], returns: I32 },
  wilis_lz_decompress: { args: [P, U64, U64, P, U64, P], returns: I32 },
} as const;

function check(rc: number, fn: string): void {
  if (rc === 0) return;
  if (rc === ERR_AUTH) throw new WilisAuthError(`${fn}: authentication failed`);
  throw new WilisError(`${fn} failed (rc=${rc})`);
}

function bufPtr(b: Uint8Array) {
  return b.length > 0 ? ptr(b) : null;
}

export class Wilis {
  private lib;
  private enc = new TextEncoder();
  private dec = new TextDecoder();

  constructor(libPath?: string) {
    const prefix = process.platform === "win32" ? "" : "lib";
    const resolved = libPath ?? path.resolve(import.meta.dir, `../../target/release/${prefix}wilis.${suffix}`);
    this.lib = dlopen(resolved, SYMBOLS);
  }

  close(): void { this.lib.close(); }

  version(): string {
    const p = this.lib.symbols.wilis_version();
    return p ? new CString(p).toString() : "";
  }

  ctEq(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    return this.lib.symbols.wilis_ct_eq(bufPtr(a), bufPtr(b), a.length) === 1;
  }

  zeroize(buf: Uint8Array): void {
    check(this.lib.symbols.wilis_zeroize(bufPtr(buf), buf.length), "wilis_zeroize");
  }

  randomBytes(len: number): Uint8Array {
    const out = new Uint8Array(len);
    check(this.lib.symbols.wilis_random_bytes(bufPtr(out), len), "wilis_random_bytes");
    return out;
  }

  hash256(data: Uint8Array): Uint8Array {
    const out = new Uint8Array(WILIS_HASH_BYTES);
    check(this.lib.symbols.wilis_hash_256(bufPtr(data), data.length, ptr(out)), "wilis_hash_256");
    return out;
  }

  treeHash256(data: Uint8Array): Uint8Array {
    const out = new Uint8Array(WILIS_HASH_BYTES);
    check(this.lib.symbols.wilis_tree_hash_256(bufPtr(data), data.length, ptr(out)), "wilis_tree_hash_256");
    return out;
  }

  mac256(key: Uint8Array, msg: Uint8Array): Uint8Array {
    const out = new Uint8Array(WILIS_TAG_BYTES);
    check(this.lib.symbols.wilis_mac_256(ptr(key), bufPtr(msg), msg.length, ptr(out)), "wilis_mac_256");
    return out;
  }

  deriveSubkey(masterKey: Uint8Array, context: Uint8Array): Uint8Array {
    const out = new Uint8Array(WILIS_KEY_BYTES);
    check(this.lib.symbols.wilis_subkey_derive(ptr(masterKey), bufPtr(context), context.length, ptr(out)), "wilis_subkey_derive");
    return out;
  }

  xofDerive(label: Uint8Array, seed: Uint8Array, outLen: number): Uint8Array {
    const out = new Uint8Array(outLen);
    check(this.lib.symbols.wilis_xof_derive(bufPtr(label), label.length, bufPtr(seed), seed.length, bufPtr(out), outLen), "wilis_xof_derive");
    return out;
  }

  aeadSeal(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, pt: Uint8Array) {
    const ct = new Uint8Array(pt.length), tag = new Uint8Array(WILIS_TAG_BYTES);
    check(this.lib.symbols.wilis_aead_seal(ptr(key), ptr(nonce), bufPtr(aad), aad.length, bufPtr(pt), pt.length, bufPtr(ct), ptr(tag)), "wilis_aead_seal");
    return { ciphertext: ct, tag };
  }

  aeadOpen(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ct: Uint8Array, tag: Uint8Array): Uint8Array {
    const pt = new Uint8Array(ct.length);
    check(this.lib.symbols.wilis_aead_open(ptr(key), ptr(nonce), bufPtr(aad), aad.length, bufPtr(ct), ct.length, ptr(tag), bufPtr(pt)), "wilis_aead_open");
    return pt;
  }

  sivSeal(key: Uint8Array, aad: Uint8Array, pt: Uint8Array) {
    const ct = new Uint8Array(pt.length), tag = new Uint8Array(WILIS_SIV_TAG_BYTES);
    check(this.lib.symbols.wilis_siv_seal(ptr(key), bufPtr(aad), aad.length, bufPtr(pt), pt.length, bufPtr(ct), ptr(tag)), "wilis_siv_seal");
    return { ciphertext: ct, tag };
  }

  sivOpen(key: Uint8Array, aad: Uint8Array, ct: Uint8Array, tag: Uint8Array): Uint8Array {
    const pt = new Uint8Array(ct.length);
    check(this.lib.symbols.wilis_siv_open(ptr(key), bufPtr(aad), aad.length, bufPtr(ct), ct.length, ptr(tag), bufPtr(pt)), "wilis_siv_open");
    return pt;
  }

  kdfDerive(pass: Uint8Array, salt: Uint8Array, memoryBlocks = 349520, passes = 3): Uint8Array {
    const out = new Uint8Array(WILIS_KEY_BYTES);
    check(this.lib.symbols.wilis_kdf_derive(bufPtr(pass), pass.length, ptr(salt), memoryBlocks, passes, ptr(out)), "wilis_kdf_derive");
    return out;
  }

  kdfParallelDerive(pass: Uint8Array, salt: Uint8Array, memoryBlocks = 349520, passes = 3, lanes = 4): Uint8Array {
    const out = new Uint8Array(WILIS_KEY_BYTES);
    check(this.lib.symbols.wilis_kdf_parallel_derive(bufPtr(pass), pass.length, ptr(salt), memoryBlocks, passes, lanes, ptr(out)), "wilis_kdf_parallel_derive");
    return out;
  }

  kemKeygen() {
    const pk = new Uint8Array(WILIS_KEM_PK_BYTES), sk = new Uint8Array(WILIS_KEM_SK_BYTES);
    check(this.lib.symbols.wilis_kem_keygen(ptr(pk), ptr(sk)), "wilis_kem_keygen");
    return { publicKey: pk, secretKey: sk };
  }

  kemEncapsulate(pk: Uint8Array) {
    const ct = new Uint8Array(WILIS_KEM_CT_BYTES), ss = new Uint8Array(WILIS_KEM_SS_BYTES);
    check(this.lib.symbols.wilis_kem_encapsulate(ptr(pk), ptr(ct), ptr(ss)), "wilis_kem_encapsulate");
    return { ciphertext: ct, sharedSecret: ss };
  }

  kemDecapsulate(sk: Uint8Array, ct: Uint8Array): Uint8Array {
    const ss = new Uint8Array(WILIS_KEM_SS_BYTES);
    check(this.lib.symbols.wilis_kem_decapsulate(ptr(sk), ptr(ct), ptr(ss)), "wilis_kem_decapsulate");
    return ss;
  }

  signKeygen(height = 6) {
    const pk = new Uint8Array(WILIS_SIGN_PK_BYTES), sk = new Uint8Array(WILIS_SIGN_SK_BYTES);
    check(this.lib.symbols.wilis_sign_keygen(height, ptr(pk), ptr(sk)), "wilis_sign_keygen");
    return { publicKey: pk, secretKey: sk };
  }

  signMessage(sk: Uint8Array, msg: Uint8Array) {
    const skCopy = new Uint8Array(sk), sig = new Uint8Array(WILIS_SIGN_MAX_SIG_BYTES);
    const outLen = new BigUint64Array(1);
    check(this.lib.symbols.wilis_sign_message(ptr(skCopy), bufPtr(msg), msg.length, ptr(sig), sig.length, ptr(outLen)), "wilis_sign_message");
    return { updatedSk: skCopy, signature: sig.subarray(0, Number(outLen[0])) };
  }

  verifyMessage(pk: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
    return this.lib.symbols.wilis_verify_message(ptr(pk), bufPtr(msg), msg.length, bufPtr(sig), sig.length) === 0;
  }

  slhKeygen() {
    const pk = new Uint8Array(WILIS_SLH_PK_BYTES), sk = new Uint8Array(WILIS_SLH_SK_BYTES);
    check(this.lib.symbols.wilis_slh_keygen(ptr(pk), ptr(sk)), "wilis_slh_keygen");
    return { publicKey: pk, secretKey: sk };
  }

  slhSign(sk: Uint8Array, msg: Uint8Array): Uint8Array {
    const sig = new Uint8Array(WILIS_SLH_SIG_BYTES);
    check(this.lib.symbols.wilis_slh_sign(ptr(sk), bufPtr(msg), msg.length, ptr(sig)), "wilis_slh_sign");
    return sig;
  }

  slhVerify(pk: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
    return this.lib.symbols.wilis_slh_verify(ptr(pk), bufPtr(msg), msg.length, ptr(sig)) === 0;
  }

  signcrypt(senderSlhSk: Uint8Array, recipientKemPk: Uint8Array, aad: Uint8Array, pt: Uint8Array): Uint8Array {
    const out = new Uint8Array(WILIS_SIGNCRYPT_OVERHEAD + pt.length), outLen = new BigUint64Array(1);
    check(this.lib.symbols.wilis_signcrypt(ptr(senderSlhSk), ptr(recipientKemPk), bufPtr(aad), aad.length, bufPtr(pt), pt.length, ptr(out), out.length, ptr(outLen)), "wilis_signcrypt");
    return out.subarray(0, Number(outLen[0]));
  }

  unsigncrypt(senderSlhPk: Uint8Array, recipientKemSk: Uint8Array, aad: Uint8Array, packet: Uint8Array): Uint8Array {
    const out = new Uint8Array(Math.max(packet.length - WILIS_SIGNCRYPT_OVERHEAD, 1)), outLen = new BigUint64Array(1);
    check(this.lib.symbols.wilis_unsigncrypt(ptr(senderSlhPk), ptr(recipientKemSk), bufPtr(aad), aad.length, bufPtr(packet), packet.length, ptr(out), out.length, ptr(outLen)), "wilis_unsigncrypt");
    return out.subarray(0, Number(outLen[0]));
  }

  totpAt(secret: Uint8Array, unixSecs: bigint, period = 30n, digits = 6) {
    const codeBuf = new Uint8Array(16), rem = new BigUint64Array(1);
    check(this.lib.symbols.wilis_totp_at(bufPtr(secret), secret.length, unixSecs, period, digits, ptr(codeBuf), 16, ptr(rem)), "wilis_totp_at");
    const nul = codeBuf.indexOf(0);
    return { code: this.dec.decode(codeBuf.subarray(0, nul >= 0 ? nul : 16)), remaining: rem[0] };
  }

  fpeEncrypt(key: Uint8Array, tweak: Uint8Array, alphabet: string, pt: string): string {
    const a = this.enc.encode(alphabet), p = this.enc.encode(pt);
    const out = new Uint8Array(p.length * 4 + 16), outLen = new BigUint64Array(1);
    check(this.lib.symbols.wilis_fpe_encrypt(ptr(key), bufPtr(tweak), tweak.length, ptr(a), a.length, ptr(p), p.length, ptr(out), out.length, ptr(outLen)), "wilis_fpe_encrypt");
    return this.dec.decode(out.subarray(0, Number(outLen[0])));
  }

  fpeDecrypt(key: Uint8Array, tweak: Uint8Array, alphabet: string, ct: string): string {
    const a = this.enc.encode(alphabet), c = this.enc.encode(ct);
    const out = new Uint8Array(c.length * 4 + 16), outLen = new BigUint64Array(1);
    check(this.lib.symbols.wilis_fpe_decrypt(ptr(key), bufPtr(tweak), tweak.length, ptr(a), a.length, ptr(c), c.length, ptr(out), out.length, ptr(outLen)), "wilis_fpe_decrypt");
    return this.dec.decode(out.subarray(0, Number(outLen[0])));
  }

  mnemonicEncode(secret: Uint8Array): string {
    const outLen = new BigUint64Array(1);
    const rc0 = this.lib.symbols.wilis_mnemonic_encode(bufPtr(secret), secret.length, null, 0, ptr(outLen));
    if (rc0 !== 0 && rc0 !== ERR_BUF_TOO_SMALL) check(rc0, "wilis_mnemonic_encode");
    const out = new Uint8Array(Number(outLen[0]));
    check(this.lib.symbols.wilis_mnemonic_encode(bufPtr(secret), secret.length, ptr(out), out.length, ptr(outLen)), "wilis_mnemonic_encode");
    return this.dec.decode(out.subarray(0, Number(outLen[0])));
  }

  mnemonicDecode(phrase: string): Uint8Array {
    const p = this.enc.encode(phrase), outLen = new BigUint64Array(1);
    const rc0 = this.lib.symbols.wilis_mnemonic_decode(bufPtr(p), p.length, null, 0, ptr(outLen));
    if (rc0 !== 0 && rc0 !== ERR_BUF_TOO_SMALL) check(rc0, "wilis_mnemonic_decode");
    const out = new Uint8Array(Number(outLen[0]));
    check(this.lib.symbols.wilis_mnemonic_decode(bufPtr(p), p.length, ptr(out), out.length, ptr(outLen)), "wilis_mnemonic_decode");
    return out.subarray(0, Number(outLen[0]));
  }

  lzCompress(data: Uint8Array): Uint8Array {
    const outLen = new BigUint64Array(1);
    const rc0 = this.lib.symbols.wilis_lz_compress(bufPtr(data), data.length, null, 0, ptr(outLen));
    if (rc0 !== 0 && rc0 !== ERR_BUF_TOO_SMALL) check(rc0, "wilis_lz_compress");
    const out = new Uint8Array(Number(outLen[0]));
    check(this.lib.symbols.wilis_lz_compress(bufPtr(data), data.length, ptr(out), out.length, ptr(outLen)), "wilis_lz_compress");
    return out.subarray(0, Number(outLen[0]));
  }

  lzDecompress(data: Uint8Array, maxOut = 16 * 1024 * 1024): Uint8Array {
    const outLen = new BigUint64Array(1);
    const rc0 = this.lib.symbols.wilis_lz_decompress(bufPtr(data), data.length, maxOut, null, 0, ptr(outLen));
    if (rc0 !== 0 && rc0 !== ERR_BUF_TOO_SMALL) check(rc0, "wilis_lz_decompress");
    const out = new Uint8Array(Number(outLen[0]));
    check(this.lib.symbols.wilis_lz_decompress(bufPtr(data), data.length, maxOut, ptr(out), out.length, ptr(outLen)), "wilis_lz_decompress");
    return out.subarray(0, Number(outLen[0]));
  }
}
