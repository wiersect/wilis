/**
 * Zero-dependency Deno native FFI binding for Wilis v0.7.0 (`libwilis` — ALL 33 C-ABI functions).
 *
 * Run with:
 *   deno run --allow-ffi --allow-read bindings/deno/wilis.ts
 */

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

const SYMBOLS = {
  wilis_version: { parameters: [], result: "pointer" },
  wilis_ct_eq: { parameters: ["buffer", "buffer", "usize"], result: "i32" },
  wilis_zeroize: { parameters: ["buffer", "usize"], result: "i32" },
  wilis_random_bytes: { parameters: ["buffer", "usize"], result: "i32" },
  wilis_hash_256: { parameters: ["buffer", "usize", "buffer"], result: "i32" },
  wilis_tree_hash_256: { parameters: ["buffer", "usize", "buffer"], result: "i32" },
  wilis_mac_256: { parameters: ["buffer", "buffer", "usize", "buffer"], result: "i32" },
  wilis_subkey_derive: { parameters: ["buffer", "buffer", "usize", "buffer"], result: "i32" },
  wilis_xof_derive: { parameters: ["buffer", "usize", "buffer", "usize", "buffer", "usize"], result: "i32" },
  wilis_aead_seal: { parameters: ["buffer", "buffer", "buffer", "usize", "buffer", "usize", "buffer", "buffer"], result: "i32" },
  wilis_aead_open: { parameters: ["buffer", "buffer", "buffer", "usize", "buffer", "usize", "buffer", "buffer"], result: "i32" },
  wilis_siv_seal: { parameters: ["buffer", "buffer", "usize", "buffer", "usize", "buffer", "buffer"], result: "i32" },
  wilis_siv_open: { parameters: ["buffer", "buffer", "usize", "buffer", "usize", "buffer", "buffer"], result: "i32" },
  wilis_kdf_derive: { parameters: ["buffer", "usize", "buffer", "u32", "u32", "buffer"], result: "i32" },
  wilis_kdf_parallel_derive: { parameters: ["buffer", "usize", "buffer", "u32", "u32", "u32", "buffer"], result: "i32" },
  wilis_kem_keygen: { parameters: ["buffer", "buffer"], result: "i32" },
  wilis_kem_encapsulate: { parameters: ["buffer", "buffer", "buffer"], result: "i32" },
  wilis_kem_decapsulate: { parameters: ["buffer", "buffer", "buffer"], result: "i32" },
  wilis_sign_keygen: { parameters: ["u8", "buffer", "buffer"], result: "i32" },
  wilis_sign_message: { parameters: ["buffer", "buffer", "usize", "buffer", "usize", "buffer"], result: "i32" },
  wilis_verify_message: { parameters: ["buffer", "buffer", "usize", "buffer", "usize"], result: "i32" },
  wilis_slh_keygen: { parameters: ["buffer", "buffer"], result: "i32" },
  wilis_slh_sign: { parameters: ["buffer", "buffer", "usize", "buffer"], result: "i32" },
  wilis_slh_verify: { parameters: ["buffer", "buffer", "usize", "buffer"], result: "i32" },
  wilis_signcrypt: { parameters: ["buffer", "buffer", "buffer", "usize", "buffer", "usize", "buffer", "usize", "buffer"], result: "i32" },
  wilis_unsigncrypt: { parameters: ["buffer", "buffer", "buffer", "usize", "buffer", "usize", "buffer", "usize", "buffer"], result: "i32" },
  wilis_totp_at: { parameters: ["buffer", "usize", "u64", "u64", "u32", "buffer", "usize", "buffer"], result: "i32" },
  wilis_fpe_encrypt: { parameters: ["buffer", "buffer", "usize", "buffer", "usize", "buffer", "usize", "buffer", "usize", "buffer"], result: "i32" },
  wilis_fpe_decrypt: { parameters: ["buffer", "buffer", "usize", "buffer", "usize", "buffer", "usize", "buffer", "usize", "buffer"], result: "i32" },
  wilis_mnemonic_encode: { parameters: ["buffer", "usize", "buffer", "usize", "buffer"], result: "i32" },
  wilis_mnemonic_decode: { parameters: ["buffer", "usize", "buffer", "usize", "buffer"], result: "i32" },
  wilis_lz_compress: { parameters: ["buffer", "usize", "buffer", "usize", "buffer"], result: "i32" },
  wilis_lz_decompress: { parameters: ["buffer", "usize", "usize", "buffer", "usize", "buffer"], result: "i32" },
} as const;

function defaultLibPath(): string {
  const os = Deno.build.os;
  const name = os === "windows" ? "wilis.dll" : os === "darwin" ? "libwilis.dylib" : "libwilis.so";
  return new URL(`../../target/release/${name}`, import.meta.url).pathname;
}

function check(rc: number, fn: string): void {
  if (rc === 0) return;
  if (rc === ERR_AUTH) throw new WilisAuthError(`${fn}: authentication failed`);
  throw new WilisError(`${fn} failed (rc=${rc})`);
}

function readUsize(buf: Uint8Array): number {
  return Number(new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getBigUint64(0, true));
}

export class Wilis {
  private lib: Deno.DynamicLibrary<typeof SYMBOLS>;
  private enc = new TextEncoder();
  private dec = new TextDecoder();

  constructor(libPath?: string) {
    this.lib = Deno.dlopen(libPath ?? defaultLibPath(), SYMBOLS);
  }

  close(): void { this.lib.close(); }

  version(): string {
    const p = this.lib.symbols.wilis_version();
    return p ? new Deno.UnsafePointerView(p).getCString() : "";
  }

  ctEq(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    return this.lib.symbols.wilis_ct_eq(a, b, BigInt(a.length)) === 1;
  }

  zeroize(buf: Uint8Array): void {
    check(this.lib.symbols.wilis_zeroize(buf, BigInt(buf.length)), "wilis_zeroize");
  }

  randomBytes(len: number): Uint8Array {
    const out = new Uint8Array(len);
    check(this.lib.symbols.wilis_random_bytes(out, BigInt(len)), "wilis_random_bytes");
    return out;
  }

  hash256(data: Uint8Array): Uint8Array {
    const out = new Uint8Array(WILIS_HASH_BYTES);
    check(this.lib.symbols.wilis_hash_256(data, BigInt(data.length), out), "wilis_hash_256");
    return out;
  }

  treeHash256(data: Uint8Array): Uint8Array {
    const out = new Uint8Array(WILIS_HASH_BYTES);
    check(this.lib.symbols.wilis_tree_hash_256(data, BigInt(data.length), out), "wilis_tree_hash_256");
    return out;
  }

  mac256(key: Uint8Array, msg: Uint8Array): Uint8Array {
    const out = new Uint8Array(WILIS_TAG_BYTES);
    check(this.lib.symbols.wilis_mac_256(key, msg, BigInt(msg.length), out), "wilis_mac_256");
    return out;
  }

  deriveSubkey(masterKey: Uint8Array, context: Uint8Array): Uint8Array {
    const out = new Uint8Array(WILIS_KEY_BYTES);
    check(this.lib.symbols.wilis_subkey_derive(masterKey, context, BigInt(context.length), out), "wilis_subkey_derive");
    return out;
  }

  xofDerive(label: Uint8Array, seed: Uint8Array, outLen: number): Uint8Array {
    const out = new Uint8Array(outLen);
    check(this.lib.symbols.wilis_xof_derive(label, BigInt(label.length), seed, BigInt(seed.length), out, BigInt(outLen)), "wilis_xof_derive");
    return out;
  }

  aeadSeal(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, pt: Uint8Array): { ciphertext: Uint8Array; tag: Uint8Array } {
    const ct = new Uint8Array(pt.length);
    const tag = new Uint8Array(WILIS_TAG_BYTES);
    check(this.lib.symbols.wilis_aead_seal(key, nonce, aad, BigInt(aad.length), pt, BigInt(pt.length), ct, tag), "wilis_aead_seal");
    return { ciphertext: ct, tag };
  }

  aeadOpen(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ct: Uint8Array, tag: Uint8Array): Uint8Array {
    const pt = new Uint8Array(ct.length);
    check(this.lib.symbols.wilis_aead_open(key, nonce, aad, BigInt(aad.length), ct, BigInt(ct.length), tag, pt), "wilis_aead_open");
    return pt;
  }

  sivSeal(key: Uint8Array, aad: Uint8Array, pt: Uint8Array): { ciphertext: Uint8Array; tag: Uint8Array } {
    const ct = new Uint8Array(pt.length);
    const tag = new Uint8Array(WILIS_SIV_TAG_BYTES);
    check(this.lib.symbols.wilis_siv_seal(key, aad, BigInt(aad.length), pt, BigInt(pt.length), ct, tag), "wilis_siv_seal");
    return { ciphertext: ct, tag };
  }

  sivOpen(key: Uint8Array, aad: Uint8Array, ct: Uint8Array, tag: Uint8Array): Uint8Array {
    const pt = new Uint8Array(ct.length);
    check(this.lib.symbols.wilis_siv_open(key, aad, BigInt(aad.length), ct, BigInt(ct.length), tag, pt), "wilis_siv_open");
    return pt;
  }

  kdfDerive(pass: Uint8Array, salt: Uint8Array, memoryBlocks = 349520, passes = 3): Uint8Array {
    const out = new Uint8Array(WILIS_KEY_BYTES);
    check(this.lib.symbols.wilis_kdf_derive(pass, BigInt(pass.length), salt, memoryBlocks, passes, out), "wilis_kdf_derive");
    return out;
  }

  kdfParallelDerive(pass: Uint8Array, salt: Uint8Array, memoryBlocks = 349520, passes = 3, lanes = 4): Uint8Array {
    const out = new Uint8Array(WILIS_KEY_BYTES);
    check(this.lib.symbols.wilis_kdf_parallel_derive(pass, BigInt(pass.length), salt, memoryBlocks, passes, lanes, out), "wilis_kdf_parallel_derive");
    return out;
  }

  kemKeygen(): { publicKey: Uint8Array; secretKey: Uint8Array } {
    const pk = new Uint8Array(WILIS_KEM_PK_BYTES);
    const sk = new Uint8Array(WILIS_KEM_SK_BYTES);
    check(this.lib.symbols.wilis_kem_keygen(pk, sk), "wilis_kem_keygen");
    return { publicKey: pk, secretKey: sk };
  }

  kemEncapsulate(pk: Uint8Array): { ciphertext: Uint8Array; sharedSecret: Uint8Array } {
    const ct = new Uint8Array(WILIS_KEM_CT_BYTES);
    const ss = new Uint8Array(WILIS_KEM_SS_BYTES);
    check(this.lib.symbols.wilis_kem_encapsulate(pk, ct, ss), "wilis_kem_encapsulate");
    return { ciphertext: ct, sharedSecret: ss };
  }

  kemDecapsulate(sk: Uint8Array, ct: Uint8Array): Uint8Array {
    const ss = new Uint8Array(WILIS_KEM_SS_BYTES);
    check(this.lib.symbols.wilis_kem_decapsulate(sk, ct, ss), "wilis_kem_decapsulate");
    return ss;
  }

  signKeygen(height = 6): { publicKey: Uint8Array; secretKey: Uint8Array } {
    const pk = new Uint8Array(WILIS_SIGN_PK_BYTES);
    const sk = new Uint8Array(WILIS_SIGN_SK_BYTES);
    check(this.lib.symbols.wilis_sign_keygen(height, pk, sk), "wilis_sign_keygen");
    return { publicKey: pk, secretKey: sk };
  }

  signMessage(sk: Uint8Array, msg: Uint8Array): { updatedSk: Uint8Array; signature: Uint8Array } {
    const skCopy = new Uint8Array(sk);
    const sig = new Uint8Array(WILIS_SIGN_MAX_SIG_BYTES);
    const lenBuf = new Uint8Array(8);
    check(this.lib.symbols.wilis_sign_message(skCopy, msg, BigInt(msg.length), sig, BigInt(sig.length), lenBuf), "wilis_sign_message");
    return { updatedSk: skCopy, signature: sig.subarray(0, readUsize(lenBuf)) };
  }

  verifyMessage(pk: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
    return this.lib.symbols.wilis_verify_message(pk, msg, BigInt(msg.length), sig, BigInt(sig.length)) === 0;
  }

  slhKeygen(): { publicKey: Uint8Array; secretKey: Uint8Array } {
    const pk = new Uint8Array(WILIS_SLH_PK_BYTES);
    const sk = new Uint8Array(WILIS_SLH_SK_BYTES);
    check(this.lib.symbols.wilis_slh_keygen(pk, sk), "wilis_slh_keygen");
    return { publicKey: pk, secretKey: sk };
  }

  slhSign(sk: Uint8Array, msg: Uint8Array): Uint8Array {
    const sig = new Uint8Array(WILIS_SLH_SIG_BYTES);
    check(this.lib.symbols.wilis_slh_sign(sk, msg, BigInt(msg.length), sig), "wilis_slh_sign");
    return sig;
  }

  slhVerify(pk: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
    return this.lib.symbols.wilis_slh_verify(pk, msg, BigInt(msg.length), sig) === 0;
  }

  signcrypt(senderSlhSk: Uint8Array, recipientKemPk: Uint8Array, aad: Uint8Array, pt: Uint8Array): Uint8Array {
    const out = new Uint8Array(WILIS_SIGNCRYPT_OVERHEAD + pt.length);
    const lenBuf = new Uint8Array(8);
    check(this.lib.symbols.wilis_signcrypt(senderSlhSk, recipientKemPk, aad, BigInt(aad.length), pt, BigInt(pt.length), out, BigInt(out.length), lenBuf), "wilis_signcrypt");
    return out.subarray(0, readUsize(lenBuf));
  }

  unsigncrypt(senderSlhPk: Uint8Array, recipientKemSk: Uint8Array, aad: Uint8Array, packet: Uint8Array): Uint8Array {
    const out = new Uint8Array(Math.max(packet.length - WILIS_SIGNCRYPT_OVERHEAD, 1));
    const lenBuf = new Uint8Array(8);
    check(this.lib.symbols.wilis_unsigncrypt(senderSlhPk, recipientKemSk, aad, BigInt(aad.length), packet, BigInt(packet.length), out, BigInt(out.length), lenBuf), "wilis_unsigncrypt");
    return out.subarray(0, readUsize(lenBuf));
  }

  totpAt(secret: Uint8Array, unixSecs: bigint, period = 30n, digits = 6): { code: string; remaining: bigint } {
    const codeBuf = new Uint8Array(16);
    const remBuf = new Uint8Array(8);
    check(this.lib.symbols.wilis_totp_at(secret, BigInt(secret.length), unixSecs, period, digits, codeBuf, 16n, remBuf), "wilis_totp_at");
    const nul = codeBuf.indexOf(0);
    const remaining = new DataView(remBuf.buffer).getBigUint64(0, true);
    return { code: this.dec.decode(codeBuf.subarray(0, nul >= 0 ? nul : codeBuf.length)), remaining };
  }

  fpeEncrypt(key: Uint8Array, tweak: Uint8Array, alphabet: string, pt: string): string {
    const a = this.enc.encode(alphabet), p = this.enc.encode(pt);
    const out = new Uint8Array(p.length * 4 + 16), lenBuf = new Uint8Array(8);
    check(this.lib.symbols.wilis_fpe_encrypt(key, tweak, BigInt(tweak.length), a, BigInt(a.length), p, BigInt(p.length), out, BigInt(out.length), lenBuf), "wilis_fpe_encrypt");
    return this.dec.decode(out.subarray(0, readUsize(lenBuf)));
  }

  fpeDecrypt(key: Uint8Array, tweak: Uint8Array, alphabet: string, ct: string): string {
    const a = this.enc.encode(alphabet), c = this.enc.encode(ct);
    const out = new Uint8Array(c.length * 4 + 16), lenBuf = new Uint8Array(8);
    check(this.lib.symbols.wilis_fpe_decrypt(key, tweak, BigInt(tweak.length), a, BigInt(a.length), c, BigInt(c.length), out, BigInt(out.length), lenBuf), "wilis_fpe_decrypt");
    return this.dec.decode(out.subarray(0, readUsize(lenBuf)));
  }

  mnemonicEncode(secret: Uint8Array): string {
    const lenBuf = new Uint8Array(8);
    const rc0 = this.lib.symbols.wilis_mnemonic_encode(secret, BigInt(secret.length), new Uint8Array(1), 0n, lenBuf);
    if (rc0 !== 0 && rc0 !== ERR_BUF_TOO_SMALL) check(rc0, "wilis_mnemonic_encode");
    const out = new Uint8Array(readUsize(lenBuf));
    check(this.lib.symbols.wilis_mnemonic_encode(secret, BigInt(secret.length), out, BigInt(out.length), lenBuf), "wilis_mnemonic_encode");
    return this.dec.decode(out.subarray(0, readUsize(lenBuf)));
  }

  mnemonicDecode(phrase: string): Uint8Array {
    const p = this.enc.encode(phrase), lenBuf = new Uint8Array(8);
    const rc0 = this.lib.symbols.wilis_mnemonic_decode(p, BigInt(p.length), new Uint8Array(1), 0n, lenBuf);
    if (rc0 !== 0 && rc0 !== ERR_BUF_TOO_SMALL) check(rc0, "wilis_mnemonic_decode");
    const out = new Uint8Array(readUsize(lenBuf));
    check(this.lib.symbols.wilis_mnemonic_decode(p, BigInt(p.length), out, BigInt(out.length), lenBuf), "wilis_mnemonic_decode");
    return out.subarray(0, readUsize(lenBuf));
  }

  lzCompress(data: Uint8Array): Uint8Array {
    const lenBuf = new Uint8Array(8);
    const rc0 = this.lib.symbols.wilis_lz_compress(data, BigInt(data.length), new Uint8Array(1), 0n, lenBuf);
    if (rc0 !== 0 && rc0 !== ERR_BUF_TOO_SMALL) check(rc0, "wilis_lz_compress");
    const out = new Uint8Array(readUsize(lenBuf));
    check(this.lib.symbols.wilis_lz_compress(data, BigInt(data.length), out, BigInt(out.length), lenBuf), "wilis_lz_compress");
    return out.subarray(0, readUsize(lenBuf));
  }

  lzDecompress(data: Uint8Array, maxOut = 16 * 1024 * 1024): Uint8Array {
    const lenBuf = new Uint8Array(8);
    const rc0 = this.lib.symbols.wilis_lz_decompress(data, BigInt(data.length), BigInt(maxOut), new Uint8Array(1), 0n, lenBuf);
    if (rc0 !== 0 && rc0 !== ERR_BUF_TOO_SMALL) check(rc0, "wilis_lz_decompress");
    const out = new Uint8Array(readUsize(lenBuf));
    check(this.lib.symbols.wilis_lz_decompress(data, BigInt(data.length), BigInt(maxOut), out, BigInt(out.length), lenBuf), "wilis_lz_decompress");
    return out.subarray(0, readUsize(lenBuf));
  }
}
