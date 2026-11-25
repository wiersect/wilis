// Wilis v0.7.0 — Zero-Dependency Zig Bindings (All 33 C-ABI exports)
//
// Test with Zig 0.13+ after `cargo build --release`:
//   zig test bindings/zig/wilis.zig -Ltarget/release -lwilis -rpath target/release

const std = @import("std");

pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 24;
pub const SALT_BYTES: usize = 24;
pub const TAG_BYTES: usize = 32;
pub const SIV_TAG_BYTES: usize = 64;
pub const HASH_BYTES: usize = 32;

pub const KEM_PK_BYTES: usize = 1284;
pub const KEM_SK_BYTES: usize = 2600;
pub const KEM_CT_BYTES: usize = 1668;
pub const KEM_SS_BYTES: usize = 32;

pub const SIGN_PK_BYTES: usize = 101;
pub const SIGN_SK_BYTES: usize = 137;
pub const SIGN_MAX_SIG_BYTES: usize = 2506;

pub const SLH_PK_BYTES: usize = 100;
pub const SLH_SK_BYTES: usize = 164;
pub const SLH_SIG_BYTES: usize = 8165;
pub const SIGNCRYPT_OVERHEAD: usize = 9894;

pub const OK: i32 = 0;
pub const ERR_INVALID_ARG: i32 = -1;
pub const ERR_AUTH_FAILED: i32 = -2;
pub const ERR_INTERNAL: i32 = -3;
pub const ERR_BUF_TOO_SMALL: i32 = -4;

pub const Error = error{
    InvalidArg,
    AuthFailed,
    InternalError,
    BufTooSmall,
    OutOfMemory,
};

pub const c = struct {
    pub extern "c" fn wilis_version() [*:0]const u8;
    pub extern "c" fn wilis_ct_eq(a: ?[*]const u8, b: ?[*]const u8, len: usize) i32;
    pub extern "c" fn wilis_zeroize(buf: ?[*]u8, len: usize) i32;
    pub extern "c" fn wilis_random_bytes(out: ?[*]u8, len: usize) i32;

    pub extern "c" fn wilis_hash_256(data: ?[*]const u8, data_len: usize, out_32: *[HASH_BYTES]u8) i32;
    pub extern "c" fn wilis_tree_hash_256(data: ?[*]const u8, data_len: usize, out_32: *[HASH_BYTES]u8) i32;
    pub extern "c" fn wilis_mac_256(key_32: *const [KEY_BYTES]u8, msg: ?[*]const u8, msg_len: usize, tag_32_out: *[TAG_BYTES]u8) i32;
    pub extern "c" fn wilis_subkey_derive(master_key_32: *const [KEY_BYTES]u8, context: ?[*]const u8, context_len: usize, subkey_32_out: *[KEY_BYTES]u8) i32;
    pub extern "c" fn wilis_xof_derive(label: ?[*]const u8, label_len: usize, seed: ?[*]const u8, seed_len: usize, out: ?[*]u8, out_len: usize) i32;

    pub extern "c" fn wilis_aead_seal(key_32: *const [KEY_BYTES]u8, nonce_24: *const [NONCE_BYTES]u8, aad: ?[*]const u8, aad_len: usize, pt: ?[*]const u8, pt_len: usize, ct_out: ?[*]u8, tag_32_out: *[TAG_BYTES]u8) i32;
    pub extern "c" fn wilis_aead_open(key_32: *const [KEY_BYTES]u8, nonce_24: *const [NONCE_BYTES]u8, aad: ?[*]const u8, aad_len: usize, ct: ?[*]const u8, ct_len: usize, tag_32: *const [TAG_BYTES]u8, pt_out: ?[*]u8) i32;
    pub extern "c" fn wilis_siv_seal(key_32: *const [KEY_BYTES]u8, aad: ?[*]const u8, aad_len: usize, pt: ?[*]const u8, pt_len: usize, ct_out: ?[*]u8, siv_tag_64_out: *[SIV_TAG_BYTES]u8) i32;
    pub extern "c" fn wilis_siv_open(key_32: *const [KEY_BYTES]u8, aad: ?[*]const u8, aad_len: usize, ct: ?[*]const u8, ct_len: usize, siv_tag_64: *const [SIV_TAG_BYTES]u8, pt_out: ?[*]u8) i32;

    pub extern "c" fn wilis_kdf_derive(pass: ?[*]const u8, pass_len: usize, salt_24: *const [SALT_BYTES]u8, memory_blocks: u32, passes: u32, key_32_out: *[KEY_BYTES]u8) i32;
    pub extern "c" fn wilis_kdf_parallel_derive(pass: ?[*]const u8, pass_len: usize, salt_24: *const [SALT_BYTES]u8, memory_blocks: u32, passes: u32, lanes: u32, key_32_out: *[KEY_BYTES]u8) i32;

    pub extern "c" fn wilis_kem_keygen(pk_out: *[KEM_PK_BYTES]u8, sk_out: *[KEM_SK_BYTES]u8) i32;
    pub extern "c" fn wilis_kem_encapsulate(pk: *const [KEM_PK_BYTES]u8, ct_out: *[KEM_CT_BYTES]u8, ss_32_out: *[KEM_SS_BYTES]u8) i32;
    pub extern "c" fn wilis_kem_decapsulate(sk: *const [KEM_SK_BYTES]u8, ct: *const [KEM_CT_BYTES]u8, ss_32_out: *[KEM_SS_BYTES]u8) i32;

    pub extern "c" fn wilis_sign_keygen(height: u8, pk_out: *[SIGN_PK_BYTES]u8, sk_out: *[SIGN_SK_BYTES]u8) i32;
    pub extern "c" fn wilis_sign_message(sk_inout: *[SIGN_SK_BYTES]u8, msg: ?[*]const u8, msg_len: usize, sig_out: [*]u8, sig_cap: usize, sig_len_out: *usize) i32;
    pub extern "c" fn wilis_verify_message(pk: *const [SIGN_PK_BYTES]u8, msg: ?[*]const u8, msg_len: usize, sig: ?[*]const u8, sig_len: usize) i32;

    pub extern "c" fn wilis_slh_keygen(pk_out: *[SLH_PK_BYTES]u8, sk_out: *[SLH_SK_BYTES]u8) i32;
    pub extern "c" fn wilis_slh_sign(sk: *const [SLH_SK_BYTES]u8, msg: ?[*]const u8, msg_len: usize, sig_out: *[SLH_SIG_BYTES]u8) i32;
    pub extern "c" fn wilis_slh_verify(pk: *const [SLH_PK_BYTES]u8, msg: ?[*]const u8, msg_len: usize, sig: *const [SLH_SIG_BYTES]u8) i32;

    pub extern "c" fn wilis_signcrypt(sender_slh_sk: *const [SLH_SK_BYTES]u8, recipient_kem_pk: *const [KEM_PK_BYTES]u8, aad: ?[*]const u8, aad_len: usize, pt: ?[*]const u8, pt_len: usize, out: ?[*]u8, out_cap: usize, out_len_out: *usize) i32;
    pub extern "c" fn wilis_unsigncrypt(sender_slh_pk: *const [SLH_PK_BYTES]u8, recipient_kem_sk: *const [KEM_SK_BYTES]u8, aad: ?[*]const u8, aad_len: usize, packet: ?[*]const u8, packet_len: usize, pt_out: ?[*]u8, pt_cap: usize, pt_len_out: *usize) i32;

    pub extern "c" fn wilis_totp_at(secret: ?[*]const u8, secret_len: usize, unix_secs: u64, period: u64, digits: u32, code_out: [*]u8, code_cap: usize, remaining_out: *u64) i32;
    pub extern "c" fn wilis_fpe_encrypt(key_32: *const [KEY_BYTES]u8, tweak: ?[*]const u8, tweak_len: usize, alphabet: ?[*]const u8, alpha_len: usize, pt: ?[*]const u8, pt_len: usize, out: ?[*]u8, out_cap: usize, out_len_out: *usize) i32;
    pub extern "c" fn wilis_fpe_decrypt(key_32: *const [KEY_BYTES]u8, tweak: ?[*]const u8, tweak_len: usize, alphabet: ?[*]const u8, alpha_len: usize, ct: ?[*]const u8, ct_len: usize, out: ?[*]u8, out_cap: usize, out_len_out: *usize) i32;
    pub extern "c" fn wilis_mnemonic_encode(secret: ?[*]const u8, secret_len: usize, out_utf8: ?[*]u8, out_cap: usize, out_len_out: *usize) i32;
    pub extern "c" fn wilis_mnemonic_decode(phrase: ?[*]const u8, phrase_len: usize, out: ?[*]u8, out_cap: usize, out_len_out: *usize) i32;
    pub extern "c" fn wilis_lz_compress(data: ?[*]const u8, data_len: usize, out: ?[*]u8, out_cap: usize, out_len_out: *usize) i32;
    pub extern "c" fn wilis_lz_decompress(data: ?[*]const u8, data_len: usize, max_out: usize, out: ?[*]u8, out_cap: usize, out_len_out: *usize) i32;
};

fn check(rc: i32) Error!void {
    return switch (rc) {
        OK => {},
        ERR_INVALID_ARG => Error.InvalidArg,
        ERR_AUTH_FAILED => Error.AuthFailed,
        ERR_BUF_TOO_SMALL => Error.BufTooSmall,
        else => Error.InternalError,
    };
}

fn cptr(s: []const u8) ?[*]const u8 {
    return if (s.len == 0) null else s.ptr;
}

fn mptr(s: []u8) ?[*]u8 {
    return if (s.len == 0) null else s.ptr;
}

pub fn version() []const u8 {
    return std.mem.span(c.wilis_version());
}

pub fn ctEq(a: []const u8, b: []const u8) Error!bool {
    if (a.len != b.len) return false;
    const rc = c.wilis_ct_eq(cptr(a), cptr(b), a.len);
    if (rc < 0) try check(rc);
    return rc == 1;
}

pub fn zeroize(buf: []u8) Error!void {
    try check(c.wilis_zeroize(mptr(buf), buf.len));
}

pub fn randomBytes(out: []u8) Error!void {
    try check(c.wilis_random_bytes(mptr(out), out.len));
}

pub fn hash256(data: []const u8) Error![HASH_BYTES]u8 {
    var out: [HASH_BYTES]u8 = undefined;
    try check(c.wilis_hash_256(cptr(data), data.len, &out));
    return out;
}

pub fn treeHash256(data: []const u8) Error![HASH_BYTES]u8 {
    var out: [HASH_BYTES]u8 = undefined;
    try check(c.wilis_tree_hash_256(cptr(data), data.len, &out));
    return out;
}

pub fn mac256(key: *const [KEY_BYTES]u8, msg: []const u8) Error![TAG_BYTES]u8 {
    var tag: [TAG_BYTES]u8 = undefined;
    try check(c.wilis_mac_256(key, cptr(msg), msg.len, &tag));
    return tag;
}

pub fn subkeyDerive(master_key: *const [KEY_BYTES]u8, context: []const u8) Error![KEY_BYTES]u8 {
    var sub: [KEY_BYTES]u8 = undefined;
    try check(c.wilis_subkey_derive(master_key, cptr(context), context.len, &sub));
    return sub;
}

pub fn xofDerive(label: []const u8, seed: []const u8, out: []u8) Error!void {
    try check(c.wilis_xof_derive(cptr(label), label.len, cptr(seed), seed.len, mptr(out), out.len));
}

pub fn aeadSeal(key: *const [KEY_BYTES]u8, nonce: *const [NONCE_BYTES]u8, aad: []const u8, pt: []const u8, ct_out: []u8) Error![TAG_BYTES]u8 {
    if (ct_out.len != pt.len) return Error.InvalidArg;
    var tag: [TAG_BYTES]u8 = undefined;
    try check(c.wilis_aead_seal(key, nonce, cptr(aad), aad.len, cptr(pt), pt.len, mptr(ct_out), &tag));
    return tag;
}

pub fn aeadOpen(key: *const [KEY_BYTES]u8, nonce: *const [NONCE_BYTES]u8, aad: []const u8, ct: []const u8, tag: *const [TAG_BYTES]u8, pt_out: []u8) Error!void {
    if (pt_out.len != ct.len) return Error.InvalidArg;
    try check(c.wilis_aead_open(key, nonce, cptr(aad), aad.len, cptr(ct), ct.len, tag, mptr(pt_out)));
}

pub fn sivSeal(key: *const [KEY_BYTES]u8, aad: []const u8, pt: []const u8, ct_out: []u8) Error![SIV_TAG_BYTES]u8 {
    if (ct_out.len != pt.len) return Error.InvalidArg;
    var tag: [SIV_TAG_BYTES]u8 = undefined;
    try check(c.wilis_siv_seal(key, cptr(aad), aad.len, cptr(pt), pt.len, mptr(ct_out), &tag));
    return tag;
}

pub fn sivOpen(key: *const [KEY_BYTES]u8, aad: []const u8, ct: []const u8, siv_tag: *const [SIV_TAG_BYTES]u8, pt_out: []u8) Error!void {
    if (pt_out.len != ct.len) return Error.InvalidArg;
    try check(c.wilis_siv_open(key, cptr(aad), aad.len, cptr(ct), ct.len, siv_tag, mptr(pt_out)));
}

pub fn kdfDerive(pass: []const u8, salt: *const [SALT_BYTES]u8, memory_blocks: u32, passes: u32) Error![KEY_BYTES]u8 {
    var key: [KEY_BYTES]u8 = undefined;
    try check(c.wilis_kdf_derive(cptr(pass), pass.len, salt, memory_blocks, passes, &key));
    return key;
}

pub fn kdfParallelDerive(pass: []const u8, salt: *const [SALT_BYTES]u8, memory_blocks: u32, passes: u32, lanes: u32) Error![KEY_BYTES]u8 {
    var key: [KEY_BYTES]u8 = undefined;
    try check(c.wilis_kdf_parallel_derive(cptr(pass), pass.len, salt, memory_blocks, passes, lanes, &key));
    return key;
}

pub const KemKeypair = struct { pk: [KEM_PK_BYTES]u8, sk: [KEM_SK_BYTES]u8 };
pub const KemEncap = struct { ct: [KEM_CT_BYTES]u8, ss: [KEM_SS_BYTES]u8 };

pub fn kemKeygen() Error!KemKeypair {
    var kp: KemKeypair = undefined;
    try check(c.wilis_kem_keygen(&kp.pk, &kp.sk));
    return kp;
}

pub fn kemEncapsulate(pk: *const [KEM_PK_BYTES]u8) Error!KemEncap {
    var r: KemEncap = undefined;
    try check(c.wilis_kem_encapsulate(pk, &r.ct, &r.ss));
    return r;
}

pub fn kemDecapsulate(sk: *const [KEM_SK_BYTES]u8, ct: *const [KEM_CT_BYTES]u8) Error![KEM_SS_BYTES]u8 {
    var ss: [KEM_SS_BYTES]u8 = undefined;
    try check(c.wilis_kem_decapsulate(sk, ct, &ss));
    return ss;
}

pub const SignKeypair = struct { pk: [SIGN_PK_BYTES]u8, sk: [SIGN_SK_BYTES]u8 };
pub const SlhKeypair = struct { pk: [SLH_PK_BYTES]u8, sk: [SLH_SK_BYTES]u8 };

pub fn signKeygen(height: u8) Error!SignKeypair {
    var kp: SignKeypair = undefined;
    try check(c.wilis_sign_keygen(height, &kp.pk, &kp.sk));
    return kp;
}

pub fn signMessage(allocator: std.mem.Allocator, sk: *[SIGN_SK_BYTES]u8, msg: []const u8) Error![]u8 {
    var buf: [SIGN_MAX_SIG_BYTES]u8 = undefined;
    var sig_len: usize = 0;
    try check(c.wilis_sign_message(sk, cptr(msg), msg.len, &buf, buf.len, &sig_len));
    return allocator.dupe(u8, buf[0..sig_len]);
}

pub fn verifyMessage(pk: *const [SIGN_PK_BYTES]u8, msg: []const u8, sig: []const u8) Error!bool {
    const rc = c.wilis_verify_message(pk, cptr(msg), msg.len, cptr(sig), sig.len);
    if (rc == OK) return true;
    if (rc == ERR_AUTH_FAILED) return false;
    try check(rc);
    return false;
}

pub fn slhKeygen() Error!SlhKeypair {
    var kp: SlhKeypair = undefined;
    try check(c.wilis_slh_keygen(&kp.pk, &kp.sk));
    return kp;
}

pub fn slhSign(sk: *const [SLH_SK_BYTES]u8, msg: []const u8) Error![SLH_SIG_BYTES]u8 {
    var sig: [SLH_SIG_BYTES]u8 = undefined;
    try check(c.wilis_slh_sign(sk, cptr(msg), msg.len, &sig));
    return sig;
}

pub fn slhVerify(pk: *const [SLH_PK_BYTES]u8, msg: []const u8, sig: *const [SLH_SIG_BYTES]u8) Error!bool {
    const rc = c.wilis_slh_verify(pk, cptr(msg), msg.len, sig);
    if (rc == OK) return true;
    if (rc == ERR_AUTH_FAILED) return false;
    try check(rc);
    return false;
}

pub fn signcrypt(allocator: std.mem.Allocator, sender_slh_sk: *const [SLH_SK_BYTES]u8, recipient_kem_pk: *const [KEM_PK_BYTES]u8, aad: []const u8, pt: []const u8) Error![]u8 {
    var needed: usize = 0;
    const rc0 = c.wilis_signcrypt(sender_slh_sk, recipient_kem_pk, cptr(aad), aad.len, cptr(pt), pt.len, null, 0, &needed);
    if (rc0 != ERR_BUF_TOO_SMALL and rc0 != OK) try check(rc0);
    const buf = try allocator.alloc(u8, needed);
    errdefer allocator.free(buf);
    var actual: usize = 0;
    try check(c.wilis_signcrypt(sender_slh_sk, recipient_kem_pk, cptr(aad), aad.len, cptr(pt), pt.len, mptr(buf), buf.len, &actual));
    return allocator.realloc(buf, actual);
}

pub fn unsigncrypt(allocator: std.mem.Allocator, sender_slh_pk: *const [SLH_PK_BYTES]u8, recipient_kem_sk: *const [KEM_SK_BYTES]u8, aad: []const u8, packet: []const u8) Error![]u8 {
    var needed: usize = 0;
    const rc0 = c.wilis_unsigncrypt(sender_slh_pk, recipient_kem_sk, cptr(aad), aad.len, cptr(packet), packet.len, null, 0, &needed);
    if (rc0 == OK and needed == 0) return allocator.alloc(u8, 0);
    if (rc0 != ERR_BUF_TOO_SMALL) try check(rc0);
    const buf = try allocator.alloc(u8, needed);
    errdefer allocator.free(buf);
    var actual: usize = 0;
    try check(c.wilis_unsigncrypt(sender_slh_pk, recipient_kem_sk, cptr(aad), aad.len, cptr(packet), packet.len, mptr(buf), buf.len, &actual));
    return allocator.realloc(buf, actual);
}

pub const TotpResult = struct { code: [11]u8, code_len: usize, remaining: u64 };

pub fn totpAt(secret: []const u8, unix_secs: u64, period: u64, digits: u32) Error!TotpResult {
    if (digits < 4 or digits > 10) return Error.InvalidArg;
    var res = TotpResult{ .code = [_]u8{0} ** 11, .code_len = digits, .remaining = 0 };
    try check(c.wilis_totp_at(cptr(secret), secret.len, unix_secs, period, digits, &res.code, res.code.len, &res.remaining));
    return res;
}

pub fn fpeEncrypt(allocator: std.mem.Allocator, key: *const [KEY_BYTES]u8, tweak: []const u8, alphabet: []const u8, pt: []const u8) Error![]u8 {
    var needed: usize = 0;
    const rc0 = c.wilis_fpe_encrypt(key, cptr(tweak), tweak.len, cptr(alphabet), alphabet.len, cptr(pt), pt.len, null, 0, &needed);
    if (rc0 != ERR_BUF_TOO_SMALL and rc0 != OK) try check(rc0);
    const buf = try allocator.alloc(u8, needed);
    errdefer allocator.free(buf);
    var actual: usize = 0;
    try check(c.wilis_fpe_encrypt(key, cptr(tweak), tweak.len, cptr(alphabet), alphabet.len, cptr(pt), pt.len, mptr(buf), buf.len, &actual));
    return allocator.realloc(buf, actual);
}

pub fn fpeDecrypt(allocator: std.mem.Allocator, key: *const [KEY_BYTES]u8, tweak: []const u8, alphabet: []const u8, ct: []const u8) Error![]u8 {
    var needed: usize = 0;
    const rc0 = c.wilis_fpe_decrypt(key, cptr(tweak), tweak.len, cptr(alphabet), alphabet.len, cptr(ct), ct.len, null, 0, &needed);
    if (rc0 != ERR_BUF_TOO_SMALL and rc0 != OK) try check(rc0);
    const buf = try allocator.alloc(u8, needed);
    errdefer allocator.free(buf);
    var actual: usize = 0;
    try check(c.wilis_fpe_decrypt(key, cptr(tweak), tweak.len, cptr(alphabet), alphabet.len, cptr(ct), ct.len, mptr(buf), buf.len, &actual));
    return allocator.realloc(buf, actual);
}

pub fn mnemonicEncode(allocator: std.mem.Allocator, secret: []const u8) Error![]u8 {
    var needed: usize = 0;
    const rc0 = c.wilis_mnemonic_encode(cptr(secret), secret.len, null, 0, &needed);
    if (rc0 != ERR_BUF_TOO_SMALL and rc0 != OK) try check(rc0);
    const buf = try allocator.alloc(u8, needed);
    errdefer allocator.free(buf);
    var actual: usize = 0;
    try check(c.wilis_mnemonic_encode(cptr(secret), secret.len, mptr(buf), buf.len, &actual));
    return allocator.realloc(buf, actual);
}

pub fn mnemonicDecode(allocator: std.mem.Allocator, phrase: []const u8) Error![]u8 {
    var needed: usize = 0;
    const rc0 = c.wilis_mnemonic_decode(cptr(phrase), phrase.len, null, 0, &needed);
    if (rc0 != ERR_BUF_TOO_SMALL and rc0 != OK) try check(rc0);
    const buf = try allocator.alloc(u8, needed);
    errdefer allocator.free(buf);
    var actual: usize = 0;
    try check(c.wilis_mnemonic_decode(cptr(phrase), phrase.len, mptr(buf), buf.len, &actual));
    return allocator.realloc(buf, actual);
}

pub fn lzCompress(allocator: std.mem.Allocator, data: []const u8) Error![]u8 {
    var needed: usize = 0;
    const rc0 = c.wilis_lz_compress(cptr(data), data.len, null, 0, &needed);
    if (rc0 != ERR_BUF_TOO_SMALL and rc0 != OK) try check(rc0);
    const buf = try allocator.alloc(u8, needed);
    errdefer allocator.free(buf);
    var actual: usize = 0;
    try check(c.wilis_lz_compress(cptr(data), data.len, mptr(buf), buf.len, &actual));
    return allocator.realloc(buf, actual);
}

pub fn lzDecompress(allocator: std.mem.Allocator, compressed: []const u8, max_out: usize) Error![]u8 {
    var needed: usize = 0;
    const rc0 = c.wilis_lz_decompress(cptr(compressed), compressed.len, max_out, null, 0, &needed);
    if (rc0 == OK and needed == 0) return allocator.alloc(u8, 0);
    if (rc0 != ERR_BUF_TOO_SMALL) try check(rc0);
    const buf = try allocator.alloc(u8, needed);
    errdefer allocator.free(buf);
    var actual: usize = 0;
    try check(c.wilis_lz_decompress(cptr(compressed), compressed.len, max_out, mptr(buf), buf.len, &actual));
    return allocator.realloc(buf, actual);
}

test "wilis core roundtrips" {
    const alloc = std.testing.allocator;
    try std.testing.expectEqualStrings("0.7.0", version());
    var key: [KEY_BYTES]u8 = undefined;
    var nonce: [NONCE_BYTES]u8 = undefined;
    try randomBytes(&key);
    try randomBytes(&nonce);
    const pt = "hello zig wilis";
    var ct: [pt.len]u8 = undefined;
    const tag = try aeadSeal(&key, &nonce, "aad", pt, &ct);
    var dec: [pt.len]u8 = undefined;
    try aeadOpen(&key, &nonce, "aad", &ct, &tag, &dec);
    try std.testing.expect(try ctEq(pt, &dec));
    const phrase = try mnemonicEncode(alloc, &key);
    defer alloc.free(phrase);
    const back = try mnemonicDecode(alloc, phrase);
    defer alloc.free(back);
    try std.testing.expect(try ctEq(&key, back));
    try zeroize(&key);
}
