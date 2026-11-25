-- Wilis v0.7.0 — Zero-Dependency LuaJIT FFI Bindings (All 33 C-ABI exports)
--
-- Run self-test with LuaJIT after `cargo build --release`:
--   luajit bindings/lua/wilis.lua

local ffi = require("ffi")

ffi.cdef[[
  const char *wilis_version(void);
  int32_t wilis_ct_eq(const uint8_t *a, const uint8_t *b, size_t len);
  int32_t wilis_zeroize(uint8_t *buf, size_t len);
  int32_t wilis_random_bytes(uint8_t *out, size_t len);

  int32_t wilis_hash_256(const uint8_t *data, size_t data_len, uint8_t *out_32);
  int32_t wilis_tree_hash_256(const uint8_t *data, size_t data_len, uint8_t *out_32);
  int32_t wilis_mac_256(const uint8_t *key_32, const uint8_t *msg, size_t msg_len, uint8_t *tag_32_out);
  int32_t wilis_subkey_derive(const uint8_t *master_key_32, const uint8_t *context, size_t context_len, uint8_t *subkey_32_out);
  int32_t wilis_xof_derive(const uint8_t *label, size_t label_len, const uint8_t *seed, size_t seed_len, uint8_t *out, size_t out_len);

  int32_t wilis_aead_seal(const uint8_t *key_32, const uint8_t *nonce_24, const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t pt_len, uint8_t *ct_out, uint8_t *tag_32_out);
  int32_t wilis_aead_open(const uint8_t *key_32, const uint8_t *nonce_24, const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t ct_len, const uint8_t *tag_32, uint8_t *pt_out);
  int32_t wilis_siv_seal(const uint8_t *key_32, const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t pt_len, uint8_t *ct_out, uint8_t *siv_tag_64_out);
  int32_t wilis_siv_open(const uint8_t *key_32, const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t ct_len, const uint8_t *siv_tag_64, uint8_t *pt_out);

  int32_t wilis_kdf_derive(const uint8_t *pass, size_t pass_len, const uint8_t *salt_24, uint32_t memory_blocks, uint32_t passes, uint8_t *key_32_out);
  int32_t wilis_kdf_parallel_derive(const uint8_t *pass, size_t pass_len, const uint8_t *salt_24, uint32_t memory_blocks, uint32_t passes, uint32_t lanes, uint8_t *key_32_out);

  int32_t wilis_kem_keygen(uint8_t *pk_out, uint8_t *sk_out);
  int32_t wilis_kem_encapsulate(const uint8_t *pk, uint8_t *ct_out, uint8_t *ss_32_out);
  int32_t wilis_kem_decapsulate(const uint8_t *sk, const uint8_t *ct, uint8_t *ss_32_out);

  int32_t wilis_sign_keygen(uint8_t height, uint8_t *pk_out, uint8_t *sk_out);
  int32_t wilis_sign_message(uint8_t *sk_inout, const uint8_t *msg, size_t msg_len, uint8_t *sig_out, size_t sig_cap, size_t *sig_len_out);
  int32_t wilis_verify_message(const uint8_t *pk, const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len);

  int32_t wilis_slh_keygen(uint8_t *pk_out, uint8_t *sk_out);
  int32_t wilis_slh_sign(const uint8_t *sk, const uint8_t *msg, size_t msg_len, uint8_t *sig_out);
  int32_t wilis_slh_verify(const uint8_t *pk, const uint8_t *msg, size_t msg_len, const uint8_t *sig);

  int32_t wilis_signcrypt(const uint8_t *sender_slh_sk, const uint8_t *recipient_kem_pk, const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t pt_len, uint8_t *out, size_t out_cap, size_t *out_len_out);
  int32_t wilis_unsigncrypt(const uint8_t *sender_slh_pk, const uint8_t *recipient_kem_sk, const uint8_t *aad, size_t aad_len, const uint8_t *packet, size_t packet_len, uint8_t *pt_out, size_t pt_cap, size_t *pt_len_out);

  int32_t wilis_totp_at(const uint8_t *secret, size_t secret_len, uint64_t unix_secs, uint64_t period, uint32_t digits, uint8_t *code_out, size_t code_cap, uint64_t *remaining_out);
  int32_t wilis_fpe_encrypt(const uint8_t *key_32, const uint8_t *tweak, size_t tweak_len, const uint8_t *alphabet, size_t alpha_len, const uint8_t *pt, size_t pt_len, uint8_t *out, size_t out_cap, size_t *out_len_out);
  int32_t wilis_fpe_decrypt(const uint8_t *key_32, const uint8_t *tweak, size_t tweak_len, const uint8_t *alphabet, size_t alpha_len, const uint8_t *ct, size_t ct_len, uint8_t *out, size_t out_cap, size_t *out_len_out);
  int32_t wilis_mnemonic_encode(const uint8_t *secret, size_t secret_len, uint8_t *out_utf8, size_t out_cap, size_t *out_len_out);
  int32_t wilis_mnemonic_decode(const uint8_t *phrase, size_t phrase_len, uint8_t *out, size_t out_cap, size_t *out_len_out);
  int32_t wilis_lz_compress(const uint8_t *data, size_t data_len, uint8_t *out, size_t out_cap, size_t *out_len_out);
  int32_t wilis_lz_decompress(const uint8_t *data, size_t data_len, size_t max_out, uint8_t *out, size_t out_cap, size_t *out_len_out);
]]

local M = {
  KEY_BYTES = 32, NONCE_BYTES = 24, SALT_BYTES = 24, TAG_BYTES = 32, SIV_TAG_BYTES = 64, HASH_BYTES = 32,
  KEM_PK_BYTES = 1284, KEM_SK_BYTES = 2600, KEM_CT_BYTES = 1668, KEM_SS_BYTES = 32,
  SIGN_PK_BYTES = 101, SIGN_SK_BYTES = 137, SIGN_MAX_SIG_BYTES = 2506,
  SLH_PK_BYTES = 100, SLH_SK_BYTES = 164, SLH_SIG_BYTES = 8165, SIGNCRYPT_OVERHEAD = 9894,
  OK = 0, ERR_INVALID_ARG = -1, ERR_AUTH_FAILED = -2, ERR_INTERNAL = -3, ERR_BUF_TOO_SMALL = -4,
}

local function load_lib(path)
  if path then return ffi.load(path) end
  local env = os.getenv("WILIS_LIB")
  if env and #env > 0 then return ffi.load(env) end
  local libname = ffi.os == "OSX" and "libwilis.dylib" or (ffi.os == "Windows" and "wilis.dll" or "libwilis.so")
  for _, p in ipairs({ "target/release/" .. libname, "target/debug/" .. libname, "../../target/release/" .. libname }) do
    local ok, lib = pcall(ffi.load, p)
    if ok then return lib end
  end
  return ffi.load(libname)
end

local function check(op, rc)
  if rc ~= 0 then error("Wilis " .. op .. " failed with code " .. tostring(rc), 2) end
end

local function check_len(name, s, n)
  if #s ~= n then error(name .. " must be exactly " .. n .. " bytes", 2) end
end

local function u8ptr(s)
  if #s == 0 then return nil end
  return ffi.cast("const uint8_t *", s)
end

local function call_var_out(op, fn)
  local len = ffi.new("size_t[1]")
  local rc = fn(nil, 0, len)
  local needed = tonumber(len[0])
  if rc == 0 and needed == 0 then return "" end
  if rc ~= M.ERR_BUF_TOO_SMALL then check(op, rc) end
  local out = ffi.new("uint8_t[?]", needed)
  rc = fn(out, needed, len)
  check(op, rc)
  return ffi.string(out, tonumber(len[0]))
end

function M.open(lib_path)
  local lib = load_lib(lib_path)
  local W = {}

  function W.version() return ffi.string(lib.wilis_version()) end

  function W.ct_eq(a, b)
    if #a ~= #b then return false end
    local rc = lib.wilis_ct_eq(u8ptr(a), u8ptr(b), #a)
    if rc < 0 then check("ct_eq", rc) end
    return rc == 1
  end

  function W.zeroize(buf, len) check("zeroize", lib.wilis_zeroize(buf, len)) end

  function W.random_bytes(n)
    if n == 0 then return "" end
    local out = ffi.new("uint8_t[?]", n)
    check("random_bytes", lib.wilis_random_bytes(out, n))
    return ffi.string(out, n)
  end

  function W.hash_256(data)
    local out = ffi.new("uint8_t[32]")
    check("hash_256", lib.wilis_hash_256(u8ptr(data), #data, out))
    return ffi.string(out, 32)
  end

  function W.tree_hash_256(data)
    local out = ffi.new("uint8_t[32]")
    check("tree_hash_256", lib.wilis_tree_hash_256(u8ptr(data), #data, out))
    return ffi.string(out, 32)
  end

  function W.mac_256(key, msg)
    check_len("key", key, 32)
    local tag = ffi.new("uint8_t[32]")
    check("mac_256", lib.wilis_mac_256(u8ptr(key), u8ptr(msg), #msg, tag))
    return ffi.string(tag, 32)
  end

  function W.subkey_derive(master, ctx)
    check_len("master", master, 32)
    local out = ffi.new("uint8_t[32]")
    check("subkey_derive", lib.wilis_subkey_derive(u8ptr(master), u8ptr(ctx), #ctx, out))
    return ffi.string(out, 32)
  end

  function W.xof_derive(label, seed, out_len)
    local out = out_len == 0 and nil or ffi.new("uint8_t[?]", out_len)
    check("xof_derive", lib.wilis_xof_derive(u8ptr(label), #label, u8ptr(seed), #seed, out, out_len))
    return out_len == 0 and "" or ffi.string(out, out_len)
  end

  function W.aead_seal(key, nonce, aad, pt)
    check_len("key", key, 32); check_len("nonce", nonce, 24)
    local ct = #pt == 0 and nil or ffi.new("uint8_t[?]", #pt)
    local tag = ffi.new("uint8_t[32]")
    check("aead_seal", lib.wilis_aead_seal(u8ptr(key), u8ptr(nonce), u8ptr(aad), #aad, u8ptr(pt), #pt, ct, tag))
    return (#pt == 0 and "" or ffi.string(ct, #pt)), ffi.string(tag, 32)
  end

  function W.aead_open(key, nonce, aad, ct, tag)
    check_len("key", key, 32); check_len("nonce", nonce, 24); check_len("tag", tag, 32)
    local pt = #ct == 0 and nil or ffi.new("uint8_t[?]", #ct)
    check("aead_open", lib.wilis_aead_open(u8ptr(key), u8ptr(nonce), u8ptr(aad), #aad, u8ptr(ct), #ct, u8ptr(tag), pt))
    return #ct == 0 and "" or ffi.string(pt, #ct)
  end

  function W.siv_seal(key, aad, pt)
    check_len("key", key, 32)
    local ct = #pt == 0 and nil or ffi.new("uint8_t[?]", #pt)
    local tag = ffi.new("uint8_t[64]")
    check("siv_seal", lib.wilis_siv_seal(u8ptr(key), u8ptr(aad), #aad, u8ptr(pt), #pt, ct, tag))
    return (#pt == 0 and "" or ffi.string(ct, #pt)), ffi.string(tag, 64)
  end

  function W.siv_open(key, aad, ct, siv_tag)
    check_len("key", key, 32); check_len("siv_tag", siv_tag, 64)
    local pt = #ct == 0 and nil or ffi.new("uint8_t[?]", #ct)
    check("siv_open", lib.wilis_siv_open(u8ptr(key), u8ptr(aad), #aad, u8ptr(ct), #ct, u8ptr(siv_tag), pt))
    return #ct == 0 and "" or ffi.string(pt, #ct)
  end

  function W.kdf_derive(pass, salt, blocks, passes)
    check_len("salt", salt, 24)
    local key = ffi.new("uint8_t[32]")
    check("kdf_derive", lib.wilis_kdf_derive(u8ptr(pass), #pass, u8ptr(salt), blocks or 16384, passes or 3, key))
    return ffi.string(key, 32)
  end

  function W.kdf_parallel_derive(pass, salt, blocks, passes, lanes)
    check_len("salt", salt, 24)
    local key = ffi.new("uint8_t[32]")
    check("kdf_parallel_derive", lib.wilis_kdf_parallel_derive(u8ptr(pass), #pass, u8ptr(salt), blocks or 16384, passes or 3, lanes or 4, key))
    return ffi.string(key, 32)
  end

  function W.kem_keygen()
    local pk, sk = ffi.new("uint8_t[1284]"), ffi.new("uint8_t[2600]")
    check("kem_keygen", lib.wilis_kem_keygen(pk, sk))
    return ffi.string(pk, 1284), ffi.string(sk, 2600)
  end

  function W.kem_encapsulate(pk)
    check_len("pk", pk, 1284)
    local ct, ss = ffi.new("uint8_t[1668]"), ffi.new("uint8_t[32]")
    check("kem_encapsulate", lib.wilis_kem_encapsulate(u8ptr(pk), ct, ss))
    return ffi.string(ct, 1668), ffi.string(ss, 32)
  end

  function W.kem_decapsulate(sk, ct)
    check_len("sk", sk, 2600); check_len("ct", ct, 1668)
    local ss = ffi.new("uint8_t[32]")
    check("kem_decapsulate", lib.wilis_kem_decapsulate(u8ptr(sk), u8ptr(ct), ss))
    return ffi.string(ss, 32)
  end

  function W.sign_keygen(height)
    local pk, sk = ffi.new("uint8_t[101]"), ffi.new("uint8_t[137]")
    check("sign_keygen", lib.wilis_sign_keygen(height or 4, pk, sk))
    return ffi.string(pk, 101), ffi.string(sk, 137)
  end

  function W.sign_message(sk, msg)
    check_len("sk", sk, 137)
    local next_sk = ffi.new("uint8_t[137]")
    ffi.copy(next_sk, sk, 137)
    local sig = ffi.new("uint8_t[2506]")
    local sig_len = ffi.new("size_t[1]")
    check("sign_message", lib.wilis_sign_message(next_sk, u8ptr(msg), #msg, sig, 2506, sig_len))
    return ffi.string(sig, tonumber(sig_len[0])), ffi.string(next_sk, 137)
  end

  function W.verify_message(pk, msg, sig)
    check_len("pk", pk, 101)
    local rc = lib.wilis_verify_message(u8ptr(pk), u8ptr(msg), #msg, u8ptr(sig), #sig)
    if rc == 0 then return true elseif rc == M.ERR_AUTH_FAILED then return false end
    check("verify_message", rc)
  end

  function W.slh_keygen()
    local pk, sk = ffi.new("uint8_t[100]"), ffi.new("uint8_t[164]")
    check("slh_keygen", lib.wilis_slh_keygen(pk, sk))
    return ffi.string(pk, 100), ffi.string(sk, 164)
  end

  function W.slh_sign(sk, msg)
    check_len("sk", sk, 164)
    local sig = ffi.new("uint8_t[8165]")
    check("slh_sign", lib.wilis_slh_sign(u8ptr(sk), u8ptr(msg), #msg, sig))
    return ffi.string(sig, 8165)
  end

  function W.slh_verify(pk, msg, sig)
    check_len("pk", pk, 100); check_len("sig", sig, 8165)
    local rc = lib.wilis_slh_verify(u8ptr(pk), u8ptr(msg), #msg, u8ptr(sig))
    if rc == 0 then return true elseif rc == M.ERR_AUTH_FAILED then return false end
    check("slh_verify", rc)
  end

  function W.signcrypt(sender_slh_sk, recipient_kem_pk, aad, pt)
    check_len("sender_slh_sk", sender_slh_sk, 164); check_len("recipient_kem_pk", recipient_kem_pk, 1284)
    return call_var_out("signcrypt", function(o, c, l)
      return lib.wilis_signcrypt(u8ptr(sender_slh_sk), u8ptr(recipient_kem_pk), u8ptr(aad), #aad, u8ptr(pt), #pt, o, c, l)
    end)
  end

  function W.unsigncrypt(sender_slh_pk, recipient_kem_sk, aad, packet)
    check_len("sender_slh_pk", sender_slh_pk, 100); check_len("recipient_kem_sk", recipient_kem_sk, 2600)
    return call_var_out("unsigncrypt", function(o, c, l)
      return lib.wilis_unsigncrypt(u8ptr(sender_slh_pk), u8ptr(recipient_kem_sk), u8ptr(aad), #aad, u8ptr(packet), #packet, o, c, l)
    end)
  end

  function W.totp_at(secret, unix_secs, period, digits)
    period = period or 30; digits = digits or 6
    local code = ffi.new("uint8_t[?]", digits + 1)
    local rem = ffi.new("uint64_t[1]")
    check("totp_at", lib.wilis_totp_at(u8ptr(secret), #secret, unix_secs, period, digits, code, digits + 1, rem))
    return ffi.string(code, digits), tonumber(rem[0])
  end

  function W.fpe_encrypt(key, tweak, alpha, pt)
    check_len("key", key, 32)
    return call_var_out("fpe_encrypt", function(o, c, l)
      return lib.wilis_fpe_encrypt(u8ptr(key), u8ptr(tweak), #tweak, u8ptr(alpha), #alpha, u8ptr(pt), #pt, o, c, l)
    end)
  end

  function W.fpe_decrypt(key, tweak, alpha, ct)
    check_len("key", key, 32)
    return call_var_out("fpe_decrypt", function(o, c, l)
      return lib.wilis_fpe_decrypt(u8ptr(key), u8ptr(tweak), #tweak, u8ptr(alpha), #alpha, u8ptr(ct), #ct, o, c, l)
    end)
  end

  function W.mnemonic_encode(secret)
    return call_var_out("mnemonic_encode", function(o, c, l)
      return lib.wilis_mnemonic_encode(u8ptr(secret), #secret, o, c, l)
    end)
  end

  function W.mnemonic_decode(phrase)
    return call_var_out("mnemonic_decode", function(o, c, l)
      return lib.wilis_mnemonic_decode(u8ptr(phrase), #phrase, o, c, l)
    end)
  end

  function W.lz_compress(data)
    return call_var_out("lz_compress", function(o, c, l)
      return lib.wilis_lz_compress(u8ptr(data), #data, o, c, l)
    end)
  end

  function W.lz_decompress(data, max_out)
    return call_var_out("lz_decompress", function(o, c, l)
      return lib.wilis_lz_decompress(u8ptr(data), #data, max_out or 67108864, o, c, l)
    end)
  end

  return W
end

if arg and arg[0] and arg[0]:match("wilis%.lua$") then
  local w = M.open()
  assert(w.version() == "0.7.0")
  local k, n = w.random_bytes(32), w.random_bytes(24)
  local ct, tag = w.aead_seal(k, n, "aad", "hello luajit")
  assert(w.ct_eq(w.aead_open(k, n, "aad", ct, tag), "hello luajit"))
  assert(w.ct_eq(w.mnemonic_decode(w.mnemonic_encode(k)), k))
  print("Wilis LuaJIT FFI OK (v" .. w.version() .. ", 33 C-ABI exports)")
end

return M
