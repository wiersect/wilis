# frozen_string_literal: true

# Wilis v0.7.0 — Zero-Dependency Ruby Bindings via stdlib Fiddle (All 33 C-ABI exports)
#
# Run self-test after `cargo build --release`:
#   ruby bindings/ruby/wilis.rb

require "fiddle"
require "rbconfig"

module Wilis
  KEY_BYTES = 32
  NONCE_BYTES = 24
  SALT_BYTES = 24
  TAG_BYTES = 32
  SIV_TAG_BYTES = 64
  HASH_BYTES = 32

  KEM_PK_BYTES = 1284
  KEM_SK_BYTES = 2600
  KEM_CT_BYTES = 1668
  KEM_SS_BYTES = 32

  SIGN_PK_BYTES = 101
  SIGN_SK_BYTES = 137
  SIGN_MAX_SIG_BYTES = 2506

  SLH_PK_BYTES = 100
  SLH_SK_BYTES = 164
  SLH_SIG_BYTES = 8165
  SIGNCRYPT_OVERHEAD = 9894

  OK = 0
  ERR_INVALID_ARG = -1
  ERR_AUTH_FAILED = -2
  ERR_INTERNAL = -3
  ERR_BUF_TOO_SMALL = -4

  class Error < StandardError
    attr_reader :code

    def initialize(op, code)
      @code = code
      super("Wilis #{op} failed with code #{code}")
    end
  end

  class AuthError < Error
    def initialize(op)
      super(op, ERR_AUTH_FAILED)
    end
  end

  class Client
    PTR = Fiddle::TYPE_VOIDP
    I32 = Fiddle::TYPE_INT
    U32 = defined?(Fiddle::TYPE_UINT32_T) ? Fiddle::TYPE_UINT32_T : -Fiddle::TYPE_INT
    U64 = defined?(Fiddle::TYPE_UINT64_T) ? Fiddle::TYPE_UINT64_T : -Fiddle::TYPE_LONG_LONG
    U8  = defined?(Fiddle::TYPE_UINT8_T) ? Fiddle::TYPE_UINT8_T : -Fiddle::TYPE_CHAR
    SZ  = Fiddle::TYPE_SIZE_T
    SIZE_PACK = Fiddle::SIZEOF_SIZE_T == 8 ? "Q" : "L"

    def initialize(lib_path = nil)
      path = lib_path || self.class.find_lib
      @handle = Fiddle.dlopen(path)
      @fns = {
        version: fn("wilis_version", [], PTR),
        ct_eq: fn("wilis_ct_eq", [PTR, PTR, SZ], I32),
        zeroize: fn("wilis_zeroize", [PTR, SZ], I32),
        random_bytes: fn("wilis_random_bytes", [PTR, SZ], I32),
        hash_256: fn("wilis_hash_256", [PTR, SZ, PTR], I32),
        tree_hash_256: fn("wilis_tree_hash_256", [PTR, SZ, PTR], I32),
        mac_256: fn("wilis_mac_256", [PTR, PTR, SZ, PTR], I32),
        subkey_derive: fn("wilis_subkey_derive", [PTR, PTR, SZ, PTR], I32),
        xof_derive: fn("wilis_xof_derive", [PTR, SZ, PTR, SZ, PTR, SZ], I32),
        aead_seal: fn("wilis_aead_seal", [PTR, PTR, PTR, SZ, PTR, SZ, PTR, PTR], I32),
        aead_open: fn("wilis_aead_open", [PTR, PTR, PTR, SZ, PTR, SZ, PTR, PTR], I32),
        siv_seal: fn("wilis_siv_seal", [PTR, PTR, SZ, PTR, SZ, PTR, PTR], I32),
        siv_open: fn("wilis_siv_open", [PTR, PTR, SZ, PTR, SZ, PTR, PTR], I32),
        kdf_derive: fn("wilis_kdf_derive", [PTR, SZ, PTR, U32, U32, PTR], I32),
        kdf_parallel_derive: fn("wilis_kdf_parallel_derive", [PTR, SZ, PTR, U32, U32, U32, PTR], I32),
        kem_keygen: fn("wilis_kem_keygen", [PTR, PTR], I32),
        kem_encapsulate: fn("wilis_kem_encapsulate", [PTR, PTR, PTR], I32),
        kem_decapsulate: fn("wilis_kem_decapsulate", [PTR, PTR, PTR], I32),
        sign_keygen: fn("wilis_sign_keygen", [U8, PTR, PTR], I32),
        sign_message: fn("wilis_sign_message", [PTR, PTR, SZ, PTR, SZ, PTR], I32),
        verify_message: fn("wilis_verify_message", [PTR, PTR, SZ, PTR, SZ], I32),
        slh_keygen: fn("wilis_slh_keygen", [PTR, PTR], I32),
        slh_sign: fn("wilis_slh_sign", [PTR, PTR, SZ, PTR], I32),
        slh_verify: fn("wilis_slh_verify", [PTR, PTR, SZ, PTR], I32),
        signcrypt: fn("wilis_signcrypt", [PTR, PTR, PTR, SZ, PTR, SZ, PTR, SZ, PTR], I32),
        unsigncrypt: fn("wilis_unsigncrypt", [PTR, PTR, PTR, SZ, PTR, SZ, PTR, SZ, PTR], I32),
        totp_at: fn("wilis_totp_at", [PTR, SZ, U64, U64, U32, PTR, SZ, PTR], I32),
        fpe_encrypt: fn("wilis_fpe_encrypt", [PTR, PTR, SZ, PTR, SZ, PTR, SZ, PTR, SZ, PTR], I32),
        fpe_decrypt: fn("wilis_fpe_decrypt", [PTR, PTR, SZ, PTR, SZ, PTR, SZ, PTR, SZ, PTR], I32),
        mnemonic_encode: fn("wilis_mnemonic_encode", [PTR, SZ, PTR, SZ, PTR], I32),
        mnemonic_decode: fn("wilis_mnemonic_decode", [PTR, SZ, PTR, SZ, PTR], I32),
        lz_compress: fn("wilis_lz_compress", [PTR, SZ, PTR, SZ, PTR], I32),
        lz_decompress: fn("wilis_lz_decompress", [PTR, SZ, SZ, PTR, SZ, PTR], I32),
      }
    end

    def self.find_lib
      return ENV["WILIS_LIB"] if ENV["WILIS_LIB"] && !ENV["WILIS_LIB"].empty?

      host = RbConfig::CONFIG["host_os"]
      lib_name = if host =~ /darwin/i
                   "libwilis.dylib"
                 elsif host =~ /mswin|mingw|cygwin/i
                   "wilis.dll"
                 else
                   "libwilis.so"
                 end
      root = File.expand_path("../..", __dir__)
      [
        File.join(root, "target", "release", lib_name),
        File.join(root, "target", "debug", lib_name),
        File.join(Dir.pwd, "target", "release", lib_name),
      ].each { |p| return p if File.file?(p) }
      lib_name
    end

    def version
      Fiddle::Pointer.new(@fns[:version].call).to_s
    end

    def ct_eq(a, b)
      a = a.b
      b = b.b
      return false if a.bytesize != b.bytesize

      rc = @fns[:ct_eq].call(in_ptr(a), in_ptr(b), a.bytesize)
      check("ct_eq", rc) if rc < 0
      rc == 1
    end

    def zeroize(buf)
      raise ArgumentError, "zeroize requires a mutable String" if buf.frozen?
      return if buf.bytesize.zero?

      check("zeroize", @fns[:zeroize].call(Fiddle::Pointer.to_ptr(buf), buf.bytesize))
    end

    def random_bytes(len)
      return "".b if len.zero?

      out = alloc(len)
      check("random_bytes", @fns[:random_bytes].call(out, len))
      out.to_str(len)
    end

    def hash_256(data)
      data = data.b
      out = alloc(HASH_BYTES)
      check("hash_256", @fns[:hash_256].call(in_ptr(data), data.bytesize, out))
      out.to_str(HASH_BYTES)
    end

    def tree_hash_256(data)
      data = data.b
      out = alloc(HASH_BYTES)
      check("tree_hash_256", @fns[:tree_hash_256].call(in_ptr(data), data.bytesize, out))
      out.to_str(HASH_BYTES)
    end

    def mac_256(key, msg)
      key = check_len("key", key, KEY_BYTES)
      msg = msg.b
      tag = alloc(TAG_BYTES)
      check("mac_256", @fns[:mac_256].call(in_ptr(key), in_ptr(msg), msg.bytesize, tag))
      tag.to_str(TAG_BYTES)
    end

    def subkey_derive(master_key, context)
      master_key = check_len("master_key", master_key, KEY_BYTES)
      context = context.b
      out = alloc(KEY_BYTES)
      check("subkey_derive", @fns[:subkey_derive].call(in_ptr(master_key), in_ptr(context), context.bytesize, out))
      out.to_str(KEY_BYTES)
    end

    def xof_derive(label, seed, out_len)
      label = label.b
      seed = seed.b
      out = out_len.zero? ? Fiddle::NULL : alloc(out_len)
      check("xof_derive", @fns[:xof_derive].call(in_ptr(label), label.bytesize, in_ptr(seed), seed.bytesize, out, out_len))
      out_len.zero? ? "".b : out.to_str(out_len)
    end

    def aead_seal(key, nonce, aad, pt)
      key = check_len("key", key, KEY_BYTES)
      nonce = check_len("nonce", nonce, NONCE_BYTES)
      aad = aad.b
      pt = pt.b
      ct = pt.empty? ? Fiddle::NULL : alloc(pt.bytesize)
      tag = alloc(TAG_BYTES)
      check("aead_seal", @fns[:aead_seal].call(in_ptr(key), in_ptr(nonce), in_ptr(aad), aad.bytesize, in_ptr(pt), pt.bytesize, ct, tag))
      [pt.empty? ? "".b : ct.to_str(pt.bytesize), tag.to_str(TAG_BYTES)]
    end

    def aead_open(key, nonce, aad, ct, tag)
      key = check_len("key", key, KEY_BYTES)
      nonce = check_len("nonce", nonce, NONCE_BYTES)
      tag = check_len("tag", tag, TAG_BYTES)
      aad = aad.b
      ct = ct.b
      pt = ct.empty? ? Fiddle::NULL : alloc(ct.bytesize)
      check("aead_open", @fns[:aead_open].call(in_ptr(key), in_ptr(nonce), in_ptr(aad), aad.bytesize, in_ptr(ct), ct.bytesize, in_ptr(tag), pt))
      ct.empty? ? "".b : pt.to_str(ct.bytesize)
    end

    def siv_seal(key, aad, pt)
      key = check_len("key", key, KEY_BYTES)
      aad = aad.b
      pt = pt.b
      ct = pt.empty? ? Fiddle::NULL : alloc(pt.bytesize)
      tag = alloc(SIV_TAG_BYTES)
      check("siv_seal", @fns[:siv_seal].call(in_ptr(key), in_ptr(aad), aad.bytesize, in_ptr(pt), pt.bytesize, ct, tag))
      [pt.empty? ? "".b : ct.to_str(pt.bytesize), tag.to_str(SIV_TAG_BYTES)]
    end

    def siv_open(key, aad, ct, siv_tag)
      key = check_len("key", key, KEY_BYTES)
      siv_tag = check_len("siv_tag", siv_tag, SIV_TAG_BYTES)
      aad = aad.b
      ct = ct.b
      pt = ct.empty? ? Fiddle::NULL : alloc(ct.bytesize)
      check("siv_open", @fns[:siv_open].call(in_ptr(key), in_ptr(aad), aad.bytesize, in_ptr(ct), ct.bytesize, in_ptr(siv_tag), pt))
      ct.empty? ? "".b : pt.to_str(ct.bytesize)
    end

    def kdf_derive(password, salt, memory_blocks: 16_384, passes: 3)
      password = password.b
      salt = check_len("salt", salt, SALT_BYTES)
      key = alloc(KEY_BYTES)
      check("kdf_derive", @fns[:kdf_derive].call(in_ptr(password), password.bytesize, in_ptr(salt), memory_blocks, passes, key))
      key.to_str(KEY_BYTES)
    end

    def kdf_parallel_derive(password, salt, memory_blocks: 16_384, passes: 3, lanes: 4)
      password = password.b
      salt = check_len("salt", salt, SALT_BYTES)
      key = alloc(KEY_BYTES)
      check("kdf_parallel_derive", @fns[:kdf_parallel_derive].call(in_ptr(password), password.bytesize, in_ptr(salt), memory_blocks, passes, lanes, key))
      key.to_str(KEY_BYTES)
    end

    def kem_keygen
      pk = alloc(KEM_PK_BYTES)
      sk = alloc(KEM_SK_BYTES)
      check("kem_keygen", @fns[:kem_keygen].call(pk, sk))
      [pk.to_str(KEM_PK_BYTES), sk.to_str(KEM_SK_BYTES)]
    end

    def kem_encapsulate(pk)
      pk = check_len("pk", pk, KEM_PK_BYTES)
      ct = alloc(KEM_CT_BYTES)
      ss = alloc(KEM_SS_BYTES)
      check("kem_encapsulate", @fns[:kem_encapsulate].call(in_ptr(pk), ct, ss))
      [ct.to_str(KEM_CT_BYTES), ss.to_str(KEM_SS_BYTES)]
    end

    def kem_decapsulate(sk, ct)
      sk = check_len("sk", sk, KEM_SK_BYTES)
      ct = check_len("ct", ct, KEM_CT_BYTES)
      ss = alloc(KEM_SS_BYTES)
      check("kem_decapsulate", @fns[:kem_decapsulate].call(in_ptr(sk), in_ptr(ct), ss))
      ss.to_str(KEM_SS_BYTES)
    end

    def sign_keygen(height = 4)
      pk = alloc(SIGN_PK_BYTES)
      sk = alloc(SIGN_SK_BYTES)
      check("sign_keygen", @fns[:sign_keygen].call(height, pk, sk))
      [pk.to_str(SIGN_PK_BYTES), sk.to_str(SIGN_SK_BYTES)]
    end

    def sign_message(sk, msg)
      sk = check_len("sk", sk, SIGN_SK_BYTES)
      msg = msg.b
      sk_buf = alloc(SIGN_SK_BYTES)
      sk_buf[0, SIGN_SK_BYTES] = sk
      sig = alloc(SIGN_MAX_SIG_BYTES)
      len_buf = alloc(Fiddle::SIZEOF_SIZE_T)
      check("sign_message", @fns[:sign_message].call(sk_buf, in_ptr(msg), msg.bytesize, sig, SIGN_MAX_SIG_BYTES, len_buf))
      sig_len = len_buf.to_str(Fiddle::SIZEOF_SIZE_T).unpack1(SIZE_PACK)
      [sig.to_str(sig_len), sk_buf.to_str(SIGN_SK_BYTES)]
    end

    def verify_message(pk, msg, sig)
      pk = check_len("pk", pk, SIGN_PK_BYTES)
      msg = msg.b
      sig = sig.b
      rc = @fns[:verify_message].call(in_ptr(pk), in_ptr(msg), msg.bytesize, in_ptr(sig), sig.bytesize)
      return true if rc == OK
      return false if rc == ERR_AUTH_FAILED

      check("verify_message", rc)
      false
    end

    def slh_keygen
      pk = alloc(SLH_PK_BYTES)
      sk = alloc(SLH_SK_BYTES)
      check("slh_keygen", @fns[:slh_keygen].call(pk, sk))
      [pk.to_str(SLH_PK_BYTES), sk.to_str(SLH_SK_BYTES)]
    end

    def slh_sign(sk, msg)
      sk = check_len("sk", sk, SLH_SK_BYTES)
      msg = msg.b
      sig = alloc(SLH_SIG_BYTES)
      check("slh_sign", @fns[:slh_sign].call(in_ptr(sk), in_ptr(msg), msg.bytesize, sig))
      sig.to_str(SLH_SIG_BYTES)
    end

    def slh_verify(pk, msg, sig)
      pk = check_len("pk", pk, SLH_PK_BYTES)
      sig = check_len("sig", sig, SLH_SIG_BYTES)
      msg = msg.b
      rc = @fns[:slh_verify].call(in_ptr(pk), in_ptr(msg), msg.bytesize, in_ptr(sig))
      return true if rc == OK
      return false if rc == ERR_AUTH_FAILED

      check("slh_verify", rc)
      false
    end

    def signcrypt(sender_slh_sk, recipient_kem_pk, aad, pt)
      sk = check_len("sender_slh_sk", sender_slh_sk, SLH_SK_BYTES)
      pk = check_len("recipient_kem_pk", recipient_kem_pk, KEM_PK_BYTES)
      aad = aad.b
      pt = pt.b
      call_var_out("signcrypt") do |out, cap, len_buf|
        @fns[:signcrypt].call(in_ptr(sk), in_ptr(pk), in_ptr(aad), aad.bytesize, in_ptr(pt), pt.bytesize, out, cap, len_buf)
      end
    end

    def unsigncrypt(sender_slh_pk, recipient_kem_sk, aad, packet)
      pk = check_len("sender_slh_pk", sender_slh_pk, SLH_PK_BYTES)
      sk = check_len("recipient_kem_sk", recipient_kem_sk, KEM_SK_BYTES)
      aad = aad.b
      packet = packet.b
      call_var_out("unsigncrypt") do |out, cap, len_buf|
        @fns[:unsigncrypt].call(in_ptr(pk), in_ptr(sk), in_ptr(aad), aad.bytesize, in_ptr(packet), packet.bytesize, out, cap, len_buf)
      end
    end

    def totp_at(secret, unix_secs, period: 30, digits: 6)
      secret = secret.b
      code = alloc(digits + 1)
      rem = alloc(8)
      check("totp_at", @fns[:totp_at].call(in_ptr(secret), secret.bytesize, unix_secs, period, digits, code, digits + 1, rem))
      [code.to_str(digits).force_encoding(Encoding::US_ASCII), rem.to_str(8).unpack1("Q")]
    end

    def fpe_encrypt(key, tweak, alphabet, plaintext)
      key = check_len("key", key, KEY_BYTES)
      tweak = tweak.b
      alpha = alphabet.encode(Encoding::UTF_8).b
      pt = plaintext.encode(Encoding::UTF_8).b
      out = call_var_out("fpe_encrypt") do |o, cap, len_buf|
        @fns[:fpe_encrypt].call(in_ptr(key), in_ptr(tweak), tweak.bytesize, in_ptr(alpha), alpha.bytesize, in_ptr(pt), pt.bytesize, o, cap, len_buf)
      end
      out.force_encoding(Encoding::UTF_8)
    end

    def fpe_decrypt(key, tweak, alphabet, ciphertext)
      key = check_len("key", key, KEY_BYTES)
      tweak = tweak.b
      alpha = alphabet.encode(Encoding::UTF_8).b
      ct = ciphertext.encode(Encoding::UTF_8).b
      out = call_var_out("fpe_decrypt") do |o, cap, len_buf|
        @fns[:fpe_decrypt].call(in_ptr(key), in_ptr(tweak), tweak.bytesize, in_ptr(alpha), alpha.bytesize, in_ptr(ct), ct.bytesize, o, cap, len_buf)
      end
      out.force_encoding(Encoding::UTF_8)
    end

    def mnemonic_encode(secret)
      secret = secret.b
      out = call_var_out("mnemonic_encode") do |o, cap, len_buf|
        @fns[:mnemonic_encode].call(in_ptr(secret), secret.bytesize, o, cap, len_buf)
      end
      out.force_encoding(Encoding::UTF_8)
    end

    def mnemonic_decode(phrase)
      utf8 = phrase.encode(Encoding::UTF_8).b
      call_var_out("mnemonic_decode") do |o, cap, len_buf|
        @fns[:mnemonic_decode].call(in_ptr(utf8), utf8.bytesize, o, cap, len_buf)
      end
    end

    def lz_compress(data)
      data = data.b
      call_var_out("lz_compress") do |o, cap, len_buf|
        @fns[:lz_compress].call(in_ptr(data), data.bytesize, o, cap, len_buf)
      end
    end

    def lz_decompress(compressed, max_out: 64 * 1024 * 1024)
      compressed = compressed.b
      call_var_out("lz_decompress") do |o, cap, len_buf|
        @fns[:lz_decompress].call(in_ptr(compressed), compressed.bytesize, max_out, o, cap, len_buf)
      end
    end

    private

    def fn(name, args, ret)
      Fiddle::Function.new(@handle[name], args, ret)
    end

    def alloc(size)
      Fiddle::Pointer.malloc(size, Fiddle::RUBY_FREE)
    end

    def in_ptr(str)
      str.empty? ? Fiddle::NULL : Fiddle::Pointer.to_ptr(str)
    end

    def check(op, rc)
      return if rc == OK
      raise AuthError, op if rc == ERR_AUTH_FAILED

      raise Error.new(op, rc)
    end

    def check_len(name, data, expected)
      b = data.b
      raise ArgumentError, "#{name} must be exactly #{expected} bytes" unless b.bytesize == expected

      b
    end

    def call_var_out(op)
      len_buf = alloc(Fiddle::SIZEOF_SIZE_T)
      rc = yield(Fiddle::NULL, 0, len_buf)
      needed = len_buf.to_str(Fiddle::SIZEOF_SIZE_T).unpack1(SIZE_PACK)
      return "".b if rc == OK && needed.zero?

      check(op, rc) unless rc == ERR_BUF_TOO_SMALL
      out = alloc(needed)
      rc = yield(out, needed, len_buf)
      check(op, rc)
      actual = len_buf.to_str(Fiddle::SIZEOF_SIZE_T).unpack1(SIZE_PACK)
      out.to_str(actual)
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  w = Wilis::Client.new
  ver = w.version
  raise "unexpected version: #{ver}" unless ver == "0.7.0"

  key = w.random_bytes(Wilis::KEY_BYTES)
  nonce = w.random_bytes(Wilis::NONCE_BYTES)
  salt = w.random_bytes(Wilis::SALT_BYTES)
  raise "hash len" unless w.hash_256("abc").bytesize == 32
  raise "tree hash len" unless w.tree_hash_256("abc").bytesize == 32
  raise "mac len" unless w.mac_256(key, "msg").bytesize == 32
  raise "subkey len" unless w.subkey_derive(key, "ctx").bytesize == 32
  raise "xof len" unless w.xof_derive("lbl", "seed", 48).bytesize == 48

  ct, tag = w.aead_seal(key, nonce, "aad", "hello ruby fiddle")
  raise "aead" unless w.ct_eq(w.aead_open(key, nonce, "aad", ct, tag), "hello ruby fiddle")

  sct, stag = w.siv_seal(key, "aad", "hello siv")
  raise "siv" unless w.ct_eq(w.siv_open(key, "aad", sct, stag), "hello siv")

  raise "kdf" unless w.kdf_derive("pw", salt, memory_blocks: 64, passes: 2).bytesize == 32
  raise "kdfp" unless w.kdf_parallel_derive("pw", salt, memory_blocks: 128, passes: 2, lanes: 2).bytesize == 32

  pk, sk = w.kem_keygen
  kct, ss1 = w.kem_encapsulate(pk)
  raise "kem" unless w.ct_eq(ss1, w.kem_decapsulate(sk, kct))

  spk, ssk = w.sign_keygen(3)
  sig, _ssk2 = w.sign_message(ssk, "ruby sign")
  raise "sign" unless w.verify_message(spk, "ruby sign", sig)

  slh_pk, slh_sk = w.slh_keygen
  slh_sig = w.slh_sign(slh_sk, "ruby slh")
  raise "slh" unless w.slh_verify(slh_pk, "ruby slh", slh_sig)

  pkt = w.signcrypt(slh_sk, pk, "ctx", "ruby signcrypt")
  raise "signcrypt" unless w.ct_eq(w.unsigncrypt(slh_pk, sk, "ctx", pkt), "ruby signcrypt")

  code, rem = w.totp_at(key, 1_700_000_000)
  raise "totp" unless code.length == 6 && rem > 0

  fpe_ct = w.fpe_encrypt(key, "tw", "0123456789", "4111111111111111")
  raise "fpe" unless w.fpe_decrypt(key, "tw", "0123456789", fpe_ct) == "4111111111111111"

  phrase = w.mnemonic_encode(key)
  raise "mnemonic" unless w.ct_eq(w.mnemonic_decode(phrase), key)

  raw = "WilisRubyFiddle!" * 20
  raise "lz" unless w.ct_eq(w.lz_decompress(w.lz_compress(raw)), raw)

  wiped = +"secret-bytes-1234"
  w.zeroize(wiped)
  raise "zeroize" unless wiped == ("\x00".b * wiped.bytesize)

  puts "Wilis Ruby Fiddle OK (v#{ver}, ALL 33/33 C-ABI functions)"
end
