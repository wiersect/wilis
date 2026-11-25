<?php
declare(strict_types=1);

/**
 * Wilis v0.7.0 — Zero-Dependency PHP 8+ FFI Bindings (All 33 C-ABI exports)
 *
 * Run self-test after `cargo build --release`:
 *   php -d ffi.enable=true bindings/php/Wilis.php
 */

namespace WilisCrypto;

use FFI;
use InvalidArgumentException;
use RuntimeException;

class WilisException extends RuntimeException
{
    public function __construct(string $op, public readonly int $wilisCode)
    {
        parent::__construct("Wilis {$op} failed with code {$wilisCode}", $wilisCode);
    }
}

final class WilisAuthException extends WilisException
{
    public function __construct(string $op)
    {
        parent::__construct($op, Wilis::ERR_AUTH_FAILED);
    }
}

final class Wilis
{
    public const KEY_BYTES = 32;
    public const NONCE_BYTES = 24;
    public const SALT_BYTES = 24;
    public const TAG_BYTES = 32;
    public const SIV_TAG_BYTES = 64;
    public const HASH_BYTES = 32;

    public const KEM_PK_BYTES = 1284;
    public const KEM_SK_BYTES = 2600;
    public const KEM_CT_BYTES = 1668;
    public const KEM_SS_BYTES = 32;

    public const SIGN_PK_BYTES = 101;
    public const SIGN_SK_BYTES = 137;
    public const SIGN_MAX_SIG_BYTES = 2506;

    public const SLH_PK_BYTES = 100;
    public const SLH_SK_BYTES = 164;
    public const SLH_SIG_BYTES = 8165;
    public const SIGNCRYPT_OVERHEAD = 9894;

    public const OK = 0;
    public const ERR_INVALID_ARG = -1;
    public const ERR_AUTH_FAILED = -2;
    public const ERR_INTERNAL = -3;
    public const ERR_BUF_TOO_SMALL = -4;

    private const CDEF = <<<'CDEF'
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
CDEF;

    private FFI $ffi;

    public function __construct(?string $libPath = null)
    {
        $this->ffi = FFI::cdef(self::CDEF, $libPath ?? self::findLib());
    }

    public static function findLib(): string
    {
        $env = getenv('WILIS_LIB');
        if (is_string($env) && $env !== '') {
            return $env;
        }
        $libName = match (PHP_OS_FAMILY) {
            'Darwin' => 'libwilis.dylib',
            'Windows' => 'wilis.dll',
            default => 'libwilis.so',
        };
        $root = dirname(__DIR__, 2);
        foreach ([
            "{$root}/target/release/{$libName}",
            "{$root}/target/debug/{$libName}",
            getcwd() . "/target/release/{$libName}",
        ] as $candidate) {
            if (is_file($candidate)) {
                return $candidate;
            }
        }
        return $libName;
    }

    private function check(string $op, int $rc): void
    {
        if ($rc === self::OK) {
            return;
        }
        if ($rc === self::ERR_AUTH_FAILED) {
            throw new WilisAuthException($op);
        }
        throw new WilisException($op, $rc);
    }

    private function checkLen(string $name, string $s, int $expected): void
    {
        if (strlen($s) !== $expected) {
            throw new InvalidArgumentException("{$name} must be exactly {$expected} bytes");
        }
    }

    private function inBuf(string $s): ?FFI\CData
    {
        $n = strlen($s);
        if ($n === 0) {
            return null;
        }
        $buf = $this->ffi->new("uint8_t[{$n}]");
        FFI::memcpy($buf, $s, $n);
        return $buf;
    }

    private function outBuf(int $n): ?FFI\CData
    {
        return $n === 0 ? null : $this->ffi->new("uint8_t[{$n}]");
    }

    private function callVarOut(string $op, callable $fn): string
    {
        $len = $this->ffi->new('size_t');
        $rc = $fn(null, 0, FFI::addr($len));
        $needed = (int) $len->cdata;
        if ($rc === self::OK && $needed === 0) {
            return '';
        }
        if ($rc !== self::ERR_BUF_TOO_SMALL) {
            $this->check($op, $rc);
        }
        $out = $this->outBuf($needed);
        $rc = $fn($out, $needed, FFI::addr($len));
        $this->check($op, $rc);
        return FFI::string($out, (int) $len->cdata);
    }

    public function version(): string
    {
        $v = $this->ffi->wilis_version();
        return is_string($v) ? $v : FFI::string($v);
    }

    public function ctEq(string $a, string $b): bool
    {
        if (strlen($a) !== strlen($b)) {
            return false;
        }
        $rc = $this->ffi->wilis_ct_eq($this->inBuf($a), $this->inBuf($b), strlen($a));
        if ($rc < 0) {
            $this->check('ct_eq', $rc);
        }
        return $rc === 1;
    }

    public function zeroizeBuffer(FFI\CData $buf, int $len): void
    {
        $this->check('zeroize', $this->ffi->wilis_zeroize($buf, $len));
    }

    public function randomBytes(int $len): string
    {
        if ($len === 0) {
            return '';
        }
        $out = $this->outBuf($len);
        $this->check('random_bytes', $this->ffi->wilis_random_bytes($out, $len));
        return FFI::string($out, $len);
    }

    public function hash256(string $data): string
    {
        $out = $this->outBuf(self::HASH_BYTES);
        $this->check('hash_256', $this->ffi->wilis_hash_256($this->inBuf($data), strlen($data), $out));
        return FFI::string($out, self::HASH_BYTES);
    }

    public function treeHash256(string $data): string
    {
        $out = $this->outBuf(self::HASH_BYTES);
        $this->check('tree_hash_256', $this->ffi->wilis_tree_hash_256($this->inBuf($data), strlen($data), $out));
        return FFI::string($out, self::HASH_BYTES);
    }

    public function mac256(string $key, string $msg): string
    {
        $this->checkLen('key', $key, self::KEY_BYTES);
        $tag = $this->outBuf(self::TAG_BYTES);
        $this->check('mac_256', $this->ffi->wilis_mac_256($this->inBuf($key), $this->inBuf($msg), strlen($msg), $tag));
        return FFI::string($tag, self::TAG_BYTES);
    }

    public function subkeyDerive(string $masterKey, string $context): string
    {
        $this->checkLen('masterKey', $masterKey, self::KEY_BYTES);
        $out = $this->outBuf(self::KEY_BYTES);
        $this->check('subkey_derive', $this->ffi->wilis_subkey_derive($this->inBuf($masterKey), $this->inBuf($context), strlen($context), $out));
        return FFI::string($out, self::KEY_BYTES);
    }

    public function xofDerive(string $label, string $seed, int $outLen): string
    {
        $out = $this->outBuf($outLen);
        $this->check('xof_derive', $this->ffi->wilis_xof_derive($this->inBuf($label), strlen($label), $this->inBuf($seed), strlen($seed), $out, $outLen));
        return $outLen === 0 ? '' : FFI::string($out, $outLen);
    }

    /** @return array{0: string, 1: string} */
    public function aeadSeal(string $key, string $nonce, string $aad, string $pt): array
    {
        $this->checkLen('key', $key, self::KEY_BYTES);
        $this->checkLen('nonce', $nonce, self::NONCE_BYTES);
        $ct = $this->outBuf(strlen($pt));
        $tag = $this->outBuf(self::TAG_BYTES);
        $this->check('aead_seal', $this->ffi->wilis_aead_seal($this->inBuf($key), $this->inBuf($nonce), $this->inBuf($aad), strlen($aad), $this->inBuf($pt), strlen($pt), $ct, $tag));
        return [$pt === '' ? '' : FFI::string($ct, strlen($pt)), FFI::string($tag, self::TAG_BYTES)];
    }

    public function aeadOpen(string $key, string $nonce, string $aad, string $ct, string $tag): string
    {
        $this->checkLen('key', $key, self::KEY_BYTES);
        $this->checkLen('nonce', $nonce, self::NONCE_BYTES);
        $this->checkLen('tag', $tag, self::TAG_BYTES);
        $pt = $this->outBuf(strlen($ct));
        $this->check('aead_open', $this->ffi->wilis_aead_open($this->inBuf($key), $this->inBuf($nonce), $this->inBuf($aad), strlen($aad), $this->inBuf($ct), strlen($ct), $this->inBuf($tag), $pt));
        return $ct === '' ? '' : FFI::string($pt, strlen($ct));
    }

    /** @return array{0: string, 1: string} */
    public function sivSeal(string $key, string $aad, string $pt): array
    {
        $this->checkLen('key', $key, self::KEY_BYTES);
        $ct = $this->outBuf(strlen($pt));
        $tag = $this->outBuf(self::SIV_TAG_BYTES);
        $this->check('siv_seal', $this->ffi->wilis_siv_seal($this->inBuf($key), $this->inBuf($aad), strlen($aad), $this->inBuf($pt), strlen($pt), $ct, $tag));
        return [$pt === '' ? '' : FFI::string($ct, strlen($pt)), FFI::string($tag, self::SIV_TAG_BYTES)];
    }

    public function sivOpen(string $key, string $aad, string $ct, string $sivTag): string
    {
        $this->checkLen('key', $key, self::KEY_BYTES);
        $this->checkLen('sivTag', $sivTag, self::SIV_TAG_BYTES);
        $pt = $this->outBuf(strlen($ct));
        $this->check('siv_open', $this->ffi->wilis_siv_open($this->inBuf($key), $this->inBuf($aad), strlen($aad), $this->inBuf($ct), strlen($ct), $this->inBuf($sivTag), $pt));
        return $ct === '' ? '' : FFI::string($pt, strlen($ct));
    }

    public function kdfDerive(string $password, string $salt, int $memoryBlocks = 16384, int $passes = 3): string
    {
        $this->checkLen('salt', $salt, self::SALT_BYTES);
        $key = $this->outBuf(self::KEY_BYTES);
        $this->check('kdf_derive', $this->ffi->wilis_kdf_derive($this->inBuf($password), strlen($password), $this->inBuf($salt), $memoryBlocks, $passes, $key));
        return FFI::string($key, self::KEY_BYTES);
    }

    public function kdfParallelDerive(string $password, string $salt, int $memoryBlocks = 16384, int $passes = 3, int $lanes = 4): string
    {
        $this->checkLen('salt', $salt, self::SALT_BYTES);
        $key = $this->outBuf(self::KEY_BYTES);
        $this->check('kdf_parallel_derive', $this->ffi->wilis_kdf_parallel_derive($this->inBuf($password), strlen($password), $this->inBuf($salt), $memoryBlocks, $passes, $lanes, $key));
        return FFI::string($key, self::KEY_BYTES);
    }

    /** @return array{0: string, 1: string} */
    public function kemKeygen(): array
    {
        $pk = $this->outBuf(self::KEM_PK_BYTES);
        $sk = $this->outBuf(self::KEM_SK_BYTES);
        $this->check('kem_keygen', $this->ffi->wilis_kem_keygen($pk, $sk));
        return [FFI::string($pk, self::KEM_PK_BYTES), FFI::string($sk, self::KEM_SK_BYTES)];
    }

    /** @return array{0: string, 1: string} */
    public function kemEncapsulate(string $pk): array
    {
        $this->checkLen('pk', $pk, self::KEM_PK_BYTES);
        $ct = $this->outBuf(self::KEM_CT_BYTES);
        $ss = $this->outBuf(self::KEM_SS_BYTES);
        $this->check('kem_encapsulate', $this->ffi->wilis_kem_encapsulate($this->inBuf($pk), $ct, $ss));
        return [FFI::string($ct, self::KEM_CT_BYTES), FFI::string($ss, self::KEM_SS_BYTES)];
    }

    public function kemDecapsulate(string $sk, string $ct): string
    {
        $this->checkLen('sk', $sk, self::KEM_SK_BYTES);
        $this->checkLen('ct', $ct, self::KEM_CT_BYTES);
        $ss = $this->outBuf(self::KEM_SS_BYTES);
        $this->check('kem_decapsulate', $this->ffi->wilis_kem_decapsulate($this->inBuf($sk), $this->inBuf($ct), $ss));
        return FFI::string($ss, self::KEM_SS_BYTES);
    }

    /** @return array{0: string, 1: string} */
    public function signKeygen(int $height = 4): array
    {
        $pk = $this->outBuf(self::SIGN_PK_BYTES);
        $sk = $this->outBuf(self::SIGN_SK_BYTES);
        $this->check('sign_keygen', $this->ffi->wilis_sign_keygen($height, $pk, $sk));
        return [FFI::string($pk, self::SIGN_PK_BYTES), FFI::string($sk, self::SIGN_SK_BYTES)];
    }

    /** @return array{0: string, 1: string} */
    public function signMessage(string $sk, string $msg): array
    {
        $this->checkLen('sk', $sk, self::SIGN_SK_BYTES);
        $skBuf = $this->inBuf($sk);
        $sig = $this->outBuf(self::SIGN_MAX_SIG_BYTES);
        $len = $this->ffi->new('size_t');
        $this->check('sign_message', $this->ffi->wilis_sign_message($skBuf, $this->inBuf($msg), strlen($msg), $sig, self::SIGN_MAX_SIG_BYTES, FFI::addr($len)));
        return [FFI::string($sig, (int) $len->cdata), FFI::string($skBuf, self::SIGN_SK_BYTES)];
    }

    public function verifyMessage(string $pk, string $msg, string $sig): bool
    {
        $this->checkLen('pk', $pk, self::SIGN_PK_BYTES);
        $rc = $this->ffi->wilis_verify_message($this->inBuf($pk), $this->inBuf($msg), strlen($msg), $this->inBuf($sig), strlen($sig));
        if ($rc === self::OK) {
            return true;
        }
        if ($rc === self::ERR_AUTH_FAILED) {
            return false;
        }
        $this->check('verify_message', $rc);
        return false;
    }

    /** @return array{0: string, 1: string} */
    public function slhKeygen(): array
    {
        $pk = $this->outBuf(self::SLH_PK_BYTES);
        $sk = $this->outBuf(self::SLH_SK_BYTES);
        $this->check('slh_keygen', $this->ffi->wilis_slh_keygen($pk, $sk));
        return [FFI::string($pk, self::SLH_PK_BYTES), FFI::string($sk, self::SLH_SK_BYTES)];
    }

    public function slhSign(string $sk, string $msg): string
    {
        $this->checkLen('sk', $sk, self::SLH_SK_BYTES);
        $sig = $this->outBuf(self::SLH_SIG_BYTES);
        $this->check('slh_sign', $this->ffi->wilis_slh_sign($this->inBuf($sk), $this->inBuf($msg), strlen($msg), $sig));
        return FFI::string($sig, self::SLH_SIG_BYTES);
    }

    public function slhVerify(string $pk, string $msg, string $sig): bool
    {
        $this->checkLen('pk', $pk, self::SLH_PK_BYTES);
        $this->checkLen('sig', $sig, self::SLH_SIG_BYTES);
        $rc = $this->ffi->wilis_slh_verify($this->inBuf($pk), $this->inBuf($msg), strlen($msg), $this->inBuf($sig));
        if ($rc === self::OK) {
            return true;
        }
        if ($rc === self::ERR_AUTH_FAILED) {
            return false;
        }
        $this->check('slh_verify', $rc);
        return false;
    }

    public function signcrypt(string $senderSlhSk, string $recipientKemPk, string $aad, string $pt): string
    {
        $this->checkLen('senderSlhSk', $senderSlhSk, self::SLH_SK_BYTES);
        $this->checkLen('recipientKemPk', $recipientKemPk, self::KEM_PK_BYTES);
        $sk = $this->inBuf($senderSlhSk);
        $pk = $this->inBuf($recipientKemPk);
        $a = $this->inBuf($aad);
        $p = $this->inBuf($pt);
        return $this->callVarOut('signcrypt', fn ($o, $c, $l) => $this->ffi->wilis_signcrypt($sk, $pk, $a, strlen($aad), $p, strlen($pt), $o, $c, $l));
    }

    public function unsigncrypt(string $senderSlhPk, string $recipientKemSk, string $aad, string $packet): string
    {
        $this->checkLen('senderSlhPk', $senderSlhPk, self::SLH_PK_BYTES);
        $this->checkLen('recipientKemSk', $recipientKemSk, self::KEM_SK_BYTES);
        $pk = $this->inBuf($senderSlhPk);
        $sk = $this->inBuf($recipientKemSk);
        $a = $this->inBuf($aad);
        $pkt = $this->inBuf($packet);
        return $this->callVarOut('unsigncrypt', fn ($o, $c, $l) => $this->ffi->wilis_unsigncrypt($pk, $sk, $a, strlen($aad), $pkt, strlen($packet), $o, $c, $l));
    }

    /** @return array{0: string, 1: int} */
    public function totpAt(string $secret, int $unixSecs, int $period = 30, int $digits = 6): array
    {
        $code = $this->outBuf($digits + 1);
        $rem = $this->ffi->new('uint64_t');
        $this->check('totp_at', $this->ffi->wilis_totp_at($this->inBuf($secret), strlen($secret), $unixSecs, $period, $digits, $code, $digits + 1, FFI::addr($rem)));
        return [FFI::string($code, $digits), (int) $rem->cdata];
    }

    public function fpeEncrypt(string $key, string $tweak, string $alphabet, string $pt): string
    {
        $this->checkLen('key', $key, self::KEY_BYTES);
        $k = $this->inBuf($key);
        $t = $this->inBuf($tweak);
        $al = $this->inBuf($alphabet);
        $p = $this->inBuf($pt);
        return $this->callVarOut('fpe_encrypt', fn ($o, $c, $l) => $this->ffi->wilis_fpe_encrypt($k, $t, strlen($tweak), $al, strlen($alphabet), $p, strlen($pt), $o, $c, $l));
    }

    public function fpeDecrypt(string $key, string $tweak, string $alphabet, string $ct): string
    {
        $this->checkLen('key', $key, self::KEY_BYTES);
        $k = $this->inBuf($key);
        $t = $this->inBuf($tweak);
        $al = $this->inBuf($alphabet);
        $cBuf = $this->inBuf($ct);
        return $this->callVarOut('fpe_decrypt', fn ($o, $cap, $l) => $this->ffi->wilis_fpe_decrypt($k, $t, strlen($tweak), $al, strlen($alphabet), $cBuf, strlen($ct), $o, $cap, $l));
    }

    public function mnemonicEncode(string $secret): string
    {
        $s = $this->inBuf($secret);
        return $this->callVarOut('mnemonic_encode', fn ($o, $c, $l) => $this->ffi->wilis_mnemonic_encode($s, strlen($secret), $o, $c, $l));
    }

    public function mnemonicDecode(string $phrase): string
    {
        $p = $this->inBuf($phrase);
        return $this->callVarOut('mnemonic_decode', fn ($o, $c, $l) => $this->ffi->wilis_mnemonic_decode($p, strlen($phrase), $o, $c, $l));
    }

    public function lzCompress(string $data): string
    {
        $d = $this->inBuf($data);
        return $this->callVarOut('lz_compress', fn ($o, $c, $l) => $this->ffi->wilis_lz_compress($d, strlen($data), $o, $c, $l));
    }

    public function lzDecompress(string $compressed, int $maxOut = 67108864): string
    {
        $d = $this->inBuf($compressed);
        return $this->callVarOut('lz_decompress', fn ($o, $c, $l) => $this->ffi->wilis_lz_decompress($d, strlen($compressed), $maxOut, $o, $c, $l));
    }
}

if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === __FILE__) {
    $check = static function (bool $ok, string $msg): void {
        if (!$ok) {
            fwrite(STDERR, "Wilis PHP FFI FAIL: {$msg}\n");
            exit(1);
        }
    };
    $w = new Wilis();
    $check($w->version() === '0.7.0', 'version');
    $key = $w->randomBytes(Wilis::KEY_BYTES);
    $nonce = $w->randomBytes(Wilis::NONCE_BYTES);
    $salt = $w->randomBytes(Wilis::SALT_BYTES);
    $check(strlen($w->hash256('abc')) === 32, 'hash256');
    $check(strlen($w->treeHash256('abc')) === 32, 'treeHash256');
    $check(strlen($w->mac256($key, 'msg')) === 32, 'mac256');
    $check(strlen($w->subkeyDerive($key, 'ctx')) === 32, 'subkeyDerive');
    $check(strlen($w->xofDerive('lbl', 'seed', 48)) === 48, 'xofDerive');
    [$ct, $tag] = $w->aeadSeal($key, $nonce, 'aad', 'hello php ffi');
    $check($w->ctEq($w->aeadOpen($key, $nonce, 'aad', $ct, $tag), 'hello php ffi'), 'aead');
    [$sct, $stag] = $w->sivSeal($key, 'aad', 'hello siv');
    $check($w->ctEq($w->sivOpen($key, 'aad', $sct, $stag), 'hello siv'), 'siv');
    $check(strlen($w->kdfDerive('pw', $salt, 64, 2)) === 32, 'kdfDerive');
    $check(strlen($w->kdfParallelDerive('pw', $salt, 128, 2, 2)) === 32, 'kdfParallelDerive');
    [$pk, $sk] = $w->kemKeygen();
    [$kct, $ss1] = $w->kemEncapsulate($pk);
    $check($w->ctEq($ss1, $w->kemDecapsulate($sk, $kct)), 'kem');
    [$spk, $ssk] = $w->signKeygen(3);
    [$sig] = $w->signMessage($ssk, 'php sign');
    $check($w->verifyMessage($spk, 'php sign', $sig), 'sign');
    [$slhPk, $slhSk] = $w->slhKeygen();
    $slhSig = $w->slhSign($slhSk, 'php slh');
    $check($w->slhVerify($slhPk, 'php slh', $slhSig), 'slh');
    $pkt = $w->signcrypt($slhSk, $pk, 'ctx', 'php signcrypt');
    $check($w->ctEq($w->unsigncrypt($slhPk, $sk, 'ctx', $pkt), 'php signcrypt'), 'signcrypt');
    [$code, $rem] = $w->totpAt($key, 1700000000);
    $check(strlen($code) === 6 && $rem > 0, 'totp');
    $fpeCt = $w->fpeEncrypt($key, 'tw', '0123456789', '4111111111111111');
    $check($w->fpeDecrypt($key, 'tw', '0123456789', $fpeCt) === '4111111111111111', 'fpe');
    $check($w->ctEq($w->mnemonicDecode($w->mnemonicEncode($key)), $key), 'mnemonic');
    $raw = str_repeat('WilisPhpFFI!', 20);
    $check($w->ctEq($w->lzDecompress($w->lzCompress($raw)), $raw), 'lz');
    echo "Wilis PHP FFI OK (v{$w->version()}, ALL 33/33 C-ABI functions)\n";
}
