//! Command-line argument parser and help text definitions for Wilis v0.6.0.

use std::fmt;
use std::path::Path;

use crate::core::constants::{HASH_BYTES, KEY_BYTES};
use crate::error::{Result, WilisError};
use crate::kdf::KdfStrength;
use crate::sign::DEFAULT_TREE_HEIGHT;
use crate::utils::hex::decode_hex;
use crate::utils::prompt::{hash_keyfile, read_hidden_passphrase};
use crate::utils::zeroize::{paths_refer_to_same_file, zeroize_bytes, SecretKey};

/// Authentication credential supplied on the command line (auto-zeroizes passphrase on drop
/// and redacts secret material in `Debug` output).
pub enum AuthInput {
    Passphrase {
        passphrase: String,
        keyfile_hash: Option<[u8; HASH_BYTES]>,
        strength: KdfStrength,
    },
    RawKey(SecretKey),
}

impl fmt::Debug for AuthInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthInput::Passphrase {
                keyfile_hash,
                strength,
                ..
            } => f
                .debug_struct("Passphrase")
                .field("passphrase", &"[REDACTED]")
                .field(
                    "keyfile_hash",
                    &if keyfile_hash.is_some() {
                        "Some([REDACTED])"
                    } else {
                        "None"
                    },
                )
                .field("strength", strength)
                .finish(),
            AuthInput::RawKey(k) => f.debug_tuple("RawKey").field(k).finish(),
        }
    }
}

impl Drop for AuthInput {
    fn drop(&mut self) {
        if let AuthInput::Passphrase {
            passphrase,
            keyfile_hash,
            ..
        } = self
        {
            zeroize_string(passphrase);
            if let Some(kf) = keyfile_hash {
                zeroize_bytes(kf);
            }
        }
    }
}

/// Vault sub-actions (auto-zeroizes secret values on drop and redacts them in `Debug` output).
pub enum VaultAction {
    Init,
    Set {
        name: String,
        value: String,
    },
    Get {
        name: String,
    },
    List,
    Search {
        query: String,
    },
    Delete {
        name: String,
    },
    Rekey {
        new_pass: Option<String>,
        new_keyfile_hash: Option<[u8; HASH_BYTES]>,
        new_strength: Option<KdfStrength>,
    },
    Totp {
        name: String,
        period: u64,
        digits: u32,
    },
    Export {
        out_path: String,
    },
    Import {
        in_path: String,
        merge: bool,
    },
}

impl fmt::Debug for VaultAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultAction::Init => f.write_str("Init"),
            VaultAction::Set { name, .. } => f
                .debug_struct("Set")
                .field("name", name)
                .field("value", &"[REDACTED]")
                .finish(),
            VaultAction::Get { name } => f.debug_struct("Get").field("name", name).finish(),
            VaultAction::List => f.write_str("List"),
            VaultAction::Search { query } => f.debug_struct("Search").field("query", query).finish(),
            VaultAction::Delete { name } => f.debug_struct("Delete").field("name", name).finish(),
            VaultAction::Rekey { new_strength, .. } => f
                .debug_struct("Rekey")
                .field("new_pass", &"[REDACTED]")
                .field("new_strength", new_strength)
                .finish(),
            VaultAction::Totp { name, period, digits } => f
                .debug_struct("Totp")
                .field("name", name)
                .field("period", period)
                .field("digits", digits)
                .finish(),
            VaultAction::Export { out_path } => {
                f.debug_struct("Export").field("out_path", out_path).finish()
            }
            VaultAction::Import { in_path, merge } => f
                .debug_struct("Import")
                .field("in_path", in_path)
                .field("merge", merge)
                .finish(),
        }
    }
}

impl Drop for VaultAction {
    fn drop(&mut self) {
        match self {
            VaultAction::Set { value, .. } => zeroize_string(value),
            VaultAction::Rekey {
                new_pass,
                new_keyfile_hash,
                ..
            } => {
                if let Some(p) = new_pass {
                    zeroize_string(p);
                }
                if let Some(h) = new_keyfile_hash {
                    zeroize_bytes(h);
                }
            }
            _ => {}
        }
    }
}

/// Mode for `wilis passgen`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassgenMode {
    Password,
    Words,
}

/// Actions for `wilis keyring`.
#[derive(Debug, Clone)]
pub enum KeyringAction {
    Add {
        name: String,
        pk_path: String,
        expires_days: Option<u64>,
    },
    List,
    Revoke {
        name: String,
        reason: String,
    },
    Remove {
        name: String,
    },
    Export {
        name: String,
        out_path: String,
    },
}

/// Actions for `wilis stego`.
pub enum StegoAction {
    Capacity {
        cover: String,
    },
    Embed {
        cover: String,
        in_file: String,
        out_file: String,
        key: SecretKey,
    },
    Extract {
        in_file: String,
        out_file: String,
        key: SecretKey,
    },
}

impl fmt::Debug for StegoAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StegoAction::Capacity { cover } => {
                f.debug_struct("Capacity").field("cover", cover).finish()
            }
            StegoAction::Embed {
                cover,
                in_file,
                out_file,
                key,
            } => f
                .debug_struct("Embed")
                .field("cover", cover)
                .field("in_file", in_file)
                .field("out_file", out_file)
                .field("key", key)
                .finish(),
            StegoAction::Extract {
                in_file,
                out_file,
                key,
            } => f
                .debug_struct("Extract")
                .field("in_file", in_file)
                .field("out_file", out_file)
                .field("key", key)
                .finish(),
        }
    }
}

/// Authentication mode for `wilis send` / `wilis recv`.
pub enum NetAuthMode {
    Pake {
        passphrase: String,
        strength: KdfStrength,
    },
    PkiSend {
        sign_sk_path: String,
        peer_kem_pk_path: String,
    },
    PkiRecv {
        kem_sk_path: String,
        peer_vk_path: String,
    },
}

impl fmt::Debug for NetAuthMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetAuthMode::Pake { strength, .. } => f
                .debug_struct("Pake")
                .field("passphrase", &"[REDACTED]")
                .field("strength", strength)
                .finish(),
            NetAuthMode::PkiSend {
                sign_sk_path,
                peer_kem_pk_path,
            } => f
                .debug_struct("PkiSend")
                .field("sign_sk_path", sign_sk_path)
                .field("peer_kem_pk_path", peer_kem_pk_path)
                .finish(),
            NetAuthMode::PkiRecv {
                kem_sk_path,
                peer_vk_path,
            } => f
                .debug_struct("PkiRecv")
                .field("kem_sk_path", kem_sk_path)
                .field("peer_vk_path", peer_vk_path)
                .finish(),
        }
    }
}

impl Drop for NetAuthMode {
    fn drop(&mut self) {
        if let NetAuthMode::Pake { passphrase, .. } = self {
            zeroize_string(passphrase);
        }
    }
}

/// Actions for persistent PQ `wilis ratchet`.
#[derive(Debug, Clone)]
pub enum RatchetAction {
    Init {
        sign_sk_path: String,
        peer_kem_pk_path: String,
        handshake_out: String,
        context: String,
    },
    Accept {
        kem_sk_path: String,
        peer_vk_path: String,
        handshake_in: String,
        context: String,
    },
    Encrypt {
        in_path: String,
        out_path: String,
        aad: String,
    },
    Decrypt {
        in_path: String,
        out_path: String,
        aad: String,
    },
    Rekey {
        out_path: String,
    },
    ApplyRekey {
        in_path: String,
    },
}

/// Internal RAII wrapper ensuring parsed CLI secrets are always volatile-zeroized on early `?` returns.
pub struct ZeroizeStr(pub String);

impl ZeroizeStr {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn into_inner(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl fmt::Debug for ZeroizeStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"[REDACTED]\"")
    }
}

impl Drop for ZeroizeStr {
    fn drop(&mut self) {
        zeroize_string(&mut self.0);
    }
}

fn zeroize_string(s: &mut String) {
    // SAFETY: Overwriting UTF-8 bytes with 0x00 preserves UTF-8 validity.
    zeroize_bytes(unsafe { s.as_bytes_mut() });
}

/// Parsed CLI subcommands (redacts secret payloads in `Debug` output).
pub enum Command {
    Help,
    EncryptText {
        auth: AuthInput,
        aad: String,
        plaintext: String,
        pad_block: Option<usize>,
        armor: bool,
    },
    DecryptText {
        auth: AuthInput,
        aad: String,
        ciphertext_b64: String,
        unpad: bool,
    },
    EncryptFile {
        auth: AuthInput,
        aad: String,
        input_path: String,
        output_path: String,
    },
    DecryptFile {
        auth: AuthInput,
        aad: String,
        input_path: String,
        output_path: String,
    },
    EncryptDir {
        auth: AuthInput,
        aad: String,
        dir_path: String,
        output_file: String,
        compress: bool,
    },
    DecryptDir {
        auth: AuthInput,
        aad: String,
        input_file: String,
        out_dir: String,
    },
    KemKeygen {
        out_prefix: String,
    },
    PubEncrypt {
        pk_paths: Vec<String>,
        aad: String,
        input_path: String,
        output_path: String,
        armor: bool,
    },
    PubDecrypt {
        sk_path: String,
        aad: String,
        input_path: String,
        output_path: String,
    },
    Vault {
        vault_path: String,
        auth: AuthInput,
        action: VaultAction,
        explicit_strength: Option<KdfStrength>,
    },
    SignKeygen {
        out_prefix: String,
        height: u8,
    },
    SignFile {
        sk_path: String,
        input_path: String,
        sig_out_path: String,
        armor: bool,
    },
    VerifyFile {
        pk_path: String,
        input_path: String,
        sig_path: String,
    },
    SlhKeygen {
        out_prefix: String,
    },
    SlhSign {
        sk_path: String,
        input_path: String,
        sig_out_path: String,
        armor: bool,
    },
    SlhVerify {
        pk_path: String,
        input_path: String,
        sig_path: String,
    },
    SplitKey {
        secret_hex: String,
        total: u8,
        threshold: u8,
    },
    CombineKey {
        shares: Vec<String>,
    },
    Mac {
        key: SecretKey,
        file_path: Option<String>,
        text: Option<String>,
    },
    MacVerify {
        key: SecretKey,
        tag_hex: String,
        file_path: Option<String>,
        text: Option<String>,
    },
    Rand {
        bytes: usize,
    },
    Passgen {
        mode: PassgenMode,
        length: usize,
        count: usize,
    },
    MnemonicEncode {
        key_hex: ZeroizeStr,
    },
    MnemonicDecode {
        phrase: ZeroizeStr,
    },
    KeyProtect {
        in_path: String,
        out_path: String,
        auth: AuthInput,
    },
    KeyUnlock {
        in_path: String,
        out_path: String,
        auth: AuthInput,
    },
    Keyring {
        file_path: String,
        action: KeyringAction,
    },
    Stego {
        action: StegoAction,
    },
    HiddenCreate {
        out_file: String,
        size: usize,
        decoy_pass: ZeroizeStr,
        decoy_in: String,
        hidden_pass: ZeroizeStr,
        hidden_in: String,
        strength: KdfStrength,
    },
    HiddenOpen {
        in_file: String,
        out_file: String,
        pass: ZeroizeStr,
        strength: KdfStrength,
    },
    Send {
        addr: String,
        file_path: String,
        mode: NetAuthMode,
    },
    Recv {
        listen_addr: String,
        out_dir: String,
        mode: NetAuthMode,
    },
    Ratchet {
        state_path: String,
        auth: AuthInput,
        action: RatchetAction,
    },
    Inspect {
        path: String,
    },
    Shred {
        path: String,
        passes: usize,
    },
    Completions {
        shell: String,
    },
    Keygen,
    HashText {
        text: String,
    },
    HashFile {
        path: String,
    },
    Bench,
    Audit,
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Command::Help => f.write_str("Help"),
            Command::EncryptText { auth, aad, .. } => f
                .debug_struct("EncryptText")
                .field("auth", auth)
                .field("aad", aad)
                .field("plaintext", &"[REDACTED]")
                .finish(),
            Command::DecryptText { auth, aad, .. } => f
                .debug_struct("DecryptText")
                .field("auth", auth)
                .field("aad", aad)
                .finish(),
            Command::EncryptFile {
                auth,
                input_path,
                output_path,
                ..
            } => f
                .debug_struct("EncryptFile")
                .field("auth", auth)
                .field("input_path", input_path)
                .field("output_path", output_path)
                .finish(),
            Command::DecryptFile {
                auth,
                input_path,
                output_path,
                ..
            } => f
                .debug_struct("DecryptFile")
                .field("auth", auth)
                .field("input_path", input_path)
                .field("output_path", output_path)
                .finish(),
            Command::EncryptDir {
                auth,
                dir_path,
                output_file,
                compress,
                ..
            } => f
                .debug_struct("EncryptDir")
                .field("auth", auth)
                .field("dir_path", dir_path)
                .field("output_file", output_file)
                .field("compress", compress)
                .finish(),
            Command::DecryptDir {
                auth,
                input_file,
                out_dir,
                ..
            } => f
                .debug_struct("DecryptDir")
                .field("auth", auth)
                .field("input_file", input_file)
                .field("out_dir", out_dir)
                .finish(),
            Command::KemKeygen { out_prefix } => f
                .debug_struct("KemKeygen")
                .field("out_prefix", out_prefix)
                .finish(),
            Command::PubEncrypt {
                pk_paths,
                input_path,
                output_path,
                armor,
                ..
            } => f
                .debug_struct("PubEncrypt")
                .field("pk_paths", pk_paths)
                .field("input_path", input_path)
                .field("output_path", output_path)
                .field("armor", armor)
                .finish(),
            Command::PubDecrypt {
                sk_path,
                input_path,
                output_path,
                ..
            } => f
                .debug_struct("PubDecrypt")
                .field("sk_path", sk_path)
                .field("input_path", input_path)
                .field("output_path", output_path)
                .finish(),
            Command::Vault {
                vault_path,
                auth,
                action,
                explicit_strength,
            } => f
                .debug_struct("Vault")
                .field("vault_path", vault_path)
                .field("auth", auth)
                .field("action", action)
                .field("explicit_strength", explicit_strength)
                .finish(),
            Command::SignKeygen { out_prefix, height } => f
                .debug_struct("SignKeygen")
                .field("out_prefix", out_prefix)
                .field("height", height)
                .finish(),
            Command::SignFile {
                sk_path,
                input_path,
                sig_out_path,
                armor,
            } => f
                .debug_struct("SignFile")
                .field("sk_path", sk_path)
                .field("input_path", input_path)
                .field("sig_out_path", sig_out_path)
                .field("armor", armor)
                .finish(),
            Command::VerifyFile {
                pk_path,
                input_path,
                sig_path,
            } => f
                .debug_struct("VerifyFile")
                .field("pk_path", pk_path)
                .field("input_path", input_path)
                .field("sig_path", sig_path)
                .finish(),
            Command::SlhKeygen { out_prefix } => f
                .debug_struct("SlhKeygen")
                .field("out_prefix", out_prefix)
                .finish(),
            Command::SlhSign {
                sk_path,
                input_path,
                sig_out_path,
                armor,
            } => f
                .debug_struct("SlhSign")
                .field("sk_path", sk_path)
                .field("input_path", input_path)
                .field("sig_out_path", sig_out_path)
                .field("armor", armor)
                .finish(),
            Command::SlhVerify {
                pk_path,
                input_path,
                sig_path,
            } => f
                .debug_struct("SlhVerify")
                .field("pk_path", pk_path)
                .field("input_path", input_path)
                .field("sig_path", sig_path)
                .finish(),
            Command::SplitKey { total, threshold, .. } => f
                .debug_struct("SplitKey")
                .field("secret_hex", &"[REDACTED]")
                .field("total", total)
                .field("threshold", threshold)
                .finish(),
            Command::CombineKey { shares } => f
                .debug_struct("CombineKey")
                .field("shares_count", &shares.len())
                .finish(),
            Command::Mac { key, file_path, .. } => f
                .debug_struct("Mac")
                .field("key", key)
                .field("file_path", file_path)
                .finish(),
            Command::MacVerify { key, file_path, .. } => f
                .debug_struct("MacVerify")
                .field("key", key)
                .field("file_path", file_path)
                .finish(),
            Command::Rand { bytes } => f.debug_struct("Rand").field("bytes", bytes).finish(),
            Command::Passgen {
                mode,
                length,
                count,
            } => f
                .debug_struct("Passgen")
                .field("mode", mode)
                .field("length", length)
                .field("count", count)
                .finish(),
            Command::MnemonicEncode { .. } => f.write_str("MnemonicEncode([REDACTED])"),
            Command::MnemonicDecode { .. } => f.write_str("MnemonicDecode([REDACTED])"),
            Command::KeyProtect {
                in_path,
                out_path,
                auth,
            } => f
                .debug_struct("KeyProtect")
                .field("in_path", in_path)
                .field("out_path", out_path)
                .field("auth", auth)
                .finish(),
            Command::KeyUnlock {
                in_path,
                out_path,
                auth,
            } => f
                .debug_struct("KeyUnlock")
                .field("in_path", in_path)
                .field("out_path", out_path)
                .field("auth", auth)
                .finish(),
            Command::Keyring { file_path, action } => f
                .debug_struct("Keyring")
                .field("file_path", file_path)
                .field("action", action)
                .finish(),
            Command::Stego { action } => f.debug_struct("Stego").field("action", action).finish(),
            Command::HiddenCreate {
                out_file,
                size,
                strength,
                ..
            } => f
                .debug_struct("HiddenCreate")
                .field("out_file", out_file)
                .field("size", size)
                .field("strength", strength)
                .finish(),
            Command::HiddenOpen {
                in_file,
                out_file,
                strength,
                ..
            } => f
                .debug_struct("HiddenOpen")
                .field("in_file", in_file)
                .field("out_file", out_file)
                .field("strength", strength)
                .finish(),
            Command::Send {
                addr,
                file_path,
                mode,
            } => f
                .debug_struct("Send")
                .field("addr", addr)
                .field("file_path", file_path)
                .field("mode", mode)
                .finish(),
            Command::Recv {
                listen_addr,
                out_dir,
                mode,
            } => f
                .debug_struct("Recv")
                .field("listen_addr", listen_addr)
                .field("out_dir", out_dir)
                .field("mode", mode)
                .finish(),
            Command::Ratchet {
                state_path,
                auth,
                action,
            } => f
                .debug_struct("Ratchet")
                .field("state_path", state_path)
                .field("auth", auth)
                .field("action", action)
                .finish(),
            Command::Inspect { path } => f.debug_struct("Inspect").field("path", path).finish(),
            Command::Shred { path, passes } => f
                .debug_struct("Shred")
                .field("path", path)
                .field("passes", passes)
                .finish(),
            Command::Completions { shell } => {
                f.debug_struct("Completions").field("shell", shell).finish()
            }
            Command::Keygen => f.write_str("Keygen"),
            Command::HashText { .. } => f.write_str("HashText"),
            Command::HashFile { path } => f.debug_struct("HashFile").field("path", path).finish(),
            Command::Bench => f.write_str("Bench"),
            Command::Audit => f.write_str("Audit"),
        }
    }
}

/// Returns formatted CLI usage documentation.
pub fn usage_text() -> String {
    format!(
        "\
Wilis v{} — Standalone Post-Quantum & Symmetric Cryptography Suite (WilisPerm-384)

USAGE:
  wilis <COMMAND> [OPTIONS]

SYMMETRIC ENCRYPTION, ARCHIVING & PIPES (use '-' for stdin/stdout):
  encrypt-text  (--pass <P> | --pass-prompt | --key <HEX>) [--keyfile <F>] [--strength S] [--aad <T>] [--pad <N>] [--armor] <TEXT>
  decrypt-text  (--pass <P> | --pass-prompt | --key <HEX>) [--keyfile <F>] [--aad <T>] [--unpad] <BASE64|ARMOR>
  encrypt-file  (--pass <P> | --pass-prompt | --key <HEX>) [--keyfile <F>] [--strength S] [--aad <T>] --in <F|-> --out <F|->
  decrypt-file  (--pass <P> | --pass-prompt | --key <HEX>) [--keyfile <F>] [--aad <T>] --in <F|-> --out <F|->
  encrypt-dir   (--pass <P> | --pass-prompt | --key <HEX>) [--keyfile <F>] [--strength S] [--aad <T>] [--compress] --in <DIR> --out <F>
  decrypt-dir   (--pass <P> | --pass-prompt | --key <HEX>) [--keyfile <F>] [--aad <T>] --in <F> --out <DIR>

POST-QUANTUM PUBLIC-KEY ENCRYPTION & SIGNATURES (NTT-Accelerated WilisKEM, WilisSign, Stateless WilisSLH):
  kem-keygen    --out <PREFIX>                    (writes <PREFIX>.wks secret & <PREFIX>.wkp public)
  pub-encrypt   --pk <KEY.wkp> [--pk <KEY2.wkp> ...] [--aad <T>] [--armor] --in <FILE> --out <FILE.wpke>
  pub-decrypt   --sk <KEY.wks> [--aad <T>] --in <FILE.wpke> --out <FILE>
  sign-keygen   --out <PREFIX> [--height 2..10]   (stateful WOTS+ Merkle: <PREFIX>.wsk / <PREFIX>.wpk)
  sign          --sk <KEY.wsk> [--armor] --in <FILE> --out <FILE.wsig>
  verify        --pk <KEY.wpk> --in <FILE> --sig <FILE.wsig>
  slh-keygen    --out <PREFIX>                    (stateless unlimited signatures: <PREFIX>.wls / <PREFIX>.wlp)
  slh-sign      --sk <KEY.wls> [--armor] --in <FILE> --out <FILE.wlsg>
  slh-verify    --pk <KEY.wlp> --in <FILE> --sig <FILE.wlsg>

POST-QUANTUM NETWORKING & PERSISTENT RATCHET (WilisNet & WRST):
  send          --addr <HOST:PORT> --in <FILE> (--pass <P> | --sign-sk <F.wsk> --peer-pk <F.wkp>) [--strength S]
  recv          --listen <HOST:PORT> --out-dir <DIR> (--pass <P> | --kem-sk <F.wks> --peer-vk <F.wpk>)
  ratchet       (init|accept|encrypt|decrypt|rekey|apply-rekey) --state <F.wrst> (--pass <P>|--pass-prompt) [...]

VAULT, KEY MANAGEMENT, MNEMONIC, HIDDEN VOLUME & STEGANOGRAPHY:
  vault         (init|set|get|list|search|del|rekey|totp|export|import) --file <V.wils> (--pass <P>|--pass-prompt) [...]
  key-protect   --in <KEY> --out <KEY.wenc> (--pass <P> | --pass-prompt) [--keyfile <F>] [--strength S]
  key-unlock    --in <KEY.wenc> --out <KEY> (--pass <P> | --pass-prompt) [--keyfile <F>]
  keyring       (add|list|revoke|remove|export) --file <RING.wkrn> [...]
  mnemonic      (encode --key <64-HEX> | decode <34 WORDS>)
  hidden        (create --out <F> --size <N> --decoy-pass <P> --decoy-in <F> --hidden-pass <P> --hidden-in <F> | open --in <F> --out <F> --pass <P>)
  stego         (capacity --cover <BMP|WAV> | embed --cover <F> --in <F> --out <F> --key <HEX> | extract --in <F> --out <F> --key <HEX>)
  split-key     --secret <HEX> --total <N> --threshold <K>
  combine-key   <SHARE_1> <SHARE_2> [...]

UTILITIES, HARDENING & CRYPTANALYSIS:
  mac           --key <64-HEX> (--file <FILE|-> | <TEXT>)
  mac-verify    --key <64-HEX> --tag <64-HEX> (--file <FILE|-> | <TEXT>)
  hash          (--file <FILE|-> | <TEXT>)
  keygen        Generate a fresh 256-bit random hex key & WilisHash-256 Key ID.
  rand          --bytes <N>                       Generate N cryptographically secure random bytes (hex).
  passgen       [--words <N> | --length <N>] [--count <C>]
  inspect       <FILE>                            Inspect any Wilis binary or armored file without secret keys.
  shred         --file <FILE> [--passes 1..=32]   Multi-pass CSPRNG+zero overwrite, truncate, rename, and delete.
  completions   <bash|zsh|fish|powershell>        Emit shell tab-completion script.
  bench         Run bijectivity, avalanche, AEAD, and NTT-accelerated WilisKEM benchmarks.
  audit         Run 8-part scientific cryptanalysis & empirical timing audit (SAC, BIC, DDT/LAT, NIST, KEM, PQ, dudect).
  help          Display this usage guide.",
        env!("CARGO_PKG_VERSION")
    )
}

/// Parses command-line arguments (excluding program name `argv[0]`).
pub fn parse_args(args: &[String]) -> Result<Command> {
    if args.is_empty() {
        return Ok(Command::Help);
    }

    match args[0].as_str() {
        "help" | "-h" | "--help" => Ok(Command::Help),
        "keygen" => ensure_no_extra_args("keygen", &args[1..]).map(|()| Command::Keygen),
        "bench" => ensure_no_extra_args("bench", &args[1..]).map(|()| Command::Bench),
        "audit" => ensure_no_extra_args("audit", &args[1..]).map(|()| Command::Audit),
        "encrypt-text" => parse_text_cmd(&args[1..], true),
        "decrypt-text" => parse_text_cmd(&args[1..], false),
        "encrypt-file" => parse_io_cmd(&args[1..], IoMode::EncryptFile),
        "decrypt-file" => parse_io_cmd(&args[1..], IoMode::DecryptFile),
        "encrypt-dir" => parse_io_cmd(&args[1..], IoMode::EncryptDir),
        "decrypt-dir" => parse_io_cmd(&args[1..], IoMode::DecryptDir),
        "kem-keygen" => parse_prefix_cmd(&args[1..], "kem-keygen")
            .map(|out_prefix| Command::KemKeygen { out_prefix }),
        "pub-encrypt" => parse_pub_enc(&args[1..]),
        "pub-decrypt" => parse_pub_dec(&args[1..]),
        "vault" => parse_vault_cmd(&args[1..]),
        "sign-keygen" => parse_sign_keygen(&args[1..]),
        "sign" => parse_sign_cmd(&args[1..], false),
        "verify" => parse_verify_cmd(&args[1..], false),
        "slh-keygen" => parse_prefix_cmd(&args[1..], "slh-keygen")
            .map(|out_prefix| Command::SlhKeygen { out_prefix }),
        "slh-sign" => parse_sign_cmd(&args[1..], true),
        "slh-verify" => parse_verify_cmd(&args[1..], true),
        "split-key" => parse_split_key(&args[1..]),
        "combine-key" => parse_combine_key(&args[1..]),
        "mac" => parse_mac_cmd(&args[1..], false),
        "mac-verify" => parse_mac_cmd(&args[1..], true),
        "rand" => parse_rand_cmd(&args[1..]),
        "hash" => parse_hash_cmd(&args[1..]),
        "passgen" => parse_passgen_cmd(&args[1..]),
        "mnemonic" => parse_mnemonic_cmd(&args[1..]),
        "key-protect" => parse_keywrap_cmd(&args[1..], true),
        "key-unlock" => parse_keywrap_cmd(&args[1..], false),
        "keyring" => parse_keyring_cmd(&args[1..]),
        "stego" => parse_stego_cmd(&args[1..]),
        "hidden" => parse_hidden_cmd(&args[1..]),
        "send" => parse_send_cmd(&args[1..]),
        "recv" => parse_recv_cmd(&args[1..]),
        "ratchet" => parse_ratchet_cmd(&args[1..]),
        "inspect" => parse_inspect_cmd(&args[1..]),
        "shred" => parse_shred_cmd(&args[1..]),
        "completions" => parse_completions_cmd(&args[1..]),
        unknown => Err(WilisError::CliUsage(format!(
            "unknown command '{unknown}'. Run 'wilis help' for usage."
        ))),
    }
}

enum IoMode {
    EncryptFile,
    DecryptFile,
    EncryptDir,
    DecryptDir,
}

fn ensure_no_extra_args(cmd: &str, rest: &[String]) -> Result<()> {
    if let Some(extra) = rest.first() {
        return Err(WilisError::CliUsage(format!(
            "unexpected argument '{extra}' for command '{cmd}'"
        )));
    }
    Ok(())
}

fn set_once<T>(slot: &mut Option<T>, val: T, flag: &str) -> Result<()> {
    if slot.is_some() {
        return Err(WilisError::CliUsage(format!("duplicate option '{flag}'")));
    }
    *slot = Some(val);
    Ok(())
}

fn parse_raw_key(hex_str: &str) -> Result<SecretKey> {
    let mut bytes = decode_hex(hex_str)?;
    if bytes.len() != KEY_BYTES {
        let len = bytes.len();
        zeroize_bytes(&mut bytes);
        return Err(WilisError::InvalidKey(format!(
            "expected {} hex chars ({} bytes), got {} bytes",
            KEY_BYTES * 2,
            KEY_BYTES,
            len
        )));
    }
    let mut arr = [0u8; KEY_BYTES];
    arr.copy_from_slice(&bytes);
    zeroize_bytes(&mut bytes);
    let sk = SecretKey::from_bytes(arr);
    zeroize_bytes(&mut arr);
    Ok(sk)
}

fn resolve_auth(
    pass: Option<ZeroizeStr>,
    pass_prompt: bool,
    raw_key: Option<SecretKey>,
    keyfile_path: Option<String>,
    strength: KdfStrength,
    is_encrypt: bool,
) -> Result<AuthInput> {
    if let Some(key) = raw_key {
        if pass.is_some() || pass_prompt {
            return Err(WilisError::CliUsage(
                "cannot combine --key with --pass or --pass-prompt".into(),
            ));
        }
        if keyfile_path.is_some() {
            return Err(WilisError::CliUsage(
                "--keyfile is only used with passphrase mode (--pass / --pass-prompt)".into(),
            ));
        }
        return Ok(AuthInput::RawKey(key));
    }

    if pass.is_some() && pass_prompt {
        return Err(WilisError::CliUsage(
            "cannot combine --pass with --pass-prompt".into(),
        ));
    }

    let mut passphrase = if pass_prompt {
        read_hidden_passphrase("Enter passphrase: ", is_encrypt)?
    } else if let Some(p) = pass {
        let s = p.into_inner();
        if s.is_empty() {
            return Err(WilisError::InvalidKey(
                "passphrase must not be empty".into(),
            ));
        }
        s
    } else {
        return Err(WilisError::CliUsage(
            "must specify --pass <PASS>, --pass-prompt, or --key <64-HEX>".into(),
        ));
    };

    let keyfile_hash = match keyfile_path {
        Some(path) => match hash_keyfile(&path) {
            Ok(h) => Some(h),
            Err(e) => {
                zeroize_string(&mut passphrase);
                return Err(e);
            }
        },
        None => None,
    };

    Ok(AuthInput::Passphrase {
        passphrase,
        keyfile_hash,
        strength,
    })
}

fn parse_text_cmd(args: &[String], encrypt: bool) -> Result<Command> {
    let mut pass: Option<ZeroizeStr> = None;
    let mut pass_prompt = false;
    let mut raw_key: Option<SecretKey> = None;
    let mut keyfile: Option<String> = None;
    let mut strength: Option<KdfStrength> = None;
    let mut aad: Option<String> = None;
    let mut pad_block: Option<usize> = None;
    let mut armor = false;
    let mut unpad = false;
    let mut positional: Option<String> = None;

    let mut i = 0;
    let mut end_of_opts = false;
    while i < args.len() {
        let arg = args[i].as_str();
        if !end_of_opts {
            match arg {
                "--" => {
                    end_of_opts = true;
                    i += 1;
                    continue;
                }
                "--pass" => {
                    i += 1;
                    set_once(&mut pass, ZeroizeStr(req_val(args, i, "--pass")?), "--pass")?;
                    i += 1;
                    continue;
                }
                "--pass-prompt" => {
                    if pass_prompt {
                        return Err(WilisError::CliUsage("duplicate option '--pass-prompt'".into()));
                    }
                    pass_prompt = true;
                    i += 1;
                    continue;
                }
                "--key" => {
                    i += 1;
                    set_once(&mut raw_key, parse_raw_key(&req_val(args, i, "--key")?)?, "--key")?;
                    i += 1;
                    continue;
                }
                "--keyfile" => {
                    i += 1;
                    set_once(&mut keyfile, req_val(args, i, "--keyfile")?, "--keyfile")?;
                    i += 1;
                    continue;
                }
                "--strength" => {
                    i += 1;
                    set_once(
                        &mut strength,
                        KdfStrength::from_name(&req_val(args, i, "--strength")?)?,
                        "--strength",
                    )?;
                    i += 1;
                    continue;
                }
                "--aad" => {
                    i += 1;
                    set_once(&mut aad, req_val(args, i, "--aad")?, "--aad")?;
                    i += 1;
                    continue;
                }
                "--pad" if encrypt => {
                    i += 1;
                    let s = req_val(args, i, "--pad")?;
                    let b = s.parse::<usize>().map_err(|_| {
                        WilisError::CliUsage(format!("invalid --pad '{s}' (expected 16..=65536)"))
                    })?;
                    set_once(&mut pad_block, b, "--pad")?;
                    i += 1;
                    continue;
                }
                "--armor" if encrypt => {
                    if armor {
                        return Err(WilisError::CliUsage("duplicate option '--armor'".into()));
                    }
                    armor = true;
                    i += 1;
                    continue;
                }
                "--unpad" if !encrypt => {
                    if unpad {
                        return Err(WilisError::CliUsage("duplicate option '--unpad'".into()));
                    }
                    unpad = true;
                    i += 1;
                    continue;
                }
                other if other.starts_with("--") => {
                    return Err(WilisError::CliUsage(format!("unknown option '{other}'")));
                }
                _ => {}
            }
        }
        if positional.is_some() {
            return Err(WilisError::CliUsage(
                "unexpected extra positional argument".into(),
            ));
        }
        positional = Some(arg.to_string());
        i += 1;
    }

    let payload = positional.ok_or_else(|| {
        WilisError::CliUsage(if encrypt {
            "missing <PLAINTEXT> argument".into()
        } else {
            "missing <BASE64|ARMOR> ciphertext argument".into()
        })
    })?;

    let auth = resolve_auth(
        pass,
        pass_prompt,
        raw_key,
        keyfile,
        strength.unwrap_or(KdfStrength::Interactive),
        encrypt,
    )?;
    let aad = aad.unwrap_or_default();
    if encrypt {
        Ok(Command::EncryptText {
            auth,
            aad,
            plaintext: payload,
            pad_block,
            armor,
        })
    } else {
        Ok(Command::DecryptText {
            auth,
            aad,
            ciphertext_b64: payload,
            unpad,
        })
    }
}

fn parse_io_cmd(args: &[String], mode: IoMode) -> Result<Command> {
    let mut pass: Option<ZeroizeStr> = None;
    let mut pass_prompt = false;
    let mut raw_key: Option<SecretKey> = None;
    let mut keyfile: Option<String> = None;
    let mut strength: Option<KdfStrength> = None;
    let mut aad: Option<String> = None;
    let mut input_path: Option<String> = None;
    let mut output_path: Option<String> = None;
    let mut compress = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--pass" => {
                i += 1;
                set_once(&mut pass, ZeroizeStr(req_val(args, i, "--pass")?), "--pass")?;
            }
            "--pass-prompt" => {
                if pass_prompt {
                    return Err(WilisError::CliUsage("duplicate option '--pass-prompt'".into()));
                }
                pass_prompt = true;
            }
            "--key" => {
                i += 1;
                set_once(&mut raw_key, parse_raw_key(&req_val(args, i, "--key")?)?, "--key")?;
            }
            "--keyfile" => {
                i += 1;
                set_once(&mut keyfile, req_val(args, i, "--keyfile")?, "--keyfile")?;
            }
            "--strength" => {
                i += 1;
                set_once(
                    &mut strength,
                    KdfStrength::from_name(&req_val(args, i, "--strength")?)?,
                    "--strength",
                )?;
            }
            "--aad" => {
                i += 1;
                set_once(&mut aad, req_val(args, i, "--aad")?, "--aad")?;
            }
            "--in" => {
                i += 1;
                set_once(&mut input_path, req_val(args, i, "--in")?, "--in")?;
            }
            "--out" => {
                i += 1;
                set_once(&mut output_path, req_val(args, i, "--out")?, "--out")?;
            }
            "--compress" if matches!(mode, IoMode::EncryptDir) => {
                if compress {
                    return Err(WilisError::CliUsage("duplicate option '--compress'".into()));
                }
                compress = true;
            }
            other => {
                return Err(WilisError::CliUsage(format!("unknown argument '{other}'")));
            }
        }
        i += 1;
    }

    let input_path =
        input_path.ok_or_else(|| WilisError::CliUsage("missing required --in <PATH>".into()))?;
    let output_path =
        output_path.ok_or_else(|| WilisError::CliUsage("missing required --out <PATH>".into()))?;

    if input_path == "-" && pass_prompt {
        return Err(WilisError::CliUsage(
            "cannot combine --in - (stdin payload) with --pass-prompt (use --pass or --key)".into(),
        ));
    }

    if let Some(ref kf) = keyfile {
        if output_path != "-" && paths_refer_to_same_file(Path::new(kf), Path::new(&output_path)) {
            return Err(WilisError::InvalidParameters(
                "output path must not overwrite the 2FA keyfile".into(),
            ));
        }
    }

    let is_encrypt = matches!(mode, IoMode::EncryptFile | IoMode::EncryptDir);
    let auth = resolve_auth(
        pass,
        pass_prompt,
        raw_key,
        keyfile,
        strength.unwrap_or(KdfStrength::Interactive),
        is_encrypt,
    )?;
    let aad = aad.unwrap_or_default();

    Ok(match mode {
        IoMode::EncryptFile => Command::EncryptFile {
            auth,
            aad,
            input_path,
            output_path,
        },
        IoMode::DecryptFile => Command::DecryptFile {
            auth,
            aad,
            input_path,
            output_path,
        },
        IoMode::EncryptDir => Command::EncryptDir {
            auth,
            aad,
            dir_path: input_path,
            output_file: output_path,
            compress,
        },
        IoMode::DecryptDir => Command::DecryptDir {
            auth,
            aad,
            input_file: input_path,
            out_dir: output_path,
        },
    })
}

fn parse_prefix_cmd(args: &[String], cmd: &str) -> Result<String> {
    let mut out_prefix: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                set_once(&mut out_prefix, req_val(args, i, "--out")?, "--out")?;
            }
            other => return Err(WilisError::CliUsage(format!("unknown option '{other}'"))),
        }
        i += 1;
    }
    out_prefix.ok_or_else(|| WilisError::CliUsage(format!("{cmd} requires --out <PREFIX>")))
}

fn parse_pub_enc(args: &[String]) -> Result<Command> {
    let mut pk_paths: Vec<String> = Vec::new();
    let mut aad: Option<String> = None;
    let mut input: Option<String> = None;
    let mut out: Option<String> = None;
    let mut armor = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--pk" => {
                i += 1;
                pk_paths.push(req_val(args, i, "--pk")?);
            }
            "--aad" => {
                i += 1;
                set_once(&mut aad, req_val(args, i, "--aad")?, "--aad")?;
            }
            "--in" => {
                i += 1;
                set_once(&mut input, req_val(args, i, "--in")?, "--in")?;
            }
            "--out" => {
                i += 1;
                set_once(&mut out, req_val(args, i, "--out")?, "--out")?;
            }
            "--armor" => {
                if armor {
                    return Err(WilisError::CliUsage("duplicate option '--armor'".into()));
                }
                armor = true;
            }
            other => return Err(WilisError::CliUsage(format!("unknown option '{other}'"))),
        }
        i += 1;
    }
    if pk_paths.is_empty() {
        return Err(WilisError::CliUsage(
            "pub-encrypt requires at least one --pk <KEY.wkp>".into(),
        ));
    }
    Ok(Command::PubEncrypt {
        pk_paths,
        aad: aad.unwrap_or_default(),
        input_path: input
            .ok_or_else(|| WilisError::CliUsage("pub-encrypt requires --in <FILE>".into()))?,
        output_path: out
            .ok_or_else(|| WilisError::CliUsage("pub-encrypt requires --out <FILE>".into()))?,
        armor,
    })
}

fn parse_pub_dec(args: &[String]) -> Result<Command> {
    let mut sk: Option<String> = None;
    let mut aad: Option<String> = None;
    let mut input: Option<String> = None;
    let mut out: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--sk" => {
                i += 1;
                set_once(&mut sk, req_val(args, i, "--sk")?, "--sk")?;
            }
            "--aad" => {
                i += 1;
                set_once(&mut aad, req_val(args, i, "--aad")?, "--aad")?;
            }
            "--in" => {
                i += 1;
                set_once(&mut input, req_val(args, i, "--in")?, "--in")?;
            }
            "--out" => {
                i += 1;
                set_once(&mut out, req_val(args, i, "--out")?, "--out")?;
            }
            other => return Err(WilisError::CliUsage(format!("unknown option '{other}'"))),
        }
        i += 1;
    }
    Ok(Command::PubDecrypt {
        sk_path: sk
            .ok_or_else(|| WilisError::CliUsage("pub-decrypt requires --sk <KEY.wks>".into()))?,
        aad: aad.unwrap_or_default(),
        input_path: input
            .ok_or_else(|| WilisError::CliUsage("pub-decrypt requires --in <FILE>".into()))?,
        output_path: out
            .ok_or_else(|| WilisError::CliUsage("pub-decrypt requires --out <FILE>".into()))?,
    })
}

fn parse_vault_cmd(args: &[String]) -> Result<Command> {
    if args.is_empty() {
        return Err(WilisError::CliUsage(
            "vault requires a subcommand: init, set, get, list, search, del, rekey, totp, export, import".into(),
        ));
    }
    let sub = args[0].as_str();
    let mut vault_file: Option<String> = None;
    let mut pass: Option<ZeroizeStr> = None;
    let mut pass_prompt = false;
    let mut keyfile: Option<String> = None;
    let mut strength: Option<KdfStrength> = None;
    let mut name: Option<String> = None;
    let mut value: Option<ZeroizeStr> = None;
    let mut query: Option<String> = None;
    let mut new_pass: Option<ZeroizeStr> = None;
    let mut new_keyfile: Option<String> = None;
    let mut new_strength: Option<KdfStrength> = None;
    let mut period: Option<u64> = None;
    let mut digits: Option<u32> = None;
    let mut out_path: Option<String> = None;
    let mut in_path: Option<String> = None;
    let mut merge = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--file" => {
                i += 1;
                set_once(&mut vault_file, req_val(args, i, "--file")?, "--file")?;
            }
            "--pass" => {
                i += 1;
                set_once(&mut pass, ZeroizeStr(req_val(args, i, "--pass")?), "--pass")?;
            }
            "--pass-prompt" => {
                if pass_prompt {
                    return Err(WilisError::CliUsage("duplicate option '--pass-prompt'".into()));
                }
                pass_prompt = true;
            }
            "--keyfile" => {
                i += 1;
                set_once(&mut keyfile, req_val(args, i, "--keyfile")?, "--keyfile")?;
            }
            "--strength" => {
                i += 1;
                set_once(
                    &mut strength,
                    KdfStrength::from_name(&req_val(args, i, "--strength")?)?,
                    "--strength",
                )?;
            }
            "--name" => {
                i += 1;
                set_once(&mut name, req_val(args, i, "--name")?, "--name")?;
            }
            "--value" => {
                i += 1;
                set_once(&mut value, ZeroizeStr(req_val(args, i, "--value")?), "--value")?;
            }
            "--query" => {
                i += 1;
                set_once(&mut query, req_val(args, i, "--query")?, "--query")?;
            }
            "--new-pass" => {
                i += 1;
                set_once(
                    &mut new_pass,
                    ZeroizeStr(req_val(args, i, "--new-pass")?),
                    "--new-pass",
                )?;
            }
            "--new-keyfile" => {
                i += 1;
                set_once(
                    &mut new_keyfile,
                    req_val(args, i, "--new-keyfile")?,
                    "--new-keyfile",
                )?;
            }
            "--new-strength" => {
                i += 1;
                set_once(
                    &mut new_strength,
                    KdfStrength::from_name(&req_val(args, i, "--new-strength")?)?,
                    "--new-strength",
                )?;
            }
            "--period" => {
                i += 1;
                let s = req_val(args, i, "--period")?;
                let p = s
                    .parse::<u64>()
                    .map_err(|_| WilisError::CliUsage(format!("invalid --period '{s}'")))?;
                set_once(&mut period, p, "--period")?;
            }
            "--digits" => {
                i += 1;
                let s = req_val(args, i, "--digits")?;
                let d = s
                    .parse::<u32>()
                    .map_err(|_| WilisError::CliUsage(format!("invalid --digits '{s}'")))?;
                set_once(&mut digits, d, "--digits")?;
            }
            "--out" => {
                i += 1;
                set_once(&mut out_path, req_val(args, i, "--out")?, "--out")?;
            }
            "--in" => {
                i += 1;
                set_once(&mut in_path, req_val(args, i, "--in")?, "--in")?;
            }
            "--merge" => {
                merge = true;
            }
            other => {
                return Err(WilisError::CliUsage(format!("unknown vault option '{other}'")));
            }
        }
        i += 1;
    }

    let vault_path = vault_file
        .ok_or_else(|| WilisError::CliUsage("missing required --file <VAULT.wils>".into()))?;
    if let Some(ref kf) = keyfile {
        if paths_refer_to_same_file(Path::new(kf), Path::new(&vault_path)) {
            return Err(WilisError::InvalidParameters(
                "vault file path must not overwrite the 2FA keyfile".into(),
            ));
        }
    }

    let action = match sub {
        "init" => {
            if name.is_some() || value.is_some() {
                return Err(WilisError::CliUsage(
                    "vault init does not accept --name or --value".into(),
                ));
            }
            VaultAction::Init
        }
        "set" => VaultAction::Set {
            name: name.ok_or_else(|| WilisError::CliUsage("vault set requires --name <KEY>".into()))?,
            value: value
                .ok_or_else(|| WilisError::CliUsage("vault set requires --value <VAL>".into()))?
                .into_inner(),
        },
        "get" => {
            if value.is_some() {
                return Err(WilisError::CliUsage(
                    "vault get does not accept --value".into(),
                ));
            }
            VaultAction::Get {
                name: name.ok_or_else(|| WilisError::CliUsage("vault get requires --name <KEY>".into()))?,
            }
        }
        "list" => {
            if name.is_some() || value.is_some() {
                return Err(WilisError::CliUsage(
                    "vault list does not accept --name or --value".into(),
                ));
            }
            VaultAction::List
        }
        "search" => {
            if name.is_some() || value.is_some() {
                return Err(WilisError::CliUsage(
                    "vault search uses --query, not --name or --value".into(),
                ));
            }
            VaultAction::Search {
                query: query
                    .ok_or_else(|| WilisError::CliUsage("vault search requires --query <TEXT>".into()))?,
            }
        }
        "del" | "delete" | "rm" => {
            if value.is_some() {
                return Err(WilisError::CliUsage(
                    "vault del does not accept --value".into(),
                ));
            }
            VaultAction::Delete {
                name: name.ok_or_else(|| WilisError::CliUsage("vault del requires --name <KEY>".into()))?,
            }
        }
        "rekey" => {
            let nkf = match new_keyfile {
                Some(ref p) => {
                    if paths_refer_to_same_file(Path::new(p), Path::new(&vault_path)) {
                        return Err(WilisError::InvalidParameters(
                            "vault file path must not overwrite --new-keyfile".into(),
                        ));
                    }
                    Some(hash_keyfile(p)?)
                }
                None => None,
            };
            let np = new_pass.map(|z| z.into_inner());
            if np.is_none() && nkf.is_none() && new_strength.is_none() && strength.is_none() {
                return Err(WilisError::CliUsage(
                    "vault rekey requires --new-pass, --new-keyfile, or --new-strength".into(),
                ));
            }
            VaultAction::Rekey {
                new_pass: np,
                new_keyfile_hash: nkf,
                new_strength,
            }
        }
        "totp" => VaultAction::Totp {
            name: name.ok_or_else(|| WilisError::CliUsage("vault totp requires --name <KEY>".into()))?,
            period: period.unwrap_or(30),
            digits: digits.unwrap_or(6),
        },
        "export" => VaultAction::Export {
            out_path: out_path
                .ok_or_else(|| WilisError::CliUsage("vault export requires --out <FILE>".into()))?,
        },
        "import" => VaultAction::Import {
            in_path: in_path
                .ok_or_else(|| WilisError::CliUsage("vault import requires --in <FILE>".into()))?,
            merge,
        },
        other => {
            return Err(WilisError::CliUsage(format!(
                "unknown vault subcommand '{other}' (expected: init, set, get, list, search, del, rekey, totp, export, import)"
            )));
        }
    };

    let confirm_pass = matches!(action, VaultAction::Init);
    let auth = resolve_auth(
        pass,
        pass_prompt,
        None,
        keyfile,
        strength.unwrap_or(KdfStrength::Interactive),
        confirm_pass,
    )?;
    Ok(Command::Vault {
        vault_path,
        auth,
        action,
        explicit_strength: strength,
    })
}

fn parse_sign_keygen(args: &[String]) -> Result<Command> {
    let mut out_prefix: Option<String> = None;
    let mut height: Option<u8> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                set_once(&mut out_prefix, req_val(args, i, "--out")?, "--out")?;
            }
            "--height" => {
                i += 1;
                let s = req_val(args, i, "--height")?;
                let h = s.parse::<u8>().map_err(|_| {
                    WilisError::CliUsage(format!("invalid --height '{s}' (expected integer 2..10)"))
                })?;
                set_once(&mut height, h, "--height")?;
            }
            other => {
                return Err(WilisError::CliUsage(format!("unknown option '{other}'")));
            }
        }
        i += 1;
    }
    let out_prefix =
        out_prefix.ok_or_else(|| WilisError::CliUsage("sign-keygen requires --out <PREFIX>".into()))?;
    Ok(Command::SignKeygen {
        out_prefix,
        height: height.unwrap_or(DEFAULT_TREE_HEIGHT),
    })
}

fn parse_sign_cmd(args: &[String], stateless: bool) -> Result<Command> {
    let mut sk: Option<String> = None;
    let mut input: Option<String> = None;
    let mut out: Option<String> = None;
    let mut armor = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--sk" => {
                i += 1;
                set_once(&mut sk, req_val(args, i, "--sk")?, "--sk")?;
            }
            "--in" => {
                i += 1;
                set_once(&mut input, req_val(args, i, "--in")?, "--in")?;
            }
            "--out" => {
                i += 1;
                set_once(&mut out, req_val(args, i, "--out")?, "--out")?;
            }
            "--armor" => {
                if armor {
                    return Err(WilisError::CliUsage("duplicate option '--armor'".into()));
                }
                armor = true;
            }
            other => return Err(WilisError::CliUsage(format!("unknown option '{other}'"))),
        }
        i += 1;
    }
    let label = if stateless { "slh-sign" } else { "sign" };
    let sk_path = sk.ok_or_else(|| WilisError::CliUsage(format!("{label} requires --sk <KEY>")))?;
    let input_path =
        input.ok_or_else(|| WilisError::CliUsage(format!("{label} requires --in <FILE>")))?;
    let sig_out_path =
        out.ok_or_else(|| WilisError::CliUsage(format!("{label} requires --out <SIG>")))?;

    if stateless {
        Ok(Command::SlhSign {
            sk_path,
            input_path,
            sig_out_path,
            armor,
        })
    } else {
        Ok(Command::SignFile {
            sk_path,
            input_path,
            sig_out_path,
            armor,
        })
    }
}

fn parse_verify_cmd(args: &[String], stateless: bool) -> Result<Command> {
    let mut pk: Option<String> = None;
    let mut input: Option<String> = None;
    let mut sig: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--pk" => {
                i += 1;
                set_once(&mut pk, req_val(args, i, "--pk")?, "--pk")?;
            }
            "--in" => {
                i += 1;
                set_once(&mut input, req_val(args, i, "--in")?, "--in")?;
            }
            "--sig" => {
                i += 1;
                set_once(&mut sig, req_val(args, i, "--sig")?, "--sig")?;
            }
            other => return Err(WilisError::CliUsage(format!("unknown option '{other}'"))),
        }
        i += 1;
    }
    let label = if stateless { "slh-verify" } else { "verify" };
    let pk_path = pk.ok_or_else(|| WilisError::CliUsage(format!("{label} requires --pk <KEY>")))?;
    let input_path =
        input.ok_or_else(|| WilisError::CliUsage(format!("{label} requires --in <FILE>")))?;
    let sig_path =
        sig.ok_or_else(|| WilisError::CliUsage(format!("{label} requires --sig <SIG>")))?;

    if stateless {
        Ok(Command::SlhVerify {
            pk_path,
            input_path,
            sig_path,
        })
    } else {
        Ok(Command::VerifyFile {
            pk_path,
            input_path,
            sig_path,
        })
    }
}

fn parse_split_key(args: &[String]) -> Result<Command> {
    let mut secret_hex: Option<ZeroizeStr> = None;
    let mut total: Option<u8> = None;
    let mut threshold: Option<u8> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--secret" => {
                i += 1;
                set_once(
                    &mut secret_hex,
                    ZeroizeStr(req_val(args, i, "--secret")?),
                    "--secret",
                )?;
            }
            "--total" | "-n" => {
                i += 1;
                let s = req_val(args, i, "--total")?;
                let v = s.parse::<u8>().map_err(|_| {
                    WilisError::CliUsage(format!("invalid --total '{s}' (expected 2..=255)"))
                })?;
                set_once(&mut total, v, "--total")?;
            }
            "--threshold" | "-k" => {
                i += 1;
                let s = req_val(args, i, "--threshold")?;
                let v = s.parse::<u8>().map_err(|_| {
                    WilisError::CliUsage(format!("invalid --threshold '{s}' (expected 2..=255)"))
                })?;
                set_once(&mut threshold, v, "--threshold")?;
            }
            other => return Err(WilisError::CliUsage(format!("unknown option '{other}'"))),
        }
        i += 1;
    }
    let total = total.ok_or_else(|| WilisError::CliUsage("split-key requires --total <N>".into()))?;
    let threshold = threshold
        .ok_or_else(|| WilisError::CliUsage("split-key requires --threshold <K>".into()))?;
    let secret_hex = secret_hex
        .ok_or_else(|| WilisError::CliUsage("split-key requires --secret <HEX>".into()))?
        .into_inner();
    Ok(Command::SplitKey {
        secret_hex,
        total,
        threshold,
    })
}

fn parse_combine_key(args: &[String]) -> Result<Command> {
    if args.len() < 2 {
        return Err(WilisError::CliUsage(
            "combine-key requires at least 2 share tokens".into(),
        ));
    }
    Ok(Command::CombineKey {
        shares: args.to_vec(),
    })
}

fn parse_mac_cmd(args: &[String], verify: bool) -> Result<Command> {
    let mut key: Option<SecretKey> = None;
    let mut tag_hex: Option<String> = None;
    let mut file_path: Option<String> = None;
    let mut text: Option<String> = None;

    let mut i = 0;
    let mut end_of_opts = false;
    while i < args.len() {
        let arg = args[i].as_str();
        if !end_of_opts {
            match arg {
                "--" => {
                    end_of_opts = true;
                    i += 1;
                    continue;
                }
                "--key" => {
                    i += 1;
                    set_once(&mut key, parse_raw_key(&req_val(args, i, "--key")?)?, "--key")?;
                    i += 1;
                    continue;
                }
                "--tag" if verify => {
                    i += 1;
                    set_once(&mut tag_hex, req_val(args, i, "--tag")?, "--tag")?;
                    i += 1;
                    continue;
                }
                "--file" => {
                    i += 1;
                    set_once(&mut file_path, req_val(args, i, "--file")?, "--file")?;
                    i += 1;
                    continue;
                }
                other if other.starts_with("--") => {
                    return Err(WilisError::CliUsage(format!("unknown option '{other}'")));
                }
                _ => {}
            }
        }
        if text.is_some() {
            return Err(WilisError::CliUsage(
                "unexpected extra positional argument".into(),
            ));
        }
        text = Some(arg.to_string());
        i += 1;
    }

    if file_path.is_some() == text.is_some() {
        return Err(WilisError::CliUsage(
            "mac requires exactly one of --file <FILE|-> or <TEXT>".into(),
        ));
    }

    let key = key.ok_or_else(|| WilisError::CliUsage("missing required --key <64-HEX>".into()))?;
    if verify {
        let tag_hex =
            tag_hex.ok_or_else(|| WilisError::CliUsage("mac-verify requires --tag <64-HEX>".into()))?;
        Ok(Command::MacVerify {
            key,
            tag_hex,
            file_path,
            text,
        })
    } else {
        Ok(Command::Mac {
            key,
            file_path,
            text,
        })
    }
}

fn parse_rand_cmd(args: &[String]) -> Result<Command> {
    let mut bytes: Option<usize> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bytes" | "-n" => {
                i += 1;
                let s = req_val(args, i, "--bytes")?;
                let b = s
                    .parse::<usize>()
                    .map_err(|_| WilisError::CliUsage(format!("invalid --bytes '{s}'")))?;
                set_once(&mut bytes, b, "--bytes")?;
            }
            other => return Err(WilisError::CliUsage(format!("unknown option '{other}'"))),
        }
        i += 1;
    }
    Ok(Command::Rand {
        bytes: bytes.unwrap_or(32),
    })
}

fn parse_hash_cmd(args: &[String]) -> Result<Command> {
    if args.is_empty() {
        return Err(WilisError::CliUsage(
            "hash requires either --file <FILE|-> or <TEXT>".into(),
        ));
    }
    if args[0] == "--file" {
        if args.len() != 2 {
            return Err(WilisError::CliUsage(
                "hash --file expects exactly one <FILE|-> path".into(),
            ));
        }
        Ok(Command::HashFile {
            path: args[1].clone(),
        })
    } else if args[0] == "--" {
        if args.len() != 2 {
            return Err(WilisError::CliUsage(
                "hash -- expects exactly one <TEXT> argument".into(),
            ));
        }
        Ok(Command::HashText {
            text: args[1].clone(),
        })
    } else if args[0].starts_with("--") {
        Err(WilisError::CliUsage(format!(
            "unknown hash option '{}'",
            args[0]
        )))
    } else if args.len() != 1 {
        Err(WilisError::CliUsage(
            "unexpected extra argument for hash".into(),
        ))
    } else {
        Ok(Command::HashText {
            text: args[0].clone(),
        })
    }
}

fn parse_passgen_cmd(args: &[String]) -> Result<Command> {
    let mut length: Option<usize> = None;
    let mut words: Option<usize> = None;
    let mut count: Option<usize> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--length" | "-l" => {
                i += 1;
                let v = req_val(args, i, "--length")?
                    .parse::<usize>()
                    .map_err(|_| WilisError::CliUsage("invalid --length".into()))?;
                set_once(&mut length, v, "--length")?;
            }
            "--words" | "-w" => {
                i += 1;
                let v = req_val(args, i, "--words")?
                    .parse::<usize>()
                    .map_err(|_| WilisError::CliUsage("invalid --words".into()))?;
                set_once(&mut words, v, "--words")?;
            }
            "--count" | "-c" => {
                i += 1;
                let v = req_val(args, i, "--count")?
                    .parse::<usize>()
                    .map_err(|_| WilisError::CliUsage("invalid --count".into()))?;
                set_once(&mut count, v, "--count")?;
            }
            other => return Err(WilisError::CliUsage(format!("unknown passgen option '{other}'"))),
        }
        i += 1;
    }
    if length.is_some() && words.is_some() {
        return Err(WilisError::CliUsage(
            "cannot combine --length (password) with --words (passphrase)".into(),
        ));
    }
    let (mode, len) = match words {
        Some(w) => (PassgenMode::Words, w),
        None => (PassgenMode::Password, length.unwrap_or(24)),
    };
    Ok(Command::Passgen {
        mode,
        length: len,
        count: count.unwrap_or(1),
    })
}

fn parse_mnemonic_cmd(args: &[String]) -> Result<Command> {
    if args.is_empty() {
        return Err(WilisError::CliUsage(
            "mnemonic requires a subcommand: encode or decode".into(),
        ));
    }
    match args[0].as_str() {
        "encode" => {
            if args.len() == 3 && args[1] == "--key" {
                Ok(Command::MnemonicEncode {
                    key_hex: ZeroizeStr(args[2].clone()),
                })
            } else {
                Err(WilisError::CliUsage(
                    "mnemonic encode requires --key <64-HEX>".into(),
                ))
            }
        }
        "decode" => {
            if args.len() < 2 {
                return Err(WilisError::CliUsage(
                    "mnemonic decode requires <34 WORDS>".into(),
                ));
            }
            Ok(Command::MnemonicDecode {
                phrase: ZeroizeStr(args[1..].join(" ")),
            })
        }
        other => Err(WilisError::CliUsage(format!(
            "unknown mnemonic subcommand '{other}' (expected encode or decode)"
        ))),
    }
}

fn parse_keywrap_cmd(args: &[String], protect: bool) -> Result<Command> {
    let mut in_path: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut pass: Option<ZeroizeStr> = None;
    let mut pass_prompt = false;
    let mut keyfile: Option<String> = None;
    let mut strength: Option<KdfStrength> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--in" => {
                i += 1;
                set_once(&mut in_path, req_val(args, i, "--in")?, "--in")?;
            }
            "--out" => {
                i += 1;
                set_once(&mut out_path, req_val(args, i, "--out")?, "--out")?;
            }
            "--pass" => {
                i += 1;
                set_once(&mut pass, ZeroizeStr(req_val(args, i, "--pass")?), "--pass")?;
            }
            "--pass-prompt" => {
                pass_prompt = true;
            }
            "--keyfile" => {
                i += 1;
                set_once(&mut keyfile, req_val(args, i, "--keyfile")?, "--keyfile")?;
            }
            "--strength" => {
                i += 1;
                set_once(
                    &mut strength,
                    KdfStrength::from_name(&req_val(args, i, "--strength")?)?,
                    "--strength",
                )?;
            }
            other => return Err(WilisError::CliUsage(format!("unknown option '{other}'"))),
        }
        i += 1;
    }
    let in_path = in_path.ok_or_else(|| WilisError::CliUsage("missing --in <FILE>".into()))?;
    let out_path = out_path.ok_or_else(|| WilisError::CliUsage("missing --out <FILE>".into()))?;
    let auth = resolve_auth(
        pass,
        pass_prompt,
        None,
        keyfile,
        strength.unwrap_or(KdfStrength::Interactive),
        protect,
    )?;
    if protect {
        Ok(Command::KeyProtect {
            in_path,
            out_path,
            auth,
        })
    } else {
        Ok(Command::KeyUnlock {
            in_path,
            out_path,
            auth,
        })
    }
}

fn parse_keyring_cmd(args: &[String]) -> Result<Command> {
    if args.is_empty() {
        return Err(WilisError::CliUsage(
            "keyring requires a subcommand: add, list, revoke, remove, export".into(),
        ));
    }
    let sub = args[0].as_str();
    let mut file_path: Option<String> = None;
    let mut name: Option<String> = None;
    let mut pk_path: Option<String> = None;
    let mut expires_days: Option<u64> = None;
    let mut reason: Option<String> = None;
    let mut out_path: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--file" => {
                i += 1;
                set_once(&mut file_path, req_val(args, i, "--file")?, "--file")?;
            }
            "--name" => {
                i += 1;
                set_once(&mut name, req_val(args, i, "--name")?, "--name")?;
            }
            "--pk" => {
                i += 1;
                set_once(&mut pk_path, req_val(args, i, "--pk")?, "--pk")?;
            }
            "--expires-days" => {
                i += 1;
                let v = req_val(args, i, "--expires-days")?
                    .parse::<u64>()
                    .map_err(|_| WilisError::CliUsage("invalid --expires-days".into()))?;
                set_once(&mut expires_days, v, "--expires-days")?;
            }
            "--reason" => {
                i += 1;
                set_once(&mut reason, req_val(args, i, "--reason")?, "--reason")?;
            }
            "--out" => {
                i += 1;
                set_once(&mut out_path, req_val(args, i, "--out")?, "--out")?;
            }
            other => return Err(WilisError::CliUsage(format!("unknown keyring option '{other}'"))),
        }
        i += 1;
    }

    let file_path =
        file_path.ok_or_else(|| WilisError::CliUsage("keyring requires --file <RING.wkrn>".into()))?;
    let action = match sub {
        "add" => KeyringAction::Add {
            name: name.ok_or_else(|| WilisError::CliUsage("keyring add requires --name <N>".into()))?,
            pk_path: pk_path
                .ok_or_else(|| WilisError::CliUsage("keyring add requires --pk <FILE>".into()))?,
            expires_days,
        },
        "list" => KeyringAction::List,
        "revoke" => KeyringAction::Revoke {
            name: name
                .ok_or_else(|| WilisError::CliUsage("keyring revoke requires --name <N>".into()))?,
            reason: reason.unwrap_or_else(|| "revoked".into()),
        },
        "remove" | "rm" | "del" => KeyringAction::Remove {
            name: name
                .ok_or_else(|| WilisError::CliUsage("keyring remove requires --name <N>".into()))?,
        },
        "export" => KeyringAction::Export {
            name: name
                .ok_or_else(|| WilisError::CliUsage("keyring export requires --name <N>".into()))?,
            out_path: out_path
                .ok_or_else(|| WilisError::CliUsage("keyring export requires --out <FILE>".into()))?,
        },
        other => {
            return Err(WilisError::CliUsage(format!(
                "unknown keyring subcommand '{other}'"
            )));
        }
    };
    Ok(Command::Keyring { file_path, action })
}

fn parse_stego_cmd(args: &[String]) -> Result<Command> {
    if args.is_empty() {
        return Err(WilisError::CliUsage(
            "stego requires a subcommand: capacity, embed, extract".into(),
        ));
    }
    let sub = args[0].as_str();
    let mut cover: Option<String> = None;
    let mut in_file: Option<String> = None;
    let mut out_file: Option<String> = None;
    let mut key: Option<SecretKey> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--cover" => {
                i += 1;
                set_once(&mut cover, req_val(args, i, "--cover")?, "--cover")?;
            }
            "--in" => {
                i += 1;
                set_once(&mut in_file, req_val(args, i, "--in")?, "--in")?;
            }
            "--out" => {
                i += 1;
                set_once(&mut out_file, req_val(args, i, "--out")?, "--out")?;
            }
            "--key" => {
                i += 1;
                set_once(&mut key, parse_raw_key(&req_val(args, i, "--key")?)?, "--key")?;
            }
            other => return Err(WilisError::CliUsage(format!("unknown stego option '{other}'"))),
        }
        i += 1;
    }

    let action = match sub {
        "capacity" => StegoAction::Capacity {
            cover: cover
                .ok_or_else(|| WilisError::CliUsage("stego capacity requires --cover <FILE>".into()))?,
        },
        "embed" => StegoAction::Embed {
            cover: cover
                .ok_or_else(|| WilisError::CliUsage("stego embed requires --cover <FILE>".into()))?,
            in_file: in_file
                .ok_or_else(|| WilisError::CliUsage("stego embed requires --in <FILE>".into()))?,
            out_file: out_file
                .ok_or_else(|| WilisError::CliUsage("stego embed requires --out <FILE>".into()))?,
            key: key
                .ok_or_else(|| WilisError::CliUsage("stego embed requires --key <64-HEX>".into()))?,
        },
        "extract" => StegoAction::Extract {
            in_file: in_file
                .ok_or_else(|| WilisError::CliUsage("stego extract requires --in <FILE>".into()))?,
            out_file: out_file
                .ok_or_else(|| WilisError::CliUsage("stego extract requires --out <FILE>".into()))?,
            key: key
                .ok_or_else(|| WilisError::CliUsage("stego extract requires --key <64-HEX>".into()))?,
        },
        other => {
            return Err(WilisError::CliUsage(format!(
                "unknown stego subcommand '{other}'"
            )));
        }
    };
    Ok(Command::Stego { action })
}

fn parse_hidden_cmd(args: &[String]) -> Result<Command> {
    if args.is_empty() {
        return Err(WilisError::CliUsage(
            "hidden requires a subcommand: create or open".into(),
        ));
    }
    let sub = args[0].as_str();
    let mut in_file: Option<String> = None;
    let mut out_file: Option<String> = None;
    let mut size: Option<usize> = None;
    let mut decoy_pass: Option<ZeroizeStr> = None;
    let mut decoy_in: Option<String> = None;
    let mut hidden_pass: Option<ZeroizeStr> = None;
    let mut hidden_in: Option<String> = None;
    let mut pass: Option<ZeroizeStr> = None;
    let mut strength: Option<KdfStrength> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--in" => {
                i += 1;
                set_once(&mut in_file, req_val(args, i, "--in")?, "--in")?;
            }
            "--out" => {
                i += 1;
                set_once(&mut out_file, req_val(args, i, "--out")?, "--out")?;
            }
            "--size" => {
                i += 1;
                let v = req_val(args, i, "--size")?
                    .parse::<usize>()
                    .map_err(|_| WilisError::CliUsage("invalid --size".into()))?;
                set_once(&mut size, v, "--size")?;
            }
            "--decoy-pass" => {
                i += 1;
                set_once(
                    &mut decoy_pass,
                    ZeroizeStr(req_val(args, i, "--decoy-pass")?),
                    "--decoy-pass",
                )?;
            }
            "--decoy-in" => {
                i += 1;
                set_once(&mut decoy_in, req_val(args, i, "--decoy-in")?, "--decoy-in")?;
            }
            "--hidden-pass" => {
                i += 1;
                set_once(
                    &mut hidden_pass,
                    ZeroizeStr(req_val(args, i, "--hidden-pass")?),
                    "--hidden-pass",
                )?;
            }
            "--hidden-in" => {
                i += 1;
                set_once(&mut hidden_in, req_val(args, i, "--hidden-in")?, "--hidden-in")?;
            }
            "--pass" => {
                i += 1;
                set_once(&mut pass, ZeroizeStr(req_val(args, i, "--pass")?), "--pass")?;
            }
            "--strength" => {
                i += 1;
                set_once(
                    &mut strength,
                    KdfStrength::from_name(&req_val(args, i, "--strength")?)?,
                    "--strength",
                )?;
            }
            other => return Err(WilisError::CliUsage(format!("unknown hidden option '{other}'"))),
        }
        i += 1;
    }

    match sub {
        "create" => Ok(Command::HiddenCreate {
            out_file: out_file
                .ok_or_else(|| WilisError::CliUsage("hidden create requires --out <FILE>".into()))?,
            size: size.unwrap_or(65_536),
            decoy_pass: decoy_pass
                .ok_or_else(|| WilisError::CliUsage("hidden create requires --decoy-pass".into()))?,
            decoy_in: decoy_in
                .ok_or_else(|| WilisError::CliUsage("hidden create requires --decoy-in".into()))?,
            hidden_pass: hidden_pass
                .ok_or_else(|| WilisError::CliUsage("hidden create requires --hidden-pass".into()))?,
            hidden_in: hidden_in
                .ok_or_else(|| WilisError::CliUsage("hidden create requires --hidden-in".into()))?,
            strength: strength.unwrap_or(KdfStrength::Interactive),
        }),
        "open" => Ok(Command::HiddenOpen {
            in_file: in_file
                .ok_or_else(|| WilisError::CliUsage("hidden open requires --in <FILE>".into()))?,
            out_file: out_file
                .ok_or_else(|| WilisError::CliUsage("hidden open requires --out <FILE>".into()))?,
            pass: pass
                .ok_or_else(|| WilisError::CliUsage("hidden open requires --pass <P>".into()))?,
            strength: strength.unwrap_or(KdfStrength::Interactive),
        }),
        other => Err(WilisError::CliUsage(format!(
            "unknown hidden subcommand '{other}' (expected create or open)"
        ))),
    }
}

fn parse_send_cmd(args: &[String]) -> Result<Command> {
    let mut addr: Option<String> = None;
    let mut file_path: Option<String> = None;
    let mut pass: Option<ZeroizeStr> = None;
    let mut strength: Option<KdfStrength> = None;
    let mut sign_sk: Option<String> = None;
    let mut peer_pk: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => {
                i += 1;
                set_once(&mut addr, req_val(args, i, "--addr")?, "--addr")?;
            }
            "--in" => {
                i += 1;
                set_once(&mut file_path, req_val(args, i, "--in")?, "--in")?;
            }
            "--pass" => {
                i += 1;
                set_once(&mut pass, ZeroizeStr(req_val(args, i, "--pass")?), "--pass")?;
            }
            "--strength" => {
                i += 1;
                set_once(
                    &mut strength,
                    KdfStrength::from_name(&req_val(args, i, "--strength")?)?,
                    "--strength",
                )?;
            }
            "--sign-sk" => {
                i += 1;
                set_once(&mut sign_sk, req_val(args, i, "--sign-sk")?, "--sign-sk")?;
            }
            "--peer-pk" => {
                i += 1;
                set_once(&mut peer_pk, req_val(args, i, "--peer-pk")?, "--peer-pk")?;
            }
            other => return Err(WilisError::CliUsage(format!("unknown send option '{other}'"))),
        }
        i += 1;
    }

    let addr = addr.ok_or_else(|| WilisError::CliUsage("send requires --addr <HOST:PORT>".into()))?;
    let file_path =
        file_path.ok_or_else(|| WilisError::CliUsage("send requires --in <FILE>".into()))?;
    let mode = if let Some(p) = pass {
        NetAuthMode::Pake {
            passphrase: p.into_inner(),
            strength: strength.unwrap_or(KdfStrength::Interactive),
        }
    } else if let (Some(sk), Some(pk)) = (sign_sk, peer_pk) {
        NetAuthMode::PkiSend {
            sign_sk_path: sk,
            peer_kem_pk_path: pk,
        }
    } else {
        return Err(WilisError::CliUsage(
            "send requires either --pass <P> (PAKE) or --sign-sk <F.wsk> --peer-pk <F.wkp>".into(),
        ));
    };

    Ok(Command::Send {
        addr,
        file_path,
        mode,
    })
}

fn parse_recv_cmd(args: &[String]) -> Result<Command> {
    let mut listen: Option<String> = None;
    let mut out_dir: Option<String> = None;
    let mut pass: Option<ZeroizeStr> = None;
    let mut kem_sk: Option<String> = None;
    let mut peer_vk: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                i += 1;
                set_once(&mut listen, req_val(args, i, "--listen")?, "--listen")?;
            }
            "--out-dir" => {
                i += 1;
                set_once(&mut out_dir, req_val(args, i, "--out-dir")?, "--out-dir")?;
            }
            "--pass" => {
                i += 1;
                set_once(&mut pass, ZeroizeStr(req_val(args, i, "--pass")?), "--pass")?;
            }
            "--kem-sk" => {
                i += 1;
                set_once(&mut kem_sk, req_val(args, i, "--kem-sk")?, "--kem-sk")?;
            }
            "--peer-vk" => {
                i += 1;
                set_once(&mut peer_vk, req_val(args, i, "--peer-vk")?, "--peer-vk")?;
            }
            other => return Err(WilisError::CliUsage(format!("unknown recv option '{other}'"))),
        }
        i += 1;
    }

    let listen_addr =
        listen.ok_or_else(|| WilisError::CliUsage("recv requires --listen <HOST:PORT>".into()))?;
    let out_dir =
        out_dir.ok_or_else(|| WilisError::CliUsage("recv requires --out-dir <DIR>".into()))?;
    let mode = if let Some(p) = pass {
        NetAuthMode::Pake {
            passphrase: p.into_inner(),
            strength: KdfStrength::Interactive,
        }
    } else if let (Some(sk), Some(vk)) = (kem_sk, peer_vk) {
        NetAuthMode::PkiRecv {
            kem_sk_path: sk,
            peer_vk_path: vk,
        }
    } else {
        return Err(WilisError::CliUsage(
            "recv requires either --pass <P> (PAKE) or --kem-sk <F.wks> --peer-vk <F.wpk>".into(),
        ));
    };

    Ok(Command::Recv {
        listen_addr,
        out_dir,
        mode,
    })
}

fn parse_ratchet_cmd(args: &[String]) -> Result<Command> {
    if args.is_empty() {
        return Err(WilisError::CliUsage(
            "ratchet requires a subcommand: init, accept, encrypt, decrypt, rekey, apply-rekey"
                .into(),
        ));
    }
    let sub = args[0].as_str();
    let mut state: Option<String> = None;
    let mut pass: Option<ZeroizeStr> = None;
    let mut pass_prompt = false;
    let mut keyfile: Option<String> = None;
    let mut strength: Option<KdfStrength> = None;
    let mut sign_sk: Option<String> = None;
    let mut kem_sk: Option<String> = None;
    let mut peer_pk: Option<String> = None;
    let mut peer_vk: Option<String> = None;
    let mut in_path: Option<String> = None;
    let mut out_path: Option<String> = None;
    let mut aad: Option<String> = None;
    let mut context: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--state" => {
                i += 1;
                set_once(&mut state, req_val(args, i, "--state")?, "--state")?;
            }
            "--pass" => {
                i += 1;
                set_once(&mut pass, ZeroizeStr(req_val(args, i, "--pass")?), "--pass")?;
            }
            "--pass-prompt" => {
                pass_prompt = true;
            }
            "--keyfile" => {
                i += 1;
                set_once(&mut keyfile, req_val(args, i, "--keyfile")?, "--keyfile")?;
            }
            "--strength" => {
                i += 1;
                set_once(
                    &mut strength,
                    KdfStrength::from_name(&req_val(args, i, "--strength")?)?,
                    "--strength",
                )?;
            }
            "--sign-sk" => {
                i += 1;
                set_once(&mut sign_sk, req_val(args, i, "--sign-sk")?, "--sign-sk")?;
            }
            "--kem-sk" => {
                i += 1;
                set_once(&mut kem_sk, req_val(args, i, "--kem-sk")?, "--kem-sk")?;
            }
            "--peer-pk" => {
                i += 1;
                set_once(&mut peer_pk, req_val(args, i, "--peer-pk")?, "--peer-pk")?;
            }
            "--peer-vk" => {
                i += 1;
                set_once(&mut peer_vk, req_val(args, i, "--peer-vk")?, "--peer-vk")?;
            }
            "--in" => {
                i += 1;
                set_once(&mut in_path, req_val(args, i, "--in")?, "--in")?;
            }
            "--out" => {
                i += 1;
                set_once(&mut out_path, req_val(args, i, "--out")?, "--out")?;
            }
            "--aad" => {
                i += 1;
                set_once(&mut aad, req_val(args, i, "--aad")?, "--aad")?;
            }
            "--context" => {
                i += 1;
                set_once(&mut context, req_val(args, i, "--context")?, "--context")?;
            }
            other => return Err(WilisError::CliUsage(format!("unknown ratchet option '{other}'"))),
        }
        i += 1;
    }

    let state_path =
        state.ok_or_else(|| WilisError::CliUsage("ratchet requires --state <FILE.wrst>".into()))?;
    let action = match sub {
        "init" => RatchetAction::Init {
            sign_sk_path: sign_sk
                .ok_or_else(|| WilisError::CliUsage("ratchet init requires --sign-sk".into()))?,
            peer_kem_pk_path: peer_pk
                .ok_or_else(|| WilisError::CliUsage("ratchet init requires --peer-pk".into()))?,
            handshake_out: out_path
                .ok_or_else(|| WilisError::CliUsage("ratchet init requires --out <HS.whsh>".into()))?,
            context: context.unwrap_or_else(|| "wilis-ratchet-v1".into()),
        },
        "accept" => RatchetAction::Accept {
            kem_sk_path: kem_sk
                .ok_or_else(|| WilisError::CliUsage("ratchet accept requires --kem-sk".into()))?,
            peer_vk_path: peer_vk
                .ok_or_else(|| WilisError::CliUsage("ratchet accept requires --peer-vk".into()))?,
            handshake_in: in_path
                .ok_or_else(|| WilisError::CliUsage("ratchet accept requires --in <HS.whsh>".into()))?,
            context: context.unwrap_or_else(|| "wilis-ratchet-v1".into()),
        },
        "encrypt" => RatchetAction::Encrypt {
            in_path: in_path
                .ok_or_else(|| WilisError::CliUsage("ratchet encrypt requires --in <FILE>".into()))?,
            out_path: out_path
                .ok_or_else(|| WilisError::CliUsage("ratchet encrypt requires --out <PKT>".into()))?,
            aad: aad.unwrap_or_default(),
        },
        "decrypt" => RatchetAction::Decrypt {
            in_path: in_path
                .ok_or_else(|| WilisError::CliUsage("ratchet decrypt requires --in <PKT>".into()))?,
            out_path: out_path
                .ok_or_else(|| WilisError::CliUsage("ratchet decrypt requires --out <FILE>".into()))?,
            aad: aad.unwrap_or_default(),
        },
        "rekey" => RatchetAction::Rekey {
            out_path: out_path
                .ok_or_else(|| WilisError::CliUsage("ratchet rekey requires --out <REKEY>".into()))?,
        },
        "apply-rekey" => RatchetAction::ApplyRekey {
            in_path: in_path
                .ok_or_else(|| WilisError::CliUsage("ratchet apply-rekey requires --in <REKEY>".into()))?,
        },
        other => {
            return Err(WilisError::CliUsage(format!(
                "unknown ratchet subcommand '{other}'"
            )));
        }
    };

    let is_new = matches!(action, RatchetAction::Init { .. } | RatchetAction::Accept { .. });
    let auth = resolve_auth(
        pass,
        pass_prompt,
        None,
        keyfile,
        strength.unwrap_or(KdfStrength::Interactive),
        is_new,
    )?;
    Ok(Command::Ratchet {
        state_path,
        auth,
        action,
    })
}

fn parse_inspect_cmd(args: &[String]) -> Result<Command> {
    if args.len() != 1 {
        return Err(WilisError::CliUsage("inspect requires exactly one <FILE> path".into()));
    }
    Ok(Command::Inspect {
        path: args[0].clone(),
    })
}

fn parse_shred_cmd(args: &[String]) -> Result<Command> {
    let mut file: Option<String> = None;
    let mut passes: Option<usize> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--file" => {
                i += 1;
                set_once(&mut file, req_val(args, i, "--file")?, "--file")?;
            }
            "--passes" => {
                i += 1;
                let v = req_val(args, i, "--passes")?
                    .parse::<usize>()
                    .map_err(|_| WilisError::CliUsage("invalid --passes".into()))?;
                set_once(&mut passes, v, "--passes")?;
            }
            other => return Err(WilisError::CliUsage(format!("unknown shred option '{other}'"))),
        }
        i += 1;
    }
    Ok(Command::Shred {
        path: file.ok_or_else(|| WilisError::CliUsage("shred requires --file <FILE>".into()))?,
        passes: passes.unwrap_or(3),
    })
}

fn parse_completions_cmd(args: &[String]) -> Result<Command> {
    if args.len() != 1 {
        return Err(WilisError::CliUsage(
            "completions requires <bash|zsh|fish|powershell>".into(),
        ));
    }
    Ok(Command::Completions {
        shell: args[0].clone(),
    })
}

fn req_val(args: &[String], idx: usize, flag: &str) -> Result<String> {
    args.get(idx)
        .cloned()
        .ok_or_else(|| WilisError::CliUsage(format!("missing value for {flag}")))
}
