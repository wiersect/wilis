//! Post-Quantum Encrypted Framed TCP Channel (`WNET` v1) & P2P File Transfer (`wilis send` / `wilis recv`).
//!
//! Wire security guarantees:
//! - Strict frame length limit (`MAX_NET_FRAME_BYTES = 1 MiB`) preventing memory-exhaustion DoS.
//! - Two mutual authentication modes:
//!   1. **PKI Mode (`connect` / `accept`)**: `WilisHandshake` (`WHSH` v1 = `WilisKEM` + `WilisSign`)
//!      followed by encrypted responder key-confirmation (`WNET-ACK-V1`).
//!   2. **Zero-PKI PAKE Mode (`connect_pake` / `accept_pake`)**: `WilisPAKE` mutual password-authenticated
//!      key exchange + authenticated exchange of ephemeral `WilisKEM` public keys to bootstrap full
//!      `PqRatchetSession` PCS protection over a single shared passphrase!
//! - Automatic Post-Compromise Security (`WPRK` v1) KEM ratchet rekey every `AUTO_REKEY_INTERVAL` messages.
//! - Authenticated EOF frame (`WNET-EOF-V1`) + full-file `WilisHash-256` verification + atomic `O_EXCL`
//!   file commit with basename sanitization (completely preventing Zip-Slip / path traversal).

use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::aead::{open, seal};
use crate::archive::unpack::sanitize_archive_path;
use crate::core::constants::{HASH_BYTES, NONCE_BYTES, SALT_BYTES, TAG_BYTES};
use crate::error::{Result, WilisError};
use crate::hash::WilisHash;
use crate::kdf::KdfParams;
use crate::kem::{keygen, KemCiphertext, KemPublicKey, KemSecretKey, KEM_CT_BYTES, KEM_PK_BYTES};
use crate::protocols::pake::{
    pake_client_finish, pake_client_start, pake_server_finish, pake_server_respond,
    PakeClientFinish, PakeClientHello, PakeServerHello,
};
use crate::ratchet::{HandshakeInit, PqMessagePacket, PqRatchetSession, PqRekeyPacket};
use crate::sign::{SigningKey, VerifyingKey};
use crate::utils::constant_time::ct_eq;
use crate::utils::random::generate_nonce;
use crate::utils::zeroize::{create_unique_temp_file, zeroize_bytes};

const FRAME_HANDSHAKE: u8 = 0x01;
const FRAME_DATA: u8 = 0x02;
const FRAME_REKEY: u8 = 0x03;
const FRAME_EOF: u8 = 0x04;
const FRAME_PAKE_1: u8 = 0x11;
const FRAME_PAKE_2: u8 = 0x12;
const FRAME_PAKE_3: u8 = 0x13;
const FRAME_EPHEMERAL_PK: u8 = 0x14;

const MAX_NET_FRAME_BYTES: usize = 1024 * 1024;
const FILE_CHUNK_BYTES: usize = 64 * 1024;
const AUTO_REKEY_INTERVAL: u64 = 32;
const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(30);

const ACK_TOKEN: &[u8] = b"WNET-ACK-V1";
const EOF_TOKEN: &[u8] = b"WNET-EOF-V1";
const NET_AAD: &[u8] = b"WNET-DATA-V1";
const PAKE_PK_AAD_C2S: &[u8] = b"WNET-PAKE-PK-C2S-V1";
const PAKE_PK_AAD_S2C: &[u8] = b"WNET-PAKE-PK-S2C-V1";

fn write_frame<W: Write>(stream: &mut W, frame_type: u8, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_NET_FRAME_BYTES {
        return Err(WilisError::InvalidParameters(
            "network frame payload exceeds 1 MiB ceiling".into(),
        ));
    }
    let mut hdr = [0u8; 5];
    hdr[0] = frame_type;
    hdr[1..5].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    stream.write_all(&hdr)?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

fn read_frame<R: Read>(stream: &mut R) -> Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    stream.read_exact(&mut hdr).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            WilisError::InvalidFormat("unexpected EOF reading WNET frame header".into())
        } else {
            WilisError::Io(e)
        }
    })?;
    let frame_type = hdr[0];
    let len = u32::from_le_bytes(hdr[1..5].try_into().expect("4 bytes")) as usize;
    if len > MAX_NET_FRAME_BYTES {
        return Err(WilisError::InvalidFormat(format!(
            "WNET frame length {len} exceeds maximum allowed ({MAX_NET_FRAME_BYTES})"
        )));
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                WilisError::InvalidFormat("truncated WNET frame payload".into())
            } else {
                WilisError::Io(e)
            }
        })?;
    }
    Ok((frame_type, payload))
}

fn configure_stream(stream: &TcpStream) {
    let _ = stream.set_read_timeout(Some(DEFAULT_IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(DEFAULT_IO_TIMEOUT));
    let _ = stream.set_nodelay(true);
}

fn seal_pake_box(key: &[u8; 32], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>> {
    let nonce = generate_nonce()?;
    let (ct, tag) = seal(key, &nonce, aad, pt);
    let mut out = Vec::with_capacity(NONCE_BYTES + ct.len() + TAG_BYTES);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&tag);
    Ok(out)
}

fn open_pake_box(key: &[u8; 32], aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < NONCE_BYTES + TAG_BYTES {
        return Err(WilisError::InvalidFormat("truncated PAKE encrypted frame".into()));
    }
    let nonce: [u8; NONCE_BYTES] = data[0..NONCE_BYTES].try_into().expect("24 bytes");
    let tag_start = data.len() - TAG_BYTES;
    let ct = &data[NONCE_BYTES..tag_start];
    let tag: [u8; TAG_BYTES] = data[tag_start..].try_into().expect("32 bytes");
    open(key, &nonce, aad, ct, &tag)
}

/// Authenticated Post-Quantum Encrypted TCP Channel backed by `PqRatchetSession`.
pub struct PqTcpChannel {
    stream: TcpStream,
    session: PqRatchetSession,
    msgs_since_rekey: u64,
}

impl PqTcpChannel {
    /// Initiates a mutually authenticated PQ TCP connection (`WilisKEM` + `WilisSign`).
    pub fn connect(
        addr: &str,
        initiator_sign_sk: &mut SigningKey,
        responder_kem_pk: &KemPublicKey,
        context: &[u8],
    ) -> Result<Self> {
        let mut stream = TcpStream::connect(addr)?;
        configure_stream(&stream);

        let (mut session, init) =
            PqRatchetSession::initiate_handshake(initiator_sign_sk, responder_kem_pk, context)?;
        write_frame(&mut stream, FRAME_HANDSHAKE, &init.to_bytes())?;

        // Wait for encrypted responder ACK confirming mutual key agreement
        let (ft, payload) = read_frame(&mut stream)?;
        if ft != FRAME_DATA {
            return Err(WilisError::AuthenticationFailed);
        }
        let pkt = PqMessagePacket::from_bytes(&payload)?;
        let ack = session.decrypt_packet(&pkt, NET_AAD)?;
        if !ct_eq(&ack, ACK_TOKEN) {
            return Err(WilisError::AuthenticationFailed);
        }

        Ok(Self {
            stream,
            session,
            msgs_since_rekey: 0,
        })
    }

    /// Accepts an incoming mutually authenticated PQ TCP connection (`WilisKEM` + `WilisSign`).
    pub fn accept(
        mut stream: TcpStream,
        responder_kem_sk: &KemSecretKey,
        initiator_vk: &VerifyingKey,
        context: &[u8],
    ) -> Result<Self> {
        configure_stream(&stream);

        let (ft, payload) = read_frame(&mut stream)?;
        if ft != FRAME_HANDSHAKE {
            return Err(WilisError::AuthenticationFailed);
        }
        let init = HandshakeInit::from_bytes(&payload)?;
        let mut session =
            PqRatchetSession::accept_handshake(responder_kem_sk, initiator_vk, &init, context)?;

        let ack_pkt = session.encrypt_next(ACK_TOKEN, NET_AAD);
        write_frame(&mut stream, FRAME_DATA, &ack_pkt.to_bytes())?;

        Ok(Self {
            stream,
            session,
            msgs_since_rekey: 0,
        })
    }

    /// Initiates a zero-PKI passphrase-authenticated PQ TCP channel using `WilisPAKE` + `PqRatchetSession`.
    pub fn connect_pake(
        addr: &str,
        passphrase: &[u8],
        context: &[u8],
        kdf_params: KdfParams,
    ) -> Result<Self> {
        let mut stream = TcpStream::connect(addr)?;
        configure_stream(&stream);

        let (client_state, hello) = pake_client_start(passphrase, context, kdf_params)?;
        let mut m1 = Vec::with_capacity(SALT_BYTES + 8 + hello.masked_pk.len());
        m1.extend_from_slice(&hello.salt);
        m1.extend_from_slice(&hello.kdf_params.memory_blocks.to_le_bytes());
        m1.extend_from_slice(&hello.kdf_params.passes.to_le_bytes());
        m1.extend_from_slice(&hello.masked_pk);
        write_frame(&mut stream, FRAME_PAKE_1, &m1)?;

        let (ft, m2) = read_frame(&mut stream)?;
        if ft != FRAME_PAKE_2 || m2.len() != KEM_CT_BYTES + TAG_BYTES {
            return Err(WilisError::AuthenticationFailed);
        }
        let kem_ct = KemCiphertext::from_bytes(&m2[..KEM_CT_BYTES])?;
        let server_confirm: [u8; TAG_BYTES] = m2[KEM_CT_BYTES..].try_into().expect("32 bytes");
        let resp = PakeServerHello {
            kem_ct,
            server_confirm,
        };
        let (pake_key, finish) = pake_client_finish(client_state, &resp)?;
        write_frame(&mut stream, FRAME_PAKE_3, &finish.client_confirm)?;

        // Exchange fresh ephemeral WilisKEM public keys authenticated under the PAKE key for PCS rekeying
        let (local_sk, local_pk) = keygen()?;
        let enc_c_pk = seal_pake_box(pake_key.as_bytes(), PAKE_PK_AAD_C2S, &local_pk.to_bytes())?;
        write_frame(&mut stream, FRAME_EPHEMERAL_PK, &enc_c_pk)?;

        let (ft2, enc_s_pk) = read_frame(&mut stream)?;
        if ft2 != FRAME_EPHEMERAL_PK {
            return Err(WilisError::AuthenticationFailed);
        }
        let peer_pk_bytes = open_pake_box(pake_key.as_bytes(), PAKE_PK_AAD_S2C, &enc_s_pk)?;
        let peer_pk = KemPublicKey::from_bytes(&peer_pk_bytes)?;

        let session =
            PqRatchetSession::from_bootstrap(pake_key.as_bytes(), context, true, local_sk, peer_pk);
        Ok(Self {
            stream,
            session,
            msgs_since_rekey: 0,
        })
    }

    /// Accepts a zero-PKI passphrase-authenticated PQ TCP channel using `WilisPAKE` + `PqRatchetSession`.
    pub fn accept_pake(mut stream: TcpStream, passphrase: &[u8], context: &[u8]) -> Result<Self> {
        configure_stream(&stream);

        let (ft, m1) = read_frame(&mut stream)?;
        if ft != FRAME_PAKE_1 || m1.len() != SALT_BYTES + 8 + KEM_PK_BYTES {
            return Err(WilisError::AuthenticationFailed);
        }
        let mut salt = [0u8; SALT_BYTES];
        salt.copy_from_slice(&m1[0..SALT_BYTES]);
        let memory_blocks =
            u32::from_le_bytes(m1[SALT_BYTES..SALT_BYTES + 4].try_into().expect("4B"));
        let passes = u32::from_le_bytes(m1[SALT_BYTES + 4..SALT_BYTES + 8].try_into().expect("4B"));
        let kdf_params = KdfParams {
            memory_blocks,
            passes,
        };
        kdf_params.validate()?;
        let hello = PakeClientHello {
            salt,
            kdf_params,
            masked_pk: m1[SALT_BYTES + 8..].to_vec(),
        };

        let (srv_state, resp) = pake_server_respond(passphrase, context, &hello)?;
        let mut m2 = Vec::with_capacity(KEM_CT_BYTES + TAG_BYTES);
        m2.extend_from_slice(&resp.kem_ct.to_bytes());
        m2.extend_from_slice(&resp.server_confirm);
        write_frame(&mut stream, FRAME_PAKE_2, &m2)?;

        let (ft3, m3) = read_frame(&mut stream)?;
        if ft3 != FRAME_PAKE_3 || m3.len() != TAG_BYTES {
            return Err(WilisError::AuthenticationFailed);
        }
        let client_confirm: [u8; TAG_BYTES] = m3.try_into().expect("32 bytes");
        let pake_key = pake_server_finish(srv_state, &PakeClientFinish { client_confirm })?;

        let (ft4, enc_c_pk) = read_frame(&mut stream)?;
        if ft4 != FRAME_EPHEMERAL_PK {
            return Err(WilisError::AuthenticationFailed);
        }
        let peer_pk_bytes = open_pake_box(pake_key.as_bytes(), PAKE_PK_AAD_C2S, &enc_c_pk)?;
        let peer_pk = KemPublicKey::from_bytes(&peer_pk_bytes)?;

        let (local_sk, local_pk) = keygen()?;
        let enc_s_pk = seal_pake_box(pake_key.as_bytes(), PAKE_PK_AAD_S2C, &local_pk.to_bytes())?;
        write_frame(&mut stream, FRAME_EPHEMERAL_PK, &enc_s_pk)?;

        let session =
            PqRatchetSession::from_bootstrap(pake_key.as_bytes(), context, false, local_sk, peer_pk);
        Ok(Self {
            stream,
            session,
            msgs_since_rekey: 0,
        })
    }

    /// Returns current Post-Compromise Security ratchet epoch.
    pub fn epoch(&self) -> u64 {
        self.session.epoch()
    }

    /// Sends an authenticated ratcheted message, triggering a fresh PQ KEM PCS rekey
    /// automatically every `AUTO_REKEY_INTERVAL` messages.
    pub fn send_message(&mut self, plaintext: &[u8]) -> Result<()> {
        if self.msgs_since_rekey >= AUTO_REKEY_INTERVAL {
            self.rekey()?;
        }
        let pkt = self.session.encrypt_next(plaintext, NET_AAD);
        write_frame(&mut self.stream, FRAME_DATA, &pkt.to_bytes())?;
        self.msgs_since_rekey += 1;
        Ok(())
    }

    /// Explicitly triggers a post-quantum Module-LWE KEM ratchet rekey (`WPRK` v1).
    pub fn rekey(&mut self) -> Result<()> {
        let rekey_pkt = self.session.initiate_rekey()?;
        write_frame(&mut self.stream, FRAME_REKEY, &rekey_pkt.to_bytes())?;
        self.msgs_since_rekey = 0;
        Ok(())
    }

    /// Sends an authenticated end-of-stream marker (`FRAME_EOF`) preventing TCP truncation attacks.
    pub fn send_eof(&mut self) -> Result<()> {
        let pkt = self.session.encrypt_next(EOF_TOKEN, NET_AAD);
        write_frame(&mut self.stream, FRAME_EOF, &pkt.to_bytes())
    }

    /// Receives the next authenticated message (`Ok(Some(bytes))`) or clean EOF (`Ok(None)`),
    /// transparently processing any interleaved `WPRK` v1 post-quantum PCS rekey frames.
    pub fn recv_message(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            let (ft, payload) = read_frame(&mut self.stream)?;
            match ft {
                FRAME_REKEY => {
                    let rekey = PqRekeyPacket::from_bytes(&payload)?;
                    self.session.accept_rekey(&rekey)?;
                }
                FRAME_DATA => {
                    let pkt = PqMessagePacket::from_bytes(&payload)?;
                    let pt = self.session.decrypt_packet(&pkt, NET_AAD)?;
                    return Ok(Some(pt));
                }
                FRAME_EOF => {
                    let pkt = PqMessagePacket::from_bytes(&payload)?;
                    let pt = self.session.decrypt_packet(&pkt, NET_AAD)?;
                    if !ct_eq(&pt, EOF_TOKEN) {
                        return Err(WilisError::AuthenticationFailed);
                    }
                    return Ok(None);
                }
                _ => {
                    return Err(WilisError::InvalidFormat(format!(
                        "unexpected WNET frame type: 0x{ft:02x}"
                    )));
                }
            }
        }
    }
}

/// Summary returned after sending a file over `WilisNet`.
#[derive(Debug, Clone)]
pub struct SentFileSummary {
    pub bytes_sent: u64,
    pub digest: [u8; HASH_BYTES],
    pub final_epoch: u64,
}

/// Summary returned after receiving and verifying a file over `WilisNet`.
#[derive(Debug, Clone)]
pub struct ReceivedFileSummary {
    pub saved_path: PathBuf,
    pub bytes_received: u64,
    pub digest: [u8; HASH_BYTES],
    pub final_epoch: u64,
}

fn stream_send_file(channel: &mut PqTcpChannel, file_path: &Path) -> Result<SentFileSummary> {
    let file_name = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| WilisError::InvalidEncoding("source filename must be valid UTF-8".into()))?;
    // Ensure basename itself is safe for receiver
    sanitize_archive_path(Path::new("."), file_name)?;

    let mut file = BufReader::new(File::open(file_path)?);
    let file_len = fs::metadata(file_path)?.len();

    let name_bytes = file_name.as_bytes();
    let mut meta = Vec::with_capacity(4 + name_bytes.len() + 8);
    meta.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
    meta.extend_from_slice(name_bytes);
    meta.extend_from_slice(&file_len.to_le_bytes());
    channel.send_message(&meta)?;

    let mut hasher = WilisHash::new();
    let mut buf = vec![0u8; FILE_CHUNK_BYTES];
    let mut sent: u64 = 0;

    let send_res = (|| -> Result<()> {
        loop {
            let n = match file.read(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            channel.send_message(&buf[..n])?;
            sent = sent
                .checked_add(n as u64)
                .ok_or_else(|| WilisError::InvalidFormat("sent byte counter overflow".into()))?;
        }
        Ok(())
    })();
    zeroize_bytes(&mut buf);
    send_res?;

    if sent != file_len {
        return Err(WilisError::InvalidFormat(
            "source file changed size while transmitting".into(),
        ));
    }

    let digest = hasher.finalize();
    let mut trailer = Vec::with_capacity(12 + HASH_BYTES);
    trailer.extend_from_slice(b"WNET-HASH-V1");
    trailer.extend_from_slice(&digest);
    channel.send_message(&trailer)?;
    channel.send_eof()?;

    Ok(SentFileSummary {
        bytes_sent: sent,
        digest,
        final_epoch: channel.epoch(),
    })
}

fn stream_recv_file(channel: &mut PqTcpChannel, out_dir: &Path) -> Result<ReceivedFileSummary> {
    let meta = channel
        .recv_message()?
        .ok_or_else(|| WilisError::InvalidFormat("unexpected EOF before file metadata".into()))?;
    if meta.len() < 12 {
        return Err(WilisError::InvalidFormat("truncated file transfer metadata".into()));
    }
    let name_len = u32::from_le_bytes(meta[0..4].try_into().expect("4 bytes")) as usize;
    if name_len == 0 || name_len > 255 || meta.len() != 4 + name_len + 8 {
        return Err(WilisError::InvalidFormat("invalid file transfer metadata".into()));
    }
    let raw_name = std::str::from_utf8(&meta[4..4 + name_len])
        .map_err(|_| WilisError::InvalidEncoding("non-UTF-8 remote filename".into()))?;
    if raw_name.contains('/') || raw_name.contains('\\') {
        return Err(WilisError::InvalidFormat(
            "remote filename must be a plain basename without directory separators".into(),
        ));
    }
    let target_path = sanitize_archive_path(out_dir, raw_name)?;
    let expected_len = u64::from_le_bytes(meta[4 + name_len..].try_into().expect("8 bytes"));

    fs::create_dir_all(out_dir)?;
    let (tmp_path, tmp_file) = create_unique_temp_file(&target_path, true)?;

    let recv_res = (|| -> Result<(u64, [u8; HASH_BYTES])> {
        let mut writer = BufWriter::new(tmp_file);
        let mut hasher = WilisHash::new();
        let mut received: u64 = 0;

        while received < expected_len {
            let mut chunk = channel.recv_message()?.ok_or_else(|| {
                WilisError::InvalidFormat("unexpected EOF before full file payload received".into())
            })?;
            let next_total = received.checked_add(chunk.len() as u64).ok_or_else(|| {
                zeroize_bytes(&mut chunk);
                WilisError::InvalidFormat("received byte counter overflow".into())
            })?;
            if next_total > expected_len {
                zeroize_bytes(&mut chunk);
                return Err(WilisError::InvalidFormat(
                    "peer sent more bytes than declared file length".into(),
                ));
            }
            hasher.update(&chunk);
            let wres = writer.write_all(&chunk);
            zeroize_bytes(&mut chunk);
            wres?;
            received = next_total;
        }

        // Expect authenticated hash trailer frame
        let trailer = channel
            .recv_message()?
            .ok_or_else(|| WilisError::InvalidFormat("missing authenticated hash trailer".into()))?;
        if trailer.len() != 12 + HASH_BYTES || &trailer[0..12] != b"WNET-HASH-V1" {
            return Err(WilisError::InvalidFormat("invalid hash trailer frame".into()));
        }
        let expected_digest = &trailer[12..];
        let actual_digest = hasher.finalize();
        if !ct_eq(&actual_digest, expected_digest) {
            return Err(WilisError::AuthenticationFailed);
        }

        // Expect authenticated EOF frame
        if channel.recv_message()?.is_some() {
            return Err(WilisError::InvalidFormat(
                "unexpected extra frame after file transfer trailer".into(),
            ));
        }

        let file = writer.into_inner().map_err(|e| e.into_error())?;
        file.sync_all()?;
        Ok((received, actual_digest))
    })();

    match recv_res {
        Ok((bytes_received, digest)) => {
            if let Err(e) = fs::rename(&tmp_path, &target_path) {
                let _ = fs::remove_file(&tmp_path);
                return Err(e.into());
            }
            Ok(ReceivedFileSummary {
                saved_path: target_path,
                bytes_received,
                digest,
                final_epoch: channel.epoch(),
            })
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}

/// Sends a file over a mutually authenticated PQ PKI TCP channel (`WilisKEM` + `WilisSign` + `PqRatchetSession`).
pub fn send_file_over_tcp(
    addr: &str,
    file_path: &Path,
    initiator_sign_sk: &mut SigningKey,
    responder_kem_pk: &KemPublicKey,
    context: &[u8],
) -> Result<SentFileSummary> {
    let mut ch = PqTcpChannel::connect(addr, initiator_sign_sk, responder_kem_pk, context)?;
    stream_send_file(&mut ch, file_path)
}

/// Accepts one connection on `listener` and receives a file over a mutually authenticated PQ PKI TCP channel.
pub fn recv_file_over_tcp(
    listener: &TcpListener,
    out_dir: &Path,
    responder_kem_sk: &KemSecretKey,
    initiator_vk: &VerifyingKey,
    context: &[u8],
) -> Result<ReceivedFileSummary> {
    let (stream, _) = listener.accept()?;
    let mut ch = PqTcpChannel::accept(stream, responder_kem_sk, initiator_vk, context)?;
    stream_recv_file(&mut ch, out_dir)
}

/// Sends a file over a zero-PKI passphrase-authenticated PQ TCP channel (`WilisPAKE` + `PqRatchetSession`).
pub fn send_file_pake(
    addr: &str,
    file_path: &Path,
    passphrase: &[u8],
    context: &[u8],
    kdf_params: KdfParams,
) -> Result<SentFileSummary> {
    let mut ch = PqTcpChannel::connect_pake(addr, passphrase, context, kdf_params)?;
    stream_send_file(&mut ch, file_path)
}

/// Accepts one connection on `listener` and receives a file over a zero-PKI `WilisPAKE` PQ TCP channel.
pub fn recv_file_pake(
    listener: &TcpListener,
    out_dir: &Path,
    passphrase: &[u8],
    context: &[u8],
) -> Result<ReceivedFileSummary> {
    let (stream, _) = listener.accept()?;
    let mut ch = PqTcpChannel::accept_pake(stream, passphrase, context)?;
    stream_recv_file(&mut ch, out_dir)
}
