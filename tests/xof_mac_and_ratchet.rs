//! Tests for `WilisXOF`, `WilisMAC`, subkey derivation, and `WilisRatchet` forward-secret sessions.

use wilis::error::WilisError;
use wilis::mac::{derive_subkey, mac, verify_mac, WilisMac};
use wilis::ratchet::{RatchetPacket, RatchetSession, MAX_SKIP_WINDOW};
use wilis::xof::WilisXof;

#[test]
fn xof_streaming_equivalence_and_domain_separation() {
    let oneshot = WilisXof::derive(b"label-a", b"seed-material-1234567890", 200);

    let mut xof = WilisXof::new(b"label-a");
    xof.absorb(b"seed-");
    xof.absorb(b"material-");
    xof.absorb(b"1234567890");
    let mut streamed = Vec::new();
    for chunk_len in [1usize, 7, 16, 33, 143] {
        streamed.extend_from_slice(&xof.squeeze_vec(chunk_len));
    }
    assert_eq!(oneshot, streamed);

    // Distinct domain labels must produce completely unrelated streams
    let other = WilisXof::derive(b"label-b", b"seed-material-1234567890", 200);
    assert_ne!(oneshot, other);
}

#[test]
fn mac_streaming_verify_tamper_and_subkey_derivation() {
    let key = [0x33u8; 32];
    let msg = b"Authenticate this payload without encrypting it!";

    let tag = mac(&key, msg);
    assert!(verify_mac(&key, msg, &tag));

    let mut m = WilisMac::new(&key);
    for chunk in msg.chunks(3) {
        m.update(chunk);
    }
    assert_eq!(m.finalize(), tag);

    let mut bad_tag = tag;
    bad_tag[0] ^= 1;
    assert!(!verify_mac(&key, msg, &bad_tag));

    let mut bad_key = key;
    bad_key[31] ^= 1;
    assert!(!verify_mac(&bad_key, msg, &tag));

    let sk_enc = derive_subkey(&key, b"encryption");
    let sk_mac = derive_subkey(&key, b"authentication");
    assert_ne!(sk_enc.as_bytes(), sk_mac.as_bytes());
    assert_ne!(sk_enc.as_bytes(), &key);
}

#[test]
fn ratchet_bidirectional_out_of_order_replay_and_forged_dos_protection() {
    let root = [0x7Au8; 32];
    let mut wildan = RatchetSession::from_shared_secret(&root, true);
    let mut elis = RatchetSession::from_shared_secret(&root, false);

    // Wildan sends 6 messages; they arrive out of order: 0, 2, 1, 5, 3, 4
    let pkts: Vec<RatchetPacket> = (0..6)
        .map(|i| {
            let p = wildan.encrypt_next(format!("msg-{i}").as_bytes(), b"chat");
            RatchetPacket::from_bytes(&p.to_bytes()).unwrap()
        })
        .collect();

    for &idx in &[0usize, 2, 1, 5, 3, 4] {
        let pt = elis.decrypt_packet(&pkts[idx], b"chat").unwrap();
        assert_eq!(pt, format!("msg-{idx}").as_bytes());
    }

    // Replay of any previously decrypted packet MUST be rejected
    for pkt in &pkts {
        assert!(matches!(
            elis.decrypt_packet(pkt, b"chat"),
            Err(WilisError::AuthenticationFailed)
        ));
    }

    // Forged future packet (+10) MUST fail AND MUST NOT corrupt Elis's chain for valid msg #6!
    let forged = RatchetPacket {
        counter: 16,
        ciphertext: vec![0xAA; 16],
        tag: [0xBB; 32],
    };
    assert!(matches!(
        elis.decrypt_packet(&forged, b"chat"),
        Err(WilisError::AuthenticationFailed)
    ));

    // Excessive counter jump (> MAX_SKIP_WINDOW) MUST be rejected
    let huge_jump = RatchetPacket {
        counter: 6 + MAX_SKIP_WINDOW + 5,
        ciphertext: vec![0; 8],
        tag: [0; 32],
    };
    assert!(matches!(
        elis.decrypt_packet(&huge_jump, b"chat"),
        Err(WilisError::AuthenticationFailed)
    ));

    // Legitimate message #6 still decrypts cleanly after forged attacks
    let pkt6 = wildan.encrypt_next(b"still-in-sync!", b"chat");
    assert_eq!(elis.decrypt_packet(&pkt6, b"chat").unwrap(), b"still-in-sync!");

    // Reverse direction (Elis -> Wildan) uses independent chain keys
    let reply = elis.encrypt_next(b"Hello Wildan!", b"chat");
    assert_eq!(wildan.decrypt_packet(&reply, b"chat").unwrap(), b"Hello Wildan!");
}
