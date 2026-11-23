//! Tests for `WilisDir` full-directory encryption (including Zip-Slip protection)
//! and `WilisVault` encrypted local secret manager.

use std::fs;
use std::path::Path;

use wilis::archive::unpack::sanitize_archive_path;
use wilis::archive::{decrypt_directory_with_passphrase, encrypt_directory_with_passphrase};
use wilis::error::WilisError;
use wilis::hash::hash;
use wilis::kdf::KdfParams;
use wilis::vault::Vault;

fn temp_test_dir(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("wilis_test_{name}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn directory_archive_round_trip_preserves_nested_hierarchy() {
    let base = temp_test_dir("dir_roundtrip");
    let src = base.join("src_folder");
    let nested = src.join("sub_a").join("deep_b");
    fs::create_dir_all(&nested).unwrap();

    fs::write(src.join("root.txt"), b"Root file content").unwrap();
    fs::write(src.join("sub_a").join("bin.dat"), vec![0xE5u8; 70_000]).unwrap();
    fs::write(nested.join("empty.txt"), b"").unwrap();

    let archive_file = base.join("bundle.wils");
    let restored = base.join("restored_folder");

    let (count_in, _) = encrypt_directory_with_passphrase(
        b"dir-pass",
        None,
        &src,
        &archive_file,
        b"dir-aad",
        KdfParams::FAST_TEST,
    )
    .unwrap();
    assert_eq!(count_in, 3);

    let count_out = decrypt_directory_with_passphrase(
        b"dir-pass",
        None,
        &archive_file,
        &restored,
        b"dir-aad",
    )
    .unwrap();
    assert_eq!(count_out, 3);

    assert_eq!(fs::read(restored.join("root.txt")).unwrap(), b"Root file content");
    assert_eq!(
        fs::read(restored.join("sub_a").join("bin.dat")).unwrap(),
        vec![0xE5u8; 70_000]
    );
    assert_eq!(
        fs::read(restored.join("sub_a").join("deep_b").join("empty.txt")).unwrap(),
        b""
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn archive_path_sanitizer_blocks_zip_slip_traversal() {
    let dest = Path::new("/tmp/safe_dest");

    assert!(sanitize_archive_path(dest, "normal/file.txt").is_ok());
    assert!(sanitize_archive_path(dest, "../escape.txt").is_err());
    assert!(sanitize_archive_path(dest, "a/../../escape.txt").is_err());
    assert!(sanitize_archive_path(dest, "/etc/passwd").is_err());
    assert!(sanitize_archive_path(dest, "win\\path\\file.txt").is_err());
    assert!(sanitize_archive_path(dest, "null\0byte.txt").is_err());
    assert!(sanitize_archive_path(dest, "").is_err());
}

#[test]
fn vault_crud_2fa_persistence_and_tamper_rejection() {
    let base = temp_test_dir("vault");
    let vault_path = base.join("secrets.wils");
    let kf = hash(b"vault-2fa-keyfile");

    let mut v = Vault::new();
    v.set("github_token", "super-secret-value-1").unwrap();
    v.set("db_password", "wildan-elis-db-pass").unwrap();
    assert_eq!(v.len(), 2);
    assert_eq!(v.list_names(), vec!["db_password", "github_token"]);

    v.save_encrypted(&vault_path, b"master-pass", Some(&kf), KdfParams::FAST_TEST)
        .unwrap();

    // Load with correct passphrase + keyfile
    let mut loaded = Vault::load_encrypted(&vault_path, b"master-pass", Some(&kf)).unwrap();
    assert_eq!(loaded.get("github_token"), Some("super-secret-value-1"));
    assert_eq!(loaded.get("db_password"), Some("wildan-elis-db-pass"));

    // Delete entry & re-save
    assert!(loaded.delete("db_password"));
    loaded
        .save_encrypted(&vault_path, b"master-pass", Some(&kf), KdfParams::FAST_TEST)
        .unwrap();

    let reloaded = Vault::load_encrypted(&vault_path, b"master-pass", Some(&kf)).unwrap();
    assert_eq!(reloaded.len(), 1);
    assert_eq!(reloaded.get("db_password"), None);

    // Wrong passphrase or missing keyfile MUST fail
    assert!(matches!(
        Vault::load_encrypted(&vault_path, b"wrong-pass", Some(&kf)),
        Err(WilisError::AuthenticationFailed)
    ));
    assert!(matches!(
        Vault::load_encrypted(&vault_path, b"master-pass", None),
        Err(WilisError::AuthenticationFailed)
    ));

    let _ = fs::remove_dir_all(&base);
}
